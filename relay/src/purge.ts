// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

// Canonical owner-purge v1 relay endpoint. It retains only opaque operation
// fingerprints and canonical request digests; it never records an owner
// association, raw operation id, envelope, integrity value, or target snapshot.

import { INSTANCE_ID_RE, hasValidBearer } from "./entitlement";
import type { Env } from "./env";
import { json, readJson } from "./http";
import { log } from "./logging";
import { base64UrlDecode, base64UrlEncode } from "./tokens";

const PURGE_ROUTE = "/internal/deletion/purge";
const PURGE_CONFIRM_ROUTE = "/internal/deletion/purge/confirm";
const MAX_PURGE_BODY_BYTES = 32 * 1024;
const MAX_OPERATION_ID_BYTES = 256;
const MAX_INSTANCE_IDS = 100;
const PROTOCOL_VERSION = 1;
const SERVICE = "relay";
const REQUEST_MAX_LIFETIME_MS = 7 * 24 * 60 * 60 * 1000;
const ATTESTATION_MAX_LIFETIME_MS = 5 * 60 * 1000;
const REQUEST_FIELDS = [
	"version",
	"key_version",
	"operation_id",
	"service",
	"association_snapshot",
	"request_digest",
	"issued_at",
	"expires_at",
	"integrity",
] as const;
const ATTESTATION_FIELDS = [
	"version",
	"key_version",
	"operation_id",
	"service",
	"request_digest",
	"state",
	"issued_at",
	"expires_at",
	"integrity",
] as const;
const CONFIRMATION_WRAPPER_FIELDS = ["envelope", "attestation"] as const;
const BASE64URL_SHA256_RE = /^[A-Za-z0-9_-]{43}$/;

type KeyVersion = 1 | 2;
type PurgeDisposition = "retryable" | "complete" | "confirmed" | "expired" | "refused";
type BindingDisposition = Exclude<PurgeDisposition, "expired" | "refused">;
type IntegrityKind = "request" | "confirm" | "response";
type RequestFailure = "malformed" | "digest_mismatch" | "instance_limit" | "lifetime" | "expired";

interface PurgeKeys {
	readonly 1: string;
	readonly 2: string;
}

interface RawRequestEnvelope {
	version: number;
	key_version: KeyVersion;
	operation_id: string;
	service: string;
	association_snapshot: unknown;
	request_digest: string;
	issued_at: number;
	expires_at: number;
	integrity: string;
}

interface AttestationEnvelope {
	version: number;
	key_version: KeyVersion;
	operation_id: string;
	service: string;
	request_digest: string;
	state: string;
	issued_at: number;
	expires_at: number;
	integrity: string;
}

interface ResponseContext {
	keyVersion: KeyVersion;
	operationId: string;
	requestDigest: string;
}

interface PurgeOperation {
	operation_id_hash: string;
	request_digest: string;
	disposition: BindingDisposition;
	expires_at: number;
}

function unixNow(): number {
	return Date.now();
}

export async function handlePurge(request: Request, env: Env, now = unixNow()): Promise<Response> {
	const keys = purgeKeys(env);
	if (!env.PURGE_SECRET || !keys) return unprovisioned();
	if (!hasValidBearer(request, env.PURGE_SECRET)) {
		log({ event: "unauthorized", route: PURGE_ROUTE, reason: "bad_bearer" });
		return json({ error: "unauthorized" }, 401);
	}

	const body = await readJson<unknown>(request, MAX_PURGE_BODY_BYTES);
	if (!body.ok) return plainRefusal("owner_purge_malformed", 400);
	const raw = parseRequestEnvelope(body.value);
	if (!raw) return plainRefusal("owner_purge_malformed", 400);
	if (raw.service !== SERVICE) return plainRefusal("owner_purge_wrong_service", 400);

	const integrity = await verifyIntegrity(raw, "request", keys);
	if (!integrity) return plainRefusal("owner_purge_bad_integrity", 401);
	const context = responseContext(raw);
	const validated = await validateRequest(raw, now);
	if (!validated.ok) {
		if (validated.reason === "expired") return expired(context, keys, 0);
		return refused(context, keys, requestFailureReason(validated.reason), 400);
	}

	const operationHash = await hashOperationId(raw.operation_id);
	let binding: PurgeOperation | null;
	try {
		await env.DB.prepare(
			"INSERT INTO purge_operations (operation_id_hash, request_digest, disposition, expires_at) VALUES (?, ?, 'retryable', ?) ON CONFLICT(operation_id_hash) DO NOTHING",
		)
			.bind(operationHash, raw.request_digest, raw.expires_at)
			.run();
		binding = await loadPurgeOperation(operationHash, env);
	} catch {
		return retryable(context, keys, 0);
	}

	if (!binding) return retryable(context, keys, 0);
	const settled = await submitBindingResponse(binding, raw, context, keys, now, 0);
	if (settled) return settled;

	let completed = 0;
	for (const instanceId of new Set(validated.instanceIds)) {
		try {
			await env.DB.batch([
				env.DB.prepare("DELETE FROM pending_grants WHERE instance_id = ?").bind(instanceId),
				env.DB.prepare("DELETE FROM instances WHERE instance_id = ?").bind(instanceId),
			]);
			completed += 1;
		} catch {
			return retryable(context, keys, completed);
		}
	}

	try {
		const result = await env.DB.prepare(
			"UPDATE purge_operations SET disposition = 'complete' WHERE operation_id_hash = ? AND disposition = 'retryable'",
		)
			.bind(operationHash)
			.run();
		if (result.meta.changes === 0) {
			binding = await loadPurgeOperation(operationHash, env);
			if (!binding) return retryable(context, keys, completed);
			const raced = await submitBindingResponse(binding, raw, context, keys, now, completed);
			if (raced) return raced;
			return retryable(context, keys, completed);
		}
	} catch {
		return retryable(context, keys, completed);
	}

	return complete(context, keys, completed);
}

export async function handlePurgeConfirm(
	request: Request,
	env: Env,
	now = unixNow(),
): Promise<Response> {
	const keys = purgeKeys(env);
	if (!env.PURGE_SECRET || !keys) return unprovisioned();
	if (!hasValidBearer(request, env.PURGE_SECRET)) {
		log({ event: "unauthorized", route: PURGE_CONFIRM_ROUTE, reason: "bad_bearer" });
		return json({ error: "unauthorized" }, 401);
	}

	const body = await readJson<unknown>(request, MAX_PURGE_BODY_BYTES);
	if (!body.ok) return plainRefusal("owner_purge_malformed", 400);
	const wrapper = exactRecord(body.value, CONFIRMATION_WRAPPER_FIELDS);
	if (!wrapper || !isRecord(wrapper.envelope) || !isRecord(wrapper.attestation)) {
		return plainRefusal("owner_purge_malformed", 400);
	}

	const envelope = parseRequestEnvelope(wrapper.envelope);
	if (!envelope) return plainRefusal("owner_purge_malformed", 400);
	if (envelope.service !== SERVICE) return plainRefusal("owner_purge_wrong_service", 400);
	const envelopeIntegrity = await verifyIntegrity(envelope, "request", keys);
	if (!envelopeIntegrity) return plainRefusal("owner_purge_bad_integrity", 401);
	const validatedEnvelope = await validateRequest(envelope, now);
	if (!validatedEnvelope.ok) {
		if (validatedEnvelope.reason === "expired")
			return plainRefusal("owner_purge_request_lifetime", 400);
		return plainRefusal(requestFailureReason(validatedEnvelope.reason), 400);
	}

	const attestation = parseAttestationEnvelope(wrapper.attestation);
	if (!attestation) return plainRefusal("owner_purge_malformed", 400);
	if (attestation.service !== SERVICE) {
		return plainRefusal("owner_purge_wrong_service", 400);
	}
	const attestationIntegrity = await verifyIntegrity(attestation, "confirm", keys);
	if (!attestationIntegrity) return plainRefusal("owner_purge_bad_integrity", 401);
	const failure = validateAttestation(attestation, now);
	if (failure) {
		if (failure === "expired") return plainRefusal("owner_purge_attestation_lifetime", 400);
		return plainRefusal(attestationFailureReason(failure), 400);
	}
	const context = responseContext(envelope);
	if (
		envelope.operation_id !== attestation.operation_id ||
		envelope.service !== attestation.service ||
		envelope.request_digest !== attestation.request_digest ||
		envelope.key_version !== attestation.key_version
	) {
		return refused(context, keys, "owner_purge_binding_mismatch", 409);
	}

	const operationHash = await hashOperationId(envelope.operation_id);
	let binding: PurgeOperation | null;
	try {
		binding = await loadPurgeOperation(operationHash, env);
	} catch {
		return retryable(context, keys, 0);
	}
	if (!binding) return refused(context, keys, "owner_purge_binding_absent", 409);
	if (binding.request_digest !== envelope.request_digest) {
		return refused(context, keys, "owner_purge_binding_mismatch", 409);
	}
	if (binding.expires_at !== envelope.expires_at) {
		return refused(context, keys, "owner_purge_binding_mismatch", 409);
	}
	if (now >= binding.expires_at) return expired(context, keys, 0);
	if (binding.disposition === "retryable") {
		return refused(context, keys, "owner_purge_binding_mismatch", 409);
	}
	if (binding.disposition === "confirmed") return confirmed(context, keys);

	try {
		const result = await env.DB.prepare(
			"UPDATE purge_operations SET disposition = 'confirmed' WHERE operation_id_hash = ? AND disposition = 'complete' AND expires_at > ?",
		)
			.bind(operationHash, now)
			.run();
		if (result.meta.changes === 0) {
			binding = await loadPurgeOperation(operationHash, env);
			if (!binding) return refused(context, keys, "owner_purge_binding_absent", 409);
			if (binding.request_digest !== envelope.request_digest) {
				return refused(context, keys, "owner_purge_binding_mismatch", 409);
			}
			if (binding.expires_at !== envelope.expires_at) {
				return refused(context, keys, "owner_purge_binding_mismatch", 409);
			}
			if (now >= binding.expires_at) return expired(context, keys, 0);
			if (binding.disposition === "confirmed") return confirmed(context, keys);
			if (binding.disposition === "retryable") {
				return refused(context, keys, "owner_purge_binding_mismatch", 409);
			}
			return retryable(context, keys, 0);
		}
	} catch {
		return retryable(context, keys, 0);
	}

	return confirmed(context, keys);
}

export function canonicalizeOwnerPurgeJson(value: unknown): string {
	if (value === null) return "null";
	if (typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
	if (typeof value === "number") {
		if (!Number.isSafeInteger(value))
			throw new TypeError("owner-purge JSON number must be a safe integer");
		return JSON.stringify(value);
	}
	if (Array.isArray(value)) return `[${value.map(canonicalizeOwnerPurgeJson).join(",")}]`;
	if (!isRecord(value)) throw new TypeError("owner-purge JSON value must be JSON");
	return `{${Object.keys(value)
		.sort(compareUtf8)
		.map((key) => `${JSON.stringify(key)}:${canonicalizeOwnerPurgeJson(value[key])}`)
		.join(",")}}`;
}

export function ownerPurgeIntegrityFrame(
	domain: string,
	canonicalWithoutIntegrity: string,
): Uint8Array {
	const encoder = new TextEncoder();
	const domainBytes = encoder.encode(domain);
	const bodyBytes = encoder.encode(canonicalWithoutIntegrity);
	const frame = new Uint8Array(16 + domainBytes.byteLength + bodyBytes.byteLength);
	frame.set(uint64be(domainBytes.byteLength), 0);
	frame.set(domainBytes, 8);
	frame.set(uint64be(bodyBytes.byteLength), 8 + domainBytes.byteLength);
	frame.set(bodyBytes, 16 + domainBytes.byteLength);
	return frame;
}

export async function ownerPurgeRequestDigest(
	version: number,
	keyVersion: number,
	service: string,
	associationSnapshot: unknown,
): Promise<string> {
	const canonical = canonicalizeOwnerPurgeJson({
		version,
		key_version: keyVersion,
		service,
		association_snapshot: associationSnapshot,
	});
	return sha256Base64Url(new TextEncoder().encode(canonical));
}

export async function purgeExpiredOperations(env: Env, now = unixNow()): Promise<number> {
	const result = await env.DB.prepare("DELETE FROM purge_operations WHERE expires_at <= ?")
		.bind(now)
		.run();
	return result.meta.changes;
}

function parseRequestEnvelope(value: unknown): RawRequestEnvelope | null {
	const record = exactRecord(value, REQUEST_FIELDS);
	const common = record ? commonEnvelopeFields(record) : null;
	if (!record || !common) return null;
	return { ...common, association_snapshot: record.association_snapshot };
}

function parseAttestationEnvelope(value: unknown): AttestationEnvelope | null {
	const record = exactRecord(value, ATTESTATION_FIELDS);
	const common = record ? commonEnvelopeFields(record) : null;
	if (!record || !common || typeof record.state !== "string") return null;
	return { ...common, state: record.state };
}

function commonEnvelopeFields(
	record: Record<string, unknown>,
): Omit<RawRequestEnvelope, "association_snapshot"> | null {
	if (
		!isSafeInteger(record.version) ||
		!isKeyVersion(record.key_version) ||
		typeof record.operation_id !== "string" ||
		typeof record.service !== "string" ||
		typeof record.request_digest !== "string" ||
		!isSafeInteger(record.issued_at) ||
		!isSafeInteger(record.expires_at) ||
		typeof record.integrity !== "string"
	) {
		return null;
	}
	return {
		version: record.version,
		key_version: record.key_version,
		operation_id: record.operation_id,
		service: record.service,
		request_digest: record.request_digest,
		issued_at: record.issued_at,
		expires_at: record.expires_at,
		integrity: record.integrity,
	};
}

async function validateRequest(
	raw: RawRequestEnvelope,
	now: number,
): Promise<{ ok: true; instanceIds: string[] } | { ok: false; reason: RequestFailure }> {
	if (
		!isRecord(raw.association_snapshot) ||
		!exactKeys(raw.association_snapshot, ["instance_ids"])
	) {
		return { ok: false, reason: "malformed" };
	}
	const instanceIds = raw.association_snapshot.instance_ids;
	if (!Array.isArray(instanceIds)) return { ok: false, reason: "malformed" };
	const expectedDigest = await ownerPurgeRequestDigest(
		raw.version,
		raw.key_version,
		raw.service,
		raw.association_snapshot,
	);
	if (!BASE64URL_SHA256_RE.test(raw.request_digest) || raw.request_digest !== expectedDigest) {
		return { ok: false, reason: "digest_mismatch" };
	}
	if (instanceIds.length > MAX_INSTANCE_IDS) return { ok: false, reason: "instance_limit" };
	if (
		!instanceIds.every(
			(instanceId) => typeof instanceId === "string" && INSTANCE_ID_RE.test(instanceId),
		)
	) {
		return { ok: false, reason: "malformed" };
	}
	if (!validOperationId(raw.operation_id)) return { ok: false, reason: "malformed" };
	if (raw.version !== PROTOCOL_VERSION) return { ok: false, reason: "malformed" };
	if (raw.expires_at <= now) return { ok: false, reason: "expired" };
	if (!validLifetime(raw.issued_at, raw.expires_at, now, REQUEST_MAX_LIFETIME_MS)) {
		return { ok: false, reason: "lifetime" };
	}
	return { ok: true, instanceIds: instanceIds as string[] };
}

function validateAttestation(attestation: AttestationEnvelope, now: number): RequestFailure | null {
	if (
		!validOperationId(attestation.operation_id) ||
		!BASE64URL_SHA256_RE.test(attestation.request_digest)
	) {
		return "malformed";
	}
	if (attestation.version !== PROTOCOL_VERSION || attestation.state !== "complete")
		return "malformed";
	if (attestation.expires_at <= now) return "expired";
	if (
		!validLifetime(attestation.issued_at, attestation.expires_at, now, ATTESTATION_MAX_LIFETIME_MS)
	) {
		return "lifetime";
	}
	return null;
}

async function verifyIntegrity(
	envelope: RawRequestEnvelope | AttestationEnvelope,
	kind: Exclude<IntegrityKind, "response">,
	keys: PurgeKeys,
): Promise<boolean> {
	let supplied: Uint8Array;
	try {
		supplied = base64UrlDecode(envelope.integrity);
	} catch {
		return false;
	}
	if (supplied.byteLength !== 32) return false;
	try {
		const frame = ownerPurgeIntegrityFrame(domain(kind), canonicalWithoutIntegrity(envelope));
		let matchingVersion: KeyVersion | null = null;
		for (const version of [1, 2] as const) {
			const expected = await hmacSha256(frame, keys[version]);
			if (crypto.subtle.timingSafeEqual(expected, supplied)) matchingVersion = version;
		}
		return matchingVersion === envelope.key_version;
	} catch {
		return false;
	}
}

async function submitBindingResponse(
	binding: PurgeOperation,
	request: Pick<RawRequestEnvelope, "request_digest" | "expires_at">,
	context: ResponseContext,
	keys: PurgeKeys,
	now: number,
	count: number,
): Promise<Response | null> {
	if (now >= binding.expires_at) return expired(context, keys, count);
	if (
		binding.request_digest !== request.request_digest ||
		binding.expires_at !== request.expires_at
	) {
		return refused(context, keys, "owner_purge_binding_mismatch", 409);
	}
	if (binding.disposition === "confirmed") return confirmed(context, keys);
	if (binding.disposition === "complete") return complete(context, keys, count);
	return null;
}

async function loadPurgeOperation(
	operationIdHash: string,
	env: Env,
): Promise<PurgeOperation | null> {
	const row = await env.DB.prepare(
		"SELECT operation_id_hash, request_digest, disposition, expires_at FROM purge_operations WHERE operation_id_hash = ?",
	)
		.bind(operationIdHash)
		.first<PurgeOperation>();
	return row ?? null;
}

async function hashOperationId(operationId: string): Promise<string> {
	return sha256Base64Url(new TextEncoder().encode(operationId));
}

async function sha256Base64Url(bytes: Uint8Array): Promise<string> {
	return base64UrlEncode(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)));
}

async function signedResponse(
	context: ResponseContext,
	keys: PurgeKeys,
	disposition: PurgeDisposition,
	status: number,
): Promise<Response> {
	const unsigned = {
		version: PROTOCOL_VERSION,
		key_version: context.keyVersion,
		service: SERVICE,
		operation_id: context.operationId,
		request_digest: context.requestDigest,
		disposition,
	};
	const integrity = base64UrlEncode(
		await responseSigner.sign(
			ownerPurgeIntegrityFrame(domain("response"), canonicalizeOwnerPurgeJson(unsigned)),
			keys[context.keyVersion],
		),
	);
	return json({ ...unsigned, integrity }, status);
}

async function complete(
	context: ResponseContext,
	keys: PurgeKeys,
	_count: number,
): Promise<Response> {
	return signedResponse(context, keys, "complete", 200);
}

async function confirmed(context: ResponseContext, keys: PurgeKeys): Promise<Response> {
	return signedResponse(context, keys, "confirmed", 200);
}

async function retryable(
	context: ResponseContext,
	keys: PurgeKeys,
	_count: number,
): Promise<Response> {
	log({ event: "owner_purge_retryable", reason: "owner_purge_database_error" });
	return signedResponse(context, keys, "retryable", 503);
}

async function expired(
	context: ResponseContext,
	keys: PurgeKeys,
	_count: number,
): Promise<Response> {
	log({ event: "owner_purge_expired" });
	return signedResponse(context, keys, "expired", 409);
}

async function refused(
	context: ResponseContext,
	keys: PurgeKeys,
	reason:
		| "owner_purge_malformed"
		| "owner_purge_bad_integrity"
		| "owner_purge_wrong_service"
		| "owner_purge_digest_mismatch"
		| "owner_purge_instance_limit"
		| "owner_purge_request_lifetime"
		| "owner_purge_attestation_lifetime"
		| "owner_purge_binding_mismatch"
		| "owner_purge_binding_absent",
	status: number,
): Promise<Response> {
	log({ event: "owner_purge_refused", reason });
	return signedResponse(context, keys, "refused", status);
}

function unprovisioned(): Response {
	return json({ error: "relay not provisioned" }, 503);
}

function plainRefusal(
	reason:
		| "owner_purge_malformed"
		| "owner_purge_bad_integrity"
		| "owner_purge_wrong_service"
		| "owner_purge_digest_mismatch"
		| "owner_purge_instance_limit"
		| "owner_purge_request_lifetime"
		| "owner_purge_attestation_lifetime",
	status: number,
): Response {
	log({ event: "owner_purge_refused", reason });
	return json({ error: status === 401 ? "unauthorized" : "bad request" }, status);
}

function responseContext(envelope: RawRequestEnvelope | AttestationEnvelope): ResponseContext {
	return {
		keyVersion: envelope.key_version,
		operationId: envelope.operation_id,
		requestDigest: envelope.request_digest,
	};
}

function canonicalWithoutIntegrity(envelope: RawRequestEnvelope | AttestationEnvelope): string {
	const { integrity: _integrity, ...unsigned } = envelope;
	return canonicalizeOwnerPurgeJson(unsigned);
}

function domain(kind: IntegrityKind): string {
	return `solpbc-owner-purge-v1:${SERVICE}:${kind}`;
}

function purgeKeys(env: Env): PurgeKeys | null {
	if (!env.OWNER_PURGE_HMAC_KEY_V1 || !env.OWNER_PURGE_HMAC_KEY_V2) return null;
	return { 1: env.OWNER_PURGE_HMAC_KEY_V1, 2: env.OWNER_PURGE_HMAC_KEY_V2 };
}

export const responseSigner = { sign: hmacSha256 };

async function hmacSha256(frame: Uint8Array, keyText: string): Promise<Uint8Array> {
	const key = await crypto.subtle.importKey(
		"raw",
		new TextEncoder().encode(keyText),
		{ name: "HMAC", hash: "SHA-256" },
		false,
		["sign"],
	);
	return new Uint8Array(await crypto.subtle.sign("HMAC", key, frame));
}

function uint64be(value: number): Uint8Array {
	const view = new DataView(new ArrayBuffer(8));
	view.setBigUint64(0, BigInt(value), false);
	return new Uint8Array(view.buffer);
}

function exactRecord(value: unknown, fields: readonly string[]): Record<string, unknown> | null {
	if (!isRecord(value) || !exactKeys(value, fields)) return null;
	return value;
}

function exactKeys(value: Record<string, unknown>, fields: readonly string[]): boolean {
	const keys = Object.keys(value);
	return keys.length === fields.length && fields.every((field) => Object.hasOwn(value, field));
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isSafeInteger(value: unknown): value is number {
	return typeof value === "number" && Number.isSafeInteger(value);
}

function isKeyVersion(value: unknown): value is KeyVersion {
	return value === 1 || value === 2;
}

function validOperationId(value: string): boolean {
	return value.length > 0 && new TextEncoder().encode(value).byteLength <= MAX_OPERATION_ID_BYTES;
}

function validLifetime(
	issuedAt: number,
	expiresAt: number,
	now: number,
	maxLifetime: number,
): boolean {
	return issuedAt <= now && expiresAt > issuedAt && expiresAt - issuedAt <= maxLifetime;
}

function requestFailureReason(
	failure: Exclude<RequestFailure, "expired">,
):
	| "owner_purge_malformed"
	| "owner_purge_digest_mismatch"
	| "owner_purge_instance_limit"
	| "owner_purge_request_lifetime" {
	switch (failure) {
		case "malformed":
			return "owner_purge_malformed";
		case "digest_mismatch":
			return "owner_purge_digest_mismatch";
		case "instance_limit":
			return "owner_purge_instance_limit";
		case "lifetime":
			return "owner_purge_request_lifetime";
	}
}

function attestationFailureReason(
	failure: Exclude<RequestFailure, "expired">,
): "owner_purge_malformed" | "owner_purge_attestation_lifetime" {
	return failure === "lifetime" ? "owner_purge_attestation_lifetime" : "owner_purge_malformed";
}

function compareUtf8(left: string, right: string): number {
	const leftBytes = new TextEncoder().encode(left);
	const rightBytes = new TextEncoder().encode(right);
	const shared = Math.min(leftBytes.length, rightBytes.length);
	for (let index = 0; index < shared; index += 1) {
		if (leftBytes[index] !== rightBytes[index]) return leftBytes[index] - rightBytes[index];
	}
	return leftBytes.length - rightBytes.length;
}
