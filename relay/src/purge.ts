// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

// Portal owner-purge v1. This control-plane endpoint deliberately persists
// only opaque-operation and target-snapshot fingerprints; it never resolves
// or records a portal-owner association.

import { INSTANCE_ID_RE, hasValidBearer } from "./entitlement";
import type { Env } from "./env";
import { json, readJson } from "./http";
import { log } from "./logging";
import { base64UrlDecode, utf8Decode } from "./tokens";

const PURGE_ROUTE = "/internal/purge";
const PURGE_CONFIRM_ROUTE = "/internal/purge/confirm";
const MAX_PURGE_BODY_BYTES = 32 * 1024;
const MAX_PURGE_CONFIRM_BODY_BYTES = 8 * 1024;
const MAX_OPERATION_ID_BYTES = 256;
const MAX_INSTANCE_IDS = 100;
const MAX_PURGE_LIFETIME_SECONDS = 7 * 24 * 60 * 60;
const MAX_CONFIRM_LIFETIME_SECONDS = 5 * 60;
const COMPLETED_BINDING_RETENTION_SECONDS = 7 * 24 * 60 * 60;

const PORTAL_ISSUER = "spl-portal";
const PURGE_AUDIENCE = "spl-relay-purge";
const PROTOCOL_VERSION = "1";

interface EnvelopeBody {
	envelope?: unknown;
}

interface CommonClaims {
	iss: string;
	aud: string;
	ver: string;
	typ: string;
	op: string;
	iat: number;
	exp: number;
}

export interface PurgeClaims extends CommonClaims {
	typ: "purge";
	instances: string[];
}

export interface PurgeConfirmClaims extends CommonClaims {
	typ: "purge-confirm";
}

interface PublicJwk {
	kty: "OKP";
	crv: "Ed25519";
	kid: string;
	x: string;
	alg?: "EdDSA";
	use?: "sig";
}

interface JwksEnvelope {
	keys: PublicJwk[];
}

interface PurgeOperation {
	operation_id_hash: string;
	snapshot_digest: string;
	state: "retryable" | "complete";
	expires_at: number;
	completed_at: number | null;
}

type VerifyFailure = "malformed" | "untrusted" | "expired" | "unavailable";
type VerifyResult<T> = { ok: true; claims: T } | { ok: false; reason: VerifyFailure };
type CanonicalizeResult =
	| { ok: true; instances: string[] }
	| { ok: false; reason: "malformed" | "too_many" };

export function unixNow(): number {
	return Math.floor(Date.now() / 1000);
}

export async function handlePurge(request: Request, env: Env, now = unixNow()): Promise<Response> {
	if (!env.PURGE_SECRET || !env.PORTAL_JWKS_PUBLIC) {
		return json({ error: "relay not provisioned" }, 503);
	}
	if (!hasValidBearer(request, env.PURGE_SECRET)) {
		log({ event: "unauthorized", route: PURGE_ROUTE, reason: "bad_bearer" });
		return json({ error: "unauthorized" }, 401);
	}

	const body = await envelopeFromRequest(request, MAX_PURGE_BODY_BYTES);
	if (!body.ok) return refused("purge_malformed", 400);

	const verified = await verifyPurgeEnvelope(body.envelope, env.PORTAL_JWKS_PUBLIC, now);
	if (!verified.ok) return verifyFailureResponse(verified.reason);

	const canonical = canonicalizeInstances(verified.claims.instances);
	if (!canonical.ok) {
		return canonical.reason === "too_many"
			? refused("purge_too_many", 400)
			: refused("purge_malformed", 400);
	}

	const operationIdHash = await sha256FingerprintText(verified.claims.op);
	const snapshotDigest = await sha256FingerprintText(JSON.stringify(canonical.instances));

	let binding: PurgeOperation | null;
	try {
		binding = await loadPurgeOperation(operationIdHash, now, env);
		if (!binding) {
			await env.DB.prepare(
				"INSERT INTO purge_operations (operation_id_hash, snapshot_digest, state, expires_at, completed_at) VALUES (?, ?, 'retryable', ?, NULL) ON CONFLICT(operation_id_hash) DO NOTHING",
			)
				.bind(operationIdHash, snapshotDigest, verified.claims.exp)
				.run();
			binding = await loadPurgeOperation(operationIdHash, now, env);
		}
	} catch {
		return retryable(0);
	}

	// An insert race cannot normally make this absent. If a concurrent hard
	// delete did, no deletion has been attempted and the portal can retry.
	if (!binding) return retryable(0);

	if (binding.snapshot_digest !== snapshotDigest) return alteredReplay();
	if (binding.state === "complete") return complete(canonical.instances.length);
	if (now >= binding.expires_at) return expired(canonical.instances.length);

	let completed = 0;
	for (const instanceId of canonical.instances) {
		try {
			await env.DB.batch([
				env.DB.prepare("DELETE FROM devices WHERE instance_id = ?").bind(instanceId),
				env.DB.prepare("DELETE FROM pending_grants WHERE instance_id = ?").bind(instanceId),
				env.DB.prepare("DELETE FROM instances WHERE instance_id = ?").bind(instanceId),
			]);
			completed += 1;
		} catch {
			return retryable(completed);
		}
	}

	try {
		const result = await env.DB.prepare(
			"UPDATE purge_operations SET state = 'complete', completed_at = ? WHERE operation_id_hash = ? AND state = 'retryable' AND completed_at IS NULL",
		)
			.bind(now, operationIdHash)
			.run();
		if (result.meta.changes === 0) {
			binding = await loadPurgeOperation(operationIdHash, now, env);
			if (!binding || binding.snapshot_digest !== snapshotDigest) return retryable(completed);
			if (binding.state === "complete") return complete(canonical.instances.length);
			return retryable(completed);
		}
	} catch {
		return retryable(completed);
	}

	return complete(canonical.instances.length);
}

export async function handlePurgeConfirm(
	request: Request,
	env: Env,
	now = unixNow(),
): Promise<Response> {
	if (!env.PURGE_SECRET || !env.PORTAL_JWKS_PUBLIC) {
		return json({ error: "relay not provisioned" }, 503);
	}
	if (!hasValidBearer(request, env.PURGE_SECRET)) {
		log({ event: "unauthorized", route: PURGE_CONFIRM_ROUTE, reason: "bad_bearer" });
		return json({ error: "unauthorized" }, 401);
	}

	const body = await envelopeFromRequest(request, MAX_PURGE_CONFIRM_BODY_BYTES);
	if (!body.ok) return refused("purge_malformed", 400);

	const verified = await verifyPurgeConfirmEnvelope(body.envelope, env.PORTAL_JWKS_PUBLIC, now);
	if (!verified.ok) return verifyFailureResponse(verified.reason);

	const operationIdHash = await sha256FingerprintText(verified.claims.op);
	let binding: PurgeOperation | null;
	try {
		binding = await loadPurgeOperation(operationIdHash, now, env);
	} catch {
		return retryable(0);
	}

	if (!binding) {
		log({ event: "purge_confirmed_absent" });
		return protocol("confirmed_absent");
	}
	if (binding.state === "retryable") {
		if (now >= binding.expires_at) return expired(0);
		log({ event: "purge_not_complete", reason: "purge_not_complete" });
		return protocol("not_complete", 409);
	}

	try {
		await env.DB.prepare("DELETE FROM purge_operations WHERE operation_id_hash = ?")
			.bind(operationIdHash)
			.run();
	} catch {
		return retryable(0);
	}

	log({ event: "purge_confirmed" });
	return protocol("complete");
}

export async function verifyPurgeEnvelope(
	envelope: string,
	jwksRaw: string,
	now = unixNow(),
): Promise<VerifyResult<PurgeClaims>> {
	const verified = await verifyCompactEdDsaJwt(envelope, jwksRaw);
	if (!verified.ok) return verified;
	const claims = toCommonClaims(verified.claims);
	if (!claims) return { ok: false, reason: "untrusted" };
	if (claims.typ !== "purge" || !Array.isArray(verified.claims.instances)) {
		return { ok: false, reason: "untrusted" };
	}
	if (!claimsFresh(claims, now, MAX_PURGE_LIFETIME_SECONDS)) {
		return { ok: false, reason: claimsExpired(claims, now) ? "expired" : "untrusted" };
	}
	return { ok: true, claims: { ...claims, typ: "purge", instances: verified.claims.instances } };
}

export async function verifyPurgeConfirmEnvelope(
	envelope: string,
	jwksRaw: string,
	now = unixNow(),
): Promise<VerifyResult<PurgeConfirmClaims>> {
	const verified = await verifyCompactEdDsaJwt(envelope, jwksRaw);
	if (!verified.ok) return verified;
	const claims = toCommonClaims(verified.claims);
	if (!claims || claims.typ !== "purge-confirm" || "instances" in verified.claims) {
		return { ok: false, reason: "untrusted" };
	}
	if (!claimsFresh(claims, now, MAX_CONFIRM_LIFETIME_SECONDS)) {
		return { ok: false, reason: claimsExpired(claims, now) ? "expired" : "untrusted" };
	}
	return { ok: true, claims: { ...claims, typ: "purge-confirm" } };
}

export function canonicalizeInstances(instances: unknown): CanonicalizeResult {
	if (!Array.isArray(instances)) return { ok: false, reason: "malformed" };
	for (const instanceId of instances) {
		if (typeof instanceId !== "string" || !INSTANCE_ID_RE.test(instanceId)) {
			return { ok: false, reason: "malformed" };
		}
	}
	const canonical = Array.from(new Set(instances)).sort();
	if (canonical.length > MAX_INSTANCE_IDS) return { ok: false, reason: "too_many" };
	return { ok: true, instances: canonical };
}

export async function sha256FingerprintText(text: string): Promise<string> {
	const hash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
	const hex = Array.from(new Uint8Array(hash), (byte) => byte.toString(16).padStart(2, "0")).join(
		"",
	);
	return `sha256:${hex}`;
}

async function envelopeFromRequest(
	request: Request,
	maxBytes: number,
): Promise<{ ok: true; envelope: string } | { ok: false }> {
	const read = await readJson<EnvelopeBody>(request, maxBytes);
	if (!read.ok || typeof read.value !== "object" || read.value === null) return { ok: false };
	if (typeof read.value.envelope !== "string") return { ok: false };
	return { ok: true, envelope: read.value.envelope };
}

async function verifyCompactEdDsaJwt(
	envelope: string,
	jwksRaw: string,
): Promise<VerifyResult<Record<string, unknown>>> {
	const parts = envelope.split(".");
	if (parts.length !== 3) return { ok: false, reason: "malformed" };
	const [headerB64, payloadB64, signatureB64] = parts;

	let header: { alg?: unknown; kid?: unknown };
	let claims: unknown;
	try {
		header = JSON.parse(utf8Decode(base64UrlDecode(headerB64))) as { alg?: unknown; kid?: unknown };
		claims = JSON.parse(utf8Decode(base64UrlDecode(payloadB64))) as unknown;
	} catch {
		return { ok: false, reason: "malformed" };
	}
	if (
		header.alg !== "EdDSA" ||
		typeof header.kid !== "string" ||
		!header.kid ||
		typeof claims !== "object" ||
		claims === null ||
		Array.isArray(claims)
	) {
		return { ok: false, reason: "malformed" };
	}

	const jwks = parsePortalJwks(jwksRaw);
	if (!jwks) return { ok: false, reason: "unavailable" };
	const jwk = jwks.keys.find((key) => key.kid === header.kid);
	if (!jwk) return { ok: false, reason: "untrusted" };

	let key: CryptoKey;
	let signature: Uint8Array;
	try {
		key = await crypto.subtle.importKey(
			"jwk",
			{ kty: jwk.kty, crv: jwk.crv, x: jwk.x },
			{ name: "Ed25519" },
			false,
			["verify"],
		);
		signature = base64UrlDecode(signatureB64);
	} catch {
		return { ok: false, reason: "unavailable" };
	}

	let valid: boolean;
	try {
		valid = await crypto.subtle.verify(
			"Ed25519",
			key,
			signature,
			new TextEncoder().encode(`${headerB64}.${payloadB64}`),
		);
	} catch {
		return { ok: false, reason: "untrusted" };
	}
	if (!valid) return { ok: false, reason: "untrusted" };
	return { ok: true, claims: claims as Record<string, unknown> };
}

function parsePortalJwks(raw: string): JwksEnvelope | null {
	try {
		const parsed = JSON.parse(raw) as unknown;
		if (
			typeof parsed !== "object" ||
			parsed === null ||
			!Array.isArray((parsed as { keys?: unknown }).keys)
		) {
			return null;
		}
		const keys = (parsed as { keys: unknown[] }).keys;
		if (!keys.length || !keys.every(isPortalPublicJwk)) return null;
		const kids = new Set(keys.map((key) => (key as PublicJwk).kid));
		if (kids.size !== keys.length) return null;
		return { keys: keys as PublicJwk[] };
	} catch {
		return null;
	}
}

function isPortalPublicJwk(value: unknown): value is PublicJwk {
	if (typeof value !== "object" || value === null) return false;
	const jwk = value as Record<string, unknown>;
	return (
		jwk.kty === "OKP" &&
		jwk.crv === "Ed25519" &&
		typeof jwk.kid === "string" &&
		jwk.kid.length > 0 &&
		typeof jwk.x === "string" &&
		jwk.x.length > 0 &&
		(jwk.alg === undefined || jwk.alg === "EdDSA") &&
		(jwk.use === undefined || jwk.use === "sig")
	);
}

function toCommonClaims(claims: Record<string, unknown>): CommonClaims | null {
	if (
		claims.iss !== PORTAL_ISSUER ||
		claims.aud !== PURGE_AUDIENCE ||
		claims.ver !== PROTOCOL_VERSION ||
		typeof claims.typ !== "string" ||
		typeof claims.op !== "string" ||
		!claims.op ||
		new TextEncoder().encode(claims.op).byteLength > MAX_OPERATION_ID_BYTES ||
		!isSafeUnixSecond(claims.iat) ||
		!isSafeUnixSecond(claims.exp)
	) {
		return null;
	}
	return {
		iss: claims.iss,
		aud: claims.aud,
		ver: claims.ver,
		typ: claims.typ,
		op: claims.op,
		iat: claims.iat,
		exp: claims.exp,
	};
}

function isSafeUnixSecond(value: unknown): value is number {
	return typeof value === "number" && Number.isSafeInteger(value);
}

function claimsFresh(claims: CommonClaims, now: number, maxLifetimeSeconds: number): boolean {
	return (
		claims.iat <= now &&
		claims.exp > claims.iat &&
		claims.exp > now &&
		claims.exp - claims.iat <= maxLifetimeSeconds
	);
}

function claimsExpired(claims: CommonClaims, now: number): boolean {
	return claims.exp <= now;
}

async function loadPurgeOperation(
	operationIdHash: string,
	now: number,
	env: Env,
): Promise<PurgeOperation | null> {
	const row = await env.DB.prepare(
		"SELECT operation_id_hash, snapshot_digest, state, expires_at, completed_at FROM purge_operations WHERE operation_id_hash = ?",
	)
		.bind(operationIdHash)
		.first<PurgeOperation>();
	if (!row) return null;
	if (
		row.state === "complete" &&
		row.completed_at !== null &&
		now > row.completed_at + COMPLETED_BINDING_RETENTION_SECONDS
	) {
		await env.DB.prepare(
			"DELETE FROM purge_operations WHERE operation_id_hash = ? AND state = 'complete' AND completed_at = ?",
		)
			.bind(operationIdHash, row.completed_at)
			.run();
		return null;
	}
	return row;
}

function protocol(disposition: string, status = 200): Response {
	return json({ ver: PROTOCOL_VERSION, disposition }, status);
}

function refused(reason: "purge_malformed" | "purge_too_many", status: number): Response {
	log({ event: "purge_rejected", reason });
	return json(
		{
			ver: PROTOCOL_VERSION,
			disposition: "refused",
			reason: reason === "purge_too_many" ? "too_many" : "malformed",
		},
		status,
	);
}

function verifyFailureResponse(reason: VerifyFailure): Response {
	if (reason === "unavailable") return json({ error: "relay not provisioned" }, 503);
	if (reason === "expired") return expired(0);
	if (reason === "malformed") return refused("purge_malformed", 400);
	log({ event: "purge_rejected", reason: "purge_untrusted" });
	return json({ ver: PROTOCOL_VERSION, disposition: "refused", reason: "untrusted" }, 401);
}

function complete(count: number): Response {
	log({ event: "purge_complete", count });
	return protocol("complete");
}

function retryable(count: number): Response {
	log({ event: "purge_retryable", count, reason: "purge_database_error" });
	return protocol("retryable", 503);
}

function expired(count: number): Response {
	log({ event: "purge_expired", count, reason: "purge_expired" });
	return protocol("expired", 409);
}

function alteredReplay(): Response {
	log({ event: "purge_rejected", reason: "purge_altered_replay" });
	return protocol("altered_replay", 409);
}
