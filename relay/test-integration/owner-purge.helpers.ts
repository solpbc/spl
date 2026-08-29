// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import { SELF, env } from "cloudflare:test";
import { base64UrlEncode } from "../src/tokens";
import fixture from "../test-fixtures/owner-purge-v1.json";

declare module "cloudflare:test" {
	interface ProvidedEnv {
		DB: D1Database;
		PURGE_SECRET: string;
		GRANT_SECRET: string;
		OWNER_PURGE_HMAC_KEY_V1: string;
		OWNER_PURGE_HMAC_KEY_V2: string;
	}
}

export type KeyVersion = 1 | 2;
type IntegrityKind = "request" | "confirm" | "response";

export interface SignedRequest {
	version: number;
	key_version: KeyVersion;
	operation_id: string;
	service: string;
	association_snapshot: Record<string, unknown>;
	request_digest: string;
	issued_at: number;
	expires_at: number;
	integrity: string;
}

export interface SignedAttestation {
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

interface FixtureEnvelope {
	version: number;
	key_version: number;
	operation_id: string;
	service: string;
	request_digest: string;
	integrity: string;
	issued_at?: number;
	expires_at?: number;
	association_snapshot?: Record<string, unknown>;
	state?: string;
	disposition?: string;
}

interface FixtureTranscript {
	name: string;
	service: string;
	request_received_at: number;
	attestation_received_at: number;
	request_canonical_without_integrity: string;
	request_frame_hex?: string;
	request: FixtureEnvelope;
	attestation_canonical_without_integrity: string;
	attestation: FixtureEnvelope;
	submit_response_canonical_without_integrity: string;
	submit_response: FixtureEnvelope;
	response_canonical_without_integrity: string;
	response: FixtureEnvelope;
	expected_submit: string;
	expected_confirm: string;
	expected_confirm_retry?: string;
	wrong_response_key_version?: {
		key_version: number;
		integrity: string;
		expected_account_disposition: string;
	};
}

export interface RejectionVector {
	name: string;
	deliveries?: number;
	expected_bindings?: number;
	expected_dispositions?: string[];
	expected_disposition?: string;
	received_at?: number;
	issued_at?: number;
	expires_at?: number;
	cases?: Array<{ received_at: number; issued_at: number; expires_at: number }>;
	original_request_key_version?: number;
	response_key_version?: number;
	expected_account_disposition?: string;
}

interface OwnerPurgeFixture {
	routes: { purge: string; confirm: string };
	integrity: {
		non_production_test_keys_utf8: Record<string, string>;
		domains: Record<IntegrityKind, string>;
	};
	time_bounds_ms: {
		request_max_lifetime: number;
		attestation_max_lifetime: number;
	};
	wire_transcripts: FixtureTranscript[];
	rejection_vectors: RejectionVector[];
}

const ownerPurgeFixture = fixture as OwnerPurgeFixture;
export const REQUEST_ROUTE = ownerPurgeFixture.routes.purge;
export const CONFIRM_ROUTE = ownerPurgeFixture.routes.confirm;
export const NOW = transcript(
	"relay_retained_key_v1_first_confirmation_and_lost_response_retry",
).request_received_at;

export function transcript(name: string): FixtureTranscript {
	const result = ownerPurgeFixture.wire_transcripts.find((candidate) => candidate.name === name);
	if (!result) throw new Error(`fixture transcript missing: ${name}`);
	return result;
}

export function rejectionVector(name: string): RejectionVector {
	const result = ownerPurgeFixture.rejection_vectors.find((candidate) => candidate.name === name);
	if (!result) throw new Error(`fixture rejection vector missing: ${name}`);
	return result;
}

export function fixtureNumber(
	vector: RejectionVector,
	field: "received_at" | "issued_at" | "expires_at",
): number {
	const value = vector[field];
	if (typeof value !== "number") throw new Error(`fixture ${vector.name} missing numeric ${field}`);
	return value;
}

export function fixtureDisposition(vector: RejectionVector): string {
	if (typeof vector.expected_disposition !== "string") {
		throw new Error(`fixture ${vector.name} missing expected_disposition`);
	}
	return vector.expected_disposition;
}

function fixtureKey(version: KeyVersion): string {
	const key = ownerPurgeFixture.integrity.non_production_test_keys_utf8[String(version)];
	if (!key) throw new Error(`fixture key missing: ${version}`);
	return key;
}

function fixtureDomain(kind: IntegrityKind, service: string): string {
	return ownerPurgeFixture.integrity.domains[kind].replace("<service>", service);
}

export function cloneFixture<T>(value: T): T {
	return structuredClone(value);
}

export function fixtureRequest(name: string): SignedRequest {
	const request = cloneFixture(transcript(name).request);
	if (!request.association_snapshot) throw new Error(`fixture request snapshot missing: ${name}`);
	return {
		...request,
		key_version: keyVersion(request.key_version),
		association_snapshot: request.association_snapshot,
		issued_at: requiredNumber(request.issued_at, `${name} request issued_at`),
		expires_at: requiredNumber(request.expires_at, `${name} request expires_at`),
	};
}

export function fixtureAttestation(name: string): SignedAttestation {
	const attestation = cloneFixture(transcript(name).attestation);
	if (!attestation.state) throw new Error(`fixture attestation state missing: ${name}`);
	return {
		...attestation,
		key_version: keyVersion(attestation.key_version),
		state: attestation.state,
		issued_at: requiredNumber(attestation.issued_at, `${name} attestation issued_at`),
		expires_at: requiredNumber(attestation.expires_at, `${name} attestation expires_at`),
	};
}

export function confirmationWrapper(
	envelope: SignedRequest,
	attestation: SignedAttestation,
): { envelope: SignedRequest; attestation: SignedAttestation } {
	return { envelope, attestation };
}

export function fixtureInstanceIds(request: SignedRequest): string[] {
	const instanceIds = request.association_snapshot.instance_ids;
	if (
		!Array.isArray(instanceIds) ||
		!instanceIds.every((instanceId) => typeof instanceId === "string")
	) {
		throw new Error("fixture request instance_ids missing");
	}
	return instanceIds;
}

export function fixtureResponse(
	name: string,
	field: "submit_response" | "response",
): FixtureEnvelope {
	return cloneFixture(transcript(name)[field]);
}

export interface PostOptions {
	bearer?: string;
	headers?: HeadersInit;
	method?: string;
}

export function post(path: string, body: unknown, options: PostOptions = {}): Promise<Response> {
	return request(path, JSON.stringify(body), options);
}

export function postRaw(path: string, body: string, options: PostOptions = {}): Promise<Response> {
	return request(path, body, options);
}

export function request(
	path: string,
	body: string | undefined,
	options: PostOptions = {},
): Promise<Response> {
	const headers = new Headers(options.headers);
	headers.set("authorization", `Bearer ${options.bearer ?? env.PURGE_SECRET}`);
	if (body !== undefined && !headers.has("content-type"))
		headers.set("content-type", "application/json");
	return SELF.fetch(`http://spl.test${path}`, {
		method: options.method ?? "POST",
		headers,
		body,
	});
}

export async function response(
	requestPromise: Promise<Response>,
): Promise<{ status: number; body: Record<string, unknown> }> {
	const result = await requestPromise;
	return { status: result.status, body: (await result.json()) as Record<string, unknown> };
}

export async function signedRequest(options: {
	operationId: string;
	instanceIds?: string[];
	associationSnapshot?: Record<string, unknown>;
	keyVersion?: KeyVersion;
	signingKeyVersion?: KeyVersion;
	service?: string;
	domainService?: string;
	issuedAt?: number;
	expiresAt?: number;
	requestDigest?: string;
}): Promise<SignedRequest> {
	const keyVersion = options.keyVersion ?? 2;
	const service = options.service ?? "relay";
	const associationSnapshot = options.associationSnapshot ?? {
		instance_ids: options.instanceIds ?? [],
	};
	const requestDigest =
		options.requestDigest ??
		(await digest({
			version: 1,
			key_version: keyVersion,
			service,
			association_snapshot: associationSnapshot,
		}));
	const unsigned = {
		version: 1,
		key_version: keyVersion,
		operation_id: options.operationId,
		service,
		association_snapshot: associationSnapshot,
		request_digest: requestDigest,
		issued_at: options.issuedAt ?? NOW,
		expires_at:
			options.expiresAt ?? NOW + ownerPurgeFixture.time_bounds_ms.attestation_max_lifetime,
	};
	return {
		...unsigned,
		integrity: await integrity(
			"request",
			unsigned,
			options.signingKeyVersion ?? keyVersion,
			options.domainService ?? service,
		),
	};
}

export async function signedAttestation(options: {
	operationId: string;
	requestDigest: string;
	keyVersion?: KeyVersion;
	signingKeyVersion?: KeyVersion;
	service?: string;
	domainService?: string;
	issuedAt?: number;
	expiresAt?: number;
	state?: string;
}): Promise<SignedAttestation> {
	const keyVersion = options.keyVersion ?? 2;
	const service = options.service ?? "relay";
	const unsigned = {
		version: 1,
		key_version: keyVersion,
		operation_id: options.operationId,
		service,
		request_digest: options.requestDigest,
		state: options.state ?? "complete",
		issued_at: options.issuedAt ?? NOW,
		expires_at:
			options.expiresAt ?? NOW + ownerPurgeFixture.time_bounds_ms.attestation_max_lifetime,
	};
	return {
		...unsigned,
		integrity: await integrity(
			"confirm",
			unsigned,
			options.signingKeyVersion ?? keyVersion,
			options.domainService ?? service,
		),
	};
}

export async function integrity(
	kind: IntegrityKind,
	value: unknown,
	keyVersion: KeyVersion,
	service = "relay",
): Promise<string> {
	const frame = frameBytes(fixtureDomain(kind, service), canonicalJson(value));
	const cryptoKey = await crypto.subtle.importKey(
		"raw",
		new TextEncoder().encode(fixtureKey(keyVersion)),
		{ name: "HMAC", hash: "SHA-256" },
		false,
		["sign"],
	);
	return base64UrlEncode(new Uint8Array(await crypto.subtle.sign("HMAC", cryptoKey, frame)));
}

export async function digest(value: unknown): Promise<string> {
	return base64UrlEncode(
		new Uint8Array(
			await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonicalJson(value))),
		),
	);
}

function canonicalJson(value: unknown): string {
	if (value === null) return "null";
	if (typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
	if (typeof value === "number") {
		if (!Number.isSafeInteger(value)) throw new Error("not canonical owner-purge JSON");
		return JSON.stringify(value);
	}
	if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
	if (typeof value !== "object") throw new Error("not canonical owner-purge JSON");
	const object = value as Record<string, unknown>;
	return `{${Object.keys(object)
		.sort(compareUtf8)
		.map((key) => `${JSON.stringify(key)}:${canonicalJson(object[key])}`)
		.join(",")}}`;
}

export async function seedInstance(instanceId: string): Promise<void> {
	const suffix = crypto.randomUUID();
	await env.DB.prepare(
		"INSERT INTO instances (instance_id, ca_fp, ca_pubkey_pem, home_label, created_at, service_token_jti) VALUES (?, ?, ?, ?, ?, ?)",
	)
		.bind(instanceId, `sha256:${suffix.replace(/-/g, "")}`, "fixture-ca", null, NOW, suffix)
		.run();
	await env.DB.prepare(
		"INSERT INTO devices (device_jti, instance_id, device_fp, device_label, created_at, attestation_jti) VALUES (?, ?, ?, ?, ?, ?)",
	)
		.bind(`device-${suffix}`, instanceId, "sha256:fixture", null, NOW, `attestation-${suffix}`)
		.run();
	await env.DB.prepare(
		"INSERT INTO pending_grants (instance_id, entitled_until, updated_at) VALUES (?, ?, ?)",
	)
		.bind(instanceId, NOW + 3_600_000, NOW)
		.run();
}

export async function clearRows(): Promise<void> {
	await env.DB.prepare("DELETE FROM purge_operations").run();
	await env.DB.prepare("DELETE FROM devices").run();
	await env.DB.prepare("DELETE FROM pending_grants").run();
	await env.DB.prepare("DELETE FROM instances").run();
}

export async function rowCount(
	table: "instances" | "devices" | "pending_grants",
	instanceId: string,
): Promise<number> {
	const row = await env.DB.prepare(`SELECT COUNT(*) AS count FROM ${table} WHERE instance_id = ?`)
		.bind(instanceId)
		.first<{ count: number }>();
	return row?.count ?? 0;
}

export async function bindingCount(): Promise<number> {
	const row = await env.DB.prepare("SELECT COUNT(*) AS count FROM purge_operations").first<{
		count: number;
	}>();
	return row?.count ?? 0;
}

export async function bindingDisposition(): Promise<string | null> {
	const row = await env.DB.prepare("SELECT disposition FROM purge_operations").first<{
		disposition: string;
	}>();
	return row?.disposition ?? null;
}

function frameBytes(domain: string, body: string): Uint8Array {
	const encoder = new TextEncoder();
	const domainBytes = encoder.encode(domain);
	const bodyBytes = encoder.encode(body);
	const frame = new Uint8Array(16 + domainBytes.length + bodyBytes.length);
	frame.set(uint64(domainBytes.length), 0);
	frame.set(domainBytes, 8);
	frame.set(uint64(bodyBytes.length), 8 + domainBytes.length);
	frame.set(bodyBytes, 16 + domainBytes.length);
	return frame;
}

function uint64(value: number): Uint8Array {
	const view = new DataView(new ArrayBuffer(8));
	view.setBigUint64(0, BigInt(value), false);
	return new Uint8Array(view.buffer);
}

function compareUtf8(left: string, right: string): number {
	const a = new TextEncoder().encode(left);
	const b = new TextEncoder().encode(right);
	for (let index = 0; index < Math.min(a.length, b.length); index += 1) {
		if (a[index] !== b[index]) return a[index] - b[index];
	}
	return a.length - b.length;
}

function keyVersion(value: number): KeyVersion {
	if (value === 1 || value === 2) return value;
	throw new Error(`fixture key version invalid: ${value}`);
}

function requiredNumber(value: number | undefined, description: string): number {
	if (typeof value !== "number") throw new Error(`fixture ${description} missing`);
	return value;
}
