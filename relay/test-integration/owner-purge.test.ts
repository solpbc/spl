// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import { SELF, env } from "cloudflare:test";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { base64UrlEncode } from "../src/tokens";
import { applyRelayD1Migrations } from "./apply-migrations";

declare module "cloudflare:test" {
	interface ProvidedEnv {
		DB: D1Database;
		PURGE_SECRET: string;
		OWNER_PURGE_HMAC_KEY_V1: string;
		OWNER_PURGE_HMAC_KEY_V2: string;
	}
}

const NOW = 2_000_000_000_050;
const REQUEST_ROUTE = "/internal/deletion/purge";
const CONFIRM_ROUTE = "/internal/deletion/purge/confirm";
const REQUEST_MAX_LIFETIME_MS = 604_800_000;
const ATTESTATION_MAX_LIFETIME_MS = 300_000;

const RELAY_V1_REQUEST = {
	version: 1,
	key_version: 1,
	operation_id: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	service: "relay",
	association_snapshot: {
		instance_ids: ["00000000-0000-4000-8000-000000000001", "00000000-0000-4000-8000-000000000002"],
	},
	request_digest: "ou_NS2c8cDEtGWNwlKWjQ3lwxlWcBWu8pTlV2ql20i4",
	issued_at: 2_000_000_000_000,
	expires_at: 2_000_000_300_000,
	integrity: "pM1F4bARL-0ncsRvNTmFadoIwYZSXjFB0LdKTar_gG8",
};
const RELAY_V1_ATTESTATION = {
	version: 1,
	key_version: 1,
	operation_id: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	service: "relay",
	request_digest: "ou_NS2c8cDEtGWNwlKWjQ3lwxlWcBWu8pTlV2ql20i4",
	state: "complete",
	issued_at: 2_000_000_000_100,
	expires_at: 2_000_000_000_200,
	integrity: "EASTL6YsY8nmeiH_CPHl9wR5FYwl_yHOHTDJyAPCB7Q",
};
const RELAY_V1_COMPLETE = {
	version: 1,
	key_version: 1,
	service: "relay",
	operation_id: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	request_digest: "ou_NS2c8cDEtGWNwlKWjQ3lwxlWcBWu8pTlV2ql20i4",
	disposition: "complete",
	integrity: "GDx9R3GjvPKKGU3G1hqLp3XkI0KtNXShRFfy8SdNBQs",
};
const RELAY_V1_CONFIRMED = {
	version: 1,
	key_version: 1,
	service: "relay",
	operation_id: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	request_digest: "ou_NS2c8cDEtGWNwlKWjQ3lwxlWcBWu8pTlV2ql20i4",
	disposition: "confirmed",
	integrity: "wsP76AE19RNm2z7f372Q3LFLCZ2-2EtHVvYq88IN7hU",
};

const RELAY_V2_REQUEST = {
	version: 1,
	key_version: 2,
	operation_id: "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD",
	service: "relay",
	association_snapshot: { instance_ids: ["00000000-0000-4000-8000-000000000003"] },
	request_digest: "giyIglrdgSn_ThNUgr0QkcxHi7p4CujUbJjznPNdPnQ",
	issued_at: 2_000_000_000_000,
	expires_at: 2_000_000_300_000,
	integrity: "A0c6VuGnYKdJK5Eu3zfgn0vDOA80mhSqheL3O6eB4EU",
};
const RELAY_V2_ATTESTATION = {
	version: 1,
	key_version: 2,
	operation_id: "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD",
	service: "relay",
	request_digest: "giyIglrdgSn_ThNUgr0QkcxHi7p4CujUbJjznPNdPnQ",
	state: "complete",
	issued_at: 2_000_000_000_100,
	expires_at: 2_000_000_000_200,
	integrity: "6OxFDXQFjt_f3VgKCOJnugc6WMOAzrpjMHiYcUYVJ4c",
};
const RELAY_V2_COMPLETE = {
	version: 1,
	key_version: 2,
	service: "relay",
	operation_id: "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD",
	request_digest: "giyIglrdgSn_ThNUgr0QkcxHi7p4CujUbJjznPNdPnQ",
	disposition: "complete",
	integrity: "HyhCGJ-cHs5f9NwvOT34kCNG8a-D4Y_-NQjXnC58sjg",
};
const RELAY_V2_CONFIRMED = {
	version: 1,
	key_version: 2,
	service: "relay",
	operation_id: "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD",
	request_digest: "giyIglrdgSn_ThNUgr0QkcxHi7p4CujUbJjznPNdPnQ",
	disposition: "confirmed",
	integrity: "-wFdX5FcH7mvOPNuhkK9fZ3qzlzApfLcYuHHKN3w7Wk",
};

interface SignedRequest {
	version: number;
	key_version: 1 | 2;
	operation_id: string;
	service: string;
	association_snapshot: { instance_ids: string[] };
	request_digest: string;
	issued_at: number;
	expires_at: number;
	integrity: string;
}

beforeAll(async () => {
	await applyRelayD1Migrations();
});

beforeEach(async () => {
	vi.useFakeTimers();
	vi.setSystemTime(NOW);
	await clearRows();
});

afterEach(() => {
	vi.useRealTimers();
});

describe("owner-purge v1 relay wire transcripts", () => {
	it("executes retained-key v1 submit, confirmation, and lost-response retry", async () => {
		for (const id of RELAY_V1_REQUEST.association_snapshot.instance_ids) await seedInstance(id);
		const control = "00000000-0000-4000-8000-000000000099";
		await seedInstance(control);

		expect(await response(post(REQUEST_ROUTE, RELAY_V1_REQUEST))).toEqual({
			status: 200,
			body: RELAY_V1_COMPLETE,
		});
		for (const id of RELAY_V1_REQUEST.association_snapshot.instance_ids) {
			expect(await rowCount("instances", id)).toBe(0);
			expect(await rowCount("devices", id)).toBe(0);
			expect(await rowCount("pending_grants", id)).toBe(0);
		}
		expect(await rowCount("instances", control)).toBe(1);

		vi.setSystemTime(2_000_000_000_150);
		expect(await response(post(CONFIRM_ROUTE, RELAY_V1_ATTESTATION))).toEqual({
			status: 200,
			body: RELAY_V1_CONFIRMED,
		});
		expect(await response(post(CONFIRM_ROUTE, RELAY_V1_ATTESTATION))).toEqual({
			status: 200,
			body: RELAY_V1_CONFIRMED,
		});
	});

	it("executes current-key v2 submit and confirmation", async () => {
		await seedInstance("00000000-0000-4000-8000-000000000003");
		expect(await response(post(REQUEST_ROUTE, RELAY_V2_REQUEST))).toEqual({
			status: 200,
			body: RELAY_V2_COMPLETE,
		});
		vi.setSystemTime(2_000_000_000_150);
		expect(await response(post(CONFIRM_ROUTE, RELAY_V2_ATTESTATION))).toEqual({
			status: 200,
			body: RELAY_V2_CONFIRMED,
		});
	});
});

describe("owner-purge v1 relay rejection vectors", () => {
	it("concurrent_or_lost_submit_retry_converges_to_one_binding", async () => {
		const target = "00000000-0000-4000-8000-000000000010";
		await seedInstance(target);
		const request = await signedRequest({ operationId: "concurrent-op", instanceIds: [target] });
		const [first, second] = await Promise.all([
			response(post(REQUEST_ROUTE, request)),
			response(post(REQUEST_ROUTE, request)),
		]);
		expect(first.body.disposition).toBe("complete");
		expect(second.body.disposition).toBe("complete");
		expect(await bindingCount()).toBe(1);
		expect(await rowCount("instances", target)).toBe(0);
	});

	it("same_operation_different_digest_is_refused_before_target_discovery", async () => {
		const first = "00000000-0000-4000-8000-000000000011";
		const second = "00000000-0000-4000-8000-000000000012";
		await seedInstance(first);
		await seedInstance(second);
		const initial = await response(
			post(REQUEST_ROUTE, await signedRequest({ operationId: "same-op", instanceIds: [first] })),
		);
		expect(initial.body.disposition).toBe("complete");
		const changed = await response(
			post(REQUEST_ROUTE, await signedRequest({ operationId: "same-op", instanceIds: [second] })),
		);
		expect(changed.body.disposition).toBe("refused");
		expect(await rowCount("instances", second)).toBe(1);
	});

	it("wrong_service_or_digest_never_advances", async () => {
		const support = {
			...RELAY_V1_REQUEST,
			service: "support",
			association_snapshot: { portal_principal: "fixture" },
		};
		expect(await response(post(REQUEST_ROUTE, support))).toEqual({
			status: 400,
			body: { error: "bad request" },
		});
		const invalidDigest = await signedRequest({ operationId: "bad-digest", instanceIds: [] });
		invalidDigest.request_digest = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
		const { integrity: _integrity, ...invalidUnsigned } = invalidDigest;
		invalidDigest.integrity = await integrity(
			"request",
			invalidUnsigned,
			invalidDigest.key_version,
		);
		expect((await response(post(REQUEST_ROUTE, invalidDigest))).body.disposition).toBe("refused");
		expect(await bindingCount()).toBe(0);
	});

	it("legacy_absence_never_certifies_completion", async () => {
		const request = await signedRequest({ operationId: "absent-op", instanceIds: [] });
		const attestation = await signedAttestation({
			operationId: request.operation_id,
			requestDigest: request.request_digest,
		});
		expect((await response(post(CONFIRM_ROUTE, attestation))).body.disposition).toBe("refused");
		expect(await bindingCount()).toBe(0);
	});

	it("response_signed_with_non_original_key_version_remains_pending", async () => {
		await seedInstance("00000000-0000-4000-8000-000000000003");
		expect(await response(post(REQUEST_ROUTE, RELAY_V2_REQUEST))).toEqual({
			status: 200,
			body: RELAY_V2_COMPLETE,
		});
		const wrongUnsigned = {
			version: 1,
			key_version: 1,
			service: "support",
			operation_id: "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
			request_digest: "32nZxoKc0q_2WakrM4Z25NZH5cKEWc-9PUhYdD97d3E",
			disposition: "confirmed",
		};
		expect(await integrity("response", wrongUnsigned, 1, "support")).toBe(
			"9y3f2e7_5q0Ewti7Z0_zW2vInQjnVZDyN84Zf6DQdr8",
		);
	});

	it("request_at_maximum_lifetime_is_accepted", async () => {
		const request = await signedRequest({
			operationId: "request-max",
			instanceIds: [],
			issuedAt: NOW,
			expiresAt: NOW + REQUEST_MAX_LIFETIME_MS,
		});
		expect((await response(post(REQUEST_ROUTE, request))).body.disposition).toBe("complete");
	});

	it("request_future_issued_is_refused_before_lookup", async () => {
		const request = await signedRequest({
			operationId: "request-future",
			instanceIds: [],
			issuedAt: NOW + 1,
			expiresAt: NOW + 300_001,
		});
		expect((await response(post(REQUEST_ROUTE, request))).body.disposition).toBe("refused");
		expect(await bindingCount()).toBe(0);
	});

	it("request_overlong_is_refused_before_lookup", async () => {
		const request = await signedRequest({
			operationId: "request-overlong",
			instanceIds: [],
			issuedAt: NOW,
			expiresAt: NOW + REQUEST_MAX_LIFETIME_MS + 1,
		});
		expect((await response(post(REQUEST_ROUTE, request))).body.disposition).toBe("refused");
		expect(await bindingCount()).toBe(0);
	});

	it("instance cap is authenticated before it is refused", async () => {
		const instanceIds = Array.from(
			{ length: 101 },
			(_, index) => `00000000-0000-4000-8000-${index.toString().padStart(12, "0")}`,
		);
		const request = await signedRequest({ operationId: "over-cap", instanceIds });
		expect((await response(post(REQUEST_ROUTE, request))).body.disposition).toBe("refused");
		expect(await bindingCount()).toBe(0);
	});

	it("never extends a matching operation's immutable original expiry", async () => {
		const request = await signedRequest({
			operationId: "immutable-expiry",
			instanceIds: [],
			issuedAt: NOW,
			expiresAt: NOW + 300_000,
		});
		expect((await response(post(REQUEST_ROUTE, request))).body.disposition).toBe("complete");
		const widened = await signedRequest({
			operationId: "immutable-expiry",
			instanceIds: [],
			issuedAt: NOW,
			expiresAt: NOW + 300_001,
		});
		expect((await response(post(REQUEST_ROUTE, widened))).body.disposition).toBe("refused");
	});

	it("attestation_at_maximum_lifetime_is_accepted", async () => {
		const request = await signedRequest({ operationId: "attestation-max", instanceIds: [] });
		expect((await response(post(REQUEST_ROUTE, request))).body.disposition).toBe("complete");
		const attestation = await signedAttestation({
			operationId: request.operation_id,
			requestDigest: request.request_digest,
			issuedAt: NOW,
			expiresAt: NOW + ATTESTATION_MAX_LIFETIME_MS,
		});
		expect((await response(post(CONFIRM_ROUTE, attestation))).body.disposition).toBe("confirmed");
	});

	it("attestation_future_or_overlong_is_refused_without_state_change", async () => {
		const request = await signedRequest({ operationId: "attestation-refused", instanceIds: [] });
		expect((await response(post(REQUEST_ROUTE, request))).body.disposition).toBe("complete");
		for (const attestation of [
			await signedAttestation({
				operationId: request.operation_id,
				requestDigest: request.request_digest,
				issuedAt: NOW + 1,
				expiresAt: NOW + 201,
			}),
			await signedAttestation({
				operationId: request.operation_id,
				requestDigest: request.request_digest,
				issuedAt: NOW,
				expiresAt: NOW + ATTESTATION_MAX_LIFETIME_MS + 1,
			}),
		]) {
			expect((await response(post(CONFIRM_ROUTE, attestation))).body.disposition).toBe("refused");
		}
		expect(await bindingDisposition()).toBe("complete");
	});

	it("logs only coarse owner-purge metadata", async () => {
		const operation = "log-hygiene-operation";
		const instanceId = "00000000-0000-4000-8000-000000000098";
		await seedInstance(instanceId);
		const request = await signedRequest({ operationId: operation, instanceIds: [instanceId] });
		const spy = vi.spyOn(console, "log").mockImplementation(() => {});
		try {
			expect((await response(post(REQUEST_ROUTE, request))).body.disposition).toBe("complete");
			const raw = spy.mock.calls.map(([line]) => String(line)).join("\n");
			expect(raw).not.toContain(operation);
			expect(raw).not.toContain(instanceId);
			expect(raw).not.toContain(request.integrity as string);
			for (const record of spy.mock.calls.map(
				([line]) => JSON.parse(String(line)) as Record<string, unknown>,
			)) {
				if (!String(record.event).startsWith("owner_purge_")) continue;
				expect(
					Object.keys(record).every((key) =>
						["timestamp", "event", "count", "reason"].includes(key),
					),
				).toBe(true);
			}
		} finally {
			spy.mockRestore();
		}
	});
});

async function post(path: string, body: unknown): Promise<Response> {
	return SELF.fetch(`http://spl.test${path}`, {
		method: "POST",
		headers: {
			Authorization: `Bearer ${env.PURGE_SECRET}`,
			"content-type": "application/json",
		},
		body: JSON.stringify(body),
	});
}

async function response(
	request: Promise<Response>,
): Promise<{ status: number; body: Record<string, unknown> }> {
	const result = await request;
	return { status: result.status, body: (await result.json()) as Record<string, unknown> };
}

async function signedRequest(options: {
	operationId: string;
	instanceIds: string[];
	keyVersion?: 1 | 2;
	issuedAt?: number;
	expiresAt?: number;
}): Promise<SignedRequest> {
	const keyVersion = options.keyVersion ?? 2;
	const issuedAt = options.issuedAt ?? NOW;
	const expiresAt = options.expiresAt ?? NOW + 300_000;
	const associationSnapshot = { instance_ids: options.instanceIds };
	const requestDigest = await digest({
		version: 1,
		key_version: keyVersion,
		service: "relay",
		association_snapshot: associationSnapshot,
	});
	const unsigned = {
		version: 1,
		key_version: keyVersion,
		operation_id: options.operationId,
		service: "relay",
		association_snapshot: associationSnapshot,
		request_digest: requestDigest,
		issued_at: issuedAt,
		expires_at: expiresAt,
	};
	return { ...unsigned, integrity: await integrity("request", unsigned, keyVersion) };
}

async function signedAttestation(options: {
	operationId: string;
	requestDigest: string;
	keyVersion?: 1 | 2;
	issuedAt?: number;
	expiresAt?: number;
}): Promise<Record<string, unknown>> {
	const keyVersion = options.keyVersion ?? 2;
	const unsigned = {
		version: 1,
		key_version: keyVersion,
		operation_id: options.operationId,
		service: "relay",
		request_digest: options.requestDigest,
		state: "complete",
		issued_at: options.issuedAt ?? NOW,
		expires_at: options.expiresAt ?? NOW + 300_000,
	};
	return { ...unsigned, integrity: await integrity("confirm", unsigned, keyVersion) };
}

async function integrity(
	kind: "request" | "confirm" | "response",
	value: unknown,
	keyVersion: 1 | 2,
	service = "relay",
): Promise<string> {
	const key = keyVersion === 1 ? env.OWNER_PURGE_HMAC_KEY_V1 : env.OWNER_PURGE_HMAC_KEY_V2;
	const frame = frameBytes(`solpbc-owner-purge-v1:${service}:${kind}`, canonicalJson(value));
	const cryptoKey = await crypto.subtle.importKey(
		"raw",
		new TextEncoder().encode(key),
		{ name: "HMAC", hash: "SHA-256" },
		false,
		["sign"],
	);
	return base64UrlEncode(new Uint8Array(await crypto.subtle.sign("HMAC", cryptoKey, frame)));
}

async function digest(value: unknown): Promise<string> {
	return base64UrlEncode(
		new Uint8Array(
			await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonicalJson(value))),
		),
	);
}

function canonicalJson(value: unknown): string {
	if (value === null) return "null";
	if (typeof value === "string" || typeof value === "boolean" || typeof value === "number") {
		return JSON.stringify(value);
	}
	if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
	if (typeof value !== "object") throw new Error("not JSON");
	const object = value as Record<string, unknown>;
	return `{${Object.keys(object)
		.sort(compareUtf8)
		.map((key) => `${JSON.stringify(key)}:${canonicalJson(object[key])}`)
		.join(",")}}`;
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

async function seedInstance(instanceId: string): Promise<void> {
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

async function clearRows(): Promise<void> {
	await env.DB.prepare("DELETE FROM purge_operations").run();
	await env.DB.prepare("DELETE FROM devices").run();
	await env.DB.prepare("DELETE FROM pending_grants").run();
	await env.DB.prepare("DELETE FROM instances").run();
}

async function rowCount(
	table: "instances" | "devices" | "pending_grants",
	instanceId: string,
): Promise<number> {
	const row = await env.DB.prepare(`SELECT COUNT(*) AS count FROM ${table} WHERE instance_id = ?`)
		.bind(instanceId)
		.first<{ count: number }>();
	return row?.count ?? 0;
}

async function bindingCount(): Promise<number> {
	const row = await env.DB.prepare("SELECT COUNT(*) AS count FROM purge_operations").first<{
		count: number;
	}>();
	return row?.count ?? 0;
}

async function bindingDisposition(): Promise<string | null> {
	const row = await env.DB.prepare("SELECT disposition FROM purge_operations").first<{
		disposition: string;
	}>();
	return row?.disposition ?? null;
}
