// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import { SELF, env } from "cloudflare:test";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import fixture from "../../proto/purge-v1-fixtures.json";
import type { Env } from "../src/env";
import {
	canonicalizeInstances,
	handlePurge,
	handlePurgeConfirm,
	sha256FingerprintText,
} from "../src/purge";
import { signClaims, tamperCompactJwsSignature } from "../test/fixtures";
import { applyRelayD1Migrations } from "./apply-migrations";

declare module "cloudflare:test" {
	interface ProvidedEnv {
		DB: D1Database;
		PURGE_SECRET: string;
		PORTAL_JWKS_PUBLIC: string;
		PORTAL_TEST_SIGNING_JWK: string;
	}
}

interface FixtureVector {
	name: string;
	route: "purge" | "confirm";
	envelope: string;
	expected: {
		status: number;
		disposition: string;
		retry_status?: number;
		retry_disposition?: string;
	};
	instances?: string[];
	control?: string;
	op?: string;
	confirmation?: string;
}

const vectors = fixture.vectors as FixtureVector[];
const DAY = 24 * 60 * 60;

beforeAll(async () => {
	await applyRelayD1Migrations();
});

beforeEach(async () => {
	await clearRows();
});

afterEach(() => {
	vi.restoreAllMocks();
});

function now(): number {
	return Math.floor(Date.now() / 1000);
}

function newId(): string {
	return crypto.randomUUID();
}

function fixtureVector(name: string): FixtureVector {
	const vector = vectors.find((candidate) => candidate.name === name);
	if (!vector) throw new Error(`missing fixture vector: ${name}`);
	return vector;
}

function dynamicPurgeClaims(
	instances: string[],
	overrides: Record<string, unknown> = {},
): Record<string, unknown> {
	const issuedAt = now();
	return {
		iss: "spl-portal",
		aud: "spl-relay-purge",
		ver: "1",
		typ: "purge",
		op: `dynamic-purge-${crypto.randomUUID()}`,
		instances,
		iat: issuedAt,
		exp: issuedAt + 300,
		...overrides,
	};
}

function dynamicConfirmClaims(
	op: string,
	snapshotDigest: string,
	overrides: Record<string, unknown> = {},
): Record<string, unknown> {
	const issuedAt = now();
	return {
		iss: "spl-portal",
		aud: "spl-relay-purge",
		ver: "1",
		typ: "purge-confirm",
		op,
		snapshot_digest: snapshotDigest,
		state: "complete",
		iat: issuedAt,
		exp: issuedAt + 300,
		...overrides,
	};
}

async function signPurge(
	instances: string[],
	overrides: Record<string, unknown> = {},
): Promise<string> {
	return signClaims(env.PORTAL_TEST_SIGNING_JWK, dynamicPurgeClaims(instances, overrides));
}

async function signConfirm(
	op: string,
	snapshotDigest: string,
	overrides: Record<string, unknown> = {},
): Promise<string> {
	return signClaims(
		env.PORTAL_TEST_SIGNING_JWK,
		dynamicConfirmClaims(op, snapshotDigest, overrides),
	);
}

function serviceRequest(path: string, envelope: string, bearer = env.PURGE_SECRET): Request {
	return new Request(`http://spl.test${path}`, {
		method: "POST",
		headers: {
			Authorization: `Bearer ${bearer}`,
			"content-type": "application/json",
		},
		body: JSON.stringify({ envelope }),
	});
}

function confirmServiceRequest(
	envelope: string,
	confirmation: string,
	bearer = env.PURGE_SECRET,
): Request {
	return new Request("http://spl.test/internal/purge/confirm", {
		method: "POST",
		headers: {
			Authorization: `Bearer ${bearer}`,
			"content-type": "application/json",
		},
		body: JSON.stringify({ envelope, confirmation }),
	});
}

function handlerEnv(overrides: Partial<Env> = {}): Env {
	return {
		DB: env.DB,
		PURGE_SECRET: env.PURGE_SECRET,
		PORTAL_JWKS_PUBLIC: env.PORTAL_JWKS_PUBLIC,
		...overrides,
	} as Env;
}

async function post(path: string, envelope: string, bearer = env.PURGE_SECRET): Promise<Response> {
	return SELF.fetch(`http://spl.test${path}`, {
		method: "POST",
		headers: {
			Authorization: `Bearer ${bearer}`,
			"content-type": "application/json",
		},
		body: JSON.stringify({ envelope }),
	});
}

async function postConfirm(
	envelope: string,
	confirmation: string,
	bearer = env.PURGE_SECRET,
): Promise<Response> {
	return SELF.fetch("http://spl.test/internal/purge/confirm", {
		method: "POST",
		headers: {
			Authorization: `Bearer ${bearer}`,
			"content-type": "application/json",
		},
		body: JSON.stringify({ envelope, confirmation }),
	});
}

async function outcome(response: Response): Promise<{ status: number; disposition: string }> {
	const body = (await response.json()) as { disposition: string };
	return { status: response.status, disposition: body.disposition };
}

async function seedInstance(
	instanceId: string,
	options: { deviceFp?: string; label?: string } = {},
): Promise<void> {
	const suffix = crypto.randomUUID();
	const caFingerprint = `sha256:${suffix.replace(/-/g, "").repeat(2)}`;
	await env.DB.prepare(
		"INSERT INTO instances (instance_id, ca_fp, ca_pubkey_pem, home_label, created_at, service_token_jti) VALUES (?, ?, ?, ?, ?, ?)",
	)
		.bind(instanceId, caFingerprint, "fixture-ca", options.label ?? null, now(), suffix)
		.run();
	await env.DB.prepare(
		"INSERT INTO devices (device_jti, instance_id, device_fp, device_label, created_at, attestation_jti) VALUES (?, ?, ?, ?, ?, ?)",
	)
		.bind(
			`device-${suffix}`,
			instanceId,
			options.deviceFp ?? `sha256:${"d".repeat(64)}`,
			options.label ?? null,
			now(),
			`attestation-${suffix}`,
		)
		.run();
	await env.DB.prepare(
		"INSERT INTO pending_grants (instance_id, entitled_until, updated_at) VALUES (?, ?, ?)",
	)
		.bind(instanceId, now() + 3600, now())
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

async function purgeBinding(
	operation: string,
): Promise<{ state: string; completed_at: number | null } | null> {
	const hash = await sha256FingerprintText(operation);
	return env.DB.prepare(
		"SELECT state, completed_at FROM purge_operations WHERE operation_id_hash = ?",
	)
		.bind(hash)
		.first<{ state: string; completed_at: number | null }>();
}

async function seedBinding(
	op: string,
	instances: string[],
	state: "retryable" | "complete",
	expiresAt: number,
	completedAt: number | null,
): Promise<void> {
	const hash = await sha256FingerprintText(op);
	const canonical = canonicalizeInstances(instances);
	if (!canonical.ok) throw new Error("seed binding instances must be canonicalizable");
	const snapshotDigest = await sha256FingerprintText(JSON.stringify(canonical.instances));
	await env.DB.prepare(
		"INSERT INTO purge_operations (operation_id_hash, snapshot_digest, state, expires_at, completed_at) VALUES (?, ?, ?, ?, ?)",
	)
		.bind(hash, snapshotDigest, state, expiresAt, completedAt)
		.run();
}

function flakyEnv(base: Env): Env {
	let batchCount = 0;
	const database = new Proxy(base.DB, {
		get(target, property, receiver) {
			if (property === "batch") {
				return async (statements: D1PreparedStatement[]) => {
					batchCount += 1;
					if (batchCount === 2) throw new Error("purge-batch-failure-canary");
					return target.batch(statements);
				};
			}
			const value = Reflect.get(target, property, receiver);
			return typeof value === "function" ? value.bind(target) : value;
		},
	});
	return { ...base, DB: database };
}

describe("portal purge routes", () => {
	it("requires the dedicated purge bearer before reading or mutating D1", async () => {
		const target = newId();
		await seedInstance(target);
		const envelope = await signPurge([target]);

		const response = await post("/internal/purge", envelope, "wrong-purge-secret");
		expect(response.status).toBe(401);
		expect(await response.json()).toEqual({ error: "unauthorized" });
		expect(await rowCount("instances", target)).toBe(1);
		const binding = await env.DB.prepare("SELECT COUNT(*) AS count FROM purge_operations").first<{
			count: number;
		}>();
		expect(binding?.count).toBe(0);
	});

	it("purges only named instances, and completion is idempotent while altered replay is refused", async () => {
		const targetA = newId();
		const targetB = newId();
		const control = newId();
		await seedInstance(targetA);
		await seedInstance(targetB);
		await seedInstance(control);

		const operation = `round-trip-${crypto.randomUUID()}`;
		const envelope = await signPurge([targetB, targetA, targetB], { op: operation });
		expect(await outcome(await post("/internal/purge", envelope))).toEqual({
			status: 200,
			disposition: "complete",
		});
		for (const target of [targetA, targetB]) {
			expect(await rowCount("instances", target)).toBe(0);
			expect(await rowCount("devices", target)).toBe(0);
			expect(await rowCount("pending_grants", target)).toBe(0);
		}
		expect(await rowCount("instances", control)).toBe(1);
		expect(await rowCount("devices", control)).toBe(1);
		expect(await rowCount("pending_grants", control)).toBe(1);

		expect(await outcome(await post("/internal/purge", envelope))).toEqual({
			status: 200,
			disposition: "complete",
		});
		const changedSnapshot = await signPurge([control], { op: operation });
		expect(await outcome(await post("/internal/purge", changedSnapshot))).toEqual({
			status: 409,
			disposition: "altered_replay",
		});
		expect(await rowCount("instances", control)).toBe(1);
	});

	it("handles zero, duplicate, and over-cap target sets without broad mutation", async () => {
		const target = newId();
		const control = newId();
		await seedInstance(target);
		await seedInstance(control);

		expect(await outcome(await post("/internal/purge", await signPurge([])))).toEqual({
			status: 200,
			disposition: "complete",
		});
		expect(await rowCount("instances", control)).toBe(1);

		expect(await outcome(await post("/internal/purge", await signPurge([target, target])))).toEqual(
			{
				status: 200,
				disposition: "complete",
			},
		);
		expect(await rowCount("instances", target)).toBe(0);

		const many = Array.from({ length: 101 }, (_, value) => value.toString(16).padStart(10, "a"));
		const before = await env.DB.prepare("SELECT COUNT(*) AS count FROM purge_operations").first<{
			count: number;
		}>();
		expect(await outcome(await post("/internal/purge", await signPurge(many)))).toEqual({
			status: 400,
			disposition: "refused",
		});
		const after = await env.DB.prepare("SELECT COUNT(*) AS count FROM purge_operations").first<{
			count: number;
		}>();
		expect(after?.count).toBe(before?.count);
		expect(await rowCount("instances", control)).toBe(1);
	});

	it("stops after a failed instance batch and resumes the unchanged operation", async () => {
		const first = newId();
		const second = newId();
		await seedInstance(first);
		await seedInstance(second);
		const operation = `retry-${crypto.randomUUID()}`;
		const envelope = await signPurge([first, second], { op: operation });
		const request = serviceRequest("/internal/purge", envelope);

		const firstAttempt = await handlePurge(request, flakyEnv(handlerEnv()), now());
		expect(await outcome(firstAttempt)).toEqual({ status: 503, disposition: "retryable" });
		const [processedFirst, untouchedSecond] = [first, second].sort();
		for (const table of ["instances", "devices", "pending_grants"] as const) {
			expect(await rowCount(table, processedFirst)).toBe(0);
			expect(await rowCount(table, untouchedSecond)).toBe(1);
		}

		expect(await outcome(await post("/internal/purge", envelope))).toEqual({
			status: 200,
			disposition: "complete",
		});
		expect(await rowCount("instances", untouchedSecond)).toBe(0);
		expect(await purgeBinding(operation)).toMatchObject({ state: "complete" });
	});

	it("does not extend an expired retryable binding with a fresh envelope", async () => {
		const first = newId();
		const second = newId();
		await seedInstance(first);
		await seedInstance(second);
		const operation = `stored-expiry-${crypto.randomUUID()}`;
		const startedAt = 2_000_000_000;
		const originalExpiry = startedAt + 60;
		const originalEnvelope = await signClaims(env.PORTAL_TEST_SIGNING_JWK, {
			iss: "spl-portal",
			aud: "spl-relay-purge",
			ver: "1",
			typ: "purge",
			op: operation,
			instances: [first, second],
			iat: startedAt,
			exp: originalExpiry,
		});

		expect(
			await outcome(
				await handlePurge(
					serviceRequest("/internal/purge", originalEnvelope),
					flakyEnv(handlerEnv()),
					startedAt,
				),
			),
		).toEqual({ status: 503, disposition: "retryable" });
		const [, untouchedSecond] = [first, second].sort();

		const retriedAt = originalExpiry + 1;
		const freshEnvelope = await signClaims(env.PORTAL_TEST_SIGNING_JWK, {
			iss: "spl-portal",
			aud: "spl-relay-purge",
			ver: "1",
			typ: "purge",
			op: operation,
			instances: [first, second],
			iat: retriedAt,
			exp: retriedAt + 300,
		});
		expect(
			await outcome(
				await handlePurge(
					serviceRequest("/internal/purge", freshEnvelope),
					handlerEnv(),
					retriedAt,
				),
			),
		).toEqual({ status: 409, disposition: "expired" });
		for (const table of ["instances", "devices", "pending_grants"] as const) {
			expect(await rowCount(table, untouchedSecond)).toBe(1);
		}
		expect(await purgeBinding(operation)).toMatchObject({ state: "retryable" });
	});

	it("garbage-collects a stale complete binding before a submit replay", async () => {
		const operation = `stale-complete-${crypto.randomUUID()}`;
		const instances = [newId(), newId()];
		const requestNow = 2_000_000_000;
		const expiresAt = requestNow + 300;

		for (const instanceId of instances) {
			await seedInstance(instanceId);
		}
		await seedBinding(
			operation,
			instances,
			"complete",
			expiresAt,
			requestNow - 7 * DAY - 1,
		);
		const envelope = await signPurge(instances, {
			op: operation,
			iat: requestNow,
			exp: expiresAt,
		});

		expect(
			await outcome(
				await handlePurge(
					serviceRequest("/internal/purge", envelope),
					handlerEnv(),
					requestNow,
				),
			),
		).toEqual({ status: 200, disposition: "complete" });
		for (const instanceId of instances) {
			expect(await rowCount("instances", instanceId)).toBe(0);
			expect(await rowCount("devices", instanceId)).toBe(0);
			expect(await rowCount("pending_grants", instanceId)).toBe(0);
		}
		expect(await purgeBinding(operation)).toEqual({
			state: "complete",
			completed_at: requestNow,
		});
	});

	it("deletes a complete binding before replying to confirmation and preserves retryable bindings", async () => {
		const target = newId();
		const targetInstances = [target];
		await seedInstance(target);
		const operation = `confirm-${crypto.randomUUID()}`;
		const envelope = await signPurge(targetInstances, { op: operation });
		expect((await post("/internal/purge", envelope)).status).toBe(200);
		const targetDigest = await sha256FingerprintText(JSON.stringify(targetInstances));
		const confirmation = await signConfirm(operation, targetDigest);

		expect(await outcome(await postConfirm(envelope, confirmation))).toEqual({
			status: 200,
			disposition: "complete",
		});
		expect(await purgeBinding(operation)).toBeNull();
		expect(await outcome(await postConfirm(envelope, confirmation))).toEqual({
			status: 200,
			disposition: "confirmed_absent",
		});

		const retryOperation = `retryable-confirm-${crypto.randomUUID()}`;
		const retryInstances: string[] = [];
		const retryIssuedAt = now();
		const retryExpiry = retryIssuedAt + 300;
		const retryEnvelope = await signPurge(retryInstances, {
			op: retryOperation,
			iat: retryIssuedAt,
			exp: retryExpiry,
		});
		const retryDigest = await sha256FingerprintText(JSON.stringify(retryInstances));
		await seedBinding(retryOperation, retryInstances, "retryable", retryExpiry, null);
		expect(
			await outcome(
				await postConfirm(
					retryEnvelope,
					await signConfirm(retryOperation, retryDigest, {
						iat: retryIssuedAt,
						exp: retryExpiry,
					}),
				),
			),
		).toEqual({ status: 409, disposition: "not_complete" });
		expect(await purgeBinding(retryOperation)).toMatchObject({ state: "retryable" });
	});

	it("refuses malformed, tampered, and expired original or confirmation before changing a complete binding", async () => {
		const operation = `confirm-refusal-${crypto.randomUUID()}`;
		const instances: string[] = [];
		const issuedAt = now();
		const expiry = issuedAt + 300;
		const digest = await sha256FingerprintText(JSON.stringify(instances));
		await seedBinding(operation, instances, "complete", expiry, issuedAt);
		const envelope = await signPurge(instances, { op: operation, iat: issuedAt, exp: expiry });
		const confirmation = await signConfirm(operation, digest, { iat: issuedAt, exp: expiry });
		const assertBindingIntact = async (): Promise<void> => {
			expect(await purgeBinding(operation)).toMatchObject({ state: "complete" });
		};
		expect(await outcome(await postConfirm("", confirmation))).toEqual({
			status: 400,
			disposition: "refused",
		});
		await assertBindingIntact();
		const [header, payload] = confirmation.split(".");
		const malformedSignature = `${header}.${payload}.!`;
		expect(await outcome(await postConfirm(envelope, malformedSignature))).toEqual({
			status: 400,
			disposition: "refused",
		});
		await assertBindingIntact();

		const tampered = tamperCompactJwsSignature(confirmation);
		expect(tampered).not.toBe(confirmation);
		expect(await outcome(await postConfirm(envelope, tampered))).toEqual({
			status: 401,
			disposition: "refused",
		});
		await assertBindingIntact();

		const expired = await signConfirm(operation, digest, {
			iat: issuedAt - 120,
			exp: issuedAt - 1,
		});
		expect(await outcome(await postConfirm(envelope, expired))).toEqual({
			status: 409,
			disposition: "expired",
		});
		await assertBindingIntact();

		const [originalHeader, originalPayload] = envelope.split(".");
		const malformedOriginal = `${originalHeader}.${originalPayload}.!`;
		expect(await outcome(await postConfirm(malformedOriginal, confirmation))).toEqual({
			status: 400,
			disposition: "refused",
		});
		await assertBindingIntact();

		const tamperedOriginal = tamperCompactJwsSignature(envelope);
		expect(await outcome(await postConfirm(tamperedOriginal, confirmation))).toEqual({
			status: 401,
			disposition: "refused",
		});
		await assertBindingIntact();

		const expiredOriginal = await signPurge(instances, {
			op: operation,
			iat: issuedAt - 8 * DAY,
			exp: issuedAt - DAY,
		});
		expect(await outcome(await postConfirm(expiredOriginal, confirmation))).toEqual({
			status: 409,
			disposition: "expired",
		});
		await assertBindingIntact();
	});

	it("refuses an expired original before touching a hard-delete-eligible complete binding", async () => {
		const operation = `expired-original-${crypto.randomUUID()}`;
		const then = 2_000_000_000;
		const instances: string[] = [];
		const originalIssuedAt = then - 8 * DAY;
		const originalExpiry = originalIssuedAt + 7 * DAY;
		const digest = await sha256FingerprintText(JSON.stringify(instances));
		await seedBinding(operation, instances, "complete", originalExpiry, then - 7 * DAY - 1);
		const envelope = await signPurge(instances, {
			op: operation,
			iat: originalIssuedAt,
			exp: originalExpiry,
		});
		const confirmation = await signConfirm(operation, digest, { iat: then - 60, exp: then + 300 });

		expect(
			await outcome(
				await handlePurgeConfirm(confirmServiceRequest(envelope, confirmation), handlerEnv(), then),
			),
		).toEqual({ status: 409, disposition: "expired" });
		expect(await purgeBinding(operation)).toMatchObject({ state: "complete" });
	});

	it("refuses a fresh envelope that mismatches a stale retryable binding expiry", async () => {
		const operation = `stale-confirm-${crypto.randomUUID()}`;
		const instances = [newId()];
		const issuedAt = now();
		const freshExpiry = issuedAt + 300;
		const digest = await sha256FingerprintText(JSON.stringify(instances));
		await seedBinding(operation, instances, "retryable", issuedAt - 1, null);
		const envelope = await signPurge(instances, { op: operation, iat: issuedAt, exp: freshExpiry });
		const confirmation = await signConfirm(operation, digest, { iat: issuedAt, exp: freshExpiry });

		expect(await outcome(await postConfirm(envelope, confirmation))).toEqual({
			status: 409,
			disposition: "altered_replay",
		});
		expect(await purgeBinding(operation)).toMatchObject({ state: "retryable" });
	});

	it("refuses mismatched confirmation operation and snapshot before mutating D1", async () => {
		const operation = `cross-check-${crypto.randomUUID()}`;
		const instances = [newId()];
		const issuedAt = now();
		const expiry = issuedAt + 300;
		const digest = await sha256FingerprintText(JSON.stringify(instances));
		const envelope = await signPurge(instances, { op: operation, iat: issuedAt, exp: expiry });

		expect(
			await outcome(
				await postConfirm(
					envelope,
					await signConfirm(`${operation}-other`, digest, { iat: issuedAt, exp: expiry }),
				),
			),
		).toEqual({ status: 401, disposition: "refused" });
		expect(
			await outcome(
				await postConfirm(
					envelope,
					await signConfirm(operation, `sha256:${"b".repeat(64)}`, {
						iat: issuedAt,
						exp: expiry,
					}),
				),
			),
		).toEqual({ status: 401, disposition: "refused" });
		const binding = await env.DB.prepare("SELECT COUNT(*) AS count FROM purge_operations").first<{
			count: number;
		}>();
		expect(binding?.count).toBe(0);
	});
});

describe("portal purge v1 fixture", () => {
	it("executes every static signed v1 vector against D1 state", async () => {
		const staticEnv = handlerEnv({ PORTAL_JWKS_PUBLIC: fixture.portal_jwks_public });
		const valid = fixtureVector("valid_purge");
		if (!valid.instances || !valid.control) throw new Error("valid fixture setup missing");
		for (const instanceId of [...valid.instances, valid.control]) await seedInstance(instanceId);

		const invoke = async (vector: FixtureVector, targetEnv = staticEnv): Promise<Response> => {
			const request =
				vector.route === "purge"
					? serviceRequest("/internal/purge", vector.envelope)
					: (() => {
							if (!vector.confirmation) {
								throw new Error(`confirm fixture missing confirmation: ${vector.name}`);
							}
							return confirmServiceRequest(vector.envelope, vector.confirmation);
						})();
			return vector.route === "purge"
				? handlePurge(request, targetEnv, fixture.now)
				: handlePurgeConfirm(request, targetEnv, fixture.now);
		};
		const expectVector = async (vector: FixtureVector, response: Response): Promise<void> => {
			expect(await outcome(response)).toEqual({
				status: vector.expected.status,
				disposition: vector.expected.disposition,
			});
		};

		await expectVector(valid, await invoke(valid));
		for (const instanceId of valid.instances)
			expect(await rowCount("instances", instanceId)).toBe(0);
		expect(await rowCount("instances", valid.control)).toBe(1);
		await expectVector(
			fixtureVector("valid_purge_replay"),
			await invoke(fixtureVector("valid_purge_replay")),
		);
		await expectVector(
			fixtureVector("altered_snapshot_replay"),
			await invoke(fixtureVector("altered_snapshot_replay")),
		);
		expect(await rowCount("instances", valid.control)).toBe(1);
		await expectVector(
			fixtureVector("expired_purge"),
			await invoke(fixtureVector("expired_purge")),
		);
		await expectVector(
			fixtureVector("too_many_instances"),
			await invoke(fixtureVector("too_many_instances")),
		);
		await expectVector(
			fixtureVector("tampered_signature"),
			await invoke(fixtureVector("tampered_signature")),
		);
		await expectVector(
			fixtureVector("legacy_confirm_refused"),
			await invoke(fixtureVector("legacy_confirm_refused")),
		);
		await expectVector(
			fixtureVector("valid_confirm"),
			await invoke(fixtureVector("valid_confirm")),
		);
		expect(await purgeBinding("fixture-complete-op")).toBeNull();
		await expectVector(
			fixtureVector("confirm_replay"),
			await invoke(fixtureVector("confirm_replay")),
		);

		const retryableConfirm = fixtureVector("confirm_retryable");
		if (!retryableConfirm.op || !retryableConfirm.instances) {
			throw new Error("retryable fixture setup missing");
		}
		await seedBinding(
			retryableConfirm.op,
			retryableConfirm.instances,
			"retryable",
			fixture.now + 300,
			null,
		);
		await expectVector(retryableConfirm, await invoke(retryableConfirm));

		const expiredOriginal = fixtureVector("confirm_original_expired");
		if (!expiredOriginal.op) throw new Error("expired fixture setup missing");
		expect(await purgeBinding(expiredOriginal.op)).toBeNull();
		await expectVector(expiredOriginal, await invoke(expiredOriginal));
		expect(await purgeBinding(expiredOriginal.op)).toBeNull();

		const fault = fixtureVector("fault_then_retry");
		if (!fault.instances) throw new Error("fault fixture setup missing");
		for (const instanceId of fault.instances) await seedInstance(instanceId);
		await expectVector(fault, await invoke(fault, flakyEnv(staticEnv)));
		expect(await rowCount("instances", fault.instances[0])).toBe(0);
		expect(await rowCount("instances", fault.instances[1])).toBe(1);
		const retried = await invoke(fault);
		expect(await outcome(retried)).toEqual({
			status: fault.expected.retry_status,
			disposition: fault.expected.retry_disposition,
		});
	});
});

describe("portal purge log hygiene", () => {
	it("logs only coarse count/reason fields across retry, submit, and confirm", async () => {
		const rawOperation = "leak-operation-canary";
		const instanceA = "aaaaaaaaaa";
		const instanceB = "aaaaaaaaab";
		const deviceFingerprint = `sha256:${"f".repeat(64)}`;
		const label = "leak-label-canary";
		const ticket = "leak-ticket-canary";
		const owner = "leak-owner-canary";
		await seedInstance(instanceA, { deviceFp: deviceFingerprint, label });
		await seedInstance(instanceB, { deviceFp: deviceFingerprint, label });
		const envelope = await signPurge([instanceA, instanceB], { op: rawOperation });
		const operationHash = await sha256FingerprintText(rawOperation);
		const snapshotDigest = await sha256FingerprintText(JSON.stringify([instanceA, instanceB]));
		const confirmation = await signConfirm(rawOperation, snapshotDigest);
		const spy = vi.spyOn(console, "log").mockImplementation(() => {});

		try {
			expect(
				await outcome(
					await handlePurge(
						serviceRequest("/internal/purge", envelope),
						flakyEnv(handlerEnv()),
						now(),
					),
				),
			).toEqual({ status: 503, disposition: "retryable" });
			expect(
				await outcome(
					await handlePurge(serviceRequest("/internal/purge", envelope), handlerEnv(), now()),
				),
			).toEqual({ status: 200, disposition: "complete" });
			expect(
				await outcome(
					await handlePurgeConfirm(
						confirmServiceRequest(envelope, confirmation),
						handlerEnv(),
						now(),
					),
				),
			).toEqual({ status: 200, disposition: "complete" });

			const records = spy.mock.calls
				.map(([line]) => line)
				.filter((line): line is string => typeof line === "string")
				.map((line) => JSON.parse(line) as Record<string, unknown>);
			const raw = spy.mock.calls.map(([line]) => String(line)).join("\n");
			for (const canary of [
				rawOperation,
				operationHash,
				snapshotDigest,
				instanceA,
				instanceB,
				deviceFingerprint,
				label,
				ticket,
				owner,
				envelope,
				confirmation,
				"purge-batch-failure-canary",
			]) {
				expect(raw).not.toContain(canary);
			}
			for (const record of records.filter((record) => String(record.event).startsWith("purge_"))) {
				expect(Object.keys(record).sort()).toEqual(expect.arrayContaining(["event", "timestamp"]));
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
