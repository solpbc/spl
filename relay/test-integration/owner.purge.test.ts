// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import { SELF, env } from "cloudflare:test";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import fixture from "../../proto/purge-v1-fixtures.json";
import type { Env } from "../src/env";
import { handlePurge, handlePurgeConfirm, sha256FingerprintText } from "../src/purge";
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
	overrides: Record<string, unknown> = {},
): Record<string, unknown> {
	const issuedAt = now();
	return {
		iss: "spl-portal",
		aud: "spl-relay-purge",
		ver: "1",
		typ: "purge-confirm",
		op,
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

async function signConfirm(op: string, overrides: Record<string, unknown> = {}): Promise<string> {
	return signClaims(env.PORTAL_TEST_SIGNING_JWK, dynamicConfirmClaims(op, overrides));
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
	state: "retryable" | "complete",
	expiresAt: number,
	completedAt: number | null,
): Promise<void> {
	const hash = await sha256FingerprintText(op);
	await env.DB.prepare(
		"INSERT INTO purge_operations (operation_id_hash, snapshot_digest, state, expires_at, completed_at) VALUES (?, ?, ?, ?, ?)",
	)
		.bind(hash, `sha256:${"e".repeat(64)}`, state, expiresAt, completedAt)
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

	it("deletes a complete binding before replying to confirmation and preserves retryable bindings", async () => {
		const target = newId();
		await seedInstance(target);
		const operation = `confirm-${crypto.randomUUID()}`;
		const envelope = await signPurge([target], { op: operation });
		expect((await post("/internal/purge", envelope)).status).toBe(200);
		const confirmation = await signConfirm(operation);

		expect(await outcome(await post("/internal/purge/confirm", confirmation))).toEqual({
			status: 200,
			disposition: "complete",
		});
		expect(await purgeBinding(operation)).toBeNull();
		expect(await outcome(await post("/internal/purge/confirm", confirmation))).toEqual({
			status: 200,
			disposition: "confirmed_absent",
		});

		const retryOperation = `retryable-confirm-${crypto.randomUUID()}`;
		await seedBinding(retryOperation, "retryable", now() + 300, null);
		expect(
			await outcome(await post("/internal/purge/confirm", await signConfirm(retryOperation))),
		).toEqual({ status: 409, disposition: "not_complete" });
		expect(await purgeBinding(retryOperation)).toMatchObject({ state: "retryable" });
	});

	it("refuses malformed, tampered, and expired confirmations before changing a complete binding", async () => {
		const operation = `confirm-refusal-${crypto.randomUUID()}`;
		await seedBinding(operation, "complete", now() + 300, now());
		const confirmation = await signConfirm(operation);
		const [header, payload] = confirmation.split(".");
		const malformedSignature = `${header}.${payload}.!`;
		expect(await outcome(await post("/internal/purge/confirm", malformedSignature))).toEqual({
			status: 400,
			disposition: "refused",
		});
		expect(await purgeBinding(operation)).toMatchObject({ state: "complete" });

		const tampered = tamperCompactJwsSignature(confirmation);
		expect(tampered).not.toBe(confirmation);
		expect(await outcome(await post("/internal/purge/confirm", tampered))).toEqual({
			status: 401,
			disposition: "refused",
		});
		expect(await purgeBinding(operation)).toMatchObject({ state: "complete" });

		const expired = await signConfirm(operation, { iat: now() - 120, exp: now() - 1 });
		expect(await outcome(await post("/internal/purge/confirm", expired))).toEqual({
			status: 409,
			disposition: "expired",
		});
		expect(await purgeBinding(operation)).toMatchObject({ state: "complete" });
	});

	it("lazily hard-deletes completed bindings after seven days", async () => {
		const operation = `old-complete-${crypto.randomUUID()}`;
		const then = 2_000_000_000;
		await seedBinding(operation, "complete", then + 300, then - 7 * DAY - 1);
		const confirmation = await signClaims(env.PORTAL_TEST_SIGNING_JWK, {
			iss: "spl-portal",
			aud: "spl-relay-purge",
			ver: "1",
			typ: "purge-confirm",
			op: operation,
			iat: then,
			exp: then + 300,
		});

		expect(
			await outcome(
				await handlePurgeConfirm(
					serviceRequest("/internal/purge/confirm", confirmation),
					handlerEnv(),
					then,
				),
			),
		).toEqual({ status: 200, disposition: "confirmed_absent" });
		expect(await purgeBinding(operation)).toBeNull();
	});
});

describe("portal purge v1 fixture", () => {
	it("executes every static signed v1 vector against D1 state", async () => {
		const staticEnv = handlerEnv({ PORTAL_JWKS_PUBLIC: fixture.portal_jwks_public });
		const valid = fixtureVector("valid_purge");
		if (!valid.instances || !valid.control) throw new Error("valid fixture setup missing");
		for (const instanceId of [...valid.instances, valid.control]) await seedInstance(instanceId);

		const invoke = async (vector: FixtureVector, targetEnv = staticEnv): Promise<Response> => {
			const request = serviceRequest(
				vector.route === "purge" ? "/internal/purge" : "/internal/purge/confirm",
				vector.envelope,
			);
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
			fixtureVector("valid_confirm"),
			await invoke(fixtureVector("valid_confirm")),
		);
		expect(await purgeBinding("fixture-complete-op")).toBeNull();
		await expectVector(
			fixtureVector("confirm_replay"),
			await invoke(fixtureVector("confirm_replay")),
		);

		const retryableConfirm = fixtureVector("confirm_retryable");
		if (!retryableConfirm.op) throw new Error("retryable fixture setup missing");
		await seedBinding(retryableConfirm.op, "retryable", fixture.now + 300, null);
		await expectVector(retryableConfirm, await invoke(retryableConfirm));

		const oldConfirm = fixtureVector("confirm_after_hard_delete");
		if (!oldConfirm.op) throw new Error("old-complete fixture setup missing");
		await seedBinding(oldConfirm.op, "complete", fixture.now + 300, fixture.now - 7 * DAY - 1);
		await expectVector(oldConfirm, await invoke(oldConfirm));
		expect(await purgeBinding(oldConfirm.op)).toBeNull();

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
		const confirmation = await signConfirm(rawOperation);
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
						serviceRequest("/internal/purge/confirm", confirmation),
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
