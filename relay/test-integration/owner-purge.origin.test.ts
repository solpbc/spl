// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import { SELF, env } from "cloudflare:test";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import type { Env } from "../src/env";
import { canonicalizeOwnerPurgeJson, handlePurge, ownerPurgeIntegrityFrame } from "../src/purge";
import { base64UrlEncode } from "../src/tokens";
import readinessFixture from "../test-fixtures/owner-purge-readiness-v1.json";
import { applyRelayD1Migrations } from "./apply-migrations";
import {
	CONFIRM_ROUTE,
	NOW,
	READINESS_NONCE,
	READINESS_PROOF_V1,
	READINESS_PROOF_V2,
	READINESS_ROUTE,
	REQUEST_ROUTE,
	bindingCount,
	clearRows,
	confirmationWrapper,
	originControl,
	originFrames,
	post,
	registerOrigin,
	response,
	rowCount,
	seedInstance,
	setOriginMode,
	signedAttestation,
	signedRequest,
} from "./owner-purge.helpers";

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

async function hmac(keyText: string, frame: Uint8Array): Promise<string> {
	const key = await crypto.subtle.importKey(
		"raw",
		new TextEncoder().encode(keyText),
		{ name: "HMAC", hash: "SHA-256" },
		false,
		["sign"],
	);
	return base64UrlEncode(new Uint8Array(await crypto.subtle.sign("HMAC", key, frame)));
}

async function readinessProofs(originCheck: boolean): Promise<[string, string]> {
	const domain = "solpbc-owner-purge-v1:relay:readiness";
	const keys = [env.OWNER_PURGE_HMAC_KEY_V1, env.OWNER_PURGE_HMAC_KEY_V2];
	return Promise.all(
		[1, 2].map((version) =>
			hmac(
				keys[version - 1],
				ownerPurgeIntegrityFrame(
					domain,
					canonicalizeOwnerPurgeJson({
						version: 1,
						key_version: version,
						service: "relay",
						nonce: READINESS_NONCE,
						origin_check: originCheck,
					}),
				),
			),
		),
	) as Promise<[string, string]>;
}

function readiness(): Promise<Response> {
	return SELF.fetch(`http://relay.internal${READINESS_ROUTE}`, {
		headers: {
			authorization: `Bearer ${env.PURGE_SECRET}`,
			"x-owner-purge-readiness-nonce": READINESS_NONCE,
		},
	});
}

function directPurge(body: unknown, overrides: Partial<Env>): Promise<Response> {
	return handlePurge(
		new Request(`https://relay.internal${REQUEST_ROUTE}`, {
			method: "POST",
			headers: {
				authorization: `Bearer ${env.PURGE_SECRET}`,
				"content-type": "application/json",
			},
			body: JSON.stringify(body),
		}),
		{ ...(env as unknown as Env), ...overrides },
		NOW,
	);
}

describe("owner-purge origin check", () => {
	it("cannot reach the portal's fetch handler through ORIGINATOR", async () => {
		// The portal stand-in's default handler answers every route...
		const direct = await originControl().fetch("https://services.solstone.app/account");
		expect(await direct.text()).toBe("portal fetch handler");
		// ...but the binding the relay holds names an entrypoint with one method
		// and no fetch, so no URL the relay chooses reaches that handler.
		for (const url of [
			"https://services.solstone.app/account",
			"https://services.solstone.app/admin/impersonate",
			"https://account.internal/internal/deletion/originated",
		]) {
			await expect(
				(env as unknown as { ORIGINATOR: Fetcher }).ORIGINATOR.fetch(url, { method: "POST" }),
			).rejects.toThrow();
		}
	});

	it("asks once at first receipt and purges an originated operation", async () => {
		const instanceId = "00000000-0000-4000-8000-000000000081";
		await seedInstance(instanceId);
		const request = await signedRequest({ operationId: "origin-yes", instanceIds: [instanceId] });

		expect((await response(post(REQUEST_ROUTE, request))).body.disposition).toBe("complete");
		expect(await rowCount("instances", instanceId)).toBe(0);
		const frames = await originFrames();
		expect(frames).toHaveLength(1);
		expect(frames[0]).toMatchObject({
			version: 1,
			key_version: request.key_version,
			service: "relay",
			operation_id: "origin-yes",
			issued_at: NOW,
		});
		expect(Object.keys(frames[0]).sort()).toEqual(
			["integrity", "issued_at", "key_version", "operation_id", "service", "version"].sort(),
		);
	});

	it("refuses an unoriginated operation and deletes nothing", async () => {
		const instanceId = "00000000-0000-4000-8000-000000000082";
		await seedInstance(instanceId);
		const request = await signedRequest({
			operationId: "origin-no",
			instanceIds: [instanceId],
			issuedAt: NOW,
			expiresAt: NOW + 61_000,
		});
		const refused = await response(post(REQUEST_ROUTE, request, { originated: false }));

		expect(refused.status).toBe(409);
		expect(refused.body.disposition).toBe("refused");
		expect(Object.keys(refused.body).sort()).toEqual(
			[
				"disposition",
				"integrity",
				"key_version",
				"operation_id",
				"request_digest",
				"service",
				"version",
			].sort(),
		);
		expect(JSON.stringify(refused.body)).not.toContain(instanceId);
		expect(await rowCount("instances", instanceId)).toBe(1);
		expect(await rowCount("pending_grants", instanceId)).toBe(1);
		expect(await bindingCount()).toBe(0);
	});

	it("retries without binding or deleting when the portal cannot answer", async () => {
		for (const mode of ["throw", "malformed"] as const) {
			await clearRows();
			const instanceId = "00000000-0000-4000-8000-000000000083";
			await seedInstance(instanceId);
			const request = await signedRequest({
				operationId: `origin-${mode}`,
				instanceIds: [instanceId],
			});
			await setOriginMode(mode);
			const result = await response(post(REQUEST_ROUTE, request));
			expect(result.status).toBe(503);
			expect(result.body.disposition).toBe("retryable");
			expect(await rowCount("instances", instanceId)).toBe(1);
			expect(await bindingCount()).toBe(0);
		}
	});

	it("does not ask again on a replay, or on confirm", async () => {
		const instanceId = "00000000-0000-4000-8000-000000000084";
		await seedInstance(instanceId);
		const request = await signedRequest({
			operationId: "origin-replay",
			instanceIds: [instanceId],
		});
		expect((await response(post(REQUEST_ROUTE, request))).body.disposition).toBe("complete");

		// The portal is now unreachable: a replay and the confirmation still settle,
		// because the existing binding is the proof of the earlier check.
		await setOriginMode("throw");
		expect((await response(post(REQUEST_ROUTE, request))).body.disposition).toBe("complete");
		const wrapper = confirmationWrapper(
			request,
			await signedAttestation({
				operationId: request.operation_id,
				requestDigest: request.request_digest,
				keyVersion: request.key_version,
				issuedAt: NOW,
				expiresAt: NOW + 60_000,
			}),
		);
		expect((await response(post(CONFIRM_ROUTE, wrapper))).body.disposition).toBe("confirmed");
		expect(await originFrames()).toHaveLength(1);
	});

	it("skips the check on a relay with no ORIGINATOR binding", async () => {
		const instanceId = "00000000-0000-4000-8000-000000000085";
		await seedInstance(instanceId);
		const request = await signedRequest({
			operationId: "origin-unbound",
			instanceIds: [instanceId],
		});
		const result = await directPurge(request, { ORIGINATOR: undefined });
		expect(((await result.json()) as { disposition: string }).disposition).toBe("complete");
		expect(await originFrames()).toEqual([]);
	});

	it("signs origin_check true only when the portal answers a live probe", async () => {
		const bound = await readiness();
		expect(bound.status).toBe(204);
		expect(bound.headers.get("x-owner-purge-readiness-proof-v1")).toBe(READINESS_PROOF_V1);
		expect(bound.headers.get("x-owner-purge-readiness-proof-v2")).toBe(READINESS_PROOF_V2);
		expect([READINESS_PROOF_V1, READINESS_PROOF_V2]).toEqual(await readinessProofs(true));
		const probes = await originFrames();
		expect(probes.map((frame) => frame.key_version).sort()).toEqual([1, 2]);
		for (const probe of probes) expect(probe.operation_id).toMatch(/^[A-Za-z0-9_-]{43}$/);
		expect(probes[0].operation_id).not.toBe(probes[1].operation_id);

		const unoriginatedProofs = await readinessProofs(false);
		await setOriginMode("throw");
		const failing = await readiness();
		expect(failing.status).toBe(204);
		expect([
			failing.headers.get("x-owner-purge-readiness-proof-v1"),
			failing.headers.get("x-owner-purge-readiness-proof-v2"),
		]).toEqual(unoriginatedProofs);
	});

	it("vendors origin frame vectors the relay reproduces", async () => {
		const keys = { 1: env.OWNER_PURGE_HMAC_KEY_V1, 2: env.OWNER_PURGE_HMAC_KEY_V2 };
		for (const name of ["v1", "v2"] as const) {
			const vector = readinessFixture.origin_check.sample_frames[name];
			const { integrity, ...unsigned } = vector.frame;
			const canonical = canonicalizeOwnerPurgeJson(unsigned);
			expect(canonical).toBe(vector.canonical_without_integrity);
			const frame = ownerPurgeIntegrityFrame(readinessFixture.origin_check.domain, canonical);
			expect(Buffer.from(frame).toString("hex")).toBe(vector.frame_hex);
			expect(await hmac(keys[unsigned.key_version as 1 | 2], frame)).toBe(integrity);
		}
	});
});
