// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import { env } from "cloudflare:test";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import type { Env } from "../src/env";
import { handlePurge } from "../src/purge";
import { PURGE_SIGNAL_TTL_SECONDS } from "../src/purge-signal";
import { applyRelayD1Migrations } from "./apply-migrations";
import {
	CONFIRM_ROUTE,
	NOW,
	REQUEST_ROUTE,
	clearRows,
	confirmationWrapper,
	fixtureAttestation,
	fixtureInstanceIds,
	fixtureRequest,
	post,
	purgeSignals,
	registerOrigin,
	response,
	seedInstance,
	signedAttestation,
	signedRequest,
	transcript,
} from "./owner-purge.helpers";

const RELAY_V1_NAME = "relay_retained_key_v1_first_confirmation_and_lost_response_retry";
const SIGNAL_KEY_RE =
	/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z\/relay\/(complete|confirmed)\/[0-9a-f]{8}$/;

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

function dispositions(signals: { name: string }[]): string[] {
	return signals.map(({ name }) => name.split("/")[2]).sort();
}

describe("owner-purge alert on use", () => {
	it("signals each successful transition once, and never a replay", async () => {
		const request = fixtureRequest(RELAY_V1_NAME);
		for (const id of fixtureInstanceIds(request)) await seedInstance(id);

		expect((await response(post(REQUEST_ROUTE, request))).body.disposition).toBe("complete");
		expect(dispositions(await purgeSignals())).toEqual(["complete"]);
		expect((await response(post(REQUEST_ROUTE, request))).body.disposition).toBe("complete");
		expect(dispositions(await purgeSignals())).toEqual(["complete"]);

		vi.setSystemTime(transcript(RELAY_V1_NAME).attestation_received_at);
		const wrapper = confirmationWrapper(request, fixtureAttestation(RELAY_V1_NAME));
		expect((await response(post(CONFIRM_ROUTE, wrapper))).body.disposition).toBe("confirmed");
		expect((await response(post(CONFIRM_ROUTE, wrapper))).body.disposition).toBe("confirmed");
		expect(dispositions(await purgeSignals())).toEqual(["complete", "confirmed"]);
	});

	it("carries only service, disposition and time, and expires seven days after the write", async () => {
		const operation = "signal-hygiene-operation";
		const instanceId = "00000000-0000-4000-8000-000000000097";
		await seedInstance(instanceId);
		const request = await signedRequest({ operationId: operation, instanceIds: [instanceId] });
		vi.useRealTimers();
		const beforeRealSeconds = Math.floor(Date.now() / 1000);
		vi.useFakeTimers();
		vi.setSystemTime(NOW);
		expect((await response(post(REQUEST_ROUTE, request))).body.disposition).toBe("complete");
		vi.useRealTimers();
		const afterRealSeconds = Math.ceil(Date.now() / 1000);

		const signals = await purgeSignals();
		expect(signals).toHaveLength(1);
		const [signal] = signals;
		expect(signal.name).toMatch(SIGNAL_KEY_RE);
		expect(signal.name.startsWith(new Date(NOW).toISOString())).toBe(true);
		for (const secret of [operation, instanceId, request.request_digest, request.integrity]) {
			expect(signal.name).not.toContain(secret);
		}
		const stored = await env.OWNER_PURGE_SIGNAL.getWithMetadata(signal.name);
		expect(stored.value).toBe("");
		expect(stored.metadata).toBeNull();
		// Miniflare stamps the expiry on the real clock while the Worker runs on
		// the fixture's, so compare against the real clock around the write.
		expect(PURGE_SIGNAL_TTL_SECONDS).toBe(7 * 24 * 60 * 60);
		expect(signal.expiration).toBeGreaterThanOrEqual(beforeRealSeconds + PURGE_SIGNAL_TTL_SECONDS);
		expect(signal.expiration).toBeLessThanOrEqual(afterRealSeconds + PURGE_SIGNAL_TTL_SECONDS);
	});

	it("keeps the fixed lifetime when the signer chooses a short envelope", async () => {
		// The envelope's expiry is the signer's choice, down to a minute. A forger
		// must not be able to shorten the record of their own purge with it.
		const instanceId = "00000000-0000-4000-8000-000000000094";
		await seedInstance(instanceId);
		const request = await signedRequest({
			operationId: "signal-short-envelope",
			instanceIds: [instanceId],
			issuedAt: NOW,
			expiresAt: NOW + 61_000,
		});
		vi.useRealTimers();
		const beforeRealSeconds = Math.floor(Date.now() / 1000);
		vi.useFakeTimers();
		vi.setSystemTime(NOW);
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
		vi.useRealTimers();
		const afterRealSeconds = Math.ceil(Date.now() / 1000);

		const signals = await purgeSignals();
		expect(dispositions(signals)).toEqual(["complete", "confirmed"]);
		for (const signal of signals) {
			expect(signal.expiration).toBeGreaterThanOrEqual(
				beforeRealSeconds + PURGE_SIGNAL_TTL_SECONDS,
			);
			expect(signal.expiration).toBeLessThanOrEqual(afterRealSeconds + PURGE_SIGNAL_TTL_SECONDS);
		}
	});

	it("keeps a finished purge complete when the signal cannot be written", async () => {
		const instanceId = "00000000-0000-4000-8000-000000000096";
		await seedInstance(instanceId);
		const request = await signedRequest({ operationId: "signal-down", instanceIds: [instanceId] });
		await registerOrigin(request.operation_id);
		const failing = {
			put: () => Promise.reject(new Error("kv unavailable")),
		} as unknown as KVNamespace;
		const spy = vi.spyOn(console, "log").mockImplementation(() => {});
		try {
			const result = await handlePurge(
				new Request(`https://relay.internal${REQUEST_ROUTE}`, {
					method: "POST",
					headers: {
						authorization: `Bearer ${env.PURGE_SECRET}`,
						"content-type": "application/json",
					},
					body: JSON.stringify(request),
				}),
				{ ...(env as unknown as Env), OWNER_PURGE_SIGNAL: failing },
				NOW,
			);
			expect(((await result.json()) as { disposition: string }).disposition).toBe("complete");
			expect(spy.mock.calls.map(([line]) => String(line))).toContain(
				JSON.stringify({ event: "internal_error", reason: "owner_purge_signal_failed" }),
			);
		} finally {
			spy.mockRestore();
		}
	});

	it("writes nothing when the deployment has no signal namespace", async () => {
		const instanceId = "00000000-0000-4000-8000-000000000095";
		await seedInstance(instanceId);
		const request = await signedRequest({
			operationId: "signal-unbound",
			instanceIds: [instanceId],
		});
		await registerOrigin(request.operation_id);
		const result = await handlePurge(
			new Request(`https://relay.internal${REQUEST_ROUTE}`, {
				method: "POST",
				headers: {
					authorization: `Bearer ${env.PURGE_SECRET}`,
					"content-type": "application/json",
				},
				body: JSON.stringify(request),
			}),
			{ ...(env as unknown as Env), OWNER_PURGE_SIGNAL: undefined },
			NOW,
		);
		expect(((await result.json()) as { disposition: string }).disposition).toBe("complete");
		expect(await purgeSignals()).toEqual([]);
	});
});
