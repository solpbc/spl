// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import fixture from "../test-fixtures/owner-purge-v1.json";
import { applyRelayD1Migrations } from "./apply-migrations";
import {
	CONFIRM_ROUTE,
	NOW,
	REQUEST_ROUTE,
	bindingCount,
	bindingDisposition,
	clearRows,
	cloneFixture,
	confirmationWrapper,
	fixtureAttestation,
	fixtureDisposition,
	fixtureInstanceIds,
	fixtureNumber,
	fixtureRequest,
	fixtureResponse,
	integrity,
	post,
	rejectionVector,
	response,
	rowCount,
	seedInstance,
	signedAttestation,
	signedRequest,
	transcript,
} from "./owner-purge.helpers";

const RELAY_V1_NAME = "relay_retained_key_v1_first_confirmation_and_lost_response_retry";
const SUPPORT_V1_NAME = "support_retained_key_v1_first_confirmation_and_lost_response_retry";
const SUPPORT_V2_NAME = "support_current_key_v2_utf8_snapshot";
const RELAY_V2_NAME = "relay_current_key_v2";

// Static fixture import: keep the integration suite coupled to the vendored
// conformance artifact rather than copied protocol values.
for (const name of [RELAY_V1_NAME, SUPPORT_V1_NAME, SUPPORT_V2_NAME, RELAY_V2_NAME]) {
	if (!fixture.wire_transcripts.some((candidate) => candidate.name === name)) {
		throw new Error(`fixture transcript missing: ${name}`);
	}
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
		const request = fixtureRequest(RELAY_V1_NAME);
		for (const id of fixtureInstanceIds(request)) await seedInstance(id);
		const control = "00000000-0000-4000-8000-000000000099";
		await seedInstance(control);

		expect(await response(post(REQUEST_ROUTE, request))).toEqual({
			status: 200,
			body: fixtureResponse(RELAY_V1_NAME, "submit_response"),
		});
		for (const id of fixtureInstanceIds(request)) {
			expect(await rowCount("instances", id)).toBe(0);
			expect(await rowCount("pending_grants", id)).toBe(0);
		}
		expect(await rowCount("instances", control)).toBe(1);
		expect(await rowCount("pending_grants", control)).toBe(1);

		const retained = transcript(RELAY_V1_NAME);
		vi.setSystemTime(retained.attestation_received_at);
		const attestation = fixtureAttestation(RELAY_V1_NAME);
		expect(await response(post(CONFIRM_ROUTE, confirmationWrapper(request, attestation)))).toEqual({
			status: 200,
			body: fixtureResponse(RELAY_V1_NAME, "response"),
		});
		expect(await response(post(CONFIRM_ROUTE, confirmationWrapper(request, attestation)))).toEqual({
			status: 200,
			body: fixtureResponse(RELAY_V1_NAME, "response"),
		});
	});

	it("executes current-key v2 submit and confirmation", async () => {
		const request = fixtureRequest(RELAY_V2_NAME);
		for (const id of fixtureInstanceIds(request)) await seedInstance(id);
		expect(await response(post(REQUEST_ROUTE, request))).toEqual({
			status: 200,
			body: fixtureResponse(RELAY_V2_NAME, "submit_response"),
		});
		vi.setSystemTime(transcript(RELAY_V2_NAME).attestation_received_at);
		expect(
			await response(
				post(CONFIRM_ROUTE, confirmationWrapper(request, fixtureAttestation(RELAY_V2_NAME))),
			),
		).toEqual({
			status: 200,
			body: fixtureResponse(RELAY_V2_NAME, "response"),
		});
	});
});

describe("owner-purge v1 relay rejection vectors", () => {
	it("concurrent_or_lost_submit_retry_converges_to_one_binding", async () => {
		const vector = rejectionVector("concurrent_or_lost_submit_retry_converges_to_one_binding");
		const request = fixtureRequest(RELAY_V1_NAME);
		for (const id of fixtureInstanceIds(request)) await seedInstance(id);
		const gateHeaders = { "x-test-owner-purge-race-gate": "insert" };
		const gated = await post(REQUEST_ROUTE, request, { headers: gateHeaders });

		expect(gated.headers.get("x-test-owner-purge-race-gate-arrivals")).toBe(
			String(vector.deliveries),
		);
		expect(await gated.json()).toEqual({
			responses: [
				{ status: 200, body: fixtureResponse(RELAY_V1_NAME, "submit_response") },
				{ status: 200, body: fixtureResponse(RELAY_V1_NAME, "submit_response") },
			],
		});
		expect(await bindingCount()).toBe(vector.expected_bindings);
		for (const id of fixtureInstanceIds(request)) expect(await rowCount("instances", id)).toBe(0);
	});

	it("confirmation expiry during the conditional transition remains unconfirmed", async () => {
		const request = fixtureRequest(RELAY_V1_NAME);
		for (const id of fixtureInstanceIds(request)) await seedInstance(id);
		const control = "00000000-0000-4000-8000-000000000096";
		await seedInstance(control);
		expect(await response(post(REQUEST_ROUTE, request))).toEqual({
			status: 200,
			body: fixtureResponse(RELAY_V1_NAME, "submit_response"),
		});
		vi.setSystemTime(transcript(RELAY_V1_NAME).attestation_received_at);
		const gated = await post(
			CONFIRM_ROUTE,
			confirmationWrapper(request, fixtureAttestation(RELAY_V1_NAME)),
			{ headers: { "x-test-owner-purge-race-gate": "confirm-expire" } },
		);

		expect(gated.headers.get("x-test-owner-purge-race-gate-arrivals")).toBe("2");
		expect(await gated.json()).toMatchObject({
			responses: [
				{ status: 409, body: { disposition: "refused" } },
				{ status: 409, body: { disposition: "refused" } },
			],
		});
		expect(await bindingDisposition()).toBe("complete");
		for (const id of fixtureInstanceIds(request)) {
			expect(await rowCount("instances", id)).toBe(0);
			expect(await rowCount("pending_grants", id)).toBe(0);
		}
		expect(await rowCount("instances", control)).toBe(1);
		expect(await rowCount("pending_grants", control)).toBe(1);
	});

	it("same_operation_different_digest_is_refused_before_lookup", async () => {
		const vector = rejectionVector("same_operation_different_digest_is_refused_before_lookup");
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
		expect(changed.body.disposition).toBe(fixtureDisposition(vector));
		expect(await rowCount("instances", second)).toBe(1);
	});

	it("wrong_service_or_digest_never_advances", async () => {
		const vector = rejectionVector("wrong_service_or_digest_never_advances");
		const support = fixtureRequest(SUPPORT_V1_NAME);
		expect(await response(post(REQUEST_ROUTE, support))).toEqual({
			status: 400,
			body: { error: "bad request" },
		});
		const invalidDigest = await signedRequest({ operationId: "bad-digest", instanceIds: [] });
		// Deliberately invalid digest sentinel, not signed-protocol authority.
		invalidDigest.request_digest = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
		const { integrity: _integrity, ...invalidUnsigned } = invalidDigest;
		invalidDigest.integrity = await integrity(
			"request",
			invalidUnsigned,
			invalidDigest.key_version,
		);
		expect((await response(post(REQUEST_ROUTE, invalidDigest))).body.disposition).toBe(
			fixtureDisposition(vector),
		);
		expect(await bindingCount()).toBe(0);
	});

	it("uncanonicalizable snapshot is rejected as bad integrity before D1", async () => {
		const malformed = {
			...fixtureRequest(RELAY_V1_NAME),
			association_snapshot: { instance_ids: [1.5] },
			// Deliberately invalid integrity sentinel, not signed-protocol authority.
			integrity: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		};
		expect(await response(post(REQUEST_ROUTE, malformed))).toEqual({
			status: 401,
			body: { error: "unauthorized" },
		});
		expect(await bindingCount()).toBe(0);
	});

	it("legacy_absence_never_certifies_completion", async () => {
		const vector = rejectionVector("legacy_absence_never_certifies_completion");
		const request = await signedRequest({ operationId: "absent-op", instanceIds: [] });
		const attestation = await signedAttestation({
			operationId: request.operation_id,
			requestDigest: request.request_digest,
		});
		expect(
			(await response(post(CONFIRM_ROUTE, confirmationWrapper(request, attestation)))).body
				.disposition,
		).toBe(fixtureDisposition(vector));
		expect(await bindingCount()).toBe(0);
	});

	it("response_signed_with_non_original_key_version_remains_pending", async () => {
		// Finalization is account-side; relay verifies only this fixture's cross-key response HMAC material.
		const vector = rejectionVector("response_signed_with_non_original_key_version_remains_pending");
		const request = fixtureRequest(RELAY_V2_NAME);
		for (const id of fixtureInstanceIds(request)) await seedInstance(id);
		expect(await response(post(REQUEST_ROUTE, request))).toEqual({
			status: 200,
			body: fixtureResponse(RELAY_V2_NAME, "submit_response"),
		});
		const support = transcript(SUPPORT_V2_NAME);
		const wrongResponse = {
			...cloneFixture(support.response),
			key_version: vector.response_key_version,
		};
		expect(
			await integrity(
				"response",
				withoutIntegrity(wrongResponse),
				vectorKeyVersion(vector.response_key_version),
				support.service,
			),
		).toBe(support.wrong_response_key_version?.integrity);
	});

	it("request_at_maximum_lifetime_is_accepted", async () => {
		const vector = rejectionVector("request_at_maximum_lifetime_is_accepted");
		vi.setSystemTime(fixtureNumber(vector, "received_at"));
		const request = await signedRequest({
			operationId: "request-max",
			instanceIds: [],
			issuedAt: fixtureNumber(vector, "issued_at"),
			expiresAt: fixtureNumber(vector, "expires_at"),
		});
		expect((await response(post(REQUEST_ROUTE, request))).body.disposition).toBe(
			fixtureDisposition(vector),
		);
	});

	it("request_future_issued_is_refused_before_lookup", async () => {
		const vector = rejectionVector("request_future_issued_is_refused_before_lookup");
		vi.setSystemTime(fixtureNumber(vector, "received_at"));
		const request = await signedRequest({
			operationId: "request-future",
			instanceIds: [],
			issuedAt: fixtureNumber(vector, "issued_at"),
			expiresAt: fixtureNumber(vector, "expires_at"),
		});
		expect((await response(post(REQUEST_ROUTE, request))).body.disposition).toBe(
			fixtureDisposition(vector),
		);
		expect(await bindingCount()).toBe(0);
	});

	it("request_overlong_is_refused_before_lookup", async () => {
		const vector = rejectionVector("request_overlong_is_refused_before_lookup");
		vi.setSystemTime(fixtureNumber(vector, "received_at"));
		const request = await signedRequest({
			operationId: "request-overlong",
			instanceIds: [],
			issuedAt: fixtureNumber(vector, "issued_at"),
			expiresAt: fixtureNumber(vector, "expires_at"),
		});
		expect((await response(post(REQUEST_ROUTE, request))).body.disposition).toBe(
			fixtureDisposition(vector),
		);
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
		const vector = rejectionVector("attestation_at_maximum_lifetime_is_accepted");
		const receivedAt = fixtureNumber(vector, "received_at");
		vi.setSystemTime(receivedAt);
		const request = await signedRequest({
			operationId: "attestation-max",
			instanceIds: [],
			issuedAt: receivedAt,
			expiresAt: fixtureNumber(vector, "expires_at"),
		});
		expect((await response(post(REQUEST_ROUTE, request))).body.disposition).toBe("complete");
		const attestation = await signedAttestation({
			operationId: request.operation_id,
			requestDigest: request.request_digest,
			issuedAt: fixtureNumber(vector, "issued_at"),
			expiresAt: fixtureNumber(vector, "expires_at"),
		});
		expect(
			(await response(post(CONFIRM_ROUTE, confirmationWrapper(request, attestation)))).body
				.disposition,
		).toBe(fixtureDisposition(vector));
	});

	it("attestation_future_or_overlong_is_refused_without_state_change", async () => {
		const vector = rejectionVector(
			"attestation_future_or_overlong_is_refused_without_state_change",
		);
		const firstCase = vector.cases?.[0];
		if (!firstCase) throw new Error(`fixture ${vector.name} has no timing cases`);
		vi.setSystemTime(firstCase.received_at);
		const request = await signedRequest({
			operationId: "attestation-refused",
			instanceIds: [],
			issuedAt: firstCase.received_at,
			expiresAt: firstCase.received_at + 1,
		});
		expect((await response(post(REQUEST_ROUTE, request))).body.disposition).toBe("complete");
		for (const timing of vector.cases ?? []) {
			const attestation = await signedAttestation({
				operationId: request.operation_id,
				requestDigest: request.request_digest,
				issuedAt: timing.issued_at,
				expiresAt: timing.expires_at,
			});
			expect(
				await response(post(CONFIRM_ROUTE, confirmationWrapper(request, attestation))),
			).toEqual({ status: 400, body: { error: "bad request" } });
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
			const attestation = await signedAttestation({
				operationId: request.operation_id,
				requestDigest: request.request_digest,
			});
			expect(
				(await response(post(CONFIRM_ROUTE, confirmationWrapper(request, attestation)))).body
					.disposition,
			).toBe("confirmed");
			const invalidAttestation = { ...attestation, state: 1 };
			expect(
				await response(post(CONFIRM_ROUTE, { envelope: request, attestation: invalidAttestation })),
			).toEqual({ status: 400, body: { error: "bad request" } });
			const raw = spy.mock.calls.map(([line]) => String(line)).join("\n");
			expect(raw).not.toContain(operation);
			expect(raw).not.toContain(instanceId);
			expect(raw).not.toContain(request.integrity);
			expect(raw).not.toContain(attestation.integrity);
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

function withoutIntegrity<T extends { integrity: string }>(value: T): Omit<T, "integrity"> {
	const { integrity: _integrity, ...unsigned } = value;
	return unsigned;
}

function vectorKeyVersion(value: number | undefined): 1 | 2 {
	if (value === 1 || value === 2) return value;
	throw new Error("fixture response key version invalid");
}
