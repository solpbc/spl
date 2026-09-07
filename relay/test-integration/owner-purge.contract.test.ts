// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import { env } from "cloudflare:test";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { responseSigner } from "../src/purge";
import fixture from "../test-fixtures/owner-purge-v1.json";
import { applyRelayD1Migrations } from "./apply-migrations";
import {
	CONFIRM_ROUTE,
	NOW,
	REQUEST_ROUTE,
	bindingCount,
	bindingDisposition,
	clearRows,
	confirmationWrapper,
	digest,
	fixtureAttestation,
	fixtureInstanceIds,
	fixtureRequest,
	fixtureResponse,
	integrity,
	post,
	postRaw,
	request,
	response,
	rowCount,
	seedInstance,
	transcript,
} from "./owner-purge.helpers";

const RELAY_V1_NAME = "relay_retained_key_v1_first_confirmation_and_lost_response_retry";
const RELAY_V2_NAME = "relay_current_key_v2";
const SUPPORT_V1_NAME = "support_retained_key_v1_first_confirmation_and_lost_response_retry";
const SUPPORT_V2_NAME = "support_current_key_v2_utf8_snapshot";

for (const name of [RELAY_V1_NAME, RELAY_V2_NAME, SUPPORT_V1_NAME, SUPPORT_V2_NAME]) {
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

describe("owner-purge v1 admission boundaries", () => {
	it("refuses GRANT_SECRET on both purge routes without binding or mutation", async () => {
		const requestEnvelope = fixtureRequest(RELAY_V1_NAME);
		for (const instanceId of fixtureInstanceIds(requestEnvelope)) await seedInstance(instanceId);

		expect(
			await response(post(REQUEST_ROUTE, requestEnvelope, { bearer: env.GRANT_SECRET })),
		).toEqual({
			status: 401,
			body: { error: "unauthorized" },
		});
		expect(
			await response(
				post(
					CONFIRM_ROUTE,
					confirmationWrapper(requestEnvelope, fixtureAttestation(RELAY_V1_NAME)),
					{ bearer: env.GRANT_SECRET },
				),
			),
		).toEqual({
			status: 401,
			body: { error: "unauthorized" },
		});
		expect(await bindingCount()).toBe(0);
		for (const instanceId of fixtureInstanceIds(requestEnvelope)) {
			expect(await rowCount("instances", instanceId)).toBe(1);
			expect(await rowCount("pending_grants", instanceId)).toBe(1);
		}
	});

	it("does not let a browser-shaped Origin header bypass the bearer gate", async () => {
		const headers = { Origin: "https://browser.example.test" };
		const requestEnvelope = fixtureRequest(RELAY_V1_NAME);
		expect(
			await response(
				post(REQUEST_ROUTE, requestEnvelope, {
					bearer: "wrong-purge-bearer",
					headers,
				}),
			),
		).toEqual({ status: 401, body: { error: "unauthorized" } });
		expect(
			await response(
				post(
					CONFIRM_ROUTE,
					confirmationWrapper(requestEnvelope, fixtureAttestation(RELAY_V1_NAME)),
					{
						bearer: "wrong-purge-bearer",
						headers,
					},
				),
			),
		).toEqual({ status: 401, body: { error: "unauthorized" } });
		expect(await bindingCount()).toBe(0);
	});

	it("does not route non-POST or legacy purge paths", async () => {
		expect((await request(REQUEST_ROUTE, undefined, { method: "GET" })).status).toBe(404);
		expect((await request(CONFIRM_ROUTE, undefined, { method: "PUT" })).status).toBe(404);
		expect((await request("/internal/purge", undefined)).status).toBe(404);
		expect(await bindingCount()).toBe(0);
	});

	it("rejects unknown and wrong-typed submit envelope fields before binding", async () => {
		const unknown = { ...fixtureRequest(RELAY_V1_NAME), unexpected: true };
		const wrongType = { ...fixtureRequest(RELAY_V1_NAME), version: "1" };

		expect(await response(post(REQUEST_ROUTE, unknown))).toEqual({
			status: 400,
			body: { error: "bad request" },
		});
		expect(await response(post(REQUEST_ROUTE, wrongType))).toEqual({
			status: 400,
			body: { error: "bad request" },
		});
		expect(await bindingCount()).toBe(0);
	});

	it("rejects duplicate submit-envelope members in hand-crafted raw JSON", async () => {
		const requestEnvelope = fixtureRequest(RELAY_V1_NAME);
		const raw = duplicateFieldJson(requestEnvelope, "expires_at", requestEnvelope.expires_at + 1);
		expect(await response(postRaw(REQUEST_ROUTE, raw))).toEqual({
			status: 401,
			body: { error: "unauthorized" },
		});
		expect(await bindingCount()).toBe(0);
	});

	it("rejects non-finite submit-envelope numbers in hand-crafted raw JSON", async () => {
		const raw = nonFiniteIssuedAtJson(fixtureRequest(RELAY_V1_NAME));
		expect(await response(postRaw(REQUEST_ROUTE, raw))).toEqual({
			status: 400,
			body: { error: "bad request" },
		});
		expect(await bindingCount()).toBe(0);
	});

	it("rejects malformed confirmation wrappers and attestation fields before binding", async () => {
		const envelope = fixtureRequest(RELAY_V1_NAME);
		const attestation = fixtureAttestation(RELAY_V1_NAME);
		const missingEnvelope = { attestation };
		const unknown = { ...confirmationWrapper(envelope, attestation), unexpected: true };
		const wrongType = {
			...confirmationWrapper(envelope, attestation),
			attestation: { ...attestation, state: 1 },
		};
		const nonObjectEnvelope = { envelope: [], attestation };
		const nonObjectAttestation = { envelope, attestation: null };

		expect(await response(post(CONFIRM_ROUTE, missingEnvelope))).toEqual({
			status: 400,
			body: { error: "bad request" },
		});
		expect(await response(post(CONFIRM_ROUTE, unknown))).toEqual({
			status: 400,
			body: { error: "bad request" },
		});
		expect(await response(post(CONFIRM_ROUTE, wrongType))).toEqual({
			status: 400,
			body: { error: "bad request" },
		});
		expect(await response(post(CONFIRM_ROUTE, nonObjectEnvelope))).toEqual({
			status: 400,
			body: { error: "bad request" },
		});
		expect(await response(post(CONFIRM_ROUTE, nonObjectAttestation))).toEqual({
			status: 400,
			body: { error: "bad request" },
		});
		expect(await bindingCount()).toBe(0);
	});

	it("rejects duplicate confirmation members in hand-crafted raw JSON", async () => {
		const envelope = fixtureRequest(RELAY_V1_NAME);
		const attestation = fixtureAttestation(RELAY_V1_NAME);
		const raw = duplicateFieldJson(confirmationWrapper(envelope, attestation), "attestation", {
			...attestation,
			state: "refused",
		});
		expect(await response(postRaw(CONFIRM_ROUTE, raw))).toEqual({
			status: 401,
			body: { error: "unauthorized" },
		});
		expect(await bindingCount()).toBe(0);
	});

	it("rejects non-finite confirmation attestation numbers in hand-crafted raw JSON", async () => {
		const raw = nonFiniteIssuedAtJson(
			confirmationWrapper(fixtureRequest(RELAY_V1_NAME), fixtureAttestation(RELAY_V1_NAME)),
		);
		expect(await response(postRaw(CONFIRM_ROUTE, raw))).toEqual({
			status: 400,
			body: { error: "bad request" },
		});
		expect(await bindingCount()).toBe(0);
	});
});

describe("owner-purge v1 integrity separation", () => {
	it("rejects wrong purpose, service-domain, and retained-key request signatures before binding", async () => {
		const requestEnvelope = fixtureRequest(RELAY_V1_NAME);
		const supportService = transcript(SUPPORT_V1_NAME).service;

		for (const altered of [
			await resignRequest(requestEnvelope, { kind: "confirm" }),
			await resignRequest(requestEnvelope, { domainService: supportService }),
			await resignRequest(requestEnvelope, { signingKeyVersion: 2 }),
		]) {
			expect(await response(post(REQUEST_ROUTE, altered))).toEqual({
				status: 401,
				body: { error: "unauthorized" },
			});
		}
		expect(await bindingCount()).toBe(0);
	});

	it("rejects wrong purpose, service-domain, and retained-key confirmation signatures before lookup", async () => {
		const envelope = fixtureRequest(RELAY_V2_NAME);
		const attestation = fixtureAttestation(RELAY_V2_NAME);
		const supportService = transcript(SUPPORT_V2_NAME).service;

		for (const altered of [
			await resignAttestation(attestation, { kind: "request" }),
			await resignAttestation(attestation, { domainService: supportService }),
			await resignAttestation(attestation, { signingKeyVersion: 1 }),
		]) {
			expect(await response(post(CONFIRM_ROUTE, confirmationWrapper(envelope, altered)))).toEqual({
				status: 401,
				body: { error: "unauthorized" },
			});
		}
		expect(await bindingCount()).toBe(0);
	});
});

describe("owner-purge v1 binding invariants", () => {
	it("does not confirm a fixture attestation with no matching binding", async () => {
		vi.setSystemTime(transcript(RELAY_V2_NAME).attestation_received_at);
		const envelope = fixtureRequest(RELAY_V2_NAME);
		for (const instanceId of fixtureInstanceIds(envelope)) await seedInstance(instanceId);
		expect(
			(
				await response(
					post(CONFIRM_ROUTE, confirmationWrapper(envelope, fixtureAttestation(RELAY_V2_NAME))),
				)
			).body.disposition,
		).toBe("refused");
		expect(await bindingCount()).toBe(0);
		for (const instanceId of fixtureInstanceIds(envelope)) {
			expect(await rowCount("instances", instanceId)).toBe(1);
			expect(await rowCount("pending_grants", instanceId)).toBe(1);
		}
	});

	it("does not confirm a retryable binding and leaves its target rows unchanged", async () => {
		const { control, purgedInstanceIds, requestEnvelope } = await completeRelayV1Binding();
		await env.DB.prepare("UPDATE purge_operations SET disposition = 'retryable'").run();

		expect(
			(
				await response(
					post(
						CONFIRM_ROUTE,
						confirmationWrapper(requestEnvelope, fixtureAttestation(RELAY_V1_NAME)),
					),
				)
			).body.disposition,
		).toBe("refused");
		await expectRetainedBinding("retryable", control, purgedInstanceIds);
	});

	it("does not confirm an expired binding and leaves its target rows unchanged", async () => {
		const { control, purgedInstanceIds, requestEnvelope } = await completeRelayV1Binding();
		vi.setSystemTime(requestEnvelope.expires_at);

		expect(
			await response(
				post(
					CONFIRM_ROUTE,
					confirmationWrapper(requestEnvelope, fixtureAttestation(RELAY_V1_NAME)),
				),
			),
		).toEqual({ status: 400, body: { error: "bad request" } });
		await expectRetainedCompleteBinding(control, purgedInstanceIds);
	});

	it("does not confirm an operation mismatch and retains the complete binding", async () => {
		const { control, purgedInstanceIds, requestEnvelope } = await completeRelayV1Binding();
		const original = fixtureAttestation(RELAY_V1_NAME);
		const mismatch = await resignAttestation(original, {
			operationId: `${original.operation_id}-other`,
		});

		expect(
			(await response(post(CONFIRM_ROUTE, confirmationWrapper(requestEnvelope, mismatch)))).body
				.disposition,
		).toBe("refused");
		await expectRetainedCompleteBinding(control, purgedInstanceIds);
	});

	it("does not confirm a digest mismatch and retains the complete binding", async () => {
		const { control, purgedInstanceIds, requestEnvelope } = await completeRelayV1Binding();
		const mismatch = await resignAttestation(fixtureAttestation(RELAY_V1_NAME), {
			requestDigest: fixtureRequest(RELAY_V2_NAME).request_digest,
		});

		expect(
			(await response(post(CONFIRM_ROUTE, confirmationWrapper(requestEnvelope, mismatch)))).body
				.disposition,
		).toBe("refused");
		await expectRetainedCompleteBinding(control, purgedInstanceIds);
	});

	it("does not confirm a service mismatch and retains the complete binding", async () => {
		const { control, purgedInstanceIds, requestEnvelope } = await completeRelayV1Binding();
		const mismatch = await resignAttestation(fixtureAttestation(RELAY_V1_NAME), {
			service: transcript(SUPPORT_V1_NAME).service,
			domainService: transcript(SUPPORT_V1_NAME).service,
		});

		expect(
			await response(post(CONFIRM_ROUTE, confirmationWrapper(requestEnvelope, mismatch))),
		).toEqual({
			status: 400,
			body: { error: "bad request" },
		});
		await expectRetainedCompleteBinding(control, purgedInstanceIds);
	});

	it("does not confirm a declared key-version mismatch and retains the complete binding", async () => {
		const { control, purgedInstanceIds, requestEnvelope } = await completeRelayV1Binding();
		const original = fixtureAttestation(RELAY_V1_NAME);
		const mismatch = { ...original, key_version: 2 as const };

		expect(
			await response(post(CONFIRM_ROUTE, confirmationWrapper(requestEnvelope, mismatch))),
		).toEqual({
			status: 401,
			body: { error: "unauthorized" },
		});
		await expectRetainedCompleteBinding(control, purgedInstanceIds);
	});

	it("refuses a fixture-derived v1 operation with a different attestation key version", async () => {
		const { control, purgedInstanceIds, requestEnvelope } = await completeRelayV1Binding();
		// Both retained keys validate independently, but a confirmation must match its request key version.
		const confirmation = await resignAttestation(fixtureAttestation(RELAY_V1_NAME), {
			keyVersion: 2,
			signingKeyVersion: 2,
		});

		expect(
			(await response(post(CONFIRM_ROUTE, confirmationWrapper(requestEnvelope, confirmation)))).body
				.disposition,
		).toBe("refused");
		await expectRetainedCompleteBinding(control, purgedInstanceIds);
	});

	it("does not confirm an envelope whose expiry differs from the binding", async () => {
		const { control, purgedInstanceIds, requestEnvelope } = await completeRelayV1Binding();
		const envelope = await resignRequest(requestEnvelope, {
			expiresAt: requestEnvelope.expires_at + 1,
		});

		expect(
			(
				await response(
					post(CONFIRM_ROUTE, confirmationWrapper(envelope, fixtureAttestation(RELAY_V1_NAME))),
				)
			).body.disposition,
		).toBe("refused");
		await expectRetainedCompleteBinding(control, purgedInstanceIds);
	});

	it("refuses a fixture-derived immutable-expiry retry and retains the complete binding", async () => {
		const { control, purgedInstanceIds } = await completeRelayV1Binding();
		const original = fixtureRequest(RELAY_V1_NAME);
		const mismatch = await resignRequest(original, { expiresAt: original.expires_at + 1 });

		expect((await response(post(REQUEST_ROUTE, mismatch))).body.disposition).toBe("refused");
		await expectRetainedCompleteBinding(control, purgedInstanceIds);
	});

	it("refuses reordered and duplicate fixture snapshots for an existing binding", async () => {
		const { control, purgedInstanceIds } = await completeRelayV1Binding();
		const original = fixtureRequest(RELAY_V1_NAME);
		const instanceIds = fixtureInstanceIds(original);
		const reordered = await resignRequest(original, {
			associationSnapshot: { instance_ids: [...instanceIds].reverse() },
		});
		const duplicate = await resignRequest(original, {
			associationSnapshot: { instance_ids: [...instanceIds, instanceIds[0]] },
		});

		expect((await response(post(REQUEST_ROUTE, reordered))).body.disposition).toBe("refused");
		expect((await response(post(REQUEST_ROUTE, duplicate))).body.disposition).toBe("refused");
		await expectRetainedCompleteBinding(control, purgedInstanceIds);
	});

	it("refuses v2 digest reuse of a v1 operation and retains the complete binding", async () => {
		const { control, purgedInstanceIds } = await completeRelayV1Binding();
		const v1 = fixtureRequest(RELAY_V1_NAME);
		const v2 = fixtureRequest(RELAY_V2_NAME);
		const mismatch = await resignRequest(v2, { operationId: v1.operation_id });

		expect((await response(post(REQUEST_ROUTE, mismatch))).body.disposition).toBe("refused");
		await expectRetainedCompleteBinding(control, purgedInstanceIds);
	});

	it("refuses a malformed attestation without signing or binding lookup", async () => {
		const { control, purgedInstanceIds, requestEnvelope } = await completeRelayV1Binding();
		const attestation = { ...fixtureAttestation(RELAY_V1_NAME), state: 1 };

		await expectUnsignedConfirmationWithoutResponseSigningOrBindingLookup(
			{ envelope: requestEnvelope, attestation },
			{ status: 400, body: { error: "bad request" } },
		);
		await expectRetainedCompleteBinding(control, purgedInstanceIds);
	});

	it("refuses an attestation with broken integrity without signing or binding lookup", async () => {
		const { control, purgedInstanceIds, requestEnvelope } = await completeRelayV1Binding();
		const attestation = {
			...fixtureAttestation(RELAY_V1_NAME),
			integrity: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		};

		await expectUnsignedConfirmationWithoutResponseSigningOrBindingLookup(
			confirmationWrapper(requestEnvelope, attestation),
			{ status: 401, body: { error: "unauthorized" } },
		);
		await expectRetainedCompleteBinding(control, purgedInstanceIds);
	});

	it("refuses an envelope that fails validation without signing or binding lookup", async () => {
		const { control, purgedInstanceIds, requestEnvelope } = await completeRelayV1Binding();
		const instanceIds = Array.from(
			{ length: 101 },
			(_, index) => `00000000-0000-4000-8000-${index.toString().padStart(12, "0")}`,
		);
		const envelope = await resignRequest(requestEnvelope, {
			associationSnapshot: { instance_ids: instanceIds },
		});

		await expectUnsignedConfirmationWithoutResponseSigningOrBindingLookup(
			confirmationWrapper(envelope, fixtureAttestation(RELAY_V1_NAME)),
			{ status: 400, body: { error: "bad request" } },
		);
		await expectRetainedCompleteBinding(control, purgedInstanceIds);
	});
});

async function completeRelayV1Binding(): Promise<{
	requestEnvelope: ReturnType<typeof fixtureRequest>;
	control: string;
	purgedInstanceIds: string[];
}> {
	const requestEnvelope = fixtureRequest(RELAY_V1_NAME);
	const purgedInstanceIds = fixtureInstanceIds(requestEnvelope);
	for (const instanceId of purgedInstanceIds) await seedInstance(instanceId);
	const control = "00000000-0000-4000-8000-000000000097";
	await seedInstance(control);
	expect(await response(post(REQUEST_ROUTE, requestEnvelope))).toEqual({
		status: 200,
		body: fixtureResponse(RELAY_V1_NAME, "submit_response"),
	});
	vi.setSystemTime(transcript(RELAY_V1_NAME).attestation_received_at);
	return { requestEnvelope, control, purgedInstanceIds };
}

async function expectRetainedCompleteBinding(
	control: string,
	purgedInstanceIds: string[],
): Promise<void> {
	return expectRetainedBinding("complete", control, purgedInstanceIds);
}

async function expectUnsignedConfirmationWithoutResponseSigningOrBindingLookup(
	body: unknown,
	expected: { status: number; body: { error: string } },
): Promise<void> {
	const signerSpy = vi.spyOn(responseSigner, "sign");
	const databaseSpy = vi.spyOn(env.DB, "prepare");
	try {
		expect(await response(post(CONFIRM_ROUTE, body))).toEqual(expected);
		expect(signerSpy).not.toHaveBeenCalled();
		expect(databaseSpy).not.toHaveBeenCalled();
	} finally {
		signerSpy.mockRestore();
		databaseSpy.mockRestore();
	}
}

async function expectRetainedBinding(
	disposition: "retryable" | "complete",
	control: string,
	purgedInstanceIds: string[],
): Promise<void> {
	expect(await bindingCount()).toBe(1);
	expect(await bindingDisposition()).toBe(disposition);
	expect(await rowCount("instances", control)).toBe(1);
	expect(await rowCount("pending_grants", control)).toBe(1);
	for (const instanceId of purgedInstanceIds) {
		expect(await rowCount("instances", instanceId)).toBe(0);
		expect(await rowCount("pending_grants", instanceId)).toBe(0);
	}
}

async function resignRequest(
	requestEnvelope: ReturnType<typeof fixtureRequest>,
	options: {
		kind?: "request" | "confirm" | "response";
		domainService?: string;
		signingKeyVersion?: 1 | 2;
		operationId?: string;
		associationSnapshot?: Record<string, unknown>;
		expiresAt?: number;
	},
): Promise<ReturnType<typeof fixtureRequest>> {
	const unsigned = {
		...withoutIntegrity(requestEnvelope),
		operation_id: options.operationId ?? requestEnvelope.operation_id,
		association_snapshot: options.associationSnapshot ?? requestEnvelope.association_snapshot,
		expires_at: options.expiresAt ?? requestEnvelope.expires_at,
	};
	const requestDigest =
		options.associationSnapshot === undefined
			? requestEnvelope.request_digest
			: await digest({
					version: unsigned.version,
					key_version: unsigned.key_version,
					service: unsigned.service,
					association_snapshot: unsigned.association_snapshot,
				});
	const signed = {
		...unsigned,
		request_digest: requestDigest,
	};
	return {
		...signed,
		integrity: await integrity(
			options.kind ?? "request",
			signed,
			options.signingKeyVersion ?? requestEnvelope.key_version,
			options.domainService ?? requestEnvelope.service,
		),
	};
}

async function resignAttestation(
	attestation: ReturnType<typeof fixtureAttestation>,
	options: {
		kind?: "request" | "confirm" | "response";
		domainService?: string;
		keyVersion?: 1 | 2;
		signingKeyVersion?: 1 | 2;
		operationId?: string;
		requestDigest?: string;
		service?: string;
	},
): Promise<ReturnType<typeof fixtureAttestation>> {
	const unsigned = {
		...withoutIntegrity(attestation),
		key_version: options.keyVersion ?? attestation.key_version,
		operation_id: options.operationId ?? attestation.operation_id,
		request_digest: options.requestDigest ?? attestation.request_digest,
		service: options.service ?? attestation.service,
	};
	return {
		...unsigned,
		integrity: await integrity(
			options.kind ?? "confirm",
			unsigned,
			options.signingKeyVersion ?? attestation.key_version,
			options.domainService ?? options.service ?? attestation.service,
		),
	};
}

function withoutIntegrity<T extends { integrity: string }>(value: T): Omit<T, "integrity"> {
	const { integrity: _integrity, ...unsigned } = value;
	return unsigned;
}

function duplicateFieldJson<T extends object>(
	value: T,
	field: string,
	duplicateValue: unknown,
): string {
	return JSON.stringify(value).replace(
		/}$/,
		`,${JSON.stringify(field)}:${JSON.stringify(duplicateValue)}}`,
	);
}

function nonFiniteIssuedAtJson(
	value: { issued_at: number } | { attestation: { issued_at: number } },
): string {
	const issuedAt = "attestation" in value ? value.attestation.issued_at : value.issued_at;
	return JSON.stringify(value).replace(`"issued_at":${issuedAt}`, '"issued_at":NaN');
}
