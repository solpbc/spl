// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
	canonicalizeOwnerPurgeJson,
	ownerPurgeIntegrityFrame,
	ownerPurgeRequestDigest,
} from "../src/purge";
import { base64UrlEncode } from "../src/tokens";

const FIXTURE_SHA256 = "716133ca9dd49b0d938720a52b8c46122d73fa2c99085eac3a4100af04bc1066";
const VENDORED_FIXTURE = join(process.cwd(), "test-fixtures", "owner-purge-v1.json");
const CANONICAL_FIXTURE = join(process.cwd(), "..", "proto", "owner-purge-v1.json");

interface FixtureEnvelope {
	version: number;
	key_version: number;
	service: string;
	operation_id: string;
	request_digest: string;
	integrity: string;
	association_snapshot?: unknown;
	state?: string;
	issued_at?: number;
	expires_at?: number;
	disposition?: string;
}

interface FixtureTranscript {
	name: string;
	service: string;
	request_canonical_without_integrity: string;
	request_frame_hex?: string;
	request: FixtureEnvelope;
	attestation_canonical_without_integrity: string;
	attestation: FixtureEnvelope;
	submit_response_canonical_without_integrity: string;
	submit_response: FixtureEnvelope;
	response_canonical_without_integrity: string;
	response: FixtureEnvelope;
}

interface OwnerPurgeFixture {
	integrity: {
		domains: Record<"request" | "confirm" | "response", string>;
		non_production_test_keys_utf8: Record<string, string>;
	};
	wire_transcripts: FixtureTranscript[];
}

describe("owner-purge v1 canonical conformance", () => {
	it("vendors the pinned canonical fixture byte-for-byte", () => {
		const vendored = readFileSync(VENDORED_FIXTURE);
		const canonical = readFileSync(CANONICAL_FIXTURE);

		expect(createHash("sha256").update(vendored).digest("hex")).toBe(FIXTURE_SHA256);
		expect(vendored).toEqual(canonical);
	});

	it("matches the retained relay-v1 canonical request, digest, frames, and HMACs", async () => {
		const fixture = loadFixture();
		const transcript = fixtureTranscript(
			fixture,
			"relay_retained_key_v1_first_confirmation_and_lost_response_retry",
		);

		await expectRequestConformance(fixture, transcript);
		await expectEnvelopeConformance(
			fixture,
			transcript,
			"confirm",
			transcript.attestation,
			transcript.attestation_canonical_without_integrity,
		);
		await expectEnvelopeConformance(
			fixture,
			transcript,
			"response",
			transcript.submit_response,
			transcript.submit_response_canonical_without_integrity,
		);
		await expectEnvelopeConformance(
			fixture,
			transcript,
			"response",
			transcript.response,
			transcript.response_canonical_without_integrity,
		);
	});

	it("matches the support UTF-8 byte-vector from the fixture", async () => {
		const fixture = loadFixture();
		const transcript = fixtureTranscript(fixture, "support_current_key_v2_utf8_snapshot");

		await expectRequestConformance(fixture, transcript);
		expect(transcript.request_frame_hex).toBeDefined();
		expect(
			toHex(
				ownerPurgeIntegrityFrame(
					domain(fixture, "request", transcript.service),
					transcript.request_canonical_without_integrity,
				),
			),
		).toBe(transcript.request_frame_hex);
		await expectEnvelopeConformance(
			fixture,
			transcript,
			"confirm",
			transcript.attestation,
			transcript.attestation_canonical_without_integrity,
		);
		await expectEnvelopeConformance(
			fixture,
			transcript,
			"response",
			transcript.submit_response,
			transcript.submit_response_canonical_without_integrity,
		);
		await expectEnvelopeConformance(
			fixture,
			transcript,
			"response",
			transcript.response,
			transcript.response_canonical_without_integrity,
		);
	});
});

async function expectRequestConformance(
	fixture: OwnerPurgeFixture,
	transcript: FixtureTranscript,
): Promise<void> {
	const request = transcript.request;
	expect(canonicalizeOwnerPurgeJson(unsigned(request))).toBe(
		transcript.request_canonical_without_integrity,
	);
	expect(
		await ownerPurgeRequestDigest(
			request.version,
			request.key_version,
			request.service,
			request.association_snapshot,
		),
	).toBe(request.request_digest);
	await expectEnvelopeConformance(
		fixture,
		transcript,
		"request",
		request,
		transcript.request_canonical_without_integrity,
	);
}

async function expectEnvelopeConformance(
	fixture: OwnerPurgeFixture,
	transcript: FixtureTranscript,
	kind: "request" | "confirm" | "response",
	envelope: FixtureEnvelope,
	canonical: string,
): Promise<void> {
	expect(canonicalizeOwnerPurgeJson(unsigned(envelope))).toBe(canonical);
	const frame = ownerPurgeIntegrityFrame(domain(fixture, kind, transcript.service), canonical);
	expect(await hmac(frame, fixtureKey(fixture, envelope.key_version))).toBe(envelope.integrity);
}

function loadFixture(): OwnerPurgeFixture {
	return JSON.parse(readFileSync(VENDORED_FIXTURE, "utf8")) as OwnerPurgeFixture;
}

function fixtureTranscript(fixture: OwnerPurgeFixture, name: string): FixtureTranscript {
	const transcript = fixture.wire_transcripts.find((candidate) => candidate.name === name);
	if (!transcript) throw new Error(`fixture transcript missing: ${name}`);
	return transcript;
}

function fixtureKey(fixture: OwnerPurgeFixture, version: number): string {
	const key = fixture.integrity.non_production_test_keys_utf8[String(version)];
	if (!key) throw new Error(`fixture key missing: ${version}`);
	return key;
}

function domain(
	fixture: OwnerPurgeFixture,
	kind: "request" | "confirm" | "response",
	service: string,
): string {
	return fixture.integrity.domains[kind].replace("<service>", service);
}

function unsigned(envelope: FixtureEnvelope): Record<string, unknown> {
	const { integrity: _integrity, ...value } = envelope;
	return value;
}

async function hmac(frame: Uint8Array, secret: string): Promise<string> {
	const key = await crypto.subtle.importKey(
		"raw",
		new TextEncoder().encode(secret),
		{ name: "HMAC", hash: "SHA-256" },
		false,
		["sign"],
	);
	return base64UrlEncode(new Uint8Array(await crypto.subtle.sign("HMAC", key, frame)));
}

function toHex(bytes: Uint8Array): string {
	return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}
