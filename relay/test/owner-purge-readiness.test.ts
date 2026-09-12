// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import { createHash, createHmac } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import type { Env } from "../src/env";
import { evaluatePurgeProvisioning } from "../src/purge";

const READINESS_FIXTURE_SHA256 = "e6456d20243c7a73542bacd8a31a2c1f321f08bee7034584d03977b6e0ba0ef4";
const VENDORED_FIXTURE = join(process.cwd(), "test-fixtures", "owner-purge-readiness-v1.json");
const CANONICAL_FIXTURE = join(process.cwd(), "..", "proto", "owner-purge-readiness-v1.json");

interface ReadinessFixture {
	version: number;
	service: string;
	route: string;
	description: string;
	domain: string;
	integrity: {
		non_production_test_keys_utf8: Record<string, string>;
	};
	sample_readiness: {
		nonce: string;
		canonical_v1: string;
		canonical_v2: string;
		frame_hex_v1: string;
		frame_hex_v2: string;
		proof_v1: string;
		proof_v2: string;
	};
}

// Independent test-only canonicalizer
function testCanonicalizeJson(value: unknown): string {
	if (value === null) return "null";
	if (typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
	if (typeof value === "number") {
		if (!Number.isSafeInteger(value)) throw new TypeError("must be safe integer");
		return JSON.stringify(value);
	}
	if (Array.isArray(value)) {
		return `[${value.map(testCanonicalizeJson).join(",")}]`;
	}
	if (typeof value !== "object") throw new TypeError("must be object");
	const record = value as Record<string, unknown>;
	const keys = Object.keys(record).sort();
	return `{${keys.map((k) => `${JSON.stringify(k)}:${testCanonicalizeJson(record[k])}`).join(",")}}`;
}

// Independent test-only uint64be framer
function testUint64be(value: number): Buffer {
	const buf = Buffer.alloc(8);
	buf.writeBigUInt64BE(BigInt(value), 0);
	return buf;
}

function testIntegrityFrame(domain: string, canonicalJson: string): Buffer {
	const domainBuf = Buffer.from(domain, "utf8");
	const bodyBuf = Buffer.from(canonicalJson, "utf8");
	return Buffer.concat([
		testUint64be(domainBuf.length),
		domainBuf,
		testUint64be(bodyBuf.length),
		bodyBuf,
	]);
}

function testHmacSha256Base64Url(frame: Buffer, keyText: string): string {
	const hmac = createHmac("sha256", Buffer.from(keyText, "utf8")).update(frame).digest();
	return hmac.toString("base64url");
}

describe("owner-purge readiness v1 canonical conformance", () => {
	it("vendors the pinned canonical fixture byte-for-byte", () => {
		const vendored = readFileSync(VENDORED_FIXTURE);
		const canonical = readFileSync(CANONICAL_FIXTURE);
		expect(vendored.equals(canonical)).toBe(true);
		expect(createHash("sha256").update(vendored).digest("hex")).toBe(READINESS_FIXTURE_SHA256);
	});

	it("computes exact sample readiness canonical strings, frame hexes, and proofs", () => {
		const fixture = JSON.parse(readFileSync(VENDORED_FIXTURE, "utf8")) as ReadinessFixture;
		const sample = fixture.sample_readiness;
		const domain = fixture.domain;
		const keys = fixture.integrity.non_production_test_keys_utf8;

		const objV1 = {
			key_version: 1,
			nonce: sample.nonce,
			service: fixture.service,
			version: fixture.version,
		};
		const canonicalV1 = testCanonicalizeJson(objV1);
		expect(canonicalV1).toBe(sample.canonical_v1);

		const frameV1 = testIntegrityFrame(domain, canonicalV1);
		expect(frameV1.toString("hex")).toBe(sample.frame_hex_v1);

		const proofV1 = testHmacSha256Base64Url(frameV1, keys["1"]);
		expect(proofV1).toBe(sample.proof_v1);

		const objV2 = {
			key_version: 2,
			nonce: sample.nonce,
			service: fixture.service,
			version: fixture.version,
		};
		const canonicalV2 = testCanonicalizeJson(objV2);
		expect(canonicalV2).toBe(sample.canonical_v2);

		const frameV2 = testIntegrityFrame(domain, canonicalV2);
		expect(frameV2.toString("hex")).toBe(sample.frame_hex_v2);

		const proofV2 = testHmacSha256Base64Url(frameV2, keys["2"]);
		expect(proofV2).toBe(sample.proof_v2);
	});

	it("detects mismatched keys, nonces, swapped proofs, and altered domains", () => {
		const fixture = JSON.parse(readFileSync(VENDORED_FIXTURE, "utf8")) as ReadinessFixture;
		const sample = fixture.sample_readiness;
		const domain = fixture.domain;
		const keys = fixture.integrity.non_production_test_keys_utf8;

		// v1 proof signed with v2 key does not match v1 proof
		const wrongKeyV1 = testHmacSha256Base64Url(
			testIntegrityFrame(domain, sample.canonical_v1),
			keys["2"],
		);
		expect(wrongKeyV1).not.toBe(sample.proof_v1);

		// v2 proof signed with v1 key does not match v2 proof
		const wrongKeyV2 = testHmacSha256Base64Url(
			testIntegrityFrame(domain, sample.canonical_v2),
			keys["1"],
		);
		expect(wrongKeyV2).not.toBe(sample.proof_v2);

		// Swapped proofs: proof_v1 does not equal proof_v2
		expect(sample.proof_v1).not.toBe(sample.proof_v2);

		// Mangled proof does not match
		const mangledProof = `X${sample.proof_v1.slice(1)}`;
		expect(mangledProof).not.toBe(sample.proof_v1);

		// Replay proof to different nonce produces different proof
		const diffNonceObj = {
			key_version: 1,
			nonce: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
			service: fixture.service,
			version: fixture.version,
		};
		const diffNonceProof = testHmacSha256Base64Url(
			testIntegrityFrame(domain, testCanonicalizeJson(diffNonceObj)),
			keys["1"],
		);
		expect(diffNonceProof).not.toBe(sample.proof_v1);

		// Wrong domains: request, confirm, response domains all produce different proofs
		for (const wrongDomain of [
			"solpbc-owner-purge-v1:relay:request",
			"solpbc-owner-purge-v1:relay:confirm",
			"solpbc-owner-purge-v1:relay:response",
		]) {
			const wrongDomainFrameV1 = testIntegrityFrame(wrongDomain, sample.canonical_v1);
			const wrongDomainProofV1 = testHmacSha256Base64Url(wrongDomainFrameV1, keys["1"]);
			expect(wrongDomainProofV1).not.toBe(sample.proof_v1);

			const wrongDomainFrameV2 = testIntegrityFrame(wrongDomain, sample.canonical_v2);
			const wrongDomainProofV2 = testHmacSha256Base64Url(wrongDomainFrameV2, keys["2"]);
			expect(wrongDomainProofV2).not.toBe(sample.proof_v2);
		}

		// Nonce reuse without ledger entries generates identical proofs deterministically
		const objV1 = {
			key_version: 1,
			nonce: sample.nonce,
			service: fixture.service,
			version: fixture.version,
		};
		const objV2 = {
			key_version: 2,
			nonce: sample.nonce,
			service: fixture.service,
			version: fixture.version,
		};
		const reusedV1 = testHmacSha256Base64Url(
			testIntegrityFrame(domain, testCanonicalizeJson(objV1)),
			keys["1"],
		);
		const reusedV2 = testHmacSha256Base64Url(
			testIntegrityFrame(domain, testCanonicalizeJson(objV2)),
			keys["2"],
		);
		expect(reusedV1).toBe(sample.proof_v1);
		expect(reusedV2).toBe(sample.proof_v2);
	});
});

describe("owner-purge provisioning evaluation", () => {
	it("accepts complete uncollided provisioning and permits v1 === v2", () => {
		const env = {
			PURGE_SECRET: "test-purge-secret",
			GRANT_SECRET: "test-grant-secret",
			OWNER_PURGE_HMAC_KEY_V1: "key-1",
			OWNER_PURGE_HMAC_KEY_V2: "key-2",
		} as unknown as Env;

		const result = evaluatePurgeProvisioning(env);
		expect(result).not.toBeNull();
		expect(result?.secret).toBe("test-purge-secret");
		expect(result?.keys[1]).toBe("key-1");
		expect(result?.keys[2]).toBe("key-2");

		// v1 === v2 is permitted
		const envSameKeys = {
			PURGE_SECRET: "test-purge-secret",
			GRANT_SECRET: "test-grant-secret",
			OWNER_PURGE_HMAC_KEY_V1: "same-key",
			OWNER_PURGE_HMAC_KEY_V2: "same-key",
		} as unknown as Env;

		const sameResult = evaluatePurgeProvisioning(envSameKeys);
		expect(sameResult).not.toBeNull();
		expect(sameResult?.keys[1]).toBe("same-key");
		expect(sameResult?.keys[2]).toBe("same-key");
	});

	it("rejects missing secrets or keys", () => {
		expect(
			evaluatePurgeProvisioning({
				PURGE_SECRET: "",
				OWNER_PURGE_HMAC_KEY_V1: "k1",
				OWNER_PURGE_HMAC_KEY_V2: "k2",
			} as unknown as Env),
		).toBeNull();

		expect(
			evaluatePurgeProvisioning({
				PURGE_SECRET: "secret",
				OWNER_PURGE_HMAC_KEY_V1: "",
				OWNER_PURGE_HMAC_KEY_V2: "k2",
			} as unknown as Env),
		).toBeNull();

		expect(
			evaluatePurgeProvisioning({
				PURGE_SECRET: "secret",
				OWNER_PURGE_HMAC_KEY_V1: "k1",
				OWNER_PURGE_HMAC_KEY_V2: "",
			} as unknown as Env),
		).toBeNull();
	});

	it("rejects secret collisions between PURGE_SECRET and GRANT_SECRET / HMAC keys", () => {
		// PURGE_SECRET === GRANT_SECRET
		expect(
			evaluatePurgeProvisioning({
				PURGE_SECRET: "colliding-secret",
				GRANT_SECRET: "colliding-secret",
				OWNER_PURGE_HMAC_KEY_V1: "k1",
				OWNER_PURGE_HMAC_KEY_V2: "k2",
			} as unknown as Env),
		).toBeNull();

		// PURGE_SECRET === OWNER_PURGE_HMAC_KEY_V1
		expect(
			evaluatePurgeProvisioning({
				PURGE_SECRET: "colliding-k1",
				GRANT_SECRET: "grant-secret",
				OWNER_PURGE_HMAC_KEY_V1: "colliding-k1",
				OWNER_PURGE_HMAC_KEY_V2: "k2",
			} as unknown as Env),
		).toBeNull();

		// PURGE_SECRET === OWNER_PURGE_HMAC_KEY_V2
		expect(
			evaluatePurgeProvisioning({
				PURGE_SECRET: "colliding-k2",
				GRANT_SECRET: "grant-secret",
				OWNER_PURGE_HMAC_KEY_V1: "k1",
				OWNER_PURGE_HMAC_KEY_V2: "colliding-k2",
			} as unknown as Env),
		).toBeNull();
	});
});
