// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import { createHash, createHmac } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import type { Env } from "../src/env";
import { evaluatePurgeProvisioning, extractCheckExpressions } from "../src/purge";
import { base64UrlDecode, base64UrlEncode } from "../src/tokens";

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

const BASE64URL_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

describe("owner-purge readiness nonce canonical terminal-bit derivations", () => {
	it("accepts a valid canonical 32-byte base64url nonce and rejects all derived noncanonical terminal-bit variants", () => {
		const fixture = JSON.parse(readFileSync(VENDORED_FIXTURE, "utf8")) as ReadinessFixture;
		const canonicalNonce = fixture.sample_readiness.nonce;
		expect(canonicalNonce).toHaveLength(43);

		const decoded = base64UrlDecode(canonicalNonce);
		expect(decoded.byteLength).toBe(32);
		expect(base64UrlEncode(decoded)).toBe(canonicalNonce);

		const lastChar = canonicalNonce[42];
		const lastCharIndex = BASE64URL_ALPHABET.indexOf(lastChar);
		expect(lastCharIndex % 4).toBe(0); // Canonical terminal bits are 00

		// Derive all 3 alternate noncanonical spellings for this exact 32-byte payload
		const noncanonicalAlternates = [1, 2, 3].map(
			(offset) => canonicalNonce.slice(0, 42) + BASE64URL_ALPHABET[lastCharIndex + offset],
		);

		for (const alt of noncanonicalAlternates) {
			expect(alt).toHaveLength(43);
			const altDecoded = base64UrlDecode(alt);
			expect(Buffer.from(altDecoded).equals(Buffer.from(decoded))).toBe(true);
			// Re-encoding reveals the canonical spelling
			expect(base64UrlEncode(altDecoded)).not.toBe(alt);
			expect(base64UrlEncode(altDecoded)).toBe(canonicalNonce);
		}

		// Verify across all 16 possible terminal nibbles (48 noncanonical trailing characters)
		for (let nibble = 0; nibble < 16; nibble++) {
			const canonicalChar = BASE64URL_ALPHABET[nibble * 4];
			const testBytes = new Uint8Array(32);
			testBytes[31] = nibble;
			const canonicalB64 = base64UrlEncode(testBytes);
			expect(canonicalB64[42]).toBe(canonicalChar);

			for (let offset = 1; offset <= 3; offset++) {
				const noncanonicalChar = BASE64URL_ALPHABET[nibble * 4 + offset];
				const noncanonicalB64 = canonicalB64.slice(0, 42) + noncanonicalChar;
				const decodedAlt = base64UrlDecode(noncanonicalB64);
				expect(Buffer.from(decodedAlt).equals(Buffer.from(testBytes))).toBe(true);
				expect(base64UrlEncode(decodedAlt) === noncanonicalB64).toBe(false);
			}
		}
	});

	it("strictly accepts 16 canonical terminal characters and rejects all 48 noncanonical variants", () => {
		const prefix42 = "A".repeat(42);

		const canonicalChars: string[] = [];
		const noncanonicalChars: string[] = [];

		for (let i = 0; i < BASE64URL_ALPHABET.length; i++) {
			const char = BASE64URL_ALPHABET[i];
			if (i % 4 === 0) {
				canonicalChars.push(char);
			} else {
				noncanonicalChars.push(char);
			}
		}

		expect(canonicalChars.length).toBe(16);
		expect(noncanonicalChars.length).toBe(48);
		expect(canonicalChars).toEqual([
			"A",
			"E",
			"I",
			"M",
			"Q",
			"U",
			"Y",
			"c",
			"g",
			"k",
			"o",
			"s",
			"w",
			"0",
			"4",
			"8",
		]);

		for (let nibble = 0; nibble < 16; nibble++) {
			const canonicalChar = BASE64URL_ALPHABET[nibble * 4];
			const canonicalNonce = prefix42 + canonicalChar;
			const decodedCanonical = base64UrlDecode(canonicalNonce);

			expect(decodedCanonical.byteLength).toBe(32);
			expect(base64UrlEncode(decodedCanonical)).toBe(canonicalNonce);

			for (let nonZeroBits = 1; nonZeroBits <= 3; nonZeroBits++) {
				const noncanonicalChar = BASE64URL_ALPHABET[nibble * 4 + nonZeroBits];
				const noncanonicalNonce = prefix42 + noncanonicalChar;
				const decodedNoncanonical = base64UrlDecode(noncanonicalNonce);

				expect(decodedNoncanonical.byteLength).toBe(32);
				expect(decodedNoncanonical).toEqual(decodedCanonical);

				expect(base64UrlEncode(decodedNoncanonical)).toBe(canonicalNonce);
				expect(base64UrlEncode(decodedNoncanonical)).not.toBe(noncanonicalNonce);
				expect(base64UrlEncode(decodedNoncanonical) === noncanonicalNonce).toBe(false);
			}
		}
	});
});

describe("extractCheckExpressions", () => {
	it("extracts single and multiple CHECK constraints ignoring whitespace and formatting", () => {
		const sqlSingle = `
			CREATE TABLE purge_operations (
				operation_id_hash TEXT PRIMARY KEY,
				request_digest TEXT NOT NULL,
				disposition TEXT NOT NULL CHECK (disposition IN ('retryable', 'complete', 'confirmed')),
				expires_at INTEGER NOT NULL
			);
		`;
		expect(extractCheckExpressions(sqlSingle)).toEqual([
			"disposition IN ('retryable', 'complete', 'confirmed')",
		]);

		const sqlMultiple = `
			CREATE TABLE purge_operations (
				operation_id_hash TEXT PRIMARY KEY,
				request_digest TEXT NOT NULL,
				disposition TEXT NOT NULL CHECK (disposition IN ('retryable', 'complete', 'confirmed')),
				expires_at INTEGER NOT NULL,
				CHECK (disposition <> 'confirmed')
			);
		`;
		expect(extractCheckExpressions(sqlMultiple)).toEqual([
			"disposition IN ('retryable', 'complete', 'confirmed')",
			"disposition <> 'confirmed'",
		]);
	});

	it("handles nested parentheses and string literals within CHECK constraints", () => {
		const sqlNested = `
			CREATE TABLE test_table (
				id TEXT PRIMARY KEY,
				status TEXT CHECK ((status = 'a' OR (status = 'b' AND id != 'c')) AND status NOT IN ('x', 'y (z)'))
			);
		`;
		expect(extractCheckExpressions(sqlNested)).toEqual([
			"(status = 'a' OR (status = 'b' AND id != 'c')) AND status NOT IN ('x', 'y (z)')",
		]);
	});

	it("returns empty array when no CHECK constraints are present", () => {
		const sqlNone = "CREATE TABLE instances (instance_id TEXT PRIMARY KEY);";
		expect(extractCheckExpressions(sqlNone)).toEqual([]);
	});

	it("ignores CHECK tokens inside comments, string literals, and identifiers", () => {
		const sqlWithComments = `
			-- line comment containing CHECK (fake_line = 1)
			/* block comment containing CHECK (fake_block = 1) */
			CREATE TABLE test_comments (
				id TEXT PRIMARY KEY, -- CHECK (fake_inline = 1)
				name TEXT DEFAULT 'CHECK (fake_string = 1)',
				"CHECK (col_ident)" TEXT,
				disposition TEXT CHECK (disposition IN ('retryable', 'complete', 'confirmed'))
			);
		`;
		expect(extractCheckExpressions(sqlWithComments)).toEqual([
			"disposition IN ('retryable', 'complete', 'confirmed')",
		]);
	});
});
