// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import { describe, expect, it } from "vitest";
import { base32Decode, generateTotp, verifyTotp } from "../src/totp";

const GOOGLE_SECRET = "JBSWY3DPEHPK3PXP";
const RFC_SHA1_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

describe("totp", () => {
	it("matches the Google/Authy-style SHA-1 vector", async () => {
		expect(await generateTotp(GOOGLE_SECRET, 0)).toBe("282760");
		expect(await verifyTotp(GOOGLE_SECRET, "282760", 0)).toBe(true);
	});

	it("matches the RFC 6238 SHA-1 6-digit vector", async () => {
		expect(await generateTotp(RFC_SHA1_SECRET, 59)).toBe("287082");
	});

	it("accepts only the +/- one-step skew window", async () => {
		const now = 1000;
		const previous = await generateTotp(GOOGLE_SECRET, now - 30);
		const current = await generateTotp(GOOGLE_SECRET, now);
		const next = await generateTotp(GOOGLE_SECRET, now + 30);
		const tooOld = await generateTotp(GOOGLE_SECRET, now - 60);
		const tooNew = await generateTotp(GOOGLE_SECRET, now + 60);

		expect(await verifyTotp(GOOGLE_SECRET, previous, now)).toBe(true);
		expect(await verifyTotp(GOOGLE_SECRET, current, now)).toBe(true);
		expect(await verifyTotp(GOOGLE_SECRET, next, now)).toBe(true);
		expect(await verifyTotp(GOOGLE_SECRET, tooOld, now)).toBe(false);
		expect(await verifyTotp(GOOGLE_SECRET, tooNew, now)).toBe(false);
	});

	it("rejects wrong and non-6-digit codes without throwing", async () => {
		expect(await verifyTotp(GOOGLE_SECRET, "000000", 0)).toBe(false);
		expect(await verifyTotp(GOOGLE_SECRET, "12345", 0)).toBe(false);
		expect(await verifyTotp(GOOGLE_SECRET, "abcdef", 0)).toBe(false);
	});

	it("decodes unpadded base32", () => {
		expect(Array.from(base32Decode("JBSWY3DP"))).toEqual([72, 101, 108, 108, 111]);
	});
});
