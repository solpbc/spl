// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import { describe, expect, test } from "bun:test";

import {
	classifyDialRejection,
	classifyRefreshOutcome,
	parseJwtClaims,
	shouldRefreshBeforeDial,
} from "../src/device_token";

describe("device token decisions", () => {
	test("parseJwtClaims extracts iat and exp from an unsigned test token", () => {
		expect(parseJwtClaims(jwtWithClaims({ iat: 10, exp: 110, ignored: "value" }))).toEqual({
			iat: 10,
			exp: 110,
		});
	});

	test("parseJwtClaims rejects malformed tokens", () => {
		const notJson = Buffer.from("not json", "utf-8").toString("base64url");
		expect(parseJwtClaims("header.payload")).toBeNull();
		expect(parseJwtClaims(`${b64urlJson({ alg: "none" })}.!!!!.sig`)).toBeNull();
		expect(parseJwtClaims(`${b64urlJson({ alg: "none" })}.${notJson}.sig`)).toBeNull();
		expect(parseJwtClaims(jwtWithClaims({ exp: 100 }))).toBeNull();
		expect(parseJwtClaims(jwtWithClaims({ iat: 0 }))).toBeNull();
		expect(parseJwtClaims(jwtWithClaims({ iat: "0", exp: 100 }))).toBeNull();
		expect(parseJwtClaims(jwtWithClaims({ iat: 0, exp: "100" }))).toBeNull();
		expect(parseJwtClaims("")).toBeNull();
	});

	test("shouldRefreshBeforeDial uses an exclusive threshold", () => {
		const claims = { iat: 0, exp: 100 };
		expect(shouldRefreshBeforeDial(claims, 81)).toBe(true);
		expect(shouldRefreshBeforeDial(claims, 79)).toBe(false);
		expect(shouldRefreshBeforeDial(claims, 80)).toBe(false);
		expect(shouldRefreshBeforeDial(claims, 120)).toBe(true);
		expect(shouldRefreshBeforeDial({ iat: 100, exp: 100 }, 120)).toBe(false);
	});

	test("classifyRefreshOutcome maps refresh statuses to actions", () => {
		expect(classifyRefreshOutcome(200)).toBe("use_new_token");
		expect(classifyRefreshOutcome(401)).toBe("reconnect");
		expect(classifyRefreshOutcome(403)).toBe("reconnect");
		expect(classifyRefreshOutcome(404)).toBe("reconnect");
		expect(classifyRefreshOutcome(413)).toBe("keep_existing");
		expect(classifyRefreshOutcome(503)).toBe("keep_existing");
		expect(classifyRefreshOutcome(500)).toBe("keep_existing");
		expect(classifyRefreshOutcome(0)).toBe("keep_existing");
	});

	test("classifyDialRejection maps native-visible handshake metadata", () => {
		expect(classifyDialRejection({ xCloseCode: 4401 })).toBe("auth");
		expect(classifyDialRejection({ status: 401 })).toBe("auth");
		expect(classifyDialRejection({ xCloseCode: 4402 })).toBe("not_entitled");
		expect(classifyDialRejection({ status: 402 })).toBe("not_entitled");
		expect(classifyDialRejection({ status: 503 })).toBe("no_home");
		expect(classifyDialRejection({})).toBe("transient");
	});
});

function b64urlJson(v: unknown): string {
	return Buffer.from(JSON.stringify(v), "utf-8").toString("base64url");
}

function jwtWithClaims(claims: Record<string, unknown>): string {
	return `${b64urlJson({ alg: "none" })}.${b64urlJson(claims)}.sig`;
}
