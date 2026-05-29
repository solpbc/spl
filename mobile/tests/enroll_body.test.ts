// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import { describe, expect, test } from "bun:test";

import { buildEnrollBody } from "../src/pair";

describe("enroll device body", () => {
	test("contains only instance_id and home_attestation", () => {
		const body = buildEnrollBody({ instance_id: "i", home_attestation: "a" });
		expect(Object.keys(body).sort()).toEqual(["home_attestation", "instance_id"]);
		expect("client_cert" in body).toBe(false);
	});
});
