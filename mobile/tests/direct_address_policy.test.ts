// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import { describe, expect, test } from "bun:test";

import {
	DirectAddressAdmissionError,
	assertDirectCandidatesAdmitted,
} from "../src/direct_address_policy";

describe("direct address admission", () => {
	test("admits the complete supported IPv4 ranges", () => {
		for (const address of [
			"10.0.0.0",
			"10.255.255.255",
			"100.64.0.0",
			"100.127.255.255",
			"127.0.0.0",
			"127.255.255.255",
			"169.254.0.0",
			"169.254.255.255",
			"172.16.0.0",
			"172.31.255.255",
			"192.168.0.0",
			"192.168.255.255",
		]) {
			expect(() => assertDirectCandidatesAdmitted([address])).not.toThrow();
		}
	});

	test("refuses addresses immediately outside the supported ranges", () => {
		for (const address of [
			"9.255.255.255",
			"11.0.0.0",
			"100.63.255.255",
			"100.128.0.0",
			"126.255.255.255",
			"128.0.0.0",
			"169.253.255.255",
			"169.255.0.0",
			"172.15.255.255",
			"172.32.0.0",
			"192.167.255.255",
			"192.169.0.0",
		]) {
			expect(() => assertDirectCandidatesAdmitted([address])).toThrow(DirectAddressAdmissionError);
		}
	});

	test("matches the RFC 6598 and link-local conformance rows", () => {
		expect(() => assertDirectCandidatesAdmitted(["100.63.255.255"])).toThrow();
		expect(() => assertDirectCandidatesAdmitted(["100.64.0.0"])).not.toThrow();
		expect(() => assertDirectCandidatesAdmitted(["100.127.255.255"])).not.toThrow();
		expect(() => assertDirectCandidatesAdmitted(["100.128.0.0"])).toThrow();
		expect(() => assertDirectCandidatesAdmitted(["169.254.0.1"])).not.toThrow();
	});

	test("admits an all-local set and refuses a mixed set as a whole", () => {
		expect(() => assertDirectCandidatesAdmitted(["192.168.1.10", "100.64.0.5"])).not.toThrow();
		expect(() => assertDirectCandidatesAdmitted(["192.168.1.10", "192.0.2.42"])).toThrow(
			DirectAddressAdmissionError,
		);
	});

	test("decodes the canonical vector address and refuses it at policy", () => {
		expect(() => assertDirectCandidatesAdmitted(["192.0.2.42"])).toThrow(
			DirectAddressAdmissionError,
		);
	});

	test("refuses the named public and special-use conformance vectors", () => {
		for (const address of [
			"0.0.0.0",
			"255.255.255.255",
			"224.0.0.1",
			"198.18.0.1",
			"240.0.0.1",
			"192.0.2.42",
			"8.8.8.8",
		]) {
			expect(() => assertDirectCandidatesAdmitted([address])).toThrow(DirectAddressAdmissionError);
		}
	});

	test("refuses empty and malformed candidate collections", () => {
		for (const candidates of [
			[],
			[""],
			["10.0.0"],
			["10.0.0.1.2"],
			["10.0.0.-1"],
			["10.0.0.256"],
			["10.0.0.01"],
			["10.0.0. 1"],
			["10.0.x.1"],
		]) {
			expect(() => assertDirectCandidatesAdmitted(candidates)).toThrow(DirectAddressAdmissionError);
		}
	});

	test("refusal errors contain no candidate material", () => {
		try {
			assertDirectCandidatesAdmitted(["192.0.2.42"]);
			throw new Error("expected refusal");
		} catch (err) {
			expect(err).toBeInstanceOf(DirectAddressAdmissionError);
			expect((err as Error).message).toBe("direct pair candidate address is not admitted");
			expect((err as Error).message).not.toContain("192.0.2.42");
		}
	});
});
