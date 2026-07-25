// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import { describe, expect, test } from "bun:test";

import {
	DIRECT_CANDIDATES_EXHAUSTED_MESSAGE,
	directPairingAnnouncement,
} from "../src/direct_pair_messages";

describe("direct pair CLI messages", () => {
	test("formats the singular pre-attempt announcement exactly", () => {
		expect(directPairingAnnouncement("test phone", 1, 7070)).toBe(
			'pairing from LAN-direct QR as "test phone" (1 candidate on port 7070)',
		);
	});

	test("pluralizes every count other than one", () => {
		expect(directPairingAnnouncement("test phone", 0, 7070)).toBe(
			'pairing from LAN-direct QR as "test phone" (0 candidates on port 7070)',
		);
		expect(directPairingAnnouncement("test phone", 4, 7070)).toBe(
			'pairing from LAN-direct QR as "test phone" (4 candidates on port 7070)',
		);
	});

	test("exports the fixed exhaustion message", () => {
		expect(DIRECT_CANDIDATES_EXHAUSTED_MESSAGE).toBe(
			"direct candidates exhausted before pairing request",
		);
	});
});
