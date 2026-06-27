// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import { describe, expect, test } from "bun:test";

import { decidePairAction, pairSummaryLine } from "../src/pair";

describe("pair guard decisions", () => {
	test("decidePairAction classifies first-time, already-connected, and reconnect", () => {
		expect(decidePairAction("scanned", null)).toBe("first-time");
		expect(decidePairAction(null, null)).toBe("first-time");
		expect(decidePairAction("same", "same")).toBe("already-connected");
		expect(decidePairAction("new", "stored")).toBe("reconnect");
	});

	test("pairSummaryLine produces distinct metadata-only summaries", () => {
		const firstTime = pairSummaryLine("first-time", "Kitchen Mac", "instance-a");
		const alreadyConnected = pairSummaryLine("already-connected", "Kitchen Mac", "instance-a");
		const reconnect = pairSummaryLine("reconnect", "Kitchen Mac", "instance-a");

		expect(new Set([firstTime, alreadyConnected, reconnect]).size).toBe(3);
		expect(firstTime).toContain("Kitchen Mac");
		expect(firstTime).toContain("Paired with");
		expect(alreadyConnected).toContain("Kitchen Mac");
		expect(alreadyConnected).toContain("Already connected");
		expect(reconnect).toContain("Kitchen Mac");
		expect(reconnect).toContain("Reconnected");
	});
});
