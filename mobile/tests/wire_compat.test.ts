// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

// Wire-compatibility snapshot — Python and TS must produce byte-identical
// encodings of the same frame. This test hardcodes known-good bytes so any
// future edit to one side that breaks compatibility fails here.

import { describe, expect, test } from "bun:test";

import { FLAG_CLOSE, FLAG_DATA, FLAG_OPEN, buildOpen, encodeFrame } from "../src/framing";

describe("wire compat vs python", () => {
	test("OPEN stream_id=1 payload='hi' matches expected bytes", () => {
		const frame = buildOpen(1, new TextEncoder().encode("hi"));
		const encoded = encodeFrame(frame);
		// Expected:
		//   stream_id u32 BE: 00 00 00 01
		//   flags: OPEN|DATA = 0x03
		//   length u24 BE: 00 00 02
		//   payload: "hi" = 68 69
		expect(Array.from(encoded)).toEqual([
			0x00, 0x00, 0x00, 0x01, 0x03, 0x00, 0x00, 0x02, 0x68, 0x69,
		]);
	});

	test("DATA|CLOSE stream_id=3 payload=empty matches expected bytes", () => {
		const frame = {
			stream_id: 3,
			flags: FLAG_DATA | FLAG_CLOSE,
			payload: new Uint8Array(0),
		};
		const encoded = encodeFrame(frame);
		// stream_id: 00 00 00 03, flags: 0x06 (DATA|CLOSE), length: 00 00 00
		expect(Array.from(encoded)).toEqual([0x00, 0x00, 0x00, 0x03, 0x06, 0x00, 0x00, 0x00]);
	});

	test("OPEN no payload matches expected bytes", () => {
		const frame = { stream_id: 5, flags: FLAG_OPEN, payload: new Uint8Array(0) };
		const encoded = encodeFrame(frame);
		expect(Array.from(encoded)).toEqual([0x00, 0x00, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00]);
	});
});
