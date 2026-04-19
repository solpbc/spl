// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import { describe, expect, test } from "bun:test";

import {
	FLAG_CLOSE,
	FLAG_DATA,
	FLAG_OPEN,
	FLAG_RESERVED_MASK,
	FLAG_WINDOW,
	FrameDecoder,
	HEADER_LEN,
	ProtocolError,
	RESET_PROTOCOL_ERROR,
	buildClose,
	buildData,
	buildOpen,
	buildReset,
	buildWindow,
	encodeFrame,
	parseResetReason,
	parseWindowCredit,
	validateFlags,
} from "../src/framing";

describe("framing encode/decode", () => {
	test("header is 8 bytes (matches Python)", () => {
		expect(HEADER_LEN).toBe(8);
	});

	test("roundtrip DATA frame", () => {
		const frame = { stream_id: 7, flags: FLAG_DATA, payload: new TextEncoder().encode("hello") };
		const encoded = encodeFrame(frame);
		const d = new FrameDecoder();
		d.feed(encoded);
		const decoded = d.next();
		expect(decoded).not.toBeNull();
		expect(decoded?.stream_id).toBe(7);
		expect(decoded?.flags).toBe(FLAG_DATA);
		expect(new TextDecoder().decode(decoded?.payload)).toBe("hello");
	});

	test("fragmented feed reassembles correctly", () => {
		const frame = buildData(5, new TextEncoder().encode("fragmented"));
		const encoded = encodeFrame(frame);
		const d = new FrameDecoder();
		for (let i = 0; i < encoded.byteLength; i++) d.feed(encoded.slice(i, i + 1));
		const decoded = d.next();
		expect(decoded).not.toBeNull();
		expect(decoded?.stream_id).toBe(5);
	});

	test("multiple frames drained in order", () => {
		const d = new FrameDecoder();
		d.feed(encodeFrame(buildData(1, new TextEncoder().encode("a"))));
		d.feed(encodeFrame(buildData(3, new TextEncoder().encode("bb"))));
		d.feed(encodeFrame(buildData(5, new TextEncoder().encode("ccc"))));
		const frames = d.drain();
		expect(frames.map((f) => f.stream_id)).toEqual([1, 3, 5]);
	});

	test("decoder returns null on incomplete header", () => {
		const d = new FrameDecoder();
		d.feed(new Uint8Array([0, 0, 0, 1]));
		expect(d.next()).toBeNull();
	});

	test("reserved flag bit rejected on encode", () => {
		expect(() =>
			encodeFrame({ stream_id: 1, flags: FLAG_RESERVED_MASK, payload: new Uint8Array(0) }),
		).toThrow(ProtocolError);
	});

	test("reserved flag bit rejected on decode", () => {
		const bad = encodeFrame(buildData(1, new TextEncoder().encode("")));
		bad[4] |= 0x80;
		const d = new FrameDecoder();
		d.feed(bad);
		expect(() => d.next()).toThrow(ProtocolError);
	});

	test("OPEN with initial bytes sets both flags", () => {
		const f = buildOpen(1, new TextEncoder().encode("init"));
		expect(f.flags & FLAG_OPEN).toBeTruthy();
		expect(f.flags & FLAG_DATA).toBeTruthy();
	});

	test("DATA with close sets both", () => {
		const f = buildData(1, new TextEncoder().encode("end"), { close: true });
		expect(f.flags & FLAG_DATA).toBeTruthy();
		expect(f.flags & FLAG_CLOSE).toBeTruthy();
	});

	test("WINDOW credit roundtrip", () => {
		const frame = buildWindow(1, 65536);
		expect(parseWindowCredit(frame)).toBe(65536);
	});

	test("RESET reason roundtrip", () => {
		const frame = buildReset(1, RESET_PROTOCOL_ERROR);
		expect(parseResetReason(frame)).toBe(RESET_PROTOCOL_ERROR);
	});

	test("validateFlags rejects illegal combos", () => {
		expect(() => validateFlags(FLAG_OPEN | FLAG_CLOSE)).toThrow(ProtocolError);
		expect(() => validateFlags(FLAG_DATA | FLAG_WINDOW)).toThrow(ProtocolError);
	});

	test("WINDOW requires 4-byte payload", () => {
		const frame = { stream_id: 1, flags: FLAG_WINDOW, payload: new Uint8Array([1, 2, 3]) };
		expect(() => parseWindowCredit(frame)).toThrow(ProtocolError);
	});

	test("close frame", () => {
		const f = buildClose(1);
		expect(f.flags & FLAG_CLOSE).toBeTruthy();
	});
});
