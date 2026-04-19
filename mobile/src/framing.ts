// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

// Multiplex framing — TS mirror of spl/home/src/spl/home/framing.py.
// Wire format is specified in ../../proto/framing.md; both endpoints must
// stay in lockstep. Changes here need a matching edit on the home side.
//
// Header layout (8 bytes):
//   stream_id : u32 big-endian
//   flags     : u8
//   length    : u24 big-endian

export const FLAG_OPEN = 0x01;
export const FLAG_DATA = 0x02;
export const FLAG_CLOSE = 0x04;
export const FLAG_RESET = 0x08;
export const FLAG_WINDOW = 0x10;
export const FLAG_RESERVED_MASK = 0xe0;

export const RESET_PROTOCOL_ERROR = 0x01;
export const RESET_FLOW_CONTROL_ERROR = 0x02;
export const RESET_STREAM_LIMIT_EXCEEDED = 0x03;
export const RESET_INTERNAL_ERROR = 0x04;
export const RESET_CANCEL = 0x05;
export const RESET_UNSPECIFIED = 0xff;

export const HEADER_LEN = 8;
export const MAX_PAYLOAD = (1 << 24) - 1;
export const INITIAL_WINDOW = 1 << 20; // 1 MiB
export const MAX_CONCURRENT_STREAMS = 256;
export const RECOMMENDED_CHUNK = 64 * 1024;

export class ProtocolError extends Error {
	constructor(message: string) {
		super(message);
		this.name = "ProtocolError";
	}
}

export interface Frame {
	stream_id: number;
	flags: number;
	payload: Uint8Array;
}

export function encodeFrame(frame: Frame): Uint8Array {
	if (frame.stream_id < 0 || frame.stream_id > 0xffffffff) {
		throw new ProtocolError(`stream_id out of range: ${frame.stream_id}`);
	}
	if (frame.flags < 0 || frame.flags > 0xff) {
		throw new ProtocolError(`flags out of range: ${frame.flags}`);
	}
	if (frame.flags & FLAG_RESERVED_MASK) {
		throw new ProtocolError(`reserved flag bits set: ${frame.flags.toString(16)}`);
	}
	const length = frame.payload.byteLength;
	if (length > MAX_PAYLOAD) {
		throw new ProtocolError(`payload exceeds 16 MiB - 1: ${length}`);
	}
	const header = new Uint8Array(HEADER_LEN);
	const view = new DataView(header.buffer);
	view.setUint32(0, frame.stream_id, false);
	view.setUint8(4, frame.flags);
	view.setUint8(5, (length >> 16) & 0xff);
	view.setUint8(6, (length >> 8) & 0xff);
	view.setUint8(7, length & 0xff);
	const out = new Uint8Array(HEADER_LEN + length);
	out.set(header, 0);
	out.set(frame.payload, HEADER_LEN);
	return out;
}

export class FrameDecoder {
	private buf: Uint8Array = new Uint8Array(0);

	feed(chunk: Uint8Array): void {
		if (chunk.byteLength === 0) return;
		const merged = new Uint8Array(this.buf.byteLength + chunk.byteLength);
		merged.set(this.buf, 0);
		merged.set(chunk, this.buf.byteLength);
		this.buf = merged;
	}

	next(): Frame | null {
		if (this.buf.byteLength < HEADER_LEN) return null;
		const view = new DataView(this.buf.buffer, this.buf.byteOffset, this.buf.byteLength);
		const stream_id = view.getUint32(0, false);
		const flags = view.getUint8(4);
		const length = (view.getUint8(5) << 16) | (view.getUint8(6) << 8) | view.getUint8(7);
		if (flags & FLAG_RESERVED_MASK) {
			throw new ProtocolError(`reserved flag bits set: ${flags.toString(16)}`);
		}
		const end = HEADER_LEN + length;
		if (this.buf.byteLength < end) return null;
		const payload = this.buf.slice(HEADER_LEN, end);
		this.buf = this.buf.slice(end);
		return { stream_id, flags, payload };
	}

	drain(): Frame[] {
		const out: Frame[] = [];
		while (true) {
			const frame = this.next();
			if (!frame) return out;
			out.push(frame);
		}
	}
}

export function buildOpen(stream_id: number, payload: Uint8Array = new Uint8Array(0)): Frame {
	return {
		stream_id,
		flags: payload.byteLength ? FLAG_OPEN | FLAG_DATA : FLAG_OPEN,
		payload,
	};
}

export function buildData(
	stream_id: number,
	payload: Uint8Array,
	opts?: { close?: boolean },
): Frame {
	const close = opts?.close ?? false;
	return {
		stream_id,
		flags: close ? FLAG_DATA | FLAG_CLOSE : FLAG_DATA,
		payload,
	};
}

export function buildClose(stream_id: number, payload: Uint8Array = new Uint8Array(0)): Frame {
	return { stream_id, flags: FLAG_CLOSE, payload };
}

export function buildReset(stream_id: number, reason: number = RESET_UNSPECIFIED): Frame {
	if (reason < 0 || reason > 0xff) {
		throw new ProtocolError(`reset reason out of range: ${reason}`);
	}
	return { stream_id, flags: FLAG_RESET, payload: new Uint8Array([reason]) };
}

export function buildWindow(stream_id: number, credit: number): Frame {
	if (credit < 0 || credit > 0xffffffff) {
		throw new ProtocolError(`window credit out of range: ${credit}`);
	}
	const payload = new Uint8Array(4);
	const view = new DataView(payload.buffer);
	view.setUint32(0, credit, false);
	return { stream_id, flags: FLAG_WINDOW, payload };
}

export function parseWindowCredit(frame: Frame): number {
	if (
		!(frame.flags & FLAG_WINDOW) ||
		frame.flags & (FLAG_OPEN | FLAG_DATA | FLAG_CLOSE | FLAG_RESET)
	) {
		throw new ProtocolError("not a WINDOW frame");
	}
	if (frame.payload.byteLength !== 4) {
		throw new ProtocolError(`WINDOW payload must be 4 bytes, got ${frame.payload.byteLength}`);
	}
	const view = new DataView(frame.payload.buffer, frame.payload.byteOffset, 4);
	return view.getUint32(0, false);
}

export function parseResetReason(frame: Frame): number {
	if (!(frame.flags & FLAG_RESET)) {
		throw new ProtocolError("not a RESET frame");
	}
	if (frame.payload.byteLength !== 1) {
		throw new ProtocolError(`RESET payload must be 1 byte, got ${frame.payload.byteLength}`);
	}
	return frame.payload[0];
}

export function validateFlags(flags: number): void {
	if (flags & FLAG_RESERVED_MASK) {
		throw new ProtocolError(`reserved flag bits set: ${flags.toString(16)}`);
	}
	const exclusive = flags & (FLAG_OPEN | FLAG_DATA | FLAG_CLOSE | FLAG_RESET | FLAG_WINDOW);
	if (!exclusive) {
		throw new ProtocolError("frame has no OPEN/DATA/CLOSE/RESET/WINDOW bit set");
	}
	const allowed = new Set([
		FLAG_OPEN,
		FLAG_DATA,
		FLAG_CLOSE,
		FLAG_RESET,
		FLAG_WINDOW,
		FLAG_OPEN | FLAG_DATA,
		FLAG_DATA | FLAG_CLOSE,
	]);
	if (!allowed.has(exclusive)) {
		throw new ProtocolError(`illegal flag combination: ${flags.toString(16)}`);
	}
}
