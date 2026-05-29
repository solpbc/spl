// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

// Crockford base32 encoding for pair-link payloads. Mirrors solstone's
// apps/link/crockford32.py exactly, including character normalization and
// trailing pad-bit validation.

const ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const DECODE = new Map(Array.from(ALPHABET, (char, idx) => [char, idx] as const));
const ASCII_WHITESPACE = new Set([" ", "\t", "\n", "\r", "\v", "\f"]);

export function encode(data: Uint8Array): string {
	if (data.byteLength === 0) return "";

	const out: string[] = [];
	let buffer = 0;
	let bits = 0;
	for (const byte of data) {
		buffer = (buffer << 8) | byte;
		bits += 8;
		while (bits >= 5) {
			bits -= 5;
			out.push(ALPHABET[(buffer >> bits) & 0x1f]);
			buffer &= (1 << bits) - 1;
		}
	}

	if (bits) {
		out.push(ALPHABET[(buffer << (5 - bits)) & 0x1f]);
	}

	return out.join("");
}

export function decode(text: string): Uint8Array {
	let value = 0n;
	let bits = 0;

	for (const rawChar of text) {
		const char = normalizeChar(rawChar);
		if (char === null) continue;
		const decoded = DECODE.get(char);
		if (decoded === undefined) {
			throw new Error(`invalid Crockford base32 character: ${rawChar}`);
		}
		value = (value << 5n) | BigInt(decoded);
		bits += 5;
	}

	if (bits === 0) return new Uint8Array(0);

	const padBits = bits % 8;
	if (padBits) {
		const padMask = padBits <= 4 ? (1n << BigInt(padBits)) - 1n : 0n;
		if (padMask && value & padMask) {
			throw new Error("non-zero trailing pad bits");
		}
		value >>= BigInt(padBits);
	}

	const byteCount = bits >> 3;
	const out = new Uint8Array(byteCount);
	for (let i = byteCount - 1; i >= 0; i--) {
		out[i] = Number(value & 0xffn);
		value >>= 8n;
	}
	return out;
}

function normalizeChar(char: string): string | null {
	if (char === "-" || ASCII_WHITESPACE.has(char)) return null;
	if (char === "I" || char === "i" || char === "L" || char === "l") return "1";
	if (char === "O" || char === "o") return "0";
	return char.toUpperCase();
}
