// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

// UUIDv7 — 48-bit unix-millis timestamp, 4-bit version=7, 12 bits random,
// 2-bit variant=10, 62 bits random. Monotonic-ish prefix lets downstream
// D1 indexing stay happy. crypto.randomUUID() is v4; we need v7 for jti.

export function uuidv7(): string {
	const bytes = new Uint8Array(16);
	crypto.getRandomValues(bytes);

	const ms = BigInt(Date.now());
	bytes[0] = Number((ms >> 40n) & 0xffn);
	bytes[1] = Number((ms >> 32n) & 0xffn);
	bytes[2] = Number((ms >> 24n) & 0xffn);
	bytes[3] = Number((ms >> 16n) & 0xffn);
	bytes[4] = Number((ms >> 8n) & 0xffn);
	bytes[5] = Number(ms & 0xffn);

	bytes[6] = (bytes[6] & 0x0f) | 0x70; // version 7
	bytes[8] = (bytes[8] & 0x3f) | 0x80; // variant 10

	const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
	return [
		hex.slice(0, 8),
		hex.slice(8, 12),
		hex.slice(12, 16),
		hex.slice(16, 20),
		hex.slice(20, 32),
	].join("-");
}
