// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

export const TOTP_SECRET_RE = /^[A-Z2-7]{16,128}$/;

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
export const TOTP_STEP_SECONDS = 30;
const TOTP_DIGITS = 6;

export function base32Decode(s: string): Uint8Array {
	let bits = 0;
	let value = 0;
	const out: number[] = [];

	for (const ch of s) {
		const next = BASE32_ALPHABET.indexOf(ch);
		if (next < 0) throw new Error(`invalid base32 character: ${ch}`);
		value = (value << 5) | next;
		bits += 5;
		if (bits >= 8) {
			bits -= 8;
			out.push((value >>> bits) & 0xff);
		}
	}

	return new Uint8Array(out);
}

async function hotp(secretBytes: Uint8Array, counter: number): Promise<string> {
	const key = await crypto.subtle.importKey(
		"raw",
		secretBytes,
		{ name: "HMAC", hash: "SHA-1" },
		false,
		["sign"],
	);
	const message = new ArrayBuffer(8);
	const view = new DataView(message);
	view.setUint32(0, Math.floor(counter / 0x100000000), false);
	view.setUint32(4, counter >>> 0, false);

	const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, message));
	const offset = mac[19] & 0x0f;
	const bin =
		((mac[offset] & 0x7f) << 24) |
		(mac[offset + 1] << 16) |
		(mac[offset + 2] << 8) |
		mac[offset + 3];
	return String(bin % 1_000_000).padStart(TOTP_DIGITS, "0");
}

export async function generateTotp(secretB32: string, nowSeconds: number): Promise<string> {
	const secretBytes = base32Decode(secretB32);
	const counter = Math.floor(nowSeconds / TOTP_STEP_SECONDS);
	return hotp(secretBytes, counter);
}

export async function verifyTotp(
	secretB32: string,
	code: string,
	nowSeconds: number,
): Promise<boolean> {
	const secretBytes = base32Decode(secretB32);
	const step = Math.floor(nowSeconds / TOTP_STEP_SECONDS);
	const previous = await hotp(secretBytes, step - 1);
	const current = await hotp(secretBytes, step);
	const next = await hotp(secretBytes, step + 1);

	const p = constantTimeEqual(previous, code);
	const c = constantTimeEqual(current, code);
	const n = constantTimeEqual(next, code);
	return p || c || n;
}

function constantTimeEqual(a: string, b: string): boolean {
	let diff = a.length ^ b.length;
	for (let i = 0; i < TOTP_DIGITS; i++) {
		const ac = i < a.length ? a.charCodeAt(i) : 0;
		const bc = i < b.length ? b.charCodeAt(i) : 0;
		diff |= ac ^ bc;
	}
	return diff === 0;
}
