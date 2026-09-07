// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import type { AttestationClaims } from "./attestation";

// Preserve UUIDv7 wire shapes with the attestation's issue timestamp and
// domain-separated hash entropy. Unknown extensions and JSON key order do
// not change issuance; every verified semantic claim participates.
export async function enrollmentIds(
	claims: AttestationClaims,
): Promise<{ deviceId: string; jti: string }> {
	const canonical = JSON.stringify([
		claims.iss,
		claims.aud,
		claims.scope,
		claims.instance_id,
		claims.device_fp,
		claims.iat,
		claims.exp,
		claims.jti,
	]);
	async function derive(domain: string): Promise<string> {
		const digest = await crypto.subtle.digest(
			"SHA-256",
			new TextEncoder().encode(`${domain}\0${canonical}`),
		);
		const bytes = new Uint8Array(digest).slice(0, 16);
		const ms = BigInt(claims.iat) * 1000n;
		for (let i = 0; i < 6; i++) bytes[i] = Number((ms >> BigInt((5 - i) * 8)) & 255n);
		bytes[6] = (bytes[6] & 15) | 0x70;
		bytes[8] = (bytes[8] & 63) | 0x80;
		const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
		return [
			hex.slice(0, 8),
			hex.slice(8, 12),
			hex.slice(12, 16),
			hex.slice(16, 20),
			hex.slice(20),
		].join("-");
	}
	return {
		deviceId: await derive("spl-enroll-device-v1"),
		jti: await derive("spl-enroll-token-v1"),
	};
}
