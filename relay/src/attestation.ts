// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

// Home-signed attestation for /enroll/device (answers proto/tokens.md O1).
//
// Shape
// -----
// During the LAN pair ceremony (proto/pairing.md §6–7), the home signs a
// short-lived JWT with its local CA private key (ECDSA-P256, ES256) and
// returns it alongside the signed client cert. The mobile forwards this
// blob verbatim to `/enroll/device` as the `home_attestation` field.
//
// Header:
//   { "alg": "ES256", "typ": "home-attest" }
// Payload:
//   { "iss": "home:<instance_id>", "aud": "spl-relay",
//     "scope": "device.enroll",
//     "instance_id": "<uuidv7>",
//     "device_fp": "sha256:<hex lowercase>",
//     "iat": <unix s>, "exp": <unix s>, "jti": "<uuidv7>" }
//
// Constraints enforced by the relay:
//   * exp > now, iat ≤ now + 60s skew
//   * exp - iat ≤ 300s (short-lived; anti-replay bound)
//   * iss == "home:<instance_id>" and matches the request's instance_id
//   * device_fp matches sha256(DER(client_cert)) computed by the relay
//   * signature verifies against the CA public key stored at /enroll/home
//   * jti has not been consumed (single-use — tracked in D1 devices table
//     via the device_jti primary key; attestation jti is distinct from the
//     issued device token jti)
//
// Why a home-signed JWT and not "client cert chains to registered CA" alone:
// chain validity only proves the home issued the cert at some point. The
// attestation additionally binds the issuance to a recent user-initiated
// pair moment (bounded by the 5-min exp) and a specific device fingerprint.
// Anyone who later captures a stale client cert cannot mint new device
// tokens — the home must sign a fresh attestation each pair.

import { base64UrlDecode } from "./tokens";

export type AttestationClaims = {
	iss: string;
	aud: "spl-relay";
	scope: "device.enroll";
	instance_id: string;
	device_fp: string;
	iat: number;
	exp: number;
	jti: string;
};

export type AttestationOk = { ok: true; claims: AttestationClaims };
export type AttestationFail = { ok: false; reason: AttestationFailReason };
export type AttestationResult = AttestationOk | AttestationFail;

export type AttestationFailReason =
	| "malformed"
	| "bad_signature"
	| "bad_claim"
	| "expired"
	| "issued_future"
	| "too_long_lived"
	| "wrong_issuer"
	| "wrong_audience"
	| "wrong_scope"
	| "wrong_instance"
	| "fp_mismatch";

// Max attestation lifetime. Matches the LAN pair ceremony nonce TTL (5 min)
// per proto/pairing.md §1.
const MAX_ATTESTATION_LIFETIME_SECONDS = 300;

interface VerifyInput {
	attestation: string;
	caPubkeyPem: string;
	expectedInstanceId: string;
	expectedDeviceFp: string;
	now?: number;
}

export async function verifyAttestation(input: VerifyInput): Promise<AttestationResult> {
	const now = input.now ?? Math.floor(Date.now() / 1000);

	const parts = input.attestation.split(".");
	if (parts.length !== 3) return { ok: false, reason: "malformed" };
	const [headerB64, payloadB64, sigB64] = parts;

	let header: { alg?: string; typ?: string };
	let claims: AttestationClaims;
	try {
		header = JSON.parse(utf8Decode(base64UrlDecode(headerB64)));
		claims = JSON.parse(utf8Decode(base64UrlDecode(payloadB64))) as AttestationClaims;
	} catch {
		return { ok: false, reason: "malformed" };
	}

	if (header.alg !== "ES256") return { ok: false, reason: "malformed" };
	if (header.typ !== "home-attest") return { ok: false, reason: "malformed" };

	const caKey = await importCaPublicKey(input.caPubkeyPem);
	if (!caKey) return { ok: false, reason: "malformed" };

	const signed = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
	const sigRaw = base64UrlDecode(sigB64);
	// Web Crypto verify for ECDSA expects IEEE P1363 raw (r||s, 64 bytes).
	// JWTs (JOSE) ship signatures in that same raw shape already. Accept
	// both raw and DER to be robust to home-side library choices.
	const sig = sigRaw.length === 64 ? sigRaw : tryDerToRaw(sigRaw);
	if (!sig) return { ok: false, reason: "bad_signature" };

	const valid = await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, caKey, sig, signed);
	if (!valid) return { ok: false, reason: "bad_signature" };

	if (claims.aud !== "spl-relay") return { ok: false, reason: "wrong_audience" };
	if (claims.scope !== "device.enroll") return { ok: false, reason: "wrong_scope" };
	if (claims.iss !== `home:${input.expectedInstanceId}`)
		return { ok: false, reason: "wrong_issuer" };
	if (claims.instance_id !== input.expectedInstanceId)
		return { ok: false, reason: "wrong_instance" };
	if (typeof claims.exp !== "number" || claims.exp <= now) return { ok: false, reason: "expired" };
	if (typeof claims.iat !== "number" || claims.iat > now + 60)
		return { ok: false, reason: "issued_future" };
	if (claims.exp - claims.iat > MAX_ATTESTATION_LIFETIME_SECONDS)
		return { ok: false, reason: "too_long_lived" };
	if (!claims.jti || !claims.device_fp) return { ok: false, reason: "bad_claim" };
	if (claims.device_fp !== input.expectedDeviceFp) return { ok: false, reason: "fp_mismatch" };

	return { ok: true, claims };
}

// Parse SPKI PEM → Web Crypto ECDSA verify key. Returns null if the PEM
// isn't a valid P-256 public key in SubjectPublicKeyInfo form.
export async function importCaPublicKey(pem: string): Promise<CryptoKey | null> {
	try {
		const body = pem
			.replace(/-----BEGIN [^-]+-----/g, "")
			.replace(/-----END [^-]+-----/g, "")
			.replace(/\s+/g, "");
		const der = base64UrlDecode(toBase64Url(body));
		return await crypto.subtle.importKey(
			"spki",
			der,
			{ name: "ECDSA", namedCurve: "P-256" },
			false,
			["verify"],
		);
	} catch {
		return null;
	}
}

// Decode a PEM-encoded X.509 certificate body to DER bytes. Accepts a cert
// that may or may not be wrapped in BEGIN/END markers. Returns null if the
// input isn't something that decodes as base64.
export function pemToDer(pem: string): Uint8Array | null {
	try {
		const body = pem
			.replace(/-----BEGIN [^-]+-----/g, "")
			.replace(/-----END [^-]+-----/g, "")
			.replace(/\s+/g, "");
		if (!body) return null;
		return base64UrlDecode(toBase64Url(body));
	} catch {
		return null;
	}
}

// SHA-256 fingerprint of a DER-encoded certificate, formatted as
// "sha256:<64 lowercase hex chars>". Matches proto/pairing.md §6 and
// authorized_clients.json shape.
export async function fingerprintDer(der: Uint8Array): Promise<string> {
	const hash = await crypto.subtle.digest("SHA-256", der);
	const bytes = new Uint8Array(hash);
	const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
	return `sha256:${hex}`;
}

function toBase64Url(b64: string): string {
	return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function utf8Decode(bytes: Uint8Array): string {
	return new TextDecoder("utf-8").decode(bytes);
}

// Convert a DER-encoded ECDSA signature (SEQUENCE { INTEGER r, INTEGER s })
// to raw IEEE P1363 (r||s, each 32 bytes for P-256). Returns null on any
// parse failure. Web Crypto's ECDSA verify requires the raw form.
function tryDerToRaw(der: Uint8Array): Uint8Array | null {
	try {
		if (der[0] !== 0x30) return null;
		let cursor = 2;
		if (der[1] & 0x80) cursor += der[1] & 0x7f;
		if (der[cursor] !== 0x02) return null;
		const rLen = der[cursor + 1];
		const rStart = cursor + 2;
		const r = der.slice(rStart, rStart + rLen);
		cursor = rStart + rLen;
		if (der[cursor] !== 0x02) return null;
		const sLen = der[cursor + 1];
		const sStart = cursor + 2;
		const s = der.slice(sStart, sStart + sLen);
		const rPad = pad32(r);
		const sPad = pad32(s);
		if (!rPad || !sPad) return null;
		const out = new Uint8Array(64);
		out.set(rPad, 0);
		out.set(sPad, 32);
		return out;
	} catch {
		return null;
	}
}

function pad32(bytes: Uint8Array): Uint8Array | null {
	// Strip leading 0x00 (ASN.1 INTEGER sign byte) then left-pad to 32 bytes.
	let start = 0;
	while (start < bytes.length && bytes[start] === 0x00) start++;
	const trimmed = bytes.slice(start);
	if (trimmed.length > 32) return null;
	const out = new Uint8Array(32);
	out.set(trimmed, 32 - trimmed.length);
	return out;
}
