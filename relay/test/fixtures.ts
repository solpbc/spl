// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

// Test fixtures: Ed25519 signing keys, ECDSA-P256 CA keys, home-signed
// attestations. All generated inline at test start — no committed key
// material in the repo.

// Node 20+ exposes Web Crypto as `globalThis.crypto` — that's the same API
// the Worker uses under workerd. Using the global avoids the `node:crypto`
// vs `@cloudflare/workers-types` CryptoKey-shape mismatch at type-check time.
import { base64UrlEncode } from "../src/tokens";

export interface SigningKeypair {
	kid: string;
	privateJwkRaw: string;
	jwksPublicRaw: string;
}

export async function genSigningKeypair(kid = "test-kid-1"): Promise<SigningKeypair> {
	const pair = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
		"sign",
		"verify",
	])) as CryptoKeyPair;
	const pubJwk = (await crypto.subtle.exportKey("jwk", pair.publicKey)) as unknown as Record<
		string,
		string
	>;
	const privJwk = (await crypto.subtle.exportKey("jwk", pair.privateKey)) as unknown as Record<
		string,
		string
	>;

	const publicJwk = {
		kty: "OKP",
		crv: "Ed25519",
		kid,
		x: pubJwk.x,
		alg: "EdDSA",
		use: "sig",
	};
	const privateJwk = { ...publicJwk, d: privJwk.d };

	return {
		kid,
		privateJwkRaw: JSON.stringify(privateJwk),
		jwksPublicRaw: JSON.stringify({ keys: [publicJwk] }),
	};
}

export interface CaKeypair {
	pubPem: string;
	privateKey: CryptoKey;
}

export async function genCaKeypair(): Promise<CaKeypair> {
	const pair = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
		"sign",
		"verify",
	])) as CryptoKeyPair;
	const spki = (await crypto.subtle.exportKey("spki", pair.publicKey)) as ArrayBuffer;
	const pubPem = derToPem(new Uint8Array(spki), "PUBLIC KEY");
	return { pubPem, privateKey: pair.privateKey };
}

// Generate a stand-in "client cert" — any DER blob works for fingerprint
// purposes. Tests don't actually exercise the TLS chain; that lives on the
// home side outside the relay.
export async function genClientCertDer(label = "device"): Promise<Uint8Array> {
	const bytes = new TextEncoder().encode(`fake-cert:${label}:${Date.now()}`);
	const out = new Uint8Array(32 + bytes.length);
	out.set(bytes, 32);
	crypto.getRandomValues(out.subarray(0, 32));
	return out;
}

export function derToPem(der: Uint8Array, label: string): string {
	const b64 = Buffer.from(der).toString("base64");
	const lines: string[] = [];
	for (let i = 0; i < b64.length; i += 64) lines.push(b64.slice(i, i + 64));
	return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----\n`;
}

// Build a home-signed attestation JWT (ES256) matching
// src/attestation.ts expectations.
export interface AttestationInput {
	caPrivateKey: CryptoKey;
	instanceId: string;
	deviceFp: string;
	now?: number;
	exp?: number;
	overrideIssuer?: string;
	overrideAudience?: string;
	overrideScope?: string;
	overrideDeviceFp?: string;
	overrideInstanceId?: string;
}

export async function mintAttestation(input: AttestationInput): Promise<string> {
	const now = input.now ?? Math.floor(Date.now() / 1000);
	const exp = input.exp ?? now + 120;
	const header = { alg: "ES256", typ: "home-attest" };
	const claims = {
		iss: input.overrideIssuer ?? `home:${input.instanceId}`,
		aud: input.overrideAudience ?? "spl-relay",
		scope: input.overrideScope ?? "device.enroll",
		instance_id: input.overrideInstanceId ?? input.instanceId,
		device_fp: input.overrideDeviceFp ?? input.deviceFp,
		iat: now,
		exp,
		jti: `jti-${now}-${Math.random().toString(16).slice(2, 8)}`,
	};
	const headerB64 = base64UrlEncode(new TextEncoder().encode(JSON.stringify(header)));
	const payloadB64 = base64UrlEncode(new TextEncoder().encode(JSON.stringify(claims)));
	const signing = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
	const sig = await crypto.subtle.sign(
		{ name: "ECDSA", hash: "SHA-256" },
		input.caPrivateKey,
		signing,
	);
	const sigB64 = base64UrlEncode(new Uint8Array(sig));
	return `${headerB64}.${payloadB64}.${sigB64}`;
}
