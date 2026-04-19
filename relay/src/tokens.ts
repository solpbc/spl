// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

// JWT verify + issue for the spl-relay rendezvous layer.
//
// Algorithm: Ed25519 / EdDSA (per proto/tokens.md §algorithm). The mTLS layer
// uses ECDSA-P256 — do not conflate; see AGENTS.md §4.
//
// Signing uses `env.SIGNING_JWK` (a single private JWK); verification uses
// `env.JWKS_PUBLIC` (an envelope `{ "keys": [<public JWK>, ...] }`) indexed
// by `kid`. Rotation is atomic over those two secrets — see
// ../docs/signing-keys.md §3.

import { uuidv7 } from "./uuid";

export interface TokenClaims {
	iss: string;
	sub: string;
	aud: "spl-relay";
	scope: "session.listen" | "session.dial";
	instance_id: string;
	iat: number;
	exp: number;
	jti: string;
	// account token only
	ca_fp?: string;
	// device token only
	device_fp?: string;
}

export interface VerifyOk {
	ok: true;
	claims: TokenClaims;
}

export interface VerifyFail {
	ok: false;
	reason: VerifyFailReason;
}

export type VerifyFailReason =
	| "malformed"
	| "unknown_kid"
	| "bad_signature"
	| "bad_claim"
	| "expired"
	| "issued_future"
	| "wrong_audience"
	| "wrong_issuer"
	| "wrong_scope"
	| "jwks_unavailable";

export type VerifyResult = VerifyOk | VerifyFail;

interface VerifyOptions {
	jwksRaw: string | undefined;
	expectedIssuer: string;
	expectedScope: "session.listen" | "session.dial";
	now?: number;
}

// Web Crypto's JWK import type for public Ed25519.
interface PublicJwk {
	kty: "OKP";
	crv: "Ed25519";
	kid: string;
	x: string;
	alg?: "EdDSA";
	use?: "sig";
}

interface PrivateJwk extends PublicJwk {
	d: string;
}

interface JwksEnvelope {
	keys: PublicJwk[];
}

export async function verifyToken(token: string, options: VerifyOptions): Promise<VerifyResult> {
	const now = options.now ?? Math.floor(Date.now() / 1000);

	const parts = token.split(".");
	if (parts.length !== 3) {
		return { ok: false, reason: "malformed" };
	}
	const [headerB64, payloadB64, sigB64] = parts;

	let header: { alg?: string; kid?: string; typ?: string };
	let claims: TokenClaims;
	try {
		header = JSON.parse(utf8Decode(base64UrlDecode(headerB64)));
		claims = JSON.parse(utf8Decode(base64UrlDecode(payloadB64))) as TokenClaims;
	} catch {
		return { ok: false, reason: "malformed" };
	}

	if (header.alg !== "EdDSA" || !header.kid) {
		return { ok: false, reason: "malformed" };
	}

	const envelope = parseJwks(options.jwksRaw);
	if (!envelope) {
		return { ok: false, reason: "jwks_unavailable" };
	}

	const jwk = envelope.keys.find((k) => k.kid === header.kid);
	if (!jwk) {
		return { ok: false, reason: "unknown_kid" };
	}

	const key = await importPublic(jwk);
	const signed = utf8Encode(`${headerB64}.${payloadB64}`);
	const sig = base64UrlDecode(sigB64);

	const valid = await crypto.subtle.verify("Ed25519", key, sig, signed);
	if (!valid) {
		return { ok: false, reason: "bad_signature" };
	}

	if (claims.aud !== "spl-relay") return { ok: false, reason: "wrong_audience" };
	if (claims.iss !== options.expectedIssuer) return { ok: false, reason: "wrong_issuer" };
	if (claims.scope !== options.expectedScope) return { ok: false, reason: "wrong_scope" };
	if (typeof claims.exp !== "number" || claims.exp <= now) return { ok: false, reason: "expired" };
	if (typeof claims.iat !== "number" || claims.iat > now + 60)
		return { ok: false, reason: "issued_future" };
	if (!claims.sub || !claims.instance_id || !claims.jti) return { ok: false, reason: "bad_claim" };

	return { ok: true, claims };
}

// Token minting — called ONLY from the control-plane enroll handlers, over
// HTTPS, never from the WebSocket upgrade path.
export interface MintAccountTokenInput {
	instance_id: string;
	ca_fp: string;
	issuer: string;
	ttlSeconds: number;
	now?: number;
}

export interface MintDeviceTokenInput {
	instance_id: string;
	device_id: string;
	device_fp: string;
	issuer: string;
	ttlSeconds: number;
	now?: number;
}

export interface MintedToken {
	jwt: string;
	jti: string;
	iat: number;
	exp: number;
}

export async function mintAccountToken(
	signingJwkRaw: string,
	input: MintAccountTokenInput,
): Promise<MintedToken> {
	const now = input.now ?? Math.floor(Date.now() / 1000);
	const jti = uuidv7();
	const exp = now + input.ttlSeconds;

	const claims: TokenClaims = {
		iss: input.issuer,
		sub: `home:${input.instance_id}`,
		aud: "spl-relay",
		scope: "session.listen",
		instance_id: input.instance_id,
		ca_fp: input.ca_fp,
		iat: now,
		exp,
		jti,
	};

	const jwt = await sign(signingJwkRaw, claims);
	return { jwt, jti, iat: now, exp };
}

export async function mintDeviceToken(
	signingJwkRaw: string,
	input: MintDeviceTokenInput,
): Promise<MintedToken> {
	const now = input.now ?? Math.floor(Date.now() / 1000);
	const jti = uuidv7();
	const exp = now + input.ttlSeconds;

	const claims: TokenClaims = {
		iss: input.issuer,
		sub: `device:${input.device_id}`,
		aud: "spl-relay",
		scope: "session.dial",
		instance_id: input.instance_id,
		device_fp: input.device_fp,
		iat: now,
		exp,
		jti,
	};

	const jwt = await sign(signingJwkRaw, claims);
	return { jwt, jti, iat: now, exp };
}

async function sign(signingJwkRaw: string, claims: TokenClaims): Promise<string> {
	const jwk = JSON.parse(signingJwkRaw) as PrivateJwk;
	if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || !jwk.d || !jwk.kid) {
		throw new Error("signing JWK has unexpected shape");
	}

	const header = { alg: "EdDSA", typ: "JWT", kid: jwk.kid };
	const headerB64 = base64UrlEncode(utf8Encode(JSON.stringify(header)));
	const payloadB64 = base64UrlEncode(utf8Encode(JSON.stringify(claims)));
	const signing = utf8Encode(`${headerB64}.${payloadB64}`);

	const key = await crypto.subtle.importKey("jwk", jwk, { name: "Ed25519" }, false, ["sign"]);
	const sig = await crypto.subtle.sign("Ed25519", key, signing);
	const sigB64 = base64UrlEncode(new Uint8Array(sig));
	return `${headerB64}.${payloadB64}.${sigB64}`;
}

async function importPublic(jwk: PublicJwk): Promise<CryptoKey> {
	// Web Crypto requires us to strip private fields even if the caller
	// supplied a full private JWK, but we only pass public JWKs here.
	return crypto.subtle.importKey(
		"jwk",
		{ kty: jwk.kty, crv: jwk.crv, x: jwk.x },
		{ name: "Ed25519" },
		false,
		["verify"],
	);
}

function parseJwks(raw: string | undefined): JwksEnvelope | null {
	if (!raw) return null;
	try {
		const parsed = JSON.parse(raw) as JwksEnvelope;
		if (!parsed || !Array.isArray(parsed.keys)) return null;
		return parsed;
	} catch {
		return null;
	}
}

// base64url helpers — RFC 4648 §5.
export function base64UrlEncode(bytes: Uint8Array): string {
	let binary = "";
	for (const b of bytes) binary += String.fromCharCode(b);
	const b64 = btoa(binary);
	return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function base64UrlDecode(s: string): Uint8Array {
	const pad = s.length % 4 === 2 ? "==" : s.length % 4 === 3 ? "=" : "";
	const b64 = s.replace(/-/g, "+").replace(/_/g, "/") + pad;
	const binary = atob(b64);
	const out = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
	return out;
}

function utf8Encode(s: string): Uint8Array {
	return new TextEncoder().encode(s);
}

function utf8Decode(bytes: Uint8Array): string {
	return new TextDecoder("utf-8").decode(bytes);
}
