// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import { describe, expect, it } from "vitest";
import {
	base64UrlDecode,
	base64UrlEncode,
	mintAccountToken,
	mintDeviceToken,
	verifyToken,
} from "../src/tokens";
import { genSigningKeypair } from "./fixtures";

const ISSUER = "spl.test";

describe("verifyToken", () => {
	it("accepts a freshly minted account token with the correct scope", async () => {
		const k = await genSigningKeypair();
		const minted = await mintAccountToken(k.privateJwkRaw, {
			instance_id: "inst-1",
			ca_fp: "sha256:abc",
			issuer: ISSUER,
			ttlSeconds: 60,
		});
		const r = await verifyToken(minted.jwt, {
			jwksRaw: k.jwksPublicRaw,
			expectedIssuer: ISSUER,
			expectedScope: "session.listen",
		});
		expect(r.ok).toBe(true);
		if (r.ok) {
			expect(r.claims.sub).toBe("home:inst-1");
			expect(r.claims.instance_id).toBe("inst-1");
			expect(r.claims.scope).toBe("session.listen");
			expect(r.claims.jti).toBe(minted.jti);
		}
	});

	it("accepts a freshly minted device token with the correct scope", async () => {
		const k = await genSigningKeypair();
		const minted = await mintDeviceToken(k.privateJwkRaw, {
			instance_id: "inst-1",
			device_id: "dev-1",
			device_fp: "sha256:dev",
			issuer: ISSUER,
			ttlSeconds: 60,
		});
		const r = await verifyToken(minted.jwt, {
			jwksRaw: k.jwksPublicRaw,
			expectedIssuer: ISSUER,
			expectedScope: "session.dial",
		});
		expect(r.ok).toBe(true);
	});

	it("rejects a token for the wrong scope", async () => {
		const k = await genSigningKeypair();
		const minted = await mintAccountToken(k.privateJwkRaw, {
			instance_id: "inst-1",
			ca_fp: "sha256:abc",
			issuer: ISSUER,
			ttlSeconds: 60,
		});
		const r = await verifyToken(minted.jwt, {
			jwksRaw: k.jwksPublicRaw,
			expectedIssuer: ISSUER,
			expectedScope: "session.dial",
		});
		expect(r).toEqual({ ok: false, reason: "wrong_scope" });
	});

	it("rejects a token signed with an unknown kid", async () => {
		const k1 = await genSigningKeypair("kid-A");
		const k2 = await genSigningKeypair("kid-B");
		const minted = await mintAccountToken(k1.privateJwkRaw, {
			instance_id: "inst-1",
			ca_fp: "sha256:abc",
			issuer: ISSUER,
			ttlSeconds: 60,
		});
		// Only k2 is in the JWKS.
		const r = await verifyToken(minted.jwt, {
			jwksRaw: k2.jwksPublicRaw,
			expectedIssuer: ISSUER,
			expectedScope: "session.listen",
		});
		expect(r).toEqual({ ok: false, reason: "unknown_kid" });
	});

	it("rejects a token signed with a key not in the JWKS (signature fails after kid match)", async () => {
		// Construct a JWKS with the right kid but the wrong `x` (public) value.
		const k = await genSigningKeypair();
		const minted = await mintAccountToken(k.privateJwkRaw, {
			instance_id: "inst-1",
			ca_fp: "sha256:abc",
			issuer: ISSUER,
			ttlSeconds: 60,
		});
		const wrong = await genSigningKeypair();
		const wrongEnvelope = JSON.parse(wrong.jwksPublicRaw) as {
			keys: Array<{ kid: string }>;
		};
		wrongEnvelope.keys[0].kid = JSON.parse(k.privateJwkRaw).kid;
		const r = await verifyToken(minted.jwt, {
			jwksRaw: JSON.stringify(wrongEnvelope),
			expectedIssuer: ISSUER,
			expectedScope: "session.listen",
		});
		expect(r).toEqual({ ok: false, reason: "bad_signature" });
	});

	it("rejects expired tokens", async () => {
		const k = await genSigningKeypair();
		const now = Math.floor(Date.now() / 1000);
		const minted = await mintAccountToken(k.privateJwkRaw, {
			instance_id: "inst-1",
			ca_fp: "sha256:abc",
			issuer: ISSUER,
			ttlSeconds: 10,
			now: now - 100,
		});
		const r = await verifyToken(minted.jwt, {
			jwksRaw: k.jwksPublicRaw,
			expectedIssuer: ISSUER,
			expectedScope: "session.listen",
			now,
		});
		expect(r).toEqual({ ok: false, reason: "expired" });
	});

	it("rejects tokens with iat too far in the future", async () => {
		const k = await genSigningKeypair();
		const now = Math.floor(Date.now() / 1000);
		const minted = await mintAccountToken(k.privateJwkRaw, {
			instance_id: "inst-1",
			ca_fp: "sha256:abc",
			issuer: ISSUER,
			ttlSeconds: 60,
			now: now + 3600,
		});
		const r = await verifyToken(minted.jwt, {
			jwksRaw: k.jwksPublicRaw,
			expectedIssuer: ISSUER,
			expectedScope: "session.listen",
			now,
		});
		expect(r).toEqual({ ok: false, reason: "issued_future" });
	});

	it("rejects tokens with the wrong issuer", async () => {
		const k = await genSigningKeypair();
		const minted = await mintAccountToken(k.privateJwkRaw, {
			instance_id: "inst-1",
			ca_fp: "sha256:abc",
			issuer: "other.iss",
			ttlSeconds: 60,
		});
		const r = await verifyToken(minted.jwt, {
			jwksRaw: k.jwksPublicRaw,
			expectedIssuer: ISSUER,
			expectedScope: "session.listen",
		});
		expect(r).toEqual({ ok: false, reason: "wrong_issuer" });
	});

	it("rejects malformed tokens", async () => {
		const k = await genSigningKeypair();
		const r = await verifyToken("not.a.jwt.at.all", {
			jwksRaw: k.jwksPublicRaw,
			expectedIssuer: ISSUER,
			expectedScope: "session.listen",
		});
		expect(r.ok).toBe(false);
	});

	it("returns jwks_unavailable when JWKS is not provisioned", async () => {
		const k = await genSigningKeypair();
		const minted = await mintAccountToken(k.privateJwkRaw, {
			instance_id: "inst-1",
			ca_fp: "sha256:abc",
			issuer: ISSUER,
			ttlSeconds: 60,
		});
		const r = await verifyToken(minted.jwt, {
			jwksRaw: undefined,
			expectedIssuer: ISSUER,
			expectedScope: "session.listen",
		});
		expect(r).toEqual({ ok: false, reason: "jwks_unavailable" });
	});
});

describe("base64url round-trip", () => {
	it("encode and decode are inverses for random bytes", () => {
		const bytes = new Uint8Array(100);
		for (let i = 0; i < bytes.length; i++) bytes[i] = (i * 7) & 0xff;
		const encoded = base64UrlEncode(bytes);
		const decoded = base64UrlDecode(encoded);
		expect(decoded.length).toBe(bytes.length);
		for (let i = 0; i < bytes.length; i++) expect(decoded[i]).toBe(bytes[i]);
	});
});
