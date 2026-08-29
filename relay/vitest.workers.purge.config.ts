// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import { defineWorkersConfig } from "@cloudflare/vitest-pool-workers/config";

// Portal-purge integration tests use a separate test-only Ed25519 keypair so
// the Worker receives the public JWKS while tests sign dynamic envelopes with
// the matching private JWK. These values exist only in Miniflare bindings.
const portal = await genSigningKeypair();

export default defineWorkersConfig({
	test: {
		include: ["test-integration/**/*.purge.test.ts"],
		poolOptions: {
			workers: {
				main: "./src/index.ts",
				isolatedStorage: false,
				miniflare: {
					compatibilityDate: "2026-04-01",
					compatibilityFlags: ["nodejs_compat"],
					durableObjects: { INSTANCE: { className: "InstanceDO", useSQLite: true } },
					d1Databases: ["DB"],
					bindings: {
						ENVIRONMENT: "test",
						ISSUER: "spl.test",
						PURGE_SECRET: "test-purge-secret",
						PORTAL_JWKS_PUBLIC: portal.jwksPublicRaw,
						PORTAL_TEST_SIGNING_JWK: portal.privateJwkRaw,
					},
				},
			},
		},
	},
});

async function genSigningKeypair(): Promise<{
	privateJwkRaw: string;
	jwksPublicRaw: string;
}> {
	const pair = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
		"sign",
		"verify",
	])) as CryptoKeyPair;
	const pub = (await crypto.subtle.exportKey("jwk", pair.publicKey)) as unknown as Record<
		string,
		string
	>;
	const priv = (await crypto.subtle.exportKey("jwk", pair.privateKey)) as unknown as Record<
		string,
		string
	>;
	const kid = "portal-test-kid-1";
	const publicJwk = {
		kty: "OKP",
		crv: "Ed25519",
		kid,
		x: pub.x,
		alg: "EdDSA",
		use: "sig",
	};
	return {
		privateJwkRaw: JSON.stringify({ ...publicJwk, d: priv.d }),
		jwksPublicRaw: JSON.stringify({ keys: [publicJwk] }),
	};
}
