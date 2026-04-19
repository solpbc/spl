// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import { defineWorkersConfig } from "@cloudflare/vitest-pool-workers/config";

// Integration-style tests that run under Miniflare with the real InstanceDO
// + D1 bindings. Used for WS-pairing, cardinality, and pending-buffer
// behavior that can't be exercised with pure-node unit tests.
//
// A fresh Ed25519 signing keypair is minted at config-load time and wired
// into the Worker's bindings. This is test-only material — never used in
// staging or prod. Tests can import the same keypair via
// `./test/test-keys.json` (written when this config loads).

const { privateJwkRaw, jwksPublicRaw } = await genSigningKeypair();

export default defineWorkersConfig({
	test: {
		include: ["test-integration/**/*.test.ts"],
		poolOptions: {
			workers: {
				main: "./src/index.ts",
				// Per-test storage snapshots don't play nicely with DO SQLite
				// classes — the snapshot/restore cycle can't always find the DO
				// instance to pop its state. The test suite handles its own
				// cleanup via beforeEach() deletes against D1, so we trade the
				// framework's guard rail for a known one.
				isolatedStorage: false,
				miniflare: {
					compatibilityDate: "2026-04-01",
					compatibilityFlags: ["nodejs_compat"],
					durableObjects: { INSTANCE: { className: "InstanceDO" } },
					d1Databases: ["DB"],
					bindings: {
						ENVIRONMENT: "test",
						ISSUER: "spl.test",
						SIGNING_JWK: privateJwkRaw,
						JWKS_PUBLIC: jwksPublicRaw,
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
	const kid = "test-kid-1";
	const publicJwk = {
		kty: "OKP",
		crv: "Ed25519",
		kid,
		x: pub.x,
		alg: "EdDSA",
		use: "sig",
	};
	const privateJwk = { ...publicJwk, d: priv.d };
	return {
		privateJwkRaw: JSON.stringify(privateJwk),
		jwksPublicRaw: JSON.stringify({ keys: [publicJwk] }),
	};
}
