// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import { existsSync } from "node:fs";
import { cloudflareTest } from "@cloudflare/vitest-plugin";
import { configDefaults, defineConfig } from "vitest/config";

// Integration-style tests that run under Miniflare with the real InstanceDO
// + D1 bindings. Used for WS-pairing, cardinality, and pending-buffer
// behavior that can't be exercised with pure-node unit tests.
//
// A fresh Ed25519 signing keypair is minted at config-load time and wired
// into the Worker's bindings. This is test-only material — never used in
// any deployed relay. Tests can import the same keypair via
// `./test/test-keys.json` (written when this config loads).


// Miniflare keeps test D1 and Durable Object storage in SQLite under the OS temp dir and
// syncs it on every query. The storage is thrown away after each run, so on Linux keep it in memory.
if (process.platform === "linux" && existsSync("/dev/shm")) process.env.TMPDIR = "/dev/shm";
const { privateJwkRaw, jwksPublicRaw } = await genSigningKeypair();

export default defineConfig({
	plugins: [
		cloudflareTest({
			main: "./src/index.ts",
			remoteBindings: false,
			miniflare: {
				compatibilityDate: "2026-04-01",
				compatibilityFlags: ["nodejs_compat"],
				durableObjects: { INSTANCE: { className: "InstanceDO", useSQLite: true } },
				d1Databases: ["DB"],
				bindings: {
					ENVIRONMENT: "test",
					ISSUER: "spl.test",
					SIGNING_JWK: privateJwkRaw,
					JWKS_PUBLIC: jwksPublicRaw,
				},
			},
		}),
	],
	test: {
		include: ["test-integration/**/*.test.ts"],
		exclude: [
			...configDefaults.exclude,
			"**/*.gate.test.ts",
			"**/*.presence.test.ts",
			"**/owner-purge.test.ts",
			"**/owner-purge.contract.test.ts",
		],
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
