// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import { defineWorkersConfig } from "@cloudflare/vitest-pool-workers/config";
import { configDefaults } from "vitest/config";
import { genSigningKeypair } from "./vitest.keys";

// Integration-style tests that run under Miniflare with the real InstanceDO
// + D1 bindings. Used for WS-pairing, cardinality, and pending-buffer
// behavior that can't be exercised with pure-node unit tests.
//
// A fresh Ed25519 signing keypair is minted at config-load time and wired
// into the Worker's bindings. This is test-only material — never used in
// any deployed relay. Tests can import the same keypair via
// `./test/test-keys.json` (written when this config loads).

const { privateJwkRaw, jwksPublicRaw } = await genSigningKeypair();

export default defineWorkersConfig({
	test: {
		include: ["test-integration/**/*.test.ts"],
		exclude: [...configDefaults.exclude, "**/*.gate.test.ts", "**/*.presence.test.ts"],
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
					durableObjects: { INSTANCE: { className: "InstanceDO", useSQLite: true } },
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
