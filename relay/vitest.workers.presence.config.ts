// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import { defineWorkersConfig } from "@cloudflare/vitest-pool-workers/config";
import { genSigningKeypair } from "./vitest.keys";

// Presence-hold integration tests run under a dedicated config because Worker
// and DO env bindings are load-time values in this test harness.

const { privateJwkRaw, jwksPublicRaw } = await genSigningKeypair();

export default defineWorkersConfig({
	test: {
		include: ["test-integration/**/*.presence.test.ts"],
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
						PRESENCE_HOLD_ENABLED: "true",
					},
				},
			},
		},
	},
});
