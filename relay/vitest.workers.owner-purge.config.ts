// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import { existsSync } from "node:fs";
import { cloudflareTest } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";


// Miniflare keeps test D1 and Durable Object storage in SQLite under the OS temp dir and
// syncs it on every query. The storage is thrown away after each run, so on Linux keep it in memory.
if (process.platform === "linux" && existsSync("/dev/shm")) process.env.TMPDIR = "/dev/shm";
export default defineConfig({
	plugins: [
		cloudflareTest({
			main: "./test-integration/support/purge-race-gate-worker.ts",
			remoteBindings: false,
			miniflare: {
				compatibilityDate: "2026-04-01",
				compatibilityFlags: ["nodejs_compat"],
				durableObjects: { INSTANCE: { className: "InstanceDO", useSQLite: true } },
				d1Databases: ["DB"],
				kvNamespaces: ["OWNER_PURGE_SIGNAL"],
				// A stand-in for the account portal. ORIGINATOR names its OwnerPurgeOrigin
				// entrypoint, as production does; ORIGIN_CONTROL reaches its default handler
				// so tests can say which operations the portal "sent".
				workers: [
					{
						name: "account-portal",
						modules: true,
						scriptPath: "./test-integration/support/originator-stand-in.js",
						compatibilityDate: "2026-04-01",
					},
				],
				serviceBindings: {
					ORIGINATOR: { name: "account-portal", entrypoint: "OwnerPurgeOrigin" },
					ORIGIN_CONTROL: "account-portal",
				},
				bindings: {
					ENVIRONMENT: "test",
					ISSUER: "spl.test",
					PURGE_SECRET: "test-purge-secret",
					GRANT_SECRET: "test-grant-secret",
					OWNER_PURGE_HMAC_KEY_V1: "owner-purge-v1-fixture-test-key",
					OWNER_PURGE_HMAC_KEY_V2: "owner-purge-v2-fixture-test-key",
				},
			},
		}),
	],
	test: {
		fileParallelism: false,
		include: [
			"test-integration/owner-purge.test.ts",
			"test-integration/owner-purge.contract.test.ts",
			"test-integration/owner-purge.signal.test.ts",
			"test-integration/owner-purge.origin.test.ts",
		],
		maxWorkers: 1,
		isolate: false,
	},
});
