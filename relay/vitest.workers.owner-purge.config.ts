// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import { defineWorkersConfig } from "@cloudflare/vitest-pool-workers/config";

export default defineWorkersConfig({
	test: {
		include: ["test-integration/**/owner-purge.test.ts"],
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
						OWNER_PURGE_HMAC_KEY_V1: "owner-purge-v1-fixture-test-key",
						OWNER_PURGE_HMAC_KEY_V2: "owner-purge-v2-fixture-test-key",
					},
				},
			},
		},
	},
});
