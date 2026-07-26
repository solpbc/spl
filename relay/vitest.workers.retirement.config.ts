// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import { defineWorkersConfig } from "@cloudflare/vitest-pool-workers/config";
import { genSigningKeypair } from "./vitest.keys";

// Retirement runs under a dedicated gate-off config so the same shared smoke
// file is exercised both with and without the entitlement admission read.

const { privateJwkRaw, jwksPublicRaw } = await genSigningKeypair();

export default defineWorkersConfig({
	test: {
		include: ["test-integration/retirement.gate.test.ts"],
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
						SIGNING_JWK: privateJwkRaw,
						JWKS_PUBLIC: jwksPublicRaw,
						GRANT_SECRET: "test-grant-secret",
					},
				},
			},
		},
	},
});
