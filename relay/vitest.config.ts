// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import { defineConfig } from "vitest/config";

// Unit tests run under node — they exercise the pure crypto/verification
// helpers. Integration tests against Miniflare+DO run from the
// vitest.workers.*.config.ts projects (@cloudflare/vitest-plugin).
export default defineConfig({
	test: {
		include: ["test/**/*.test.ts"],
		environment: "node",
	},
});
