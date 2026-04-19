// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import { defineConfig } from "vitest/config";

// Unit tests run under node — they exercise the pure crypto/verification
// helpers. Integration tests against Miniflare+DO live in a separate project
// once we wire them up (see @cloudflare/vitest-pool-workers).
export default defineConfig({
	test: {
		include: ["test/**/*.test.ts"],
		environment: "node",
	},
});
