// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

// This file intentionally runs in the base Workers configuration, where
// portal-purge secrets are absent. Provisioned behavior belongs to the
// dedicated *.purge.test.ts configuration.

import { SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";

describe("portal purge unprovisioned", () => {
	it("returns 503 from submit and confirmation when purge secrets are unset", async () => {
		const submit = await SELF.fetch("http://spl.test/internal/purge", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({ envelope: "ignored" }),
		});
		const confirm = await SELF.fetch("http://spl.test/internal/purge/confirm", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({ envelope: "ignored" }),
		});

		expect(submit.status).toBe(503);
		expect(confirm.status).toBe(503);
	});
});
