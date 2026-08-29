// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import { SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";

describe("owner-purge v1 unprovisioned", () => {
	it("returns 503 from submit and confirmation when owner-purge secrets are unset", async () => {
		const submit = await SELF.fetch("http://spl.test/internal/deletion/purge", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({}),
		});
		expect(submit.status).toBe(503);
		expect(await submit.json()).toEqual({ error: "relay not provisioned" });

		const confirm = await SELF.fetch("http://spl.test/internal/deletion/purge/confirm", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({}),
		});
		expect(confirm.status).toBe(503);
		expect(await confirm.json()).toEqual({ error: "relay not provisioned" });
	});
});
