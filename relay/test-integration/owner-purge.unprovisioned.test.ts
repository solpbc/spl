// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import { SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";

describe("owner-purge v1 unprovisioned", () => {
	it("returns 503 from submit and confirmation when owner-purge secrets are unset", async () => {
		// Submit and confirm are gated on arriving via the internal caller
		// host before they are gated on provisioning — see purge.ts
		// PURGE_INTERNAL_HOST. Reached via that host, unprovisioned still 503s.
		const submit = await SELF.fetch("http://relay.internal/internal/deletion/purge", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({}),
		});
		expect(submit.status).toBe(503);
		expect(await submit.json()).toEqual({ error: "relay not provisioned" });

		const confirm = await SELF.fetch("http://relay.internal/internal/deletion/purge/confirm", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({}),
		});
		expect(confirm.status).toBe(503);
		expect(await confirm.json()).toEqual({ error: "relay not provisioned" });

		const nonce = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";

		// Precedence before unprovisioned check:
		// 1. Method failure -> 405 before unprovisioned
		const postReadiness = await SELF.fetch("http://spl.test/internal/deletion/purge/ready", {
			method: "POST",
			headers: { "x-owner-purge-readiness-nonce": nonce },
		});
		expect(postReadiness.status).toBe(405);
		expect(postReadiness.headers.get("allow")).toBe("GET, HEAD");
		expect(postReadiness.headers.get("cache-control")).toBe("no-store");
		expect(await postReadiness.text()).toBe("");

		// 2. Origin failure -> 403 before unprovisioned
		const originReadiness = await SELF.fetch("http://spl.test/internal/deletion/purge/ready", {
			headers: {
				Origin: "https://browser.example.test",
				"x-owner-purge-readiness-nonce": nonce,
			},
		});
		expect(originReadiness.status).toBe(403);
		expect(originReadiness.headers.get("cache-control")).toBe("no-store");
		expect(await originReadiness.text()).toBe("");

		// 3. Nonce failure -> 400 before unprovisioned
		const badNonceReadiness = await SELF.fetch("http://spl.test/internal/deletion/purge/ready", {
			headers: { "x-owner-purge-readiness-nonce": "invalid-nonce" },
		});
		expect(badNonceReadiness.status).toBe(400);
		expect(badNonceReadiness.headers.get("cache-control")).toBe("no-store");
		expect(await badNonceReadiness.text()).toBe("");

		// 4. Unprovisioned readiness probe -> 503
		const readiness = await SELF.fetch("http://spl.test/internal/deletion/purge/ready", {
			headers: { "x-owner-purge-readiness-nonce": nonce },
		});
		expect(readiness.status).toBe(503);
		expect(readiness.headers.get("cache-control")).toBe("no-store");
		expect(await readiness.text()).toBe("");

		const readinessHead = await SELF.fetch("http://spl.test/internal/deletion/purge/ready", {
			method: "HEAD",
			headers: { "x-owner-purge-readiness-nonce": nonce },
		});
		expect(readinessHead.status).toBe(503);
		expect(readinessHead.headers.get("cache-control")).toBe("no-store");
		expect(await readinessHead.text()).toBe("");
	});
});
