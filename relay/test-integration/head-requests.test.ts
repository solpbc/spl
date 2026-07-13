// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

// HEAD requests were 404ing on every route because the top-level dispatch
// gated on exact request.method matches with no HEAD handling.

import { SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";

describe("HEAD requests", () => {
	it.each([
		["/", 200],
		["/.well-known/jwks.json", 200],
		["/does-not-exist", 404],
	])("HEAD %s mirrors the GET status with no body", async (path, status) => {
		const getResponse = await SELF.fetch(`http://spl.test${path}`);
		const headResponse = await SELF.fetch(`http://spl.test${path}`, { method: "HEAD" });

		expect(getResponse.status).toBe(status);
		expect(headResponse.status).toBe(getResponse.status);
		expect(await headResponse.text()).toBe("");
		expect(headResponse.headers.get("content-type")).toBe(getResponse.headers.get("content-type"));
	});
});
