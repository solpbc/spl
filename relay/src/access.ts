// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import { DEVICE_TOKEN_TTL_SECONDS } from "./enroll";
import type { Env } from "./env";
import { json, readJson } from "./http";
import { mintInstanceToken, verifyToken } from "./tokens";

// Only the home service can acquire shared instance access here. Devices get
// this capability from their authenticated home, never its service token.
export async function handleTokenAccess(request: Request, env: Env): Promise<Response> {
	if (!env.SIGNING_JWK) return json({ error: "relay not provisioned" }, 503);
	const read = await readJson<{ service_token?: string }>(request, 16 * 1024);
	if (!read.ok) return json({ error: "invalid request" }, read.reason === "too_large" ? 413 : 400);
	const body = read.value;
	if (
		!body ||
		typeof body !== "object" ||
		Array.isArray(body) ||
		Object.keys(body).some((key) => key !== "service_token") ||
		typeof body.service_token !== "string" ||
		!body.service_token
	)
		return json({ error: "service_token required" }, 400);
	const verified = await verifyToken(body.service_token, {
		jwksRaw: env.JWKS_PUBLIC,
		expectedIssuer: env.ISSUER,
		expectedScope: "session.listen",
	});
	if (!verified.ok)
		return json(
			{ error: "invalid service_token" },
			verified.reason === "jwks_unavailable" ? 503 : 401,
		);
	const { instance_id, ca_fp } = verified.claims;
	if (verified.claims.sub !== `home:${instance_id}`)
		return json({ error: "invalid service_token" }, 401);
	const instance = await env.DB.prepare(
		"SELECT ca_fp, revoked_at FROM instances WHERE instance_id = ?",
	)
		.bind(instance_id)
		.first<{ ca_fp: string; revoked_at: number | null }>();
	if (!instance) return json({ error: "unknown instance_id" }, 404);
	if (instance.revoked_at !== null) return json({ error: "instance revoked" }, 403);
	if (instance.ca_fp !== ca_fp) return json({ error: "invalid service_token" }, 401);
	const minted = await mintInstanceToken(env.SIGNING_JWK, {
		instance_id,
		issuer: env.ISSUER,
		ttlSeconds: DEVICE_TOKEN_TTL_SECONDS,
	});
	return json({
		protocol_version: 2,
		device_token: minted.jwt,
		expires_at: new Date(minted.exp * 1000).toISOString(),
	});
}
