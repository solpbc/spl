// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import { DEVICE_TOKEN_TTL_SECONDS } from "./enroll";
import type { Env } from "./env";
import { json, readJson } from "./http";
import { mintInstanceToken, verifyToken } from "./tokens";

// Only the home service can acquire shared instance access here. Devices get
// this capability from their authenticated home, never its service token.
// A home that also renews its devices declares it with this header, and from
// then on /token/refresh renews nothing for the instance (refresh.ts).
export const DEVICE_RENEWAL_HEADER = "SPL-Device-Renewal";
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
		"SELECT ca_fp, revoked_at, service_token_jti, proof_iat, device_renewal_at FROM instances WHERE instance_id = ?",
	)
		.bind(instance_id)
		.first<{
			ca_fp: string;
			revoked_at: number | null;
			service_token_jti: string;
			proof_iat: number | null;
			device_renewal_at: number | null;
		}>();
	if (!instance) return json({ error: "unknown instance_id" }, 404);
	if (instance.revoked_at !== null) return json({ error: "instance revoked" }, 403);
	if (instance.ca_fp !== ca_fp) return json({ error: "invalid service_token" }, 401);
	// A proven instance honors only its newest service token (enroll.ts
	// serviceTokenSuperseded; proto/tokens.md § proof of possession).
	if (instance.proof_iat !== null && instance.service_token_jti !== verified.claims.jti)
		return json({ error: "invalid service_token" }, 401);
	// The latest call decides, so a home moved back to a version that does not
	// renew its devices gets relay renewal back for them.
	const renewsDevices = request.headers.get(DEVICE_RENEWAL_HEADER) === "home";
	if (renewsDevices !== (instance.device_renewal_at !== null)) {
		await env.DB.prepare("UPDATE instances SET device_renewal_at = ? WHERE instance_id = ?")
			.bind(renewsDevices ? Math.floor(Date.now() / 1000) : null, instance_id)
			.run();
	}
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
