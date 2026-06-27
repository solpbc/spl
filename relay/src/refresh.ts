// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

// Control-plane HTTPS endpoint: re-issues a device token from a client's current
// (or <=30-day-expired) device token by verifying the relay's OWN prior Ed25519
// signature; no attestation, no client cert, no QR; blind and stateless.

import { DEVICE_TOKEN_TTL_SECONDS } from "./enroll";
import type { Env } from "./env";
import { json, readJson } from "./http";
import { log } from "./logging";
import { mintDeviceToken, verifyToken } from "./tokens";

const MAX_REFRESH_BYTES = 16 * 1024;
// 30-day reactive grace so a token that just lapsed can still re-issue without re-pairing.
const REFRESH_GRACE_SECONDS = 30 * 24 * 60 * 60;

interface RefreshBody {
	device_token?: string;
}

export async function handleTokenRefresh(request: Request, env: Env): Promise<Response> {
	if (!env.SIGNING_JWK) return json({ error: "relay not provisioned" }, 503);

	// No entitlement check here: this mirrors /enroll/device, and the dial-path
	// 4402 entitlement gate still applies, so refresh confers no entitlement bypass.
	// Per-endpoint rate limiting is a possible follow-up, not implemented in v1.
	const read = await readJson<RefreshBody>(request, MAX_REFRESH_BYTES);
	if (!read.ok) {
		if (read.reason === "too_large") return json({ error: "request body too large" }, 413);
		return json({ error: "device_token required" }, 400);
	}
	const body = read.value;
	if (typeof body.device_token !== "string" || !body.device_token) {
		return json({ error: "device_token required" }, 400);
	}

	const result = await verifyToken(body.device_token, {
		jwksRaw: env.JWKS_PUBLIC,
		expectedIssuer: env.ISSUER,
		expectedScope: "session.dial",
		graceSeconds: REFRESH_GRACE_SECONDS,
	});
	if (!result.ok) {
		if (result.reason === "jwks_unavailable") return json({ error: "relay not provisioned" }, 503);
		return json({ error: "invalid device_token", reason: result.reason }, 401);
	}

	const { instance_id, device_fp } = result.claims;
	const device_id = result.claims.sub.slice("device:".length);

	// Deliberately do NOT read or write `devices`: /session/dial verification
	// (instance-do.ts handleDial) authenticates by signature alone and never
	// consults `devices`, so a refreshed token dials with no row. Adding a row
	// here would only worsen the known unbounded device-row accrual (G6).
	// Statelessness is the point.
	const instance = await env.DB.prepare("SELECT revoked_at FROM instances WHERE instance_id = ?")
		.bind(instance_id)
		.first<{ revoked_at: number | null }>();
	if (!instance) return json({ error: "unknown instance_id" }, 404);
	if (instance.revoked_at !== null) return json({ error: "instance revoked" }, 403);

	const minted = await mintDeviceToken(env.SIGNING_JWK, {
		instance_id,
		device_id,
		device_fp: device_fp as string,
		issuer: env.ISSUER,
		ttlSeconds: DEVICE_TOKEN_TTL_SECONDS,
	});

	log({ event: "device_refresh", instance_id, jti: minted.jti });
	return json({
		device_token: minted.jwt,
		expires_at: new Date(minted.exp * 1000).toISOString(),
	});
}
