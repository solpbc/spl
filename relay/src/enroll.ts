// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

// Control-plane enrollment endpoints. HTTPS-only; never reachable on the
// WebSocket upgrade path.
//
// POST /enroll/home   — home install → service token
// POST /enroll/device — paired mobile → device token
//
// See proto/tokens.md §issuance for the on-the-wire payloads and TTL rules.

import { fingerprintDer, importCaPublicKey, pemToDer, verifyAttestation } from "./attestation";
import type { Env } from "./env";
import { log } from "./logging";
import { mintDeviceToken, mintServiceToken } from "./tokens";
import { uuidv7 } from "./uuid";

// 365 days / 60 days per proto/tokens.md §TTLs.
const SERVICE_TOKEN_TTL_SECONDS = 365 * 24 * 60 * 60;
const DEVICE_TOKEN_TTL_SECONDS = 60 * 24 * 60 * 60;

interface EnrollHomeBody {
	instance_id?: string;
	ca_pubkey?: string;
	home_label?: string;
}

interface EnrollDeviceBody {
	instance_id?: string;
	home_attestation?: string;
}

export async function handleEnrollHome(request: Request, env: Env): Promise<Response> {
	if (!env.SIGNING_JWK) return json({ error: "relay not provisioned" }, 503);

	const body = (await readJson<EnrollHomeBody>(request)) ?? null;
	if (!body || !body.instance_id || !body.ca_pubkey) {
		log({ event: "enroll_rejected", route: "/enroll/home", reason: "missing_fields" });
		return json({ error: "instance_id and ca_pubkey required" }, 400);
	}

	// Reject obviously bad instance_id shapes to keep D1 primary-key safe.
	if (!/^[0-9a-fA-F-]{10,64}$/.test(body.instance_id)) {
		log({ event: "enroll_rejected", route: "/enroll/home", reason: "bad_instance_id" });
		return json({ error: "bad instance_id" }, 400);
	}

	// ca_pubkey must be an ECDSA-P256 SPKI public key — matches the mTLS
	// layer per proto/pairing.md §"the local CA". Reject at enroll so we
	// fail early, before a pair ceremony silently produces an unverifiable
	// attestation. This is also the only algorithm verifyAttestation() knows.
	const caKey = await importCaPublicKey(body.ca_pubkey);
	if (!caKey) {
		log({ event: "enroll_rejected", route: "/enroll/home", reason: "bad_ca_pubkey" });
		return json({ error: "ca_pubkey must be ECDSA-P256 SPKI PEM" }, 400);
	}
	const caDer = pemToDer(body.ca_pubkey);
	if (!caDer) {
		log({ event: "enroll_rejected", route: "/enroll/home", reason: "bad_ca_pubkey" });
		return json({ error: "ca_pubkey must be PEM" }, 400);
	}
	const caFp = await fingerprintDer(caDer);

	const minted = await mintServiceToken(env.SIGNING_JWK, {
		instance_id: body.instance_id,
		ca_fp: caFp,
		issuer: env.ISSUER,
		ttlSeconds: SERVICE_TOKEN_TTL_SECONDS,
	});

	// Idempotent: same instance_id rotates the token. Preserves ca_pubkey
	// only if it matches what we already have — otherwise the call is a
	// takeover attempt and we reject. Home-side CA rotation is a separate
	// (post-MVP) flow.
	const existing = await env.DB.prepare("SELECT ca_pubkey_pem FROM instances WHERE instance_id = ?")
		.bind(body.instance_id)
		.first<{ ca_pubkey_pem: string }>();

	if (existing) {
		if (existing.ca_pubkey_pem.trim() !== body.ca_pubkey.trim()) {
			log({
				event: "enroll_rejected",
				route: "/enroll/home",
				reason: "ca_mismatch",
				instance_id: body.instance_id,
			});
			return json({ error: "ca_pubkey mismatch — rotation not supported in v1" }, 409);
		}
		await env.DB.prepare(
			"UPDATE instances SET ca_fp = ?, home_label = ?, service_token_jti = ?, rotated_at = ? WHERE instance_id = ?",
		)
			.bind(caFp, body.home_label ?? null, minted.jti, minted.iat, body.instance_id)
			.run();
		log({ event: "enroll_home_rotate", instance_id: body.instance_id, jti: minted.jti });
	} else {
		await env.DB.prepare(
			"INSERT INTO instances (instance_id, ca_fp, ca_pubkey_pem, home_label, created_at, service_token_jti) VALUES (?, ?, ?, ?, ?, ?)",
		)
			.bind(body.instance_id, caFp, body.ca_pubkey, body.home_label ?? null, minted.iat, minted.jti)
			.run();
		log({ event: "enroll_home", instance_id: body.instance_id, jti: minted.jti });
	}

	return json({
		service_token: minted.jwt,
		expires_at: new Date(minted.exp * 1000).toISOString(),
	});
}

export async function handleEnrollDevice(request: Request, env: Env): Promise<Response> {
	if (!env.SIGNING_JWK) return json({ error: "relay not provisioned" }, 503);

	const body = (await readJson<EnrollDeviceBody>(request)) ?? null;
	if (!body || !body.instance_id || !body.home_attestation) {
		log({
			event: "enroll_rejected",
			route: "/enroll/device",
			reason: "missing_fields",
		});
		return json({ error: "instance_id and home_attestation required" }, 400);
	}

	const instance = await env.DB.prepare(
		"SELECT ca_pubkey_pem, revoked_at FROM instances WHERE instance_id = ?",
	)
		.bind(body.instance_id)
		.first<{ ca_pubkey_pem: string; revoked_at: number | null }>();

	if (!instance) {
		log({
			event: "enroll_rejected",
			route: "/enroll/device",
			reason: "unknown_instance",
			instance_id: body.instance_id,
		});
		return json({ error: "unknown instance_id" }, 404);
	}
	if (instance.revoked_at !== null) {
		log({
			event: "enroll_rejected",
			route: "/enroll/device",
			reason: "instance_revoked",
			instance_id: body.instance_id,
		});
		return json({ error: "instance revoked" }, 403);
	}

	const result = await verifyAttestation({
		attestation: body.home_attestation,
		caPubkeyPem: instance.ca_pubkey_pem,
		expectedInstanceId: body.instance_id,
	});
	if (!result.ok) {
		log({
			event: "enroll_rejected",
			route: "/enroll/device",
			reason: `attestation_${result.reason}`,
			instance_id: body.instance_id,
		});
		return json({ error: `attestation invalid: ${result.reason}` }, 401);
	}
	const deviceFp = result.claims.device_fp;

	// Each enroll generates a fresh device_id (the token's sub). We persist
	// it so a retried request whose response was lost can re-mint the
	// byte-identical device token instead of failing replay defense.
	const device_id = uuidv7();
	const minted = await mintDeviceToken(env.SIGNING_JWK, {
		instance_id: body.instance_id,
		device_id,
		device_fp: deviceFp,
		issuer: env.ISSUER,
		ttlSeconds: DEVICE_TOKEN_TTL_SECONDS,
	});

	try {
		await env.DB.prepare(
			"INSERT INTO devices (device_jti, device_id, instance_id, device_fp, device_label, created_at, attestation_jti) VALUES (?, ?, ?, ?, ?, ?, ?)",
		)
			.bind(minted.jti, device_id, body.instance_id, deviceFp, null, minted.iat, result.claims.jti)
			.run();
	} catch (err) {
		// UNIQUE(attestation_jti) means this attestation was already consumed.
		// If a prior *successful* enroll of the same (instance_id, device_fp)
		// consumed it, this is a retry whose response was lost — re-mint the
		// byte-identical device token from the stored row (idempotent).
		// Anything else (different instance/fp, or a pre-migration row with no
		// device_id to reconstruct sub from) is a genuine replay → 409.
		const msg = err instanceof Error ? err.message : String(err);
		if (!/UNIQUE/.test(msg)) throw err;

		const existing = await env.DB.prepare(
			"SELECT device_jti, device_id, instance_id, device_fp, created_at FROM devices WHERE attestation_jti = ?",
		)
			.bind(result.claims.jti)
			.first<{
				device_jti: string;
				device_id: string | null;
				instance_id: string;
				device_fp: string;
				created_at: number;
			}>();

		if (
			existing &&
			existing.device_id !== null &&
			existing.instance_id === body.instance_id &&
			existing.device_fp === deviceFp
		) {
			const reminted = await mintDeviceToken(env.SIGNING_JWK, {
				instance_id: existing.instance_id,
				device_id: existing.device_id,
				device_fp: existing.device_fp,
				issuer: env.ISSUER,
				ttlSeconds: DEVICE_TOKEN_TTL_SECONDS,
				now: existing.created_at,
				jti: existing.device_jti,
			});
			log({
				event: "enroll_device_remint",
				instance_id: body.instance_id,
				jti: existing.device_jti,
			});
			return json({
				device_token: reminted.jwt,
				expires_at: new Date(reminted.exp * 1000).toISOString(),
			});
		}

		log({
			event: "enroll_rejected",
			route: "/enroll/device",
			reason: "attestation_replay",
			instance_id: body.instance_id,
			jti: result.claims.jti,
		});
		return json({ error: "attestation already consumed" }, 409);
	}

	log({
		event: "enroll_device",
		instance_id: body.instance_id,
		jti: minted.jti,
	});

	return json({
		device_token: minted.jwt,
		expires_at: new Date(minted.exp * 1000).toISOString(),
	});
}

async function readJson<T>(request: Request): Promise<T | null> {
	const ct = request.headers.get("content-type") ?? "";
	if (!ct.includes("application/json")) return null;
	try {
		return (await request.json()) as T;
	} catch {
		return null;
	}
}

function json(body: unknown, status = 200): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "content-type": "application/json; charset=utf-8" },
	});
}
