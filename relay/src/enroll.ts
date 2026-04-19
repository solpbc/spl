// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

// Control-plane enrollment endpoints. HTTPS-only; never reachable on the
// WebSocket upgrade path.
//
// POST /enroll/home   — home install → account token
// POST /enroll/device — paired mobile → device token
//
// See proto/tokens.md §issuance for the on-the-wire payloads and TTL rules.

import { fingerprintDer, importCaPublicKey, pemToDer, verifyAttestation } from "./attestation";
import type { Env } from "./env";
import { log } from "./logging";
import { mintAccountToken, mintDeviceToken } from "./tokens";
import { uuidv7 } from "./uuid";

// 365 days / 60 days per proto/tokens.md §TTLs.
const ACCOUNT_TOKEN_TTL_SECONDS = 365 * 24 * 60 * 60;
const DEVICE_TOKEN_TTL_SECONDS = 60 * 24 * 60 * 60;

interface EnrollHomeBody {
	instance_id?: string;
	ca_pubkey?: string;
	home_label?: string;
}

interface EnrollDeviceBody {
	instance_id?: string;
	client_cert?: string;
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

	const minted = await mintAccountToken(env.SIGNING_JWK, {
		instance_id: body.instance_id,
		ca_fp: caFp,
		issuer: env.ISSUER,
		ttlSeconds: ACCOUNT_TOKEN_TTL_SECONDS,
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
			"UPDATE instances SET ca_fp = ?, home_label = ?, account_token_jti = ?, rotated_at = ? WHERE instance_id = ?",
		)
			.bind(caFp, body.home_label ?? null, minted.jti, minted.iat, body.instance_id)
			.run();
		log({ event: "enroll_home_rotate", instance_id: body.instance_id, jti: minted.jti });
	} else {
		await env.DB.prepare(
			"INSERT INTO instances (instance_id, ca_fp, ca_pubkey_pem, home_label, created_at, account_token_jti) VALUES (?, ?, ?, ?, ?, ?)",
		)
			.bind(body.instance_id, caFp, body.ca_pubkey, body.home_label ?? null, minted.iat, minted.jti)
			.run();
		log({ event: "enroll_home", instance_id: body.instance_id, jti: minted.jti });
	}

	return json({
		account_token: minted.jwt,
		expires_at: new Date(minted.exp * 1000).toISOString(),
	});
}

export async function handleEnrollDevice(request: Request, env: Env): Promise<Response> {
	if (!env.SIGNING_JWK) return json({ error: "relay not provisioned" }, 503);

	const body = (await readJson<EnrollDeviceBody>(request)) ?? null;
	if (!body || !body.instance_id || !body.client_cert || !body.home_attestation) {
		log({
			event: "enroll_rejected",
			route: "/enroll/device",
			reason: "missing_fields",
		});
		return json({ error: "instance_id, client_cert, and home_attestation required" }, 400);
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

	const certDer = pemToDer(body.client_cert);
	if (!certDer) {
		log({
			event: "enroll_rejected",
			route: "/enroll/device",
			reason: "bad_client_cert",
			instance_id: body.instance_id,
		});
		return json({ error: "client_cert must be PEM" }, 400);
	}
	const deviceFp = await fingerprintDer(certDer);

	const result = await verifyAttestation({
		attestation: body.home_attestation,
		caPubkeyPem: instance.ca_pubkey_pem,
		expectedInstanceId: body.instance_id,
		expectedDeviceFp: deviceFp,
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

	// Single-use attestation: refuse if this jti has already been consumed
	// for this instance. INSERT with jti as part of the PK gives us atomic
	// replay defense.
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
			"INSERT INTO devices (device_jti, instance_id, device_fp, device_label, created_at, attestation_jti) VALUES (?, ?, ?, ?, ?, ?)",
		)
			.bind(minted.jti, body.instance_id, deviceFp, null, minted.iat, result.claims.jti)
			.run();
	} catch (err) {
		// UNIQUE constraint on attestation_jti prevents replay.
		const msg = err instanceof Error ? err.message : String(err);
		if (/UNIQUE/.test(msg)) {
			log({
				event: "enroll_rejected",
				route: "/enroll/device",
				reason: "attestation_replay",
				instance_id: body.instance_id,
				jti: result.claims.jti,
			});
			return json({ error: "attestation already consumed" }, 409);
		}
		throw err;
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
