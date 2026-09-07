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
import { enrollmentIds } from "./enrollment-ids";
import type { Env } from "./env";
import { json, readJson } from "./http";
import { log } from "./logging";
import { mintDeviceToken, mintServiceToken } from "./tokens";

// 365 days / 60 days per proto/tokens.md §TTLs.
const SERVICE_TOKEN_TTL_SECONDS = 365 * 24 * 60 * 60;
export const DEVICE_TOKEN_TTL_SECONDS = 60 * 24 * 60 * 60;
const MAX_ENROLL_HOME_BYTES = 32 * 1024;
const MAX_ENROLL_DEVICE_BYTES = 16 * 1024;

interface EnrollHomeBody {
	instance_id?: string;
	ca_pubkey?: string;
}

interface EnrollDeviceBody {
	instance_id?: string;
	home_attestation?: string;
}

export async function handleEnrollHome(request: Request, env: Env): Promise<Response> {
	if (!env.SIGNING_JWK) return json({ error: "relay not provisioned" }, 503);

	const read = await readJson<EnrollHomeBody>(request, MAX_ENROLL_HOME_BYTES);
	if (!read.ok) {
		if (read.reason === "too_large") {
			log({ event: "enroll_rejected", route: "/enroll/home", reason: "body_too_large" });
			return json({ error: "request body too large" }, 413);
		}
		log({ event: "enroll_rejected", route: "/enroll/home", reason: "missing_fields" });
		return json({ error: "instance_id and ca_pubkey required" }, 400);
	}
	const body = read.value;
	if (
		typeof body.instance_id !== "string" ||
		!body.instance_id ||
		typeof body.ca_pubkey !== "string" ||
		!body.ca_pubkey
	) {
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
			log({ event: "enroll_rejected", route: "/enroll/home", reason: "ca_mismatch" });
			return json({ error: "ca_pubkey mismatch — rotation not supported in v1" }, 409);
		}
		await env.DB.prepare(
			"UPDATE instances SET ca_fp = ?, service_token_jti = ?, rotated_at = ? WHERE instance_id = ?",
		)
			.bind(caFp, minted.jti, minted.iat, body.instance_id)
			.run();
	} else {
		try {
			await env.DB.prepare(
				"INSERT INTO instances (instance_id, ca_fp, ca_pubkey_pem, created_at, service_token_jti) VALUES (?, ?, ?, ?, ?)",
			)
				.bind(body.instance_id, caFp, body.ca_pubkey, minted.iat, minted.jti)
				.run();
		} catch (err) {
			// instance_id PK can't collide here — we just SELECTed and found none.
			// A UNIQUE failure is therefore the ca_fp index: a different instance
			// already registered this CA. Reject without leaking the fp or the
			// other instance's id.
			const msg = err instanceof Error ? err.message : String(err);
			if (!/UNIQUE/.test(msg)) throw err;
			log({ event: "enroll_rejected", route: "/enroll/home", reason: "ca_fp_conflict" });
			return json({ error: "ca_pubkey already registered to another instance" }, 409);
		}
	}

	// Claim any grant that arrived before this enroll (grant-before-enroll
	// race; see migrations/0006_pending_grants.sql). Placed after both the
	// insert and re-enroll branches so the single claim covers both. A held
	// grant for an already-enrolled instance is rare but handled correctly.
	const pending = await env.DB.prepare(
		"SELECT entitled_until FROM pending_grants WHERE instance_id = ?",
	)
		.bind(body.instance_id)
		.first<{ entitled_until: number }>();
	if (pending) {
		await env.DB.prepare("UPDATE instances SET entitled_until = ? WHERE instance_id = ?")
			.bind(pending.entitled_until, body.instance_id)
			.run();
		await env.DB.prepare("DELETE FROM pending_grants WHERE instance_id = ?")
			.bind(body.instance_id)
			.run();
	}

	return json({
		service_token: minted.jwt,
		expires_at: new Date(minted.exp * 1000).toISOString(),
	});
}

export async function handleEnrollDevice(request: Request, env: Env): Promise<Response> {
	// Drain the accepted attestation window before a signing-key/issuer change
	// or the transition from row-backed issuance. Dial and refresh stay live.
	if (env.ENROLLMENT_PAUSED === "true") {
		return new Response(JSON.stringify({ error: "enrollment temporarily paused" }), {
			status: 503,
			headers: { "Content-Type": "application/json", "Retry-After": "360" },
		});
	}
	if (!env.SIGNING_JWK) return json({ error: "relay not provisioned" }, 503);

	const read = await readJson<EnrollDeviceBody>(request, MAX_ENROLL_DEVICE_BYTES);
	if (!read.ok) {
		if (read.reason === "too_large") {
			log({ event: "enroll_rejected", route: "/enroll/device", reason: "body_too_large" });
			return json({ error: "request body too large" }, 413);
		}
		log({ event: "enroll_rejected", route: "/enroll/device", reason: "missing_fields" });
		return json({ error: "instance_id and home_attestation required" }, 400);
	}
	const body = read.value;
	if (
		typeof body.instance_id !== "string" ||
		!body.instance_id ||
		typeof body.home_attestation !== "string" ||
		!body.home_attestation
	) {
		log({ event: "enroll_rejected", route: "/enroll/device", reason: "missing_fields" });
		return json({ error: "instance_id and home_attestation required" }, 400);
	}

	const instance = await env.DB.prepare(
		"SELECT ca_pubkey_pem, revoked_at FROM instances WHERE instance_id = ?",
	)
		.bind(body.instance_id)
		.first<{ ca_pubkey_pem: string; revoked_at: number | null }>();

	if (!instance) {
		log({ event: "enroll_rejected", route: "/enroll/device", reason: "unknown_instance" });
		return json({ error: "unknown instance_id" }, 404);
	}
	if (instance.revoked_at !== null) {
		log({ event: "enroll_rejected", route: "/enroll/device", reason: "instance_revoked" });
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
		});
		return json({ error: `attestation invalid: ${result.reason}` }, 401);
	}
	// Canonical verified claims, not the nondeterministic ES256 signature,
	// determine retries. No device or replay record is written.
	const ids = await enrollmentIds(result.claims);
	const minted = await mintDeviceToken(env.SIGNING_JWK, {
		instance_id: body.instance_id,
		device_id: ids.deviceId,
		device_fp: result.claims.device_fp,
		issuer: env.ISSUER,
		ttlSeconds: DEVICE_TOKEN_TTL_SECONDS,
		now: result.claims.iat,
		jti: ids.jti,
	});
	return json({
		device_token: minted.jwt,
		expires_at: new Date(minted.exp * 1000).toISOString(),
	});
}
