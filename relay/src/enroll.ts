// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

// Control-plane enrollment endpoints. HTTPS-only; never reachable on the
// WebSocket upgrade path.
//
// POST /enroll/home   — home install → service token (CA-signed proof of possession)
// POST /enroll/device — paired mobile → device token
//
// See proto/tokens.md §issuance for the on-the-wire payloads and TTL rules.

import {
	deriveJid,
	fingerprintDer,
	importCaPublicKey,
	pemToDer,
	verifyAttestation,
	verifyEnrollProof,
} from "./attestation";
import { enrollmentIds } from "./enrollment-ids";
import type { Env } from "./env";
import { json, readJson } from "./http";
import { log } from "./logging";
import { mintDeviceToken, mintInstanceToken, mintServiceToken } from "./tokens";

// 365 days / 60 days per proto/tokens.md §TTLs.
const SERVICE_TOKEN_TTL_SECONDS = 365 * 24 * 60 * 60;
export const DEVICE_TOKEN_TTL_SECONDS = 60 * 24 * 60 * 60;
const MAX_ENROLL_HOME_BYTES = 32 * 1024;
const MAX_ENROLL_DEVICE_BYTES = 16 * 1024;

interface EnrollHomeBody {
	instance_id?: string;
	ca_pubkey?: string;
	mode?: unknown;
	proof?: unknown;
}

interface EnrollDeviceBody {
	protocol_version?: number;
	instance_id?: string;
	home_attestation?: string;
}

export async function handleEnrollHome(request: Request, env: Env): Promise<Response> {
	if (!env.SIGNING_JWK) return json({ error: "relay not provisioned" }, 503);

	const read = await readJson<EnrollHomeBody>(request, MAX_ENROLL_HOME_BYTES);
	if (!read.ok) {
		if (read.reason === "too_large") {
			log({
				event: "enroll_rejected",
				route: "/enroll/home",
				reason: "body_too_large",
			});
			return json({ error: "request body too large" }, 413);
		}
		log({
			event: "enroll_rejected",
			route: "/enroll/home",
			reason: "missing_fields",
		});
		return json({ error: "instance_id and ca_pubkey required" }, 400);
	}
	const body = read.value;
	if (!body || typeof body !== "object" || Array.isArray(body))
		return json({ error: "invalid request" }, 400);
	if (
		typeof body.instance_id !== "string" ||
		!body.instance_id ||
		typeof body.ca_pubkey !== "string" ||
		!body.ca_pubkey
	) {
		log({
			event: "enroll_rejected",
			route: "/enroll/home",
			reason: "missing_fields",
		});
		return json({ error: "instance_id and ca_pubkey required" }, 400);
	}

	// `mode: "renew"` marks an unattended renewal by a home that is already
	// enrolled. It rotates an existing record exactly like a repeat enroll,
	// but never creates one: a record the owner deleted stays deleted until
	// the owner enables the link again.
	if (body.mode !== undefined && body.mode !== "renew") {
		log({
			event: "enroll_rejected",
			route: "/enroll/home",
			reason: "bad_mode",
		});
		return json({ error: "unsupported mode" }, 400);
	}
	const renewOnly = body.mode === "renew";

	// Reject obviously bad instance_id shapes to keep D1 primary-key safe.
	if (!/^[0-9a-fA-F-]{10,64}$/.test(body.instance_id)) {
		log({
			event: "enroll_rejected",
			route: "/enroll/home",
			reason: "bad_instance_id",
		});
		return json({ error: "bad instance_id" }, 400);
	}

	// ca_pubkey must be an ECDSA-P256 SPKI public key — matches the mTLS
	// layer per proto/pairing.md §"the local CA". Reject at enroll so we
	// fail early, before a pair ceremony silently produces an unverifiable
	// attestation. This is also the only algorithm verifyAttestation() knows.
	const caKey = await importCaPublicKey(body.ca_pubkey);
	if (!caKey) {
		log({
			event: "enroll_rejected",
			route: "/enroll/home",
			reason: "bad_ca_pubkey",
		});
		return json({ error: "ca_pubkey must be ECDSA-P256 SPKI PEM" }, 400);
	}
	const caDer = pemToDer(body.ca_pubkey);
	if (!caDer) {
		log({
			event: "enroll_rejected",
			route: "/enroll/home",
			reason: "bad_ca_pubkey",
		});
		return json({ error: "ca_pubkey must be PEM" }, 400);
	}
	const caFp = await fingerprintDer(caDer);

	// Proof of possession of the CA private key (proto/tokens.md § proof of
	// possession). The CA public key is not a secret: every paired device holds
	// it and the home presents it in its TLS chain. So a call without a proof
	// is accepted only for an instance that has never proven possession, and
	// only while the deployment allows unsigned calls at all.
	let proofIat: number | null = null;
	if (body.proof !== undefined) {
		if (typeof body.proof !== "string" || !body.proof) {
			log({ event: "enroll_rejected", route: "/enroll/home", reason: "proof_malformed" });
			return json({ error: "proof invalid: malformed" }, 401);
		}
		const proof = await verifyEnrollProof({
			attestation: body.proof,
			caPubkeyPem: body.ca_pubkey,
			expectedInstanceId: body.instance_id,
			expectedAudience: new URL(request.url).host,
		});
		if (!proof.ok) {
			log({ event: "enroll_rejected", route: "/enroll/home", reason: `proof_${proof.reason}` });
			return json({ error: `proof invalid: ${proof.reason}` }, 401);
		}
		proofIat = proof.claims.iat;
	} else if (env.HOME_PROOF_REQUIRED === "true") {
		log({ event: "enroll_rejected", route: "/enroll/home", reason: "proof_required" });
		return json({ error: "proof_required" }, 401);
	}

	const minted = await mintServiceToken(env.SIGNING_JWK, {
		instance_id: body.instance_id,
		ca_fp: caFp,
		issuer: env.ISSUER,
		ttlSeconds: SERVICE_TOKEN_TTL_SECONDS,
		proven: proofIat !== null,
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
			});
			return json({ error: "ca_pubkey mismatch — rotation not supported in v1" }, 409);
		}
		// Each guard sits in the UPDATE itself, so a proof landing between the
		// read above and this write is still honored. An unsigned call rotates
		// only an instance that has never proven possession; a proof rotates
		// only if it is newer than the last accepted one, which makes each
		// proof single use.
		const rotated =
			proofIat === null
				? await env.DB.prepare(
						"UPDATE instances SET ca_fp = ?, service_token_jti = ?, rotated_at = ? WHERE instance_id = ? AND proof_iat IS NULL",
					)
						.bind(caFp, minted.jti, minted.iat, body.instance_id)
						.run()
				: await env.DB.prepare(
						"UPDATE instances SET ca_fp = ?, service_token_jti = ?, rotated_at = ?, proof_iat = ? WHERE instance_id = ? AND (proof_iat IS NULL OR proof_iat < ?)",
					)
						.bind(caFp, minted.jti, minted.iat, proofIat, body.instance_id, proofIat)
						.run();
		if (rotated.meta.changes !== 1) {
			const reason = proofIat === null ? "proof_required" : "proof_replay";
			log({ event: "enroll_rejected", route: "/enroll/home", reason });
			return json({ error: reason }, 401);
		}
	} else if (renewOnly) {
		log({
			event: "enroll_rejected",
			route: "/enroll/home",
			reason: "not_enrolled",
		});
		return json({ error: "not_enrolled" }, 404);
	} else {
		// A first enroll that proves possession must also be the jid of the key
		// it proves (proto/identity.md). Otherwise a device that knows another
		// home's instance id could claim it with its own key while no row
		// exists, and lock the real home out with ca_mismatch.
		if (proofIat !== null && body.instance_id !== (await deriveJid(caKey))) {
			log({ event: "enroll_rejected", route: "/enroll/home", reason: "instance_not_jid" });
			return json({ error: "instance_id is not the jid of ca_pubkey" }, 400);
		}
		try {
			await env.DB.prepare(
				"INSERT INTO instances (instance_id, ca_fp, ca_pubkey_pem, created_at, service_token_jti, proof_iat) VALUES (?, ?, ?, ?, ?, ?)",
			)
				.bind(body.instance_id, caFp, body.ca_pubkey, minted.iat, minted.jti, proofIat)
				.run();
		} catch (err) {
			// instance_id PK can't collide here — we just SELECTed and found none.
			// A UNIQUE failure is therefore the ca_fp index: a different instance
			// already registered this CA. Reject without leaking the fp or the
			// other instance's id.
			const msg = err instanceof Error ? err.message : String(err);
			if (!/UNIQUE/.test(msg)) throw err;
			log({
				event: "enroll_rejected",
				route: "/enroll/home",
				reason: "ca_fp_conflict",
			});
			return json({ error: "ca_pubkey already registered to another instance" }, 409);
		}
	}

	// Claim any grant that arrived before this enroll (grant-before-enroll
	// race; see migrations/0006_pending_grants.sql). Placed after both the
	// insert and re-enroll branches so the single claim covers both. A held
	// grant for an already-enrolled instance is rare but handled correctly.
	// The token is already committed, so a failed claim must not lose the
	// response: the grant stays pending and the next enroll claims it.
	try {
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
	} catch {
		log({ event: "internal_error", reason: "pending_grant_claim_failed" });
	}

	return json({
		service_token: minted.jwt,
		expires_at: new Date(minted.exp * 1000).toISOString(),
	});
}

// A service token is superseded when its instance has proven possession of
// its CA key and has since been issued a different token. Before the first
// proof every unexpired service token for the instance is honored, as it
// always was; from it on, only the newest. See proto/tokens.md § proof of
// possession.
export async function serviceTokenSuperseded(
	db: D1Database,
	instanceId: string,
	jti: string,
): Promise<boolean> {
	const row = await db
		.prepare("SELECT service_token_jti, proof_iat FROM instances WHERE instance_id = ?")
		.bind(instanceId)
		.first<{ service_token_jti: string; proof_iat: number | null }>();
	return row !== null && row.proof_iat !== null && row.service_token_jti !== jti;
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
			log({
				event: "enroll_rejected",
				route: "/enroll/device",
				reason: "body_too_large",
			});
			return json({ error: "request body too large" }, 413);
		}
		log({
			event: "enroll_rejected",
			route: "/enroll/device",
			reason: "missing_fields",
		});
		return json({ error: "instance_id and home_attestation required" }, 400);
	}
	const body = read.value;
	if (!body || typeof body !== "object" || Array.isArray(body))
		return json({ error: "invalid request" }, 400);
	if (body.protocol_version !== undefined && body.protocol_version !== 2)
		return json({ error: "unsupported protocol_version" }, 400);
	if (
		typeof body.instance_id !== "string" ||
		!body.instance_id ||
		typeof body.home_attestation !== "string" ||
		!body.home_attestation
	) {
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
		});
		return json({ error: "unknown instance_id" }, 404);
	}
	if (instance.revoked_at !== null) {
		log({
			event: "enroll_rejected",
			route: "/enroll/device",
			reason: "instance_revoked",
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
		});
		return json({ error: `attestation invalid: ${result.reason}` }, 401);
	}
	// Canonical verified claims, not the nondeterministic ES256 signature,
	// determine retries. No device or replay record is written.
	const v2 = body.protocol_version === 2;
	const ids = await enrollmentIds(result.claims, v2 ? 2 : 1);
	const input = {
		instance_id: body.instance_id,
		issuer: env.ISSUER,
		ttlSeconds: DEVICE_TOKEN_TTL_SECONDS,
		now: result.claims.iat,
		jti: ids.jti,
	};
	const minted = v2
		? await mintInstanceToken(env.SIGNING_JWK, input)
		: await mintDeviceToken(env.SIGNING_JWK, {
				...input,
				device_id: ids.deviceId,
				device_fp: result.claims.device_fp,
			});

	return json({
		...(v2 ? { protocol_version: 2 } : {}),
		device_token: minted.jwt,
		expires_at: new Date(minted.exp * 1000).toISOString(),
	});
}
