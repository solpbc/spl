// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

// Proof of possession on /enroll/home, and the current-token rule it turns on
// for the session routes. See proto/tokens.md § proof of possession.

import { SELF, env } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";
import { deriveJid, importCaPublicKey } from "../src/attestation";
import { handleEnrollHome } from "../src/enroll";
import type { Env } from "../src/env";
import { base64UrlDecode } from "../src/tokens";
import { genCaKeypair, mintAttestation, mintEnrollProof } from "../test/fixtures";
import { applyRelayD1Migrations } from "./apply-migrations";

beforeAll(applyRelayD1Migrations);

// A home's instance id is the jid of its CA key.
async function jidOf(pubPem: string): Promise<string> {
	const key = await importCaPublicKey(pubPem);
	if (!key) throw new Error("bad test key");
	return deriveJid(key);
}

function enroll(body: Record<string, unknown>): Promise<Response> {
	return SELF.fetch("http://spl.test/enroll/home", {
		method: "POST",
		headers: { "content-type": "application/json" },
		body: JSON.stringify(body),
	});
}

async function serviceToken(res: Response): Promise<string> {
	expect(res.status).toBe(200);
	return ((await res.json()) as { service_token: string }).service_token;
}

function claimsOf(jwt: string): Record<string, unknown> {
	return JSON.parse(new TextDecoder().decode(base64UrlDecode(jwt.split(".")[1])));
}

async function row(instanceId: string) {
	return env.DB.prepare(
		"SELECT service_token_jti, rotated_at, proof_iat FROM instances WHERE instance_id = ?",
	)
		.bind(instanceId)
		.first<{ service_token_jti: string; rotated_at: number | null; proof_iat: number | null }>();
}

function listen(instanceId: string, token: string): Promise<Response> {
	return SELF.fetch(`http://spl.test/session/listen?instance=${instanceId}`, {
		headers: { Upgrade: "websocket", Authorization: `Bearer ${token}` },
	});
}

async function provenHome() {
	const ca = await genCaKeypair();
	const instanceId = await jidOf(ca.pubPem);
	const now = Math.floor(Date.now() / 1000);
	const unsigned = await serviceToken(
		await enroll({ instance_id: instanceId, ca_pubkey: ca.pubPem }),
	);
	const proof = await mintEnrollProof({ caPrivateKey: ca.privateKey, instanceId, now: now - 5 });
	const proven = await serviceToken(
		await enroll({ instance_id: instanceId, ca_pubkey: ca.pubPem, mode: "renew", proof }),
	);
	return { ca, instanceId, unsigned, proven, now };
}

describe("POST /enroll/home proof of possession", () => {
	it("a signed enroll is marked proven and its token carries pop", async () => {
		const ca = await genCaKeypair();
		const instanceId = await jidOf(ca.pubPem);
		const proof = await mintEnrollProof({ caPrivateKey: ca.privateKey, instanceId });
		const token = await serviceToken(
			await enroll({ instance_id: instanceId, ca_pubkey: ca.pubPem, proof }),
		);
		expect(claimsOf(token).pop).toBe(true);
		expect((await row(instanceId))?.proof_iat).toBe(claimsOf(proof).iat);
	});

	it("an unsigned enroll of an unproven instance still works and carries no pop", async () => {
		const ca = await genCaKeypair();
		const instanceId = await jidOf(ca.pubPem);
		const first = await serviceToken(
			await enroll({ instance_id: instanceId, ca_pubkey: ca.pubPem }),
		);
		const renewed = await serviceToken(
			await enroll({ instance_id: instanceId, ca_pubkey: ca.pubPem, mode: "renew" }),
		);
		expect(claimsOf(first).pop).toBeUndefined();
		expect(claimsOf(renewed).pop).toBeUndefined();
		expect((await row(instanceId))?.proof_iat).toBeNull();
	});

	it("once proven, an unsigned call holding only the public key rotates nothing", async () => {
		const { ca, instanceId, proven } = await provenHome();
		const before = await row(instanceId);
		for (const mode of [undefined, "renew"]) {
			const res = await enroll({ instance_id: instanceId, ca_pubkey: ca.pubPem, mode });
			expect(res.status).toBe(401);
			expect(await res.json()).toEqual({ error: "proof_required" });
		}
		expect(await row(instanceId)).toEqual(before);
		expect(before?.service_token_jti).toBe(claimsOf(proven).jti);
	});

	it("a proof signed by any other key is refused and writes nothing", async () => {
		const { ca, instanceId } = await provenHome();
		const attacker = await genCaKeypair();
		const before = await row(instanceId);
		const proof = await mintEnrollProof({ caPrivateKey: attacker.privateKey, instanceId });
		const res = await enroll({
			instance_id: instanceId,
			ca_pubkey: ca.pubPem,
			mode: "renew",
			proof,
		});
		expect(res.status).toBe(401);
		expect(await res.json()).toEqual({ error: "proof invalid: bad_signature" });
		expect(await row(instanceId)).toEqual(before);
	});

	it("refuses an unproven takeover too when the proof is forged", async () => {
		const ca = await genCaKeypair();
		const instanceId = await jidOf(ca.pubPem);
		await serviceToken(await enroll({ instance_id: instanceId, ca_pubkey: ca.pubPem }));
		const attacker = await genCaKeypair();
		const proof = await mintEnrollProof({ caPrivateKey: attacker.privateKey, instanceId });
		const res = await enroll({ instance_id: instanceId, ca_pubkey: ca.pubPem, proof });
		expect(res.status).toBe(401);
		expect((await row(instanceId))?.proof_iat).toBeNull();
	});

	it("each proof is single use, and only a newer one rotates", async () => {
		const { ca, instanceId, now } = await provenHome();
		const replayOfFirst = await mintEnrollProof({
			caPrivateKey: ca.privateKey,
			instanceId,
			now: now - 5,
		});
		const replay = await enroll({
			instance_id: instanceId,
			ca_pubkey: ca.pubPem,
			mode: "renew",
			proof: replayOfFirst,
		});
		expect(replay.status).toBe(401);
		expect(await replay.json()).toEqual({ error: "proof_replay" });

		const newer = await mintEnrollProof({ caPrivateKey: ca.privateKey, instanceId, now });
		await serviceToken(
			await enroll({ instance_id: instanceId, ca_pubkey: ca.pubPem, mode: "renew", proof: newer }),
		);
		const again = await enroll({
			instance_id: instanceId,
			ca_pubkey: ca.pubPem,
			mode: "renew",
			proof: newer,
		});
		expect(again.status).toBe(401);
		expect(await again.json()).toEqual({ error: "proof_replay" });
	});

	it("refuses a device attestation, a wrong scope, an expired or a long-lived proof", async () => {
		const ca = await genCaKeypair();
		const instanceId = await jidOf(ca.pubPem);
		const now = Math.floor(Date.now() / 1000);
		const cases: Array<[string, string]> = [
			[
				await mintAttestation({
					caPrivateKey: ca.privateKey,
					instanceId,
					deviceFp: `sha256:${"a".repeat(64)}`,
				}),
				"proof invalid: malformed",
			],
			[
				await mintEnrollProof({ caPrivateKey: ca.privateKey, instanceId, scope: "device.enroll" }),
				"proof invalid: wrong_scope",
			],
			[
				await mintEnrollProof({
					caPrivateKey: ca.privateKey,
					instanceId,
					now: now - 600,
					exp: now - 360,
				}),
				"proof invalid: expired",
			],
			[
				await mintEnrollProof({ caPrivateKey: ca.privateKey, instanceId, now, exp: now + 3600 }),
				"proof invalid: too_long_lived",
			],
			[
				await mintEnrollProof({ caPrivateKey: ca.privateKey, instanceId: crypto.randomUUID() }),
				"proof invalid: wrong_issuer",
			],
		];
		for (const [proof, error] of cases) {
			const res = await enroll({ instance_id: instanceId, ca_pubkey: ca.pubPem, proof });
			expect(res.status).toBe(401);
			expect(await res.json()).toEqual({ error });
		}
		expect(await row(instanceId)).toBeNull();
	});

	it("a signed renewal never creates a record", async () => {
		const ca = await genCaKeypair();
		const instanceId = await jidOf(ca.pubPem);
		const proof = await mintEnrollProof({ caPrivateKey: ca.privateKey, instanceId });
		const res = await enroll({
			instance_id: instanceId,
			ca_pubkey: ca.pubPem,
			mode: "renew",
			proof,
		});
		expect(res.status).toBe(404);
		expect(await res.json()).toEqual({ error: "not_enrolled" });
		expect(await row(instanceId)).toBeNull();
	});

	it("derives the jid of the published canonical vector", async () => {
		const hex =
			"3059301306072a8648ce3d020106082a8648ce3d030107034200046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";
		const der = new Uint8Array(hex.match(/../g)?.map((h) => Number.parseInt(h, 16)) ?? []);
		const key = await crypto.subtle.importKey(
			"spki",
			der,
			{ name: "ECDSA", namedCurve: "P-256" },
			true,
			["verify"],
		);
		expect(await deriveJid(key)).toBe("5620bab1-476a-88df-93d4-f4f525b991dd");
	});

	it("a signed first enroll must claim the jid of its own key", async () => {
		const victim = await genCaKeypair();
		const squatter = await genCaKeypair();
		const instanceId = await jidOf(victim.pubPem);
		const proof = await mintEnrollProof({ caPrivateKey: squatter.privateKey, instanceId });
		const res = await enroll({ instance_id: instanceId, ca_pubkey: squatter.pubPem, proof });
		expect(res.status).toBe(400);
		expect(await res.json()).toEqual({ error: "instance_id is not the jid of ca_pubkey" });
		expect(await row(instanceId)).toBeNull();
	});

	it("a proof addressed to another relay is refused", async () => {
		const ca = await genCaKeypair();
		const instanceId = await jidOf(ca.pubPem);
		for (const audience of ["spl-relay", "other-relay.example"]) {
			const proof = await mintEnrollProof({ caPrivateKey: ca.privateKey, instanceId, audience });
			const res = await enroll({ instance_id: instanceId, ca_pubkey: ca.pubPem, proof });
			expect(res.status).toBe(401);
			expect(await res.json()).toEqual({ error: "proof invalid: wrong_audience" });
		}
		expect(await row(instanceId)).toBeNull();
	});

	it("HOME_PROOF_REQUIRED refuses every unsigned call", async () => {
		const strict = { ...(env as unknown as Env), HOME_PROOF_REQUIRED: "true" };
		const ca = await genCaKeypair();
		const instanceId = await jidOf(ca.pubPem);
		const unsigned = await handleEnrollHome(
			new Request("http://spl.test/enroll/home", {
				method: "POST",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({ instance_id: instanceId, ca_pubkey: ca.pubPem }),
			}),
			strict,
		);
		expect(unsigned.status).toBe(401);
		expect(await unsigned.json()).toEqual({ error: "proof_required" });
		expect(await row(instanceId)).toBeNull();
		const proof = await mintEnrollProof({ caPrivateKey: ca.privateKey, instanceId });
		const signed = await handleEnrollHome(
			new Request("http://spl.test/enroll/home", {
				method: "POST",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({ instance_id: instanceId, ca_pubkey: ca.pubPem, proof }),
			}),
			strict,
		);
		expect(signed.status).toBe(200);
	});
});

describe("a proven instance honors only its current service token", () => {
	it("listen and /token/access refuse a superseded token", async () => {
		const { instanceId, unsigned, proven } = await provenHome();
		const stale = await listen(instanceId, unsigned);
		expect(stale.status).toBe(401);
		const access = await SELF.fetch("http://spl.test/token/access", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({ service_token: unsigned }),
		});
		expect(access.status).toBe(401);

		const current = await listen(instanceId, proven);
		expect(current.status).toBe(101);
		current.webSocket?.accept();
		current.webSocket?.close();
		const currentAccess = await SELF.fetch("http://spl.test/token/access", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({ service_token: proven }),
		});
		expect(currentAccess.status).toBe(200);
	});

	it("a pair window refuses a superseded token", async () => {
		const { instanceId, unsigned, proven } = await provenHome();
		const rk = Array.from(crypto.getRandomValues(new Uint8Array(16)), (b) =>
			b.toString(16).padStart(2, "0"),
		).join("");
		const open = (token: string) =>
			SELF.fetch("http://spl.test/session/pair-window", {
				headers: { Upgrade: "websocket", "Sec-Pair-Key": rk, Authorization: `Bearer ${token}` },
			});
		expect((await open(unsigned)).status).toBe(401);
		const current = await open(proven);
		expect(current.status).toBe(101);
		current.webSocket?.accept();
		current.webSocket?.close();
		expect(instanceId).toBeTruthy();
	});

	it("an unproven instance keeps honoring every unexpired token, as before", async () => {
		const ca = await genCaKeypair();
		const instanceId = await jidOf(ca.pubPem);
		const first = await serviceToken(
			await enroll({ instance_id: instanceId, ca_pubkey: ca.pubPem }),
		);
		await serviceToken(
			await enroll({ instance_id: instanceId, ca_pubkey: ca.pubPem, mode: "renew" }),
		);
		const res = await listen(instanceId, first);
		expect(res.status).toBe(101);
		res.webSocket?.accept();
		res.webSocket?.close();
	});
});
