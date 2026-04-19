// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

// Integration tests for the /enroll/* control plane. Runs under Miniflare
// with real DB + SIGNING_JWK + JWKS_PUBLIC bindings. These are the tests
// that exercise attestation-replay defense and D1 idempotency.

import { SELF, applyD1Migrations, env } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";
import { fingerprintDer } from "../src/attestation";
import { verifyToken } from "../src/tokens";
import { genCaKeypair, genClientCertDer, mintAttestation } from "../test/fixtures";
import { migrations } from "./migrations";

declare module "cloudflare:test" {
	interface ProvidedEnv {
		DB: D1Database;
		SIGNING_JWK: string;
		JWKS_PUBLIC: string;
		ISSUER: string;
	}
}

beforeAll(async () => {
	await applyD1Migrations(env.DB, migrations);
});
// No beforeEach cleanup — every test uses a freshly-minted UUID instance_id
// so rows from other tests (or other test files sharing this D1 binding)
// can't collide.

function newInstanceId(): string {
	return crypto.randomUUID();
}

describe("POST /enroll/home", () => {
	it("enrolls a new home and returns a valid account token", async () => {
		const ca = await genCaKeypair();
		const instanceId = newInstanceId();
		const res = await SELF.fetch("http://spl.test/enroll/home", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({
				instance_id: instanceId,
				ca_pubkey: ca.pubPem,
				home_label: "living room",
			}),
		});
		expect(res.status).toBe(200);
		const body = (await res.json()) as { account_token: string; expires_at: string };
		expect(body.account_token).toBeTruthy();
		const verified = await verifyToken(body.account_token, {
			jwksRaw: env.JWKS_PUBLIC,
			expectedIssuer: env.ISSUER,
			expectedScope: "session.listen",
		});
		expect(verified.ok).toBe(true);
		if (verified.ok) {
			expect(verified.claims.sub).toBe(`home:${instanceId}`);
			expect(verified.claims.instance_id).toBe(instanceId);
			expect(verified.claims.ca_fp).toBeTruthy();
		}
	});

	it("is idempotent — same instance_id rotates the token", async () => {
		const ca = await genCaKeypair();
		const instanceId = newInstanceId();
		const body = {
			instance_id: instanceId,
			ca_pubkey: ca.pubPem,
			home_label: "home-2",
		};
		const r1 = await SELF.fetch("http://spl.test/enroll/home", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify(body),
		});
		expect(r1.status).toBe(200);
		const t1 = (await r1.json()) as { account_token: string };
		const r2 = await SELF.fetch("http://spl.test/enroll/home", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify(body),
		});
		expect(r2.status).toBe(200);
		const t2 = (await r2.json()) as { account_token: string };
		expect(t1.account_token).not.toBe(t2.account_token);

		const instance = await env.DB.prepare(
			"SELECT account_token_jti, rotated_at FROM instances WHERE instance_id = ?",
		)
			.bind(instanceId)
			.first<{ account_token_jti: string; rotated_at: number | null }>();
		expect(instance?.rotated_at).not.toBeNull();
	});

	it("rejects ca_pubkey mismatch on re-enroll (takeover attempt)", async () => {
		const caOrig = await genCaKeypair();
		const caAttacker = await genCaKeypair();
		const instanceId = newInstanceId();
		const r1 = await SELF.fetch("http://spl.test/enroll/home", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({ instance_id: instanceId, ca_pubkey: caOrig.pubPem }),
		});
		expect(r1.status).toBe(200);
		const r2 = await SELF.fetch("http://spl.test/enroll/home", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({ instance_id: instanceId, ca_pubkey: caAttacker.pubPem }),
		});
		expect(r2.status).toBe(409);
	});

	it("rejects non-ECDSA-P256 ca_pubkey", async () => {
		const res = await SELF.fetch("http://spl.test/enroll/home", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({
				instance_id: newInstanceId(),
				ca_pubkey: "not a pem",
			}),
		});
		expect(res.status).toBe(400);
	});

	it("rejects missing fields", async () => {
		const res = await SELF.fetch("http://spl.test/enroll/home", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({ instance_id: newInstanceId() }),
		});
		expect(res.status).toBe(400);
	});
});

describe("POST /enroll/device", () => {
	async function setupEnrolled(): Promise<{
		instanceId: string;
		ca: Awaited<ReturnType<typeof genCaKeypair>>;
	}> {
		const ca = await genCaKeypair();
		const instanceId = newInstanceId();
		const r = await SELF.fetch("http://spl.test/enroll/home", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({ instance_id: instanceId, ca_pubkey: ca.pubPem }),
		});
		expect(r.status).toBe(200);
		return { instanceId, ca };
	}

	function certPem(der: Uint8Array): string {
		return `-----BEGIN CERTIFICATE-----\n${Buffer.from(der).toString("base64")}\n-----END CERTIFICATE-----\n`;
	}

	it("issues a device token given a valid home attestation", async () => {
		const { instanceId, ca } = await setupEnrolled();
		const certDer = await genClientCertDer();
		const fp = await fingerprintDer(certDer);
		const attestation = await mintAttestation({
			caPrivateKey: ca.privateKey,
			instanceId,
			deviceFp: fp,
		});
		const res = await SELF.fetch("http://spl.test/enroll/device", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({
				instance_id: instanceId,
				client_cert: certPem(certDer),
				home_attestation: attestation,
			}),
		});
		expect(res.status).toBe(200);
		const body = (await res.json()) as { device_token: string };
		const verified = await verifyToken(body.device_token, {
			jwksRaw: env.JWKS_PUBLIC,
			expectedIssuer: env.ISSUER,
			expectedScope: "session.dial",
		});
		expect(verified.ok).toBe(true);
		if (verified.ok) {
			expect(verified.claims.device_fp).toBe(fp);
			expect(verified.claims.instance_id).toBe(instanceId);
		}
	});

	it("refuses to reuse an attestation (replay defense)", async () => {
		const { instanceId, ca } = await setupEnrolled();
		const certDer = await genClientCertDer();
		const fp = await fingerprintDer(certDer);
		const attestation = await mintAttestation({
			caPrivateKey: ca.privateKey,
			instanceId,
			deviceFp: fp,
		});
		const body = JSON.stringify({
			instance_id: instanceId,
			client_cert: certPem(certDer),
			home_attestation: attestation,
		});
		const r1 = await SELF.fetch("http://spl.test/enroll/device", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body,
		});
		expect(r1.status).toBe(200);
		const r2 = await SELF.fetch("http://spl.test/enroll/device", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body,
		});
		expect(r2.status).toBe(409);
	});

	it("rejects device enroll for an unknown instance_id", async () => {
		const ca = await genCaKeypair();
		const certDer = await genClientCertDer();
		const fp = await fingerprintDer(certDer);
		const instanceId = newInstanceId();
		const attestation = await mintAttestation({
			caPrivateKey: ca.privateKey,
			instanceId,
			deviceFp: fp,
		});
		const res = await SELF.fetch("http://spl.test/enroll/device", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({
				instance_id: instanceId,
				client_cert: certPem(certDer),
				home_attestation: attestation,
			}),
		});
		expect(res.status).toBe(404);
	});

	it("rejects attestation signed with the wrong CA", async () => {
		const { instanceId } = await setupEnrolled();
		const attackerCa = await genCaKeypair();
		const certDer = await genClientCertDer();
		const fp = await fingerprintDer(certDer);
		const badAttestation = await mintAttestation({
			caPrivateKey: attackerCa.privateKey,
			instanceId,
			deviceFp: fp,
		});
		const res = await SELF.fetch("http://spl.test/enroll/device", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({
				instance_id: instanceId,
				client_cert: certPem(certDer),
				home_attestation: badAttestation,
			}),
		});
		expect(res.status).toBe(401);
	});

	it("rejects attestation whose device_fp doesn't match the presented client_cert", async () => {
		const { instanceId, ca } = await setupEnrolled();
		const cert1 = await genClientCertDer("a");
		const cert2 = await genClientCertDer("b");
		const fp1 = await fingerprintDer(cert1);
		const attestation = await mintAttestation({
			caPrivateKey: ca.privateKey,
			instanceId,
			deviceFp: fp1,
		});
		const res = await SELF.fetch("http://spl.test/enroll/device", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({
				instance_id: instanceId,
				client_cert: certPem(cert2),
				home_attestation: attestation,
			}),
		});
		expect(res.status).toBe(401);
	});
});

describe("GET /.well-known/jwks.json", () => {
	it("mirrors env.JWKS_PUBLIC verbatim", async () => {
		const res = await SELF.fetch("http://spl.test/.well-known/jwks.json");
		expect(res.status).toBe(200);
		expect(res.headers.get("content-type")).toMatch(/jwk-set\+json/);
		const body = await res.text();
		expect(body).toBe(env.JWKS_PUBLIC);
	});
});
