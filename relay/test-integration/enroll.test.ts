// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

// Integration tests for the /enroll/* control plane. Runs under Miniflare
// with real DB + SIGNING_JWK + JWKS_PUBLIC bindings. These are the tests
// that exercise attestation-replay defense and D1 idempotency.

import { SELF, env } from "cloudflare:test";
import { beforeAll, describe, expect, it, vi } from "vitest";
import { fingerprintDer } from "../src/attestation";
import { base64UrlDecode, verifyToken } from "../src/tokens";
import { genCaKeypair, genClientCertDer, mintAttestation } from "../test/fixtures";
import { applyRelayD1Migrations } from "./apply-migrations";

declare module "cloudflare:test" {
	interface ProvidedEnv {
		DB: D1Database;
		SIGNING_JWK: string;
		JWKS_PUBLIC: string;
		ISSUER: string;
	}
}

const VALID_TOTP_SECRET = "JBSWY3DPEHPK3PXP";

beforeAll(async () => {
	await applyRelayD1Migrations();
});
// No beforeEach cleanup — every test uses a freshly-minted UUID instance_id
// so rows from other tests (or other test files sharing this D1 binding)
// can't collide.

function newInstanceId(): string {
	return crypto.randomUUID();
}

describe("POST /enroll/home", () => {
	it("enrolls a new home and returns a valid service token", async () => {
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
		const body = (await res.json()) as { service_token: string; expires_at: string };
		expect(body.service_token).toBeTruthy();
		const verified = await verifyToken(body.service_token, {
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
		const t1 = (await r1.json()) as { service_token: string };
		const r2 = await SELF.fetch("http://spl.test/enroll/home", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify(body),
		});
		expect(r2.status).toBe(200);
		const t2 = (await r2.json()) as { service_token: string };
		expect(t1.service_token).not.toBe(t2.service_token);

		const instance = await env.DB.prepare(
			"SELECT service_token_jti, rotated_at FROM instances WHERE instance_id = ?",
		)
			.bind(instanceId)
			.first<{ service_token_jti: string; rotated_at: number | null }>();
		expect(instance?.rotated_at).not.toBeNull();
	});

	it("stores an optional totp_secret and preserves it on re-enroll", async () => {
		const ca = await genCaKeypair();
		const instanceId = newInstanceId();
		const r1 = await SELF.fetch("http://spl.test/enroll/home", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({
				instance_id: instanceId,
				ca_pubkey: ca.pubPem,
				totp_secret: VALID_TOTP_SECRET,
			}),
		});
		expect(r1.status).toBe(200);
		const stored = await env.DB.prepare("SELECT totp_secret FROM instances WHERE instance_id = ?")
			.bind(instanceId)
			.first<{ totp_secret: string | null }>();
		expect(stored?.totp_secret).toBe(VALID_TOTP_SECRET);

		const r2 = await SELF.fetch("http://spl.test/enroll/home", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({
				instance_id: instanceId,
				ca_pubkey: ca.pubPem,
			}),
		});
		expect(r2.status).toBe(200);
		const afterReenroll = await env.DB.prepare(
			"SELECT totp_secret FROM instances WHERE instance_id = ?",
		)
			.bind(instanceId)
			.first<{ totp_secret: string | null }>();
		expect(afterReenroll?.totp_secret).toBe(VALID_TOTP_SECRET);

		const noSecretInstanceId = newInstanceId();
		const r3 = await SELF.fetch("http://spl.test/enroll/home", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({
				instance_id: noSecretInstanceId,
				ca_pubkey: (await genCaKeypair()).pubPem,
			}),
		});
		expect(r3.status).toBe(200);
		const omitted = await env.DB.prepare("SELECT totp_secret FROM instances WHERE instance_id = ?")
			.bind(noSecretInstanceId)
			.first<{ totp_secret: string | null }>();
		expect(omitted?.totp_secret).toBeNull();
	});

	it("rejects a malformed totp_secret", async () => {
		const ca = await genCaKeypair();
		const res = await SELF.fetch("http://spl.test/enroll/home", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({
				instance_id: newInstanceId(),
				ca_pubkey: ca.pubPem,
				totp_secret: "short",
			}),
		});
		expect(res.status).toBe(400);
	});

	it("rejects a different instance presenting an already-registered ca_pubkey", async () => {
		const ca = await genCaKeypair();
		const r1 = await SELF.fetch("http://spl.test/enroll/home", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({ instance_id: newInstanceId(), ca_pubkey: ca.pubPem }),
		});
		expect(r1.status).toBe(200);
		const r2 = await SELF.fetch("http://spl.test/enroll/home", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({ instance_id: newInstanceId(), ca_pubkey: ca.pubPem }),
		});
		expect(r2.status).toBe(409);
		expect(await r2.text()).not.toContain("sha256:");
	});

	it("rejects an oversized /enroll/home body with 413", async () => {
		const ca = await genCaKeypair();
		const res = await SELF.fetch("http://spl.test/enroll/home", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({
				instance_id: newInstanceId(),
				ca_pubkey: ca.pubPem,
				home_label: "x".repeat(40000),
			}),
		});
		expect(res.status).toBe(413);
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

	function payload(jwt: string): unknown {
		return JSON.parse(new TextDecoder().decode(base64UrlDecode(jwt.split(".")[1])));
	}

	it("does not log enrollment tokens or secret-bearing payloads", async () => {
		const ca = await genCaKeypair();
		const instanceId = newInstanceId();
		const spy = vi.spyOn(console, "log").mockImplementation(() => {});

		try {
			const home = await SELF.fetch("http://spl.test/enroll/home", {
				method: "POST",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({
					instance_id: instanceId,
					ca_pubkey: ca.pubPem,
					totp_secret: VALID_TOTP_SECRET,
				}),
			});
			expect(home.status).toBe(200);
			const homeBody = (await home.json()) as { service_token: string };

			const certDer = await genClientCertDer();
			const attestation = await mintAttestation({
				caPrivateKey: ca.privateKey,
				instanceId,
				deviceFp: await fingerprintDer(certDer),
			});
			const device = await SELF.fetch("http://spl.test/enroll/device", {
				method: "POST",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({
					instance_id: instanceId,
					home_attestation: attestation,
				}),
			});
			expect(device.status).toBe(200);
			const deviceBody = (await device.json()) as { device_token: string };

			const caBodyLine = ca.pubPem.split("\n").find((line) => line.length > 20);
			if (!caBodyLine) throw new Error("test CA PEM missing body line");
			const lines = spy.mock.calls.map((args) => args.map(String).join(" "));
			for (const line of lines) {
				expect(line).not.toContain(homeBody.service_token);
				expect(line).not.toContain(deviceBody.device_token);
				expect(line).not.toContain(VALID_TOTP_SECRET);
				expect(line).not.toContain(caBodyLine);
				expect(line).not.toContain(attestation);
			}
		} finally {
			spy.mockRestore();
		}
	});

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

	it("re-mints the byte-identical device token on replay of a still-valid attestation", async () => {
		const { instanceId, ca } = await setupEnrolled();
		const fp = await fingerprintDer(await genClientCertDer());
		const attestation = await mintAttestation({
			caPrivateKey: ca.privateKey,
			instanceId,
			deviceFp: fp,
		});
		const body = JSON.stringify({
			instance_id: instanceId,
			home_attestation: attestation,
		});
		const opts = {
			method: "POST",
			headers: { "content-type": "application/json" },
			body,
		};
		const r1 = await SELF.fetch("http://spl.test/enroll/device", opts);
		expect(r1.status).toBe(200);
		const r2 = await SELF.fetch("http://spl.test/enroll/device", opts);
		expect(r2.status).toBe(200);
		const t1 = (await r1.json()) as { device_token: string };
		const t2 = (await r2.json()) as { device_token: string };
		expect(t2.device_token).toBe(t1.device_token);
		expect(payload(t2.device_token)).toEqual(payload(t1.device_token));
	});

	it("rejects a device enroll missing home_attestation", async () => {
		const { instanceId } = await setupEnrolled();
		const res = await SELF.fetch("http://spl.test/enroll/device", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({ instance_id: instanceId }),
		});
		expect(res.status).toBe(400);
	});

	it("rejects an oversized /enroll/device body with 413", async () => {
		const res = await SELF.fetch("http://spl.test/enroll/device", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({
				instance_id: newInstanceId(),
				home_attestation: "x".repeat(20000),
			}),
		});
		expect(res.status).toBe(413);
	});

	it("rejects device enroll for an unknown instance_id", async () => {
		const ca = await genCaKeypair();
		const fp = await fingerprintDer(await genClientCertDer());
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
				home_attestation: attestation,
			}),
		});
		expect(res.status).toBe(404);
	});

	it("rejects attestation signed with the wrong CA", async () => {
		const { instanceId } = await setupEnrolled();
		const attackerCa = await genCaKeypair();
		const fp = await fingerprintDer(await genClientCertDer());
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
				home_attestation: badAttestation,
			}),
		});
		expect(res.status).toBe(401);
	});

	it("rejects an attestation with a malformed device_fp (M4)", async () => {
		const { instanceId, ca } = await setupEnrolled();
		const attestation = await mintAttestation({
			caPrivateKey: ca.privateKey,
			instanceId,
			deviceFp: "ignored",
			overrideDeviceFp: `sha256:${"A".repeat(64)}`,
		});
		const res = await SELF.fetch("http://spl.test/enroll/device", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({
				instance_id: instanceId,
				home_attestation: attestation,
			}),
		});
		expect(res.status).toBe(401);
	});

	it("rejects a consumed attestation_jti re-presented with a different device_fp (M5)", async () => {
		const { instanceId, ca } = await setupEnrolled();
		const jti = `jti-collide-${instanceId}`;
		const fp1 = await fingerprintDer(await genClientCertDer("a"));
		const fp2 = await fingerprintDer(await genClientCertDer("b"));
		const a1 = await mintAttestation({
			caPrivateKey: ca.privateKey,
			instanceId,
			deviceFp: fp1,
			overrideJti: jti,
		});
		const a2 = await mintAttestation({
			caPrivateKey: ca.privateKey,
			instanceId,
			deviceFp: fp2,
			overrideJti: jti,
		});
		const r1 = await SELF.fetch("http://spl.test/enroll/device", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({ instance_id: instanceId, home_attestation: a1 }),
		});
		expect(r1.status).toBe(200);
		const r2 = await SELF.fetch("http://spl.test/enroll/device", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({ instance_id: instanceId, home_attestation: a2 }),
		});
		expect(r2.status).toBe(409);
	});

	it("ignores a legacy client_cert field and still succeeds", async () => {
		const { instanceId, ca } = await setupEnrolled();
		const fp = await fingerprintDer(await genClientCertDer());
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
				client_cert: "-----BEGIN CERTIFICATE-----\nignored\n-----END CERTIFICATE-----\n",
				home_attestation: attestation,
			}),
		});
		expect(res.status).toBe(200);
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
