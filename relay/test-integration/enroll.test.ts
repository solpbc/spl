// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

// Integration tests for the /enroll/* control plane. Runs under Miniflare
// with real DB + SIGNING_JWK + JWKS_PUBLIC bindings. These are the tests
// that exercise stateless retry issuance and minimized D1 persistence.

import { SELF, env } from "cloudflare:test";
import { beforeAll, describe, expect, it, vi } from "vitest";
import { fingerprintDer } from "../src/attestation";
import { handleEnrollDevice } from "../src/enroll";
import type { Env } from "../src/env";
import { base64UrlDecode, verifyToken } from "../src/tokens";
import { genCaKeypair, genClientCertDer, mintAttestation } from "../test/fixtures";
import { applyRelayD1Migrations } from "./apply-migrations";

declare global {
	namespace Cloudflare {
		interface Env {
			DB: D1Database;
			SIGNING_JWK: string;
			JWKS_PUBLIC: string;
			ISSUER: string;
		}
	}
}

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

	it("retries concurrently and after re-signing without retaining device metadata", async () => {
		const { instanceId, ca } = await setupEnrolled();
		const input = {
			caPrivateKey: ca.privateKey,
			instanceId,
			deviceFp: await fingerprintDer(await genClientCertDer()),
			now: Math.floor(Date.now() / 1000),
			overrideJti: crypto.randomUUID(),
		};
		const original = await mintAttestation(input);
		const resigned = await mintAttestation(input);
		const send = async (attestation: string) => {
			const response = await SELF.fetch("http://spl.test/enroll/device", {
				method: "POST",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({ instance_id: instanceId, home_attestation: attestation }),
			});
			expect(response.status).toBe(200);
			return response.text();
		};
		const spy = vi.spyOn(console, "log").mockImplementation(() => {});
		try {
			const responses = await Promise.all([send(original), send(original), send(resigned)]);
			expect(new Set(responses).size).toBe(1);
			expect(
				await env.DB.prepare(
					"SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'devices'",
				).first(),
			).toBeNull();
			const columns = await env.DB.prepare("PRAGMA table_info(instances)").all<{ name: string }>();
			expect(columns.results.map((c) => c.name)).not.toContain("home_label");
			expect(spy.mock.calls).toEqual([]);
		} finally {
			spy.mockRestore();
		}
	});

	it("pauses enrollment before parsing during key and writer drains", async () => {
		const response = await handleEnrollDevice(
			new Request("http://spl.test/enroll/device", {
				method: "POST",
				body: "malformed",
			}),
			{ ...env, ENROLLMENT_PAUSED: "true" } as Env,
		);
		expect(response.status).toBe(503);
		expect(response.headers.get("Retry-After")).toBe("360");
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

	it("treats different home-authorized claims sharing a jti as independent issuance", async () => {
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
		expect(r2.status).toBe(200);
		expect(((await r1.json()) as { device_token: string }).device_token).not.toBe(
			((await r2.json()) as { device_token: string }).device_token,
		);
		expect(
			await env.DB.prepare(
				"SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'devices'",
			).first(),
		).toBeNull();
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
