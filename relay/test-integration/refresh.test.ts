// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

// Integration tests for POST /token/refresh: device-token re-issue from the
// relay's own prior signature, without attestation or devices-table writes.

import { SELF, env } from "cloudflare:test";
import { beforeAll, describe, expect, it, vi } from "vitest";
import type { Env } from "../src/env";
import { handleTokenRefresh } from "../src/refresh";
import { base64UrlDecode, mintDeviceToken, mintServiceToken, verifyToken } from "../src/tokens";
import { applyRelayD1Migrations } from "./apply-migrations";

const VALID_FP = `sha256:${"a".repeat(64)}`;
const DEVICE_TOKEN_TTL_SECONDS = 60 * 24 * 60 * 60;
const REFRESH_GRACE_SECONDS = 30 * 86400;

declare module "cloudflare:test" {
	interface ProvidedEnv {
		DB: D1Database;
		SIGNING_JWK: string;
		JWKS_PUBLIC: string;
		ISSUER: string;
	}
}

beforeAll(async () => {
	await applyRelayD1Migrations();
});

function newInstanceId(): string {
	return crypto.randomUUID();
}

function randomFp(): string {
	const bytes = new Uint8Array(32);
	crypto.getRandomValues(bytes);
	return `sha256:${Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("")}`;
}

async function insertInstance(instanceId: string): Promise<void> {
	const now = Math.floor(Date.now() / 1000);
	await env.DB.prepare(
		"INSERT INTO instances (instance_id, ca_fp, ca_pubkey_pem, home_label, created_at, service_token_jti) VALUES (?, ?, ?, ?, ?, ?)",
	)
		.bind(
			instanceId,
			randomFp(),
			"-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----\n",
			null,
			now,
			crypto.randomUUID(),
		)
		.run();
}

async function mintCurrentDeviceToken(
	instanceId: string,
	options: { now?: number; issuer?: string } = {},
): Promise<{
	jwt: string;
	jti: string;
	device_id: string;
	device_fp: string;
}> {
	const device_id = crypto.randomUUID();
	const device_fp = VALID_FP;
	const minted = await mintDeviceToken(env.SIGNING_JWK, {
		instance_id: instanceId,
		device_id,
		device_fp,
		issuer: options.issuer ?? env.ISSUER,
		ttlSeconds: DEVICE_TOKEN_TTL_SECONDS,
		now: options.now,
	});
	return { jwt: minted.jwt, jti: minted.jti, device_id, device_fp };
}

async function mintService(instanceId: string): Promise<string> {
	const minted = await mintServiceToken(env.SIGNING_JWK, {
		instance_id: instanceId,
		ca_fp: VALID_FP,
		issuer: env.ISSUER,
		ttlSeconds: 300,
	});
	return minted.jwt;
}

async function postRefresh(deviceToken: string): Promise<Response> {
	return SELF.fetch("http://spl.test/token/refresh", {
		method: "POST",
		headers: { "content-type": "application/json" },
		body: JSON.stringify({ device_token: deviceToken }),
	});
}

function payload(jwt: string): Record<string, unknown> {
	return JSON.parse(new TextDecoder().decode(base64UrlDecode(jwt.split(".")[1])));
}

function tamperSignature(jwt: string): string {
	const parts = jwt.split(".");
	const sig = parts[2];
	parts[2] = `${sig[0] === "A" ? "B" : "A"}${sig.slice(1)}`;
	return parts.join(".");
}

async function wsOpen(url: string, token: string): Promise<WebSocket> {
	const res = await SELF.fetch(url, {
		headers: {
			Upgrade: "websocket",
			Authorization: `Bearer ${token}`,
		},
	});
	if (!res.webSocket) {
		throw new Error(`no webSocket on response: status=${res.status}`);
	}
	const ws = res.webSocket;
	ws.accept();
	return ws;
}

function onMessage(ws: WebSocket): Promise<string | ArrayBuffer> {
	return new Promise((resolve, reject) => {
		const timer = setTimeout(() => reject(new Error("onMessage timeout")), 5000);
		ws.addEventListener(
			"message",
			(ev) => {
				clearTimeout(timer);
				resolve(ev.data);
			},
			{ once: true },
		);
		ws.addEventListener(
			"close",
			() => {
				clearTimeout(timer);
				reject(new Error("socket closed before message"));
			},
			{ once: true },
		);
	});
}

async function devicesCount(instanceId: string): Promise<number> {
	const row = await env.DB.prepare("SELECT COUNT(*) AS count FROM devices WHERE instance_id = ?")
		.bind(instanceId)
		.first<{ count: number }>();
	return row?.count ?? 0;
}

describe("POST /token/refresh", () => {
	it("refreshes a valid device token with a fresh jti and stable device identity", async () => {
		const instanceId = newInstanceId();
		await insertInstance(instanceId);
		const input = await mintCurrentDeviceToken(instanceId);
		const realNow = Math.floor(Date.now() / 1000);

		const res = await postRefresh(input.jwt);
		expect(res.status).toBe(200);
		const body = (await res.json()) as { device_token: string; expires_at: string };
		expect(Object.keys(body)).toEqual(["device_token", "expires_at"]);
		expect(body.device_token).toBeTruthy();
		expect(body.expires_at).toBeTruthy();

		const verified = await verifyToken(body.device_token, {
			jwksRaw: env.JWKS_PUBLIC,
			expectedIssuer: env.ISSUER,
			expectedScope: "session.dial",
			now: realNow,
		});
		expect(verified.ok).toBe(true);
		if (verified.ok) {
			expect(verified.claims.instance_id).toBe(instanceId);
			expect(verified.claims.sub).toBe(`device:${input.device_id}`);
			expect(verified.claims.device_fp).toBe(input.device_fp);
			expect(verified.claims.jti).not.toBe(input.jti);
			expect(verified.claims.exp).toBeGreaterThanOrEqual(realNow + DEVICE_TOKEN_TTL_SECONDS - 5);
			expect(verified.claims.exp).toBeLessThanOrEqual(realNow + DEVICE_TOKEN_TTL_SECONDS + 5);
		}
		expect(payload(body.device_token).sub).toBe(`device:${input.device_id}`);
	});

	it("rejects missing invalid and oversized refresh bodies", async () => {
		const missing = await SELF.fetch("http://spl.test/token/refresh", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({}),
		});
		expect(missing.status).toBe(400);

		const invalid = await SELF.fetch("http://spl.test/token/refresh", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: "not-json",
		});
		expect(invalid.status).toBe(400);

		const oversized = await SELF.fetch("http://spl.test/token/refresh", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({ device_token: "x".repeat(16 * 1024 + 1) }),
		});
		expect(oversized.status).toBe(413);
	});

	it("refreshes a device token expired within the refresh grace window", async () => {
		const instanceId = newInstanceId();
		await insertInstance(instanceId);
		const realNow = Math.floor(Date.now() / 1000);
		const input = await mintCurrentDeviceToken(instanceId, {
			now: realNow - DEVICE_TOKEN_TTL_SECONDS - 10 * 86400,
		});

		const res = await postRefresh(input.jwt);
		expect(res.status).toBe(200);
		const body = (await res.json()) as { device_token: string };
		const verified = await verifyToken(body.device_token, {
			jwksRaw: env.JWKS_PUBLIC,
			expectedIssuer: env.ISSUER,
			expectedScope: "session.dial",
			now: realNow,
		});
		expect(verified.ok).toBe(true);
	});

	it("rejects a device token expired beyond the refresh grace window with reason expired", async () => {
		const instanceId = newInstanceId();
		await insertInstance(instanceId);
		const realNow = Math.floor(Date.now() / 1000);
		const input = await mintCurrentDeviceToken(instanceId, {
			now: realNow - DEVICE_TOKEN_TTL_SECONDS - 40 * 86400,
		});

		const res = await postRefresh(input.jwt);
		expect(res.status).toBe(401);
		const body = (await res.json()) as Record<string, unknown>;
		expect(body.reason).toBe("expired");
		expect(body).not.toHaveProperty("device_token");
	});

	it("maps instance state failures to documented statuses", async () => {
		const revokedId = newInstanceId();
		await insertInstance(revokedId);
		await env.DB.prepare("UPDATE instances SET revoked_at = ? WHERE instance_id = ?")
			.bind(Math.floor(Date.now() / 1000), revokedId)
			.run();
		const revokedToken = await mintCurrentDeviceToken(revokedId);
		const revoked = await postRefresh(revokedToken.jwt);
		expect(revoked.status).toBe(403);
		expect((await revoked.json()) as Record<string, unknown>).not.toHaveProperty("device_token");

		const unknownToken = await mintCurrentDeviceToken(newInstanceId());
		const unknown = await postRefresh(unknownToken.jwt);
		expect(unknown.status).toBe(404);
		expect((await unknown.json()) as Record<string, unknown>).not.toHaveProperty("device_token");
	});

	it("maps verification failures to 401 without minting", async () => {
		const instanceId = newInstanceId();
		await insertInstance(instanceId);
		const valid = await mintCurrentDeviceToken(instanceId);
		const serviceToken = await mintService(instanceId);
		const wrongIssuer = await mintCurrentDeviceToken(instanceId, { issuer: "wrong.example" });
		const cases: Array<{ name: string; token: string; reason: string }> = [
			{ name: "tampered signature", token: tamperSignature(valid.jwt), reason: "bad_signature" },
			{ name: "wrong scope", token: serviceToken, reason: "wrong_scope" },
			{ name: "wrong issuer", token: wrongIssuer.jwt, reason: "wrong_issuer" },
			{ name: "malformed", token: "not.a.jwt", reason: "malformed" },
		];

		for (const c of cases) {
			const res = await postRefresh(c.token);
			expect(res.status, c.name).toBe(401);
			const body = (await res.json()) as Record<string, unknown>;
			expect(body.reason, c.name).toBe(c.reason);
			expect(body, c.name).not.toHaveProperty("device_token");
		}
	});

	it("returns 503 when JWKS is unavailable", async () => {
		const token = await mintCurrentDeviceToken(newInstanceId());
		const res = await handleTokenRefresh(
			new Request("http://spl.test/token/refresh", {
				method: "POST",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({ device_token: token.jwt }),
			}),
			{ ...env, JWKS_PUBLIC: undefined } as unknown as Env,
		);
		expect(res.status).toBe(503);
	});

	it("uses a refreshed token to dial an existing listen websocket", async () => {
		const instanceId = newInstanceId();
		await insertInstance(instanceId);
		const listenToken = await mintService(instanceId);
		const input = await mintCurrentDeviceToken(instanceId);
		const refresh = await postRefresh(input.jwt);
		expect(refresh.status).toBe(200);
		const refreshBody = (await refresh.json()) as { device_token: string };

		const home = await wsOpen(`http://spl.test/session/listen?instance=${instanceId}`, listenToken);
		const incoming = onMessage(home);
		const mobile = await wsOpen(
			`http://spl.test/session/dial?instance=${instanceId}`,
			refreshBody.device_token,
		);
		const signal = (await incoming) as string;
		const parsed = JSON.parse(signal) as { type: string; tunnel_id: string };
		expect(parsed.type).toBe("incoming");
		expect(parsed.tunnel_id).toBeTruthy();

		mobile.close(1000, "test_done");
		home.close(1000, "test_done");
	});

	it("keeps session dial expiry strict outside refresh", async () => {
		const instanceId = newInstanceId();
		await insertInstance(instanceId);
		const listenToken = await mintService(instanceId);
		const realNow = Math.floor(Date.now() / 1000);
		const expired = await mintCurrentDeviceToken(instanceId, {
			now: realNow - DEVICE_TOKEN_TTL_SECONDS - 1,
		});

		const home = await wsOpen(`http://spl.test/session/listen?instance=${instanceId}`, listenToken);
		const res = await SELF.fetch(`http://spl.test/session/dial?instance=${instanceId}`, {
			headers: {
				Upgrade: "websocket",
				Authorization: `Bearer ${expired.jwt}`,
			},
		});
		expect(res.status).toBe(401);
		home.close(1000, "test_done");
	});

	it("does not insert devices rows while refreshing", async () => {
		const instanceId = newInstanceId();
		await insertInstance(instanceId);
		const before = await devicesCount(instanceId);
		const input = await mintCurrentDeviceToken(instanceId);

		const res = await postRefresh(input.jwt);
		expect(res.status).toBe(200);
		const after = await devicesCount(instanceId);
		expect(before).toBe(0);
		expect(after).toBe(before);
	});

	it("does not log refresh token bytes", async () => {
		const instanceId = newInstanceId();
		await insertInstance(instanceId);
		const input = await mintCurrentDeviceToken(instanceId);
		const spy = vi.spyOn(console, "log").mockImplementation(() => {});

		try {
			const res = await postRefresh(input.jwt);
			expect(res.status).toBe(200);
			const body = (await res.json()) as { device_token: string };
			const lines = spy.mock.calls.map((args) => args.map(String).join(" "));
			for (const line of lines) {
				expect(line).not.toContain(input.jwt);
				expect(line).not.toContain(body.device_token);
			}
			expect(
				lines.some((line) => {
					try {
						return (JSON.parse(line) as { event?: string }).event === "device_refresh";
					} catch {
						return false;
					}
				}),
			).toBe(true);
		} finally {
			spy.mockRestore();
		}
	});
});
