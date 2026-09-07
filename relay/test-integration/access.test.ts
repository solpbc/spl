// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import { SELF, env } from "cloudflare:test";
import { beforeAll, describe, expect, it, vi } from "vitest";
import { base64UrlDecode, mintDeviceToken, mintServiceToken, verifyToken } from "../src/tokens";
import { genCaKeypair, mintAttestation } from "../test/fixtures";
import { applyRelayD1Migrations } from "./apply-migrations";

beforeAll(applyRelayD1Migrations);
const fp = `sha256:${"a".repeat(64)}`;
async function post(path: string, body: unknown): Promise<Response> {
	return SELF.fetch(`http://spl.test${path}`, {
		method: "POST",
		headers: { "content-type": "application/json" },
		body: JSON.stringify(body),
	});
}
async function home() {
	const instanceId = crypto.randomUUID();
	const ca = await genCaKeypair();
	const response = await post("/enroll/home", {
		instance_id: instanceId,
		ca_pubkey: ca.pubPem,
	});
	expect(response.status).toBe(200);
	const { service_token } = (await response.json()) as {
		service_token: string;
	};
	return { instanceId, ca, serviceToken: service_token };
}
async function capability(response: Response, instanceId: string) {
	expect(response.status).toBe(200);
	const body = (await response.json()) as {
		protocol_version: number;
		device_token: string;
		expires_at: string;
	};
	expect(body.protocol_version).toBe(2);
	const verified = await verifyToken(body.device_token, {
		jwksRaw: env.JWKS_PUBLIC,
		expectedIssuer: env.ISSUER,
		expectedScope: "session.dial",
	});
	expect(verified.ok).toBe(true);
	if (!verified.ok) throw new Error("invalid capability");
	expect(verified.claims).toMatchObject({
		ver: 2,
		sub: `instance:${instanceId}`,
		instance_id: instanceId,
	});
	expect(Object.keys(verified.claims).sort()).toEqual(
		["iss", "sub", "aud", "scope", "ver", "instance_id", "iat", "exp", "jti"].sort(),
	);
	expect(Date.parse(body.expires_at)).toBe(verified.claims.exp * 1000);
	return { body, claims: verified.claims };
}

describe("instance relay capability v2", () => {
	it("issues only instance claims, with independent renewals and no durable device state or logs", async () => {
		const h = await home();
		const spy = vi.spyOn(console, "log").mockImplementation(() => {});
		try {
			const first = await capability(
				await post("/token/access", { service_token: h.serviceToken }),
				h.instanceId,
			);
			const second = await capability(
				await post("/token/refresh", { device_token: first.body.device_token }),
				h.instanceId,
			);
			const third = await capability(
				await post("/token/refresh", { device_token: first.body.device_token }),
				h.instanceId,
			);
			expect(new Set([first.claims.jti, second.claims.jti, third.claims.jti]).size).toBe(3);
			expect(
				await env.DB.prepare(
					"SELECT name FROM sqlite_master WHERE type='table' AND name='devices'",
				).first(),
			).toBeNull();
			expect(spy.mock.calls).toEqual([]);
		} finally {
			spy.mockRestore();
		}
	});
	it("uses a v2 capability on the actual dial route, with instance and listen separation", async () => {
		const h = await home();
		const { body } = await capability(
			await post("/token/access", { service_token: h.serviceToken }),
			h.instanceId,
		);
		const open = (path: string, token: string) =>
			SELF.fetch(`http://spl.test${path}`, {
				headers: { Upgrade: "websocket", Authorization: `Bearer ${token}` },
			});
		expect((await open(`/session/listen?instance=${h.instanceId}`, body.device_token)).status).toBe(
			401,
		);
		expect(
			(await open(`/session/dial?instance=${crypto.randomUUID()}`, body.device_token)).status,
		).toBe(401);
		const listener = await open(`/session/listen?instance=${h.instanceId}`, h.serviceToken);
		expect(listener.status).toBe(101);
		const homeSocket = listener.webSocket;
		if (!homeSocket) throw new Error("listener upgrade missing socket");
		homeSocket.accept();
		const incoming = new Promise<MessageEvent>((resolve) =>
			homeSocket.addEventListener("message", resolve, { once: true }),
		);
		const dial = await open(`/session/dial?instance=${h.instanceId}`, body.device_token);
		try {
			expect(dial.status).toBe(101);
			if (!dial.webSocket) throw new Error("dial upgrade missing socket");
			dial.webSocket.accept();
			expect(JSON.parse(String((await incoming).data)).type).toBe("incoming");
		} finally {
			dial.webSocket?.close(1000, "test_done");
			homeSocket.close(1000, "test_done");
		}
	});
	it("upgrades legacy access only on explicit request, dropping fingerprint and subject", async () => {
		const h = await home();
		const old = await mintDeviceToken(env.SIGNING_JWK, {
			instance_id: h.instanceId,
			device_id: "legacy-device",
			device_fp: fp,
			issuer: env.ISSUER,
			ttlSeconds: 3600,
		});
		const legacy = await post("/token/refresh", { device_token: old.jwt });
		const legacyBody = (await legacy.json()) as { device_token: string };
		expect(legacyBody).not.toHaveProperty("protocol_version");
		const legacyClaims = JSON.parse(
			new TextDecoder().decode(base64UrlDecode(legacyBody.device_token.split(".")[1])),
		);
		expect(legacyClaims.sub).toBe("device:legacy-device");
		expect(legacyClaims.device_fp).toBe(fp);
		const upgraded = await capability(
			await post("/token/refresh", {
				device_token: old.jwt,
				protocol_version: 2,
			}),
			h.instanceId,
		);
		expect(upgraded.claims.jti).not.toBe(old.jti);
	});
	it("does not let dial access issue service-authorized capabilities or listen", async () => {
		const h = await home();
		const { body } = await capability(
			await post("/token/access", { service_token: h.serviceToken }),
			h.instanceId,
		);
		expect((await post("/token/access", { service_token: body.device_token })).status).toBe(401);
		expect(
			(
				await verifyToken(body.device_token, {
					jwksRaw: env.JWKS_PUBLIC,
					expectedIssuer: env.ISSUER,
					expectedScope: "session.listen",
				})
			).ok,
		).toBe(false);
		expect(
			(
				await post("/token/access", {
					service_token: h.serviceToken,
					instance_id: crypto.randomUUID(),
				})
			).status,
		).toBe(400);
	});
	it("requires the enrolled CA and a non-revoked instance for access and refresh", async () => {
		const h = await home();
		const wrong = await mintServiceToken(env.SIGNING_JWK, {
			instance_id: h.instanceId,
			ca_fp: fp,
			issuer: env.ISSUER,
			ttlSeconds: 3600,
		});
		expect((await post("/token/access", { service_token: wrong.jwt })).status).toBe(401);
		const { body } = await capability(
			await post("/token/access", { service_token: h.serviceToken }),
			h.instanceId,
		);
		await env.DB.prepare("UPDATE instances SET revoked_at = 1 WHERE instance_id = ?")
			.bind(h.instanceId)
			.run();
		expect((await post("/token/access", { service_token: h.serviceToken })).status).toBe(403);
		expect((await post("/token/refresh", { device_token: body.device_token })).status).toBe(403);
		await env.DB.prepare("DELETE FROM instances WHERE instance_id = ?").bind(h.instanceId).run();
		expect((await post("/token/access", { service_token: h.serviceToken })).status).toBe(404);
	});
	it("enrolls older-journal attestations as explicitly negotiated v2 with stable retries", async () => {
		const h = await home();
		const attestation = await mintAttestation({
			caPrivateKey: h.ca.privateKey,
			instanceId: h.instanceId,
			deviceFp: fp,
		});
		const request = {
			instance_id: h.instanceId,
			home_attestation: attestation,
			protocol_version: 2,
		};
		const first = await capability(await post("/enroll/device", request), h.instanceId);
		const retry = await capability(await post("/enroll/device", request), h.instanceId);
		expect(first.body).toEqual(retry.body);
		const legacy = await post("/enroll/device", {
			...request,
			protocol_version: undefined,
		});
		expect(((await legacy.json()) as { device_token: string }).device_token).not.toBe(
			first.body.device_token,
		);
	});
	it("refuses non-object acquisition and refresh bodies", async () => {
		for (const body of [null, [], "token", 2]) {
			expect((await post("/token/access", body)).status).toBe(400);
			expect((await post("/token/refresh", body)).status).toBe(400);
			expect((await post("/enroll/device", body)).status).toBe(400);
			expect((await post("/enroll/home", body)).status).toBe(400);
		}
	});
	it("refuses unsupported versions and oversized acquisition bodies", async () => {
		expect(
			(
				await post("/token/refresh", {
					protocol_version: 3,
					device_token: "invalid",
				})
			).status,
		).toBe(400);
		expect((await post("/enroll/device", { protocol_version: 3 })).status).toBe(400);
		expect((await post("/token/access", { service_token: "x".repeat(17000) })).status).toBe(413);
	});
});
