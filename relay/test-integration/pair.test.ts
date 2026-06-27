// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

// Integration tests for TOTP-gated pair tickets and the pair-dial WebSocket path.
// Runs under Miniflare with real D1, InstanceDO SQLite storage, and JWT signing.

import { SELF, env, runInDurableObject } from "cloudflare:test";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { base64UrlDecode, mintDeviceToken, mintServiceToken } from "../src/tokens";
import { generateTotp } from "../src/totp";
import { genCaKeypair } from "../test/fixtures";
import { applyRelayD1Migrations } from "./apply-migrations";

declare module "cloudflare:test" {
	interface ProvidedEnv {
		DB: D1Database;
		INSTANCE: DurableObjectNamespace;
		SIGNING_JWK: string;
		JWKS_PUBLIC: string;
		ISSUER: string;
	}
}

const VALID_TOTP_SECRET = "JBSWY3DPEHPK3PXP";
const VALID_FP = `sha256:${"a".repeat(64)}`;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

beforeAll(async () => {
	await applyRelayD1Migrations();
});

afterEach(() => {
	vi.restoreAllMocks();
});

function newInstanceId(): string {
	return crypto.randomUUID();
}

async function enrollHome(instanceId: string, totpSecret?: string): Promise<void> {
	const ca = await genCaKeypair();
	const body: { instance_id: string; ca_pubkey: string; totp_secret?: string } = {
		instance_id: instanceId,
		ca_pubkey: ca.pubPem,
	};
	if (totpSecret !== undefined) body.totp_secret = totpSecret;
	const res = await SELF.fetch("http://spl.test/enroll/home", {
		method: "POST",
		headers: { "content-type": "application/json" },
		body: JSON.stringify(body),
	});
	expect(res.status).toBe(200);
}

async function validTotp(): Promise<string> {
	return generateTotp(VALID_TOTP_SECRET, Math.floor(Date.now() / 1000));
}

async function postPairTicket(instanceId: string, body: unknown): Promise<Response> {
	return SELF.fetch(`http://spl.test/session/pair-ticket?instance=${instanceId}`, {
		method: "POST",
		headers: { "content-type": "application/json" },
		body: JSON.stringify(body),
	});
}

async function issuePairTicket(instanceId: string): Promise<{
	pairTicket: string;
	expiresAt: string;
	payload: Record<string, unknown>;
}> {
	const code = await validTotp();
	const res = await postPairTicket(instanceId, { instance_id: instanceId, totp: code });
	expect(res.status).toBe(200);
	const body = (await res.json()) as { pair_ticket: string; expires_at: string };
	const payload = jwtPayload(body.pair_ticket);
	return { pairTicket: body.pair_ticket, expiresAt: body.expires_at, payload };
}

function jwtPayload(jwt: string): Record<string, unknown> {
	return JSON.parse(new TextDecoder().decode(base64UrlDecode(jwt.split(".")[1])));
}

async function mintService(instanceId: string): Promise<string> {
	return (
		await mintServiceToken(env.SIGNING_JWK, {
			instance_id: instanceId,
			ca_fp: VALID_FP,
			issuer: env.ISSUER,
			ttlSeconds: 300,
		})
	).jwt;
}

async function mintDevice(instanceId: string): Promise<string> {
	return (
		await mintDeviceToken(env.SIGNING_JWK, {
			instance_id: instanceId,
			device_id: crypto.randomUUID(),
			device_fp: VALID_FP,
			issuer: env.ISSUER,
			ttlSeconds: 300,
		})
	).jwt;
}

async function wsOpen(url: string, token: string): Promise<WebSocket> {
	const res = await SELF.fetch(url, {
		headers: {
			Upgrade: "websocket",
			Authorization: `Bearer ${token}`,
		},
	});
	if (!res.webSocket) {
		throw new Error(`no webSocket on response: status=${res.status} body=${await res.text()}`);
	}
	const ws = res.webSocket;
	ws.accept();
	return ws;
}

function wsFetch(url: string, token: string): Promise<Response> {
	return SELF.fetch(url, {
		headers: {
			Upgrade: "websocket",
			Authorization: `Bearer ${token}`,
		},
	});
}

function onMessage(ws: WebSocket): Promise<string> {
	return new Promise((resolve, reject) => {
		const timer = setTimeout(() => reject(new Error("onMessage timeout")), 5000);
		ws.addEventListener(
			"message",
			(ev) => {
				clearTimeout(timer);
				resolve(String(ev.data));
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

describe("POST /session/pair-ticket", () => {
	it("issues a short-lived session.pair ticket", async () => {
		const instanceId = newInstanceId();
		await enrollHome(instanceId, VALID_TOTP_SECRET);

		const { payload, expiresAt } = await issuePairTicket(instanceId);
		expect(payload.scope).toBe("session.pair");
		expect(payload.sub).toBe(`pair:${instanceId}`);
		expect(payload.instance_id).toBe(instanceId);
		expect(payload.exp).toBe((payload.iat as number) + 60);
		expect(payload.ca_fp).toBeUndefined();
		expect(payload.device_fp).toBeUndefined();
		expect(expiresAt).toBe(new Date((payload.exp as number) * 1000).toISOString());
	});

	it("rejects a stale or invalid TOTP", async () => {
		const instanceId = newInstanceId();
		await enrollHome(instanceId, VALID_TOTP_SECRET);

		const res = await postPairTicket(instanceId, {
			instance_id: instanceId,
			totp: "000000",
		});
		expect(res.status).toBe(401);
		expect(await res.text()).toBe('{"error":"unauthorized"}');
	});

	it("returns byte-identical bodies for unknown/no-secret/wrong-code/revoked", async () => {
		const unknown = newInstanceId();
		const noSecret = newInstanceId();
		const wrongCode = newInstanceId();
		const revoked = newInstanceId();
		await enrollHome(noSecret);
		await enrollHome(wrongCode, VALID_TOTP_SECRET);
		await enrollHome(revoked, VALID_TOTP_SECRET);
		await env.DB.prepare("UPDATE instances SET revoked_at = ? WHERE instance_id = ?")
			.bind(Math.floor(Date.now() / 1000), revoked)
			.run();

		const valid = await validTotp();
		const cases = [
			await postPairTicket(unknown, { instance_id: unknown, totp: valid }),
			await postPairTicket(noSecret, { instance_id: noSecret, totp: valid }),
			await postPairTicket(wrongCode, { instance_id: wrongCode, totp: "000000" }),
			await postPairTicket(revoked, { instance_id: revoked, totp: valid }),
		];
		const bodies = await Promise.all(cases.map((res) => res.text()));

		for (const res of cases) expect(res.status).toBe(401);
		expect(new Set(bodies).size).toBe(1);
		expect(bodies[0]).toBe('{"error":"unauthorized"}');
	});

	it("rate-limits successful issuance to one ticket per TOTP step", async () => {
		const instanceId = newInstanceId();
		await enrollHome(instanceId, VALID_TOTP_SECRET);

		const code = await validTotp();
		const first = await postPairTicket(instanceId, { instance_id: instanceId, totp: code });
		const second = await postPairTicket(instanceId, { instance_id: instanceId, totp: code });

		expect(first.status).toBe(200);
		expect(second.status).toBe(429);
		expect(await second.text()).toBe('{"error":"rate limited"}');
	});

	it("ignores an extra nonce field", async () => {
		const instanceId = newInstanceId();
		await enrollHome(instanceId, VALID_TOTP_SECRET);

		const res = await postPairTicket(instanceId, {
			instance_id: instanceId,
			totp: await validTotp(),
			nonce: "abc123",
		});
		expect(res.status).toBe(200);
	});

	it("does not log TOTP secrets, codes, or pair tickets", async () => {
		const instanceId = newInstanceId();
		await enrollHome(instanceId, VALID_TOTP_SECRET);
		const spy = vi.spyOn(console, "log").mockImplementation(() => {});

		const code = await validTotp();
		const issued = await postPairTicket(instanceId, { instance_id: instanceId, totp: code });
		expect(issued.status).toBe(200);
		const issuedBody = (await issued.json()) as { pair_ticket: string };
		const rejected = await postPairTicket(instanceId, { instance_id: instanceId, totp: "000000" });
		expect(rejected.status).toBe(401);

		const lines = spy.mock.calls.map((args) => args.map(String).join(" "));
		for (const line of lines) {
			expect(line).not.toContain(VALID_TOTP_SECRET);
			expect(line).not.toContain(code);
			expect(line).not.toContain("000000");
			expect(line).not.toContain(issuedBody.pair_ticket);
		}
	});
});

describe("GET /session/pair-dial", () => {
	it("sends the same incoming signal shape as /session/dial", async () => {
		const instanceId = newInstanceId();
		await enrollHome(instanceId, VALID_TOTP_SECRET);
		const listenToken = await mintService(instanceId);
		const deviceToken = await mintDevice(instanceId);
		const home = await wsOpen(`http://spl.test/session/listen?instance=${instanceId}`, listenToken);

		const normalIncoming = onMessage(home);
		const normalMobile = await wsOpen(
			`http://spl.test/session/dial?instance=${instanceId}`,
			deviceToken,
		);
		const normalSignal = await normalIncoming;

		const { pairTicket } = await issuePairTicket(instanceId);
		const pairIncoming = onMessage(home);
		const pairMobile = await wsOpen(
			`http://spl.test/session/pair-dial?instance=${instanceId}`,
			pairTicket,
		);
		const pairSignal = await pairIncoming;

		const normal = JSON.parse(normalSignal) as { type: string; tunnel_id: string };
		const pair = JSON.parse(pairSignal) as { type: string; tunnel_id: string };
		expect(normal.type).toBe("incoming");
		expect(pair.type).toBe("incoming");
		expect(Object.keys(normal).sort()).toEqual(["tunnel_id", "type"]);
		expect(Object.keys(pair).sort()).toEqual(Object.keys(normal).sort());
		expect(normal.tunnel_id).toMatch(UUID_RE);
		expect(pair.tunnel_id).toMatch(UUID_RE);
		expect(normalSignal.replace(normal.tunnel_id, "<uuid>")).toBe(
			pairSignal.replace(pair.tunnel_id, "<uuid>"),
		);

		normalMobile.close(1000, "test_done");
		pairMobile.close(1000, "test_done");
		home.close(1000, "test_done");
	});

	it("consumes pair tickets once and stores the jti durably", async () => {
		const instanceId = newInstanceId();
		await enrollHome(instanceId, VALID_TOTP_SECRET);
		const listenToken = await mintService(instanceId);
		const { pairTicket, payload } = await issuePairTicket(instanceId);
		const jti = payload.jti as string;
		const home = await wsOpen(`http://spl.test/session/listen?instance=${instanceId}`, listenToken);

		const incoming = onMessage(home);
		const mobile = await wsOpen(
			`http://spl.test/session/pair-dial?instance=${instanceId}`,
			pairTicket,
		);
		await incoming;

		const replay = await wsFetch(
			`http://spl.test/session/pair-dial?instance=${instanceId}`,
			pairTicket,
		);
		expect(replay.status).toBe(401);
		expect(await replay.text()).toBe("unauthorized");

		const id = env.INSTANCE.idFromName(instanceId);
		const stub = env.INSTANCE.get(id);
		const beforeAbort = await runInDurableObject(stub, (_instance, state) =>
			state.storage.sql.exec<{ jti: string }>("SELECT jti FROM pair_jti_consumed").toArray(),
		);
		expect(beforeAbort.map((row) => row.jti)).toContain(jti);

		await runInDurableObject(stub, (_instance, state) => state.abort("evict")).catch(
			() => undefined,
		);
		const freshStub = env.INSTANCE.get(id);
		const afterAbort = await runInDurableObject(freshStub, (_instance, state) =>
			state.storage.sql.exec<{ jti: string }>("SELECT jti FROM pair_jti_consumed").toArray(),
		);
		expect(afterAbort.map((row) => row.jti)).toContain(jti);

		mobile.close(1000, "test_done");
		home.close(1000, "test_done");
	});

	it("does not burn a ticket when no home is listening", async () => {
		const instanceId = newInstanceId();
		await enrollHome(instanceId, VALID_TOTP_SECRET);
		const listenToken = await mintService(instanceId);
		const { pairTicket } = await issuePairTicket(instanceId);

		const offline = await wsFetch(
			`http://spl.test/session/pair-dial?instance=${instanceId}`,
			pairTicket,
		);
		expect(offline.status).toBe(503);
		expect(await offline.text()).toBe("no home listening");

		const home = await wsOpen(`http://spl.test/session/listen?instance=${instanceId}`, listenToken);
		const incoming = onMessage(home);
		const mobile = await wsOpen(
			`http://spl.test/session/pair-dial?instance=${instanceId}`,
			pairTicket,
		);
		await incoming;

		mobile.close(1000, "test_done");
		home.close(1000, "test_done");
	});

	it("enforces pair and dial scopes on their distinct routes", async () => {
		const instanceId = newInstanceId();
		await enrollHome(instanceId, VALID_TOTP_SECRET);
		const deviceToken = await mintDevice(instanceId);
		const { pairTicket } = await issuePairTicket(instanceId);

		const deviceOnPair = await wsFetch(
			`http://spl.test/session/pair-dial?instance=${instanceId}`,
			deviceToken,
		);
		const pairOnDial = await wsFetch(
			`http://spl.test/session/dial?instance=${instanceId}`,
			pairTicket,
		);

		expect(deviceOnPair.status).toBe(401);
		expect(pairOnDial.status).toBe(401);
	});
});
