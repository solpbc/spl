// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

// Integration tests for the WebSocket session plane: /session/listen,
// /session/dial, /tunnel/<id>. Exercises the DO-level byte relay, WS-tag
// cardinality enforcement, and the pending-buffer behavior.

import { SELF, applyD1Migrations, env } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";
import { mintAccountToken, mintDeviceToken } from "../src/tokens";
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

function newInstanceId(): string {
	return crypto.randomUUID();
}

async function mintAccount(instanceId: string): Promise<string> {
	const m = await mintAccountToken(env.SIGNING_JWK, {
		instance_id: instanceId,
		ca_fp: "sha256:test",
		issuer: env.ISSUER,
		ttlSeconds: 300,
	});
	return m.jwt;
}

async function mintDevice(instanceId: string): Promise<string> {
	const m = await mintDeviceToken(env.SIGNING_JWK, {
		instance_id: instanceId,
		device_id: crypto.randomUUID(),
		device_fp: "sha256:test",
		issuer: env.ISSUER,
		ttlSeconds: 300,
	});
	return m.jwt;
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

function onClose(ws: WebSocket): Promise<CloseEvent> {
	return new Promise((resolve) => {
		ws.addEventListener(
			"close",
			(ev) => {
				resolve(ev as CloseEvent);
			},
			{ once: true },
		);
	});
}

describe("/session/listen auth", () => {
	it("rejects missing tokens with 401", async () => {
		const res = await SELF.fetch(`http://spl.test/session/listen?instance=${newInstanceId()}`, {
			headers: { Upgrade: "websocket" },
		});
		expect(res.status).toBe(401);
	});

	it("rejects a dial token on the listen route (wrong_scope)", async () => {
		const instanceId = newInstanceId();
		const token = await mintDevice(instanceId);
		const res = await SELF.fetch(`http://spl.test/session/listen?instance=${instanceId}`, {
			headers: {
				Upgrade: "websocket",
				Authorization: `Bearer ${token}`,
			},
		});
		expect(res.status).toBe(401);
	});

	it("accepts a valid account token and holds the WS open", async () => {
		const instanceId = newInstanceId();
		const token = await mintAccount(instanceId);
		const ws = await wsOpen(`http://spl.test/session/listen?instance=${instanceId}`, token);
		ws.close(1000, "test_done");
	});
});

describe("pair signal + tunnel pairing", () => {
	it("minted dial triggers an incoming message on the home listen WS", async () => {
		const instanceId = newInstanceId();
		const listenToken = await mintAccount(instanceId);
		const dialToken = await mintDevice(instanceId);

		const home = await wsOpen(`http://spl.test/session/listen?instance=${instanceId}`, listenToken);
		const incoming = onMessage(home);

		const mobile = await wsOpen(`http://spl.test/session/dial?instance=${instanceId}`, dialToken);
		const signal = (await incoming) as string;
		const parsed = JSON.parse(signal) as { type: string; tunnel_id: string };
		expect(parsed.type).toBe("incoming");
		expect(parsed.tunnel_id).toBeTruthy();

		mobile.close(1000, "test_done");
		home.close(1000, "test_done");
	});

	it("home tunnel WS + mobile tunnel WS relay opaque bytes after pair", async () => {
		const instanceId = newInstanceId();
		const listenToken = await mintAccount(instanceId);
		const dialToken = await mintDevice(instanceId);

		const home = await wsOpen(`http://spl.test/session/listen?instance=${instanceId}`, listenToken);
		const incoming = onMessage(home);
		const mobile = await wsOpen(`http://spl.test/session/dial?instance=${instanceId}`, dialToken);
		const signal = (await incoming) as string;
		const { tunnel_id } = JSON.parse(signal);

		const homeTunnel = await wsOpen(
			`http://spl.test/tunnel/${tunnel_id}?instance=${instanceId}`,
			listenToken,
		);

		// Round-trip a string both ways.
		const fromMobile = onMessage(homeTunnel);
		mobile.send("hello from mobile");
		expect(await fromMobile).toBe("hello from mobile");

		const fromHome = onMessage(mobile);
		homeTunnel.send("hello from home");
		expect(await fromHome).toBe("hello from home");

		homeTunnel.close(1000, "test_done");
		mobile.close(1000, "test_done");
		home.close(1000, "test_done");
	});

	it("/tunnel/<id> returns 404 if mobile never attached", async () => {
		const instanceId = newInstanceId();
		const listenToken = await mintAccount(instanceId);
		const home = await wsOpen(`http://spl.test/session/listen?instance=${instanceId}`, listenToken);
		const res = await SELF.fetch(
			`http://spl.test/tunnel/${crypto.randomUUID()}?instance=${instanceId}`,
			{
				headers: {
					Upgrade: "websocket",
					Authorization: `Bearer ${listenToken}`,
				},
			},
		);
		expect(res.status).toBe(404);
		home.close(1000, "test_done");
	});
});

describe("WS-tag cardinality enforcement", () => {
	it("second listen WS replaces the first", async () => {
		const instanceId = newInstanceId();
		const token = await mintAccount(instanceId);
		const first = await wsOpen(`http://spl.test/session/listen?instance=${instanceId}`, token);
		const firstClose = onClose(first);
		const second = await wsOpen(`http://spl.test/session/listen?instance=${instanceId}`, token);
		const ev = await firstClose;
		expect(ev.code).toBe(1000);
		expect(ev.reason).toBe("replaced");
		second.close(1000, "test_done");
	});
});

describe("/session/dial fails if no home is listening", () => {
	it("returns 503 when listen WS is not open", async () => {
		const instanceId = newInstanceId();
		const dialToken = await mintDevice(instanceId);
		const res = await SELF.fetch(`http://spl.test/session/dial?instance=${instanceId}`, {
			headers: {
				Upgrade: "websocket",
				Authorization: `Bearer ${dialToken}`,
			},
		});
		expect(res.status).toBe(503);
	});
});
