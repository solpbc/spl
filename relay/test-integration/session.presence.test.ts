// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

// Presence-hold integration tests run under vitest.workers.presence.config.ts
// with PRESENCE_HOLD_ENABLED set at Worker/DO env-bindings load time.

import { SELF, env } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";
import { mintDeviceToken, mintServiceToken } from "../src/tokens";
import { applyRelayD1Migrations } from "./apply-migrations";

const VALID_FP = `sha256:${"a".repeat(64)}`;

declare module "cloudflare:test" {
	interface ProvidedEnv {
		DB: D1Database;
		SIGNING_JWK: string;
		JWKS_PUBLIC: string;
		ISSUER: string;
		PRESENCE_HOLD_ENABLED: string;
	}
}

beforeAll(async () => {
	await applyRelayD1Migrations();
});

function newInstanceId(): string {
	return crypto.randomUUID();
}

async function mintService(instanceId: string): Promise<string> {
	const m = await mintServiceToken(env.SIGNING_JWK, {
		instance_id: instanceId,
		ca_fp: VALID_FP,
		issuer: env.ISSUER,
		ttlSeconds: 300,
	});
	return m.jwt;
}

async function mintDevice(instanceId: string): Promise<string> {
	const m = await mintDeviceToken(env.SIGNING_JWK, {
		instance_id: instanceId,
		device_id: crypto.randomUUID(),
		device_fp: VALID_FP,
		issuer: env.ISSUER,
		ttlSeconds: 300,
	});
	return m.jwt;
}

function wsFetch(url: string, token: string): Promise<Response> {
	return SELF.fetch(url, {
		headers: {
			Upgrade: "websocket",
			Authorization: `Bearer ${token}`,
		},
	});
}

async function wsConnect(url: string, token: string): Promise<WebSocket> {
	const res = await wsFetch(url, token);
	expect(res.status).toBe(101);
	if (!res.webSocket) {
		throw new Error(`no webSocket on response: status=${res.status}`);
	}
	return res.webSocket;
}

async function wsOpen(url: string, token: string): Promise<WebSocket> {
	const ws = await wsConnect(url, token);
	ws.accept();
	return ws;
}

async function wsHeldDial(url: string, token: string): Promise<WebSocket> {
	const res = await wsFetch(url, token);
	expect(res.status).toBe(101);
	expect(await res.text()).toBe("");
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

function sleep(ms: number): Promise<void> {
	return new Promise((resolve) => setTimeout(resolve, ms));
}

function expectNoMessage(ws: WebSocket, timeoutMs = 400): Promise<void> {
	return new Promise((resolve, reject) => {
		const timer = setTimeout(() => {
			cleanup();
			resolve();
		}, timeoutMs);
		const onMsg = () => {
			cleanup();
			reject(new Error("unexpected incoming message"));
		};
		const cleanup = () => {
			clearTimeout(timer);
			ws.removeEventListener("message", onMsg);
		};
		ws.addEventListener("message", onMsg);
	});
}

function collectMessages(ws: WebSocket, count: number): Promise<Array<string | ArrayBuffer>> {
	return new Promise((resolve, reject) => {
		const messages: Array<string | ArrayBuffer> = [];
		const timer = setTimeout(() => {
			cleanup();
			reject(new Error(`collectMessages timeout: got ${messages.length}/${count}`));
		}, 5000);
		const onMsg = (ev: MessageEvent) => {
			messages.push(ev.data);
			if (messages.length === count) {
				cleanup();
				resolve(messages);
			}
		};
		const onClose = () => {
			cleanup();
			reject(new Error("socket closed before all messages"));
		};
		const cleanup = () => {
			clearTimeout(timer);
			ws.removeEventListener("message", onMsg);
			ws.removeEventListener("close", onClose);
		};
		ws.addEventListener("message", onMsg);
		ws.addEventListener("close", onClose);
	});
}

function parseIncoming(signal: string | ArrayBuffer): string {
	expect(typeof signal).toBe("string");
	const parsed = JSON.parse(signal as string) as { type: string; tunnel_id: string };
	expect(parsed.type).toBe("incoming");
	expect(parsed.tunnel_id).toBeTruthy();
	return parsed.tunnel_id;
}

async function assertRoundTrip(mobile: WebSocket, homeTunnel: WebSocket): Promise<void> {
	const fromMobile = onMessage(homeTunnel);
	mobile.send("hello from mobile");
	expect(await fromMobile).toBe("hello from mobile");

	const fromHome = onMessage(mobile);
	homeTunnel.send("hello from home");
	expect(await fromHome).toBe("hello from home");
}

describe("presence-hold /session/dial", () => {
	it("holds an offline dial, brokers it when listen opens, and relays opaque bytes", async () => {
		const instanceId = newInstanceId();
		const listenToken = await mintService(instanceId);
		const dialToken = await mintDevice(instanceId);

		const mobile = await wsHeldDial(
			`http://spl.test/session/dial?instance=${instanceId}`,
			dialToken,
		);

		const home = await wsConnect(
			`http://spl.test/session/listen?instance=${instanceId}`,
			listenToken,
		);
		const incoming = onMessage(home);
		home.accept();
		const tunnelId = parseIncoming(await incoming);

		const homeTunnel = await wsOpen(
			`http://spl.test/tunnel/${tunnelId}?instance=${instanceId}`,
			listenToken,
		);
		await assertRoundTrip(mobile, homeTunnel);

		homeTunnel.close(1000, "test_done");
		mobile.close(1000, "test_done");
		home.close(1000, "test_done");
	});

	it("cleans up a held dial that closes before any home appears", async () => {
		const instanceId = newInstanceId();
		const listenToken = await mintService(instanceId);
		const dialToken = await mintDevice(instanceId);

		const mobile = await wsHeldDial(
			`http://spl.test/session/dial?instance=${instanceId}`,
			dialToken,
		);
		const mobileClose = Promise.race([onClose(mobile), sleep(100)]);
		mobile.close(1000, "test_done");
		await mobileClose;

		const home = await wsConnect(
			`http://spl.test/session/listen?instance=${instanceId}`,
			listenToken,
		);
		const noIncoming = expectNoMessage(home);
		home.accept();
		await noIncoming;

		home.close(1000, "test_done");
	});

	it("brokers every waiting dial with a distinct tunnel id", async () => {
		const instanceId = newInstanceId();
		const listenToken = await mintService(instanceId);
		const dialTokens = await Promise.all([
			mintDevice(instanceId),
			mintDevice(instanceId),
			mintDevice(instanceId),
		]);
		const mobiles = await Promise.all(
			dialTokens.map((token) =>
				wsHeldDial(`http://spl.test/session/dial?instance=${instanceId}`, token),
			),
		);

		const home = await wsConnect(
			`http://spl.test/session/listen?instance=${instanceId}`,
			listenToken,
		);
		const incoming = collectMessages(home, 3);
		home.accept();
		const tunnelIds = (await incoming).map(parseIncoming);

		expect(new Set(tunnelIds).size).toBe(3);

		for (const mobile of mobiles) mobile.close(1000, "test_done");
		home.close(1000, "test_done");
	});

	it("does not re-signal an already-paired waiting dial after listen flap", async () => {
		const instanceId = newInstanceId();
		const listenToken = await mintService(instanceId);
		const dialToken = await mintDevice(instanceId);

		const mobile = await wsHeldDial(
			`http://spl.test/session/dial?instance=${instanceId}`,
			dialToken,
		);

		const firstHome = await wsConnect(
			`http://spl.test/session/listen?instance=${instanceId}`,
			listenToken,
		);
		const incoming = onMessage(firstHome);
		firstHome.accept();
		const tunnelId = parseIncoming(await incoming);

		const homeTunnel = await wsOpen(
			`http://spl.test/tunnel/${tunnelId}?instance=${instanceId}`,
			listenToken,
		);
		await assertRoundTrip(mobile, homeTunnel);

		const firstHomeClose = Promise.race([onClose(firstHome), sleep(100)]);
		firstHome.close(1000, "listen_flap");
		await firstHomeClose;

		const secondHome = await wsConnect(
			`http://spl.test/session/listen?instance=${instanceId}`,
			listenToken,
		);
		const noIncoming = expectNoMessage(secondHome);
		secondHome.accept();
		await noIncoming;

		homeTunnel.close(1000, "test_done");
		mobile.close(1000, "test_done");
		secondHome.close(1000, "test_done");
	});
});
