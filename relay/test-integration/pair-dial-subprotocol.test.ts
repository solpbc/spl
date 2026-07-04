// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

// Integration tests for browser-compatible RK carriage on /session/pair-dial.
// The relay uses Sec-WebSocket-Protocol only as an HTTP-upgrade rendezvous
// credential carrier; it never logs RK and never parses tunnel payload bytes.

import { SELF } from "cloudflare:test";
import { beforeAll, describe, expect, it, vi } from "vitest";
import { PAIR_TOKEN_PREFIX, SUBPROTOCOL_V1, parsePairSubprotocol } from "../src/pair-subprotocol";
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

const RK = "0123456789abcdeffedcba9876543210";
const ALT_RK = "11111111111111112222222222222222";

beforeAll(async () => {
	await applyRelayD1Migrations();
});

function newInstanceId(): string {
	return crypto.randomUUID();
}

function rkFor(label: string): string {
	const bytes = new TextEncoder().encode(label);
	const out = new Uint8Array(16);
	for (let i = 0; i < bytes.length; i++) out[i % out.length] ^= bytes[i];
	return Array.from(out, (b) => b.toString(16).padStart(2, "0")).join("");
}

function pairToken(rk: string): string {
	return `${PAIR_TOKEN_PREFIX}${rk}`;
}

function pairSubprotocol(rk: string): string {
	return `${SUBPROTOCOL_V1}, ${pairToken(rk)}`;
}

async function enrollHome(instanceId = newInstanceId()): Promise<{
	instanceId: string;
	serviceToken: string;
}> {
	const ca = await genCaKeypair();
	const res = await SELF.fetch("http://spl.test/enroll/home", {
		method: "POST",
		headers: { "content-type": "application/json" },
		body: JSON.stringify({
			instance_id: instanceId,
			ca_pubkey: ca.pubPem,
		}),
	});
	expect(res.status).toBe(200);
	const body = (await res.json()) as { service_token: string };
	return { instanceId, serviceToken: body.service_token };
}

function pairFetch(
	path: string,
	options: { rk?: string; token?: string; subprotocol?: string } = {},
): Promise<Response> {
	const headers = new Headers({ Upgrade: "websocket" });
	if (options.rk !== undefined) headers.set("Sec-Pair-Key", options.rk);
	if (options.token !== undefined) headers.set("Authorization", `Bearer ${options.token}`);
	if (options.subprotocol !== undefined) {
		headers.set("Sec-WebSocket-Protocol", options.subprotocol);
	}
	return SELF.fetch(`http://spl.test${path}`, { headers });
}

async function acceptWebSocket(res: Response): Promise<WebSocket> {
	if (!res.webSocket) {
		throw new Error(`no webSocket on response: status=${res.status} body=${await res.text()}`);
	}
	const ws = res.webSocket;
	ws.accept();
	return ws;
}

async function pairOpen(
	path: string,
	options: { rk?: string; token?: string; subprotocol?: string },
): Promise<WebSocket> {
	return acceptWebSocket(await pairFetch(path, options));
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

function parseIncoming(signal: string | ArrayBuffer): string {
	expect(typeof signal).toBe("string");
	const parsed = JSON.parse(signal as string) as { type: string; tunnel_id: string };
	expect(parsed.type).toBe("incoming");
	expect(parsed.tunnel_id).toBeTruthy();
	return parsed.tunnel_id;
}

async function coarseKey(res: Response): Promise<string> {
	const headers = Array.from(res.headers.entries())
		.sort(([a], [b]) => a.localeCompare(b))
		.map(([k, v]) => `${k}:${v}`)
		.join(",");
	return `${res.status}|${headers}|${await res.text()}`;
}

async function expectCoarseUnauthorized(res: Response): Promise<string> {
	expect(res.status).toBe(401);
	expect(res.headers.get("x-close-code")).toBe("4401");
	expect(await res.clone().text()).toBe("unauthorized");
	return coarseKey(res);
}

describe("pair-dial subprotocol RK carrier", () => {
	it("keeps a selected subprotocol header on a 101 Response with a webSocket", () => {
		const pair = new WebSocketPair();
		const res = new Response(null, {
			status: 101,
			webSocket: pair[0],
			headers: { "Sec-WebSocket-Protocol": SUBPROTOCOL_V1 },
		});

		expect(res.webSocket).toBeTruthy();
		expect(res.headers.get("sec-websocket-protocol")).toBe(SUBPROTOCOL_V1);
	});

	it("brokers a browser subprotocol pair-dial and echoes only spl-v1", async () => {
		const { serviceToken } = await enrollHome();
		const window = await pairOpen("/session/pair-window", { rk: RK, token: serviceToken });
		const incoming = onMessage(window);

		const mobileRes = await pairFetch("/session/pair-dial", {
			subprotocol: pairSubprotocol(RK),
		});
		const selected = mobileRes.headers.get("sec-websocket-protocol");
		expect(selected).toBe(SUBPROTOCOL_V1);
		expect(selected).not.toContain(pairToken(RK));
		const mobile = await acceptWebSocket(mobileRes);

		const tunnelId = parseIncoming(await incoming);
		const homeTunnel = await pairOpen(`/tunnel/${tunnelId}`, { rk: RK, token: serviceToken });

		const fromMobile = onMessage(homeTunnel);
		mobile.send("hello from browser");
		expect(await fromMobile).toBe("hello from browser");

		const fromHome = onMessage(mobile);
		homeTunnel.send("hello from home");
		expect(await fromHome).toBe("hello from home");

		homeTunnel.close(1000, "test_done");
		mobile.close(1000, "test_done");
		window.close(1000, "test_done");
	});

	it("rejects a subprotocol pair-dial when no window exists", async () => {
		await expectCoarseUnauthorized(
			await pairFetch("/session/pair-dial", {
				subprotocol: pairSubprotocol(rkFor("subprotocol-no-window")),
			}),
		);
	});

	it("collapses malformed carrier rejects to the same coarse 401 as no-window", async () => {
		const noWindow = await pairFetch("/session/pair-dial", {
			subprotocol: pairSubprotocol(rkFor("oracle-no-window")),
		});
		const noRk = await pairFetch("/session/pair-dial");
		const disagree = await pairFetch("/session/pair-dial", {
			rk: RK,
			subprotocol: pairSubprotocol(ALT_RK),
		});
		const missingV1 = await pairFetch("/session/pair-dial", {
			subprotocol: pairToken(rkFor("missing-v1")),
		});
		const duplicateDistinct = await pairFetch("/session/pair-dial", {
			subprotocol: `${SUBPROTOCOL_V1}, ${pairToken(RK)}, ${pairToken(ALT_RK)}`,
		});

		const keys = await Promise.all(
			[noWindow, noRk, disagree, missingV1, duplicateDistinct].map(expectCoarseUnauthorized),
		);
		expect(new Set(keys).size).toBe(1);
	});

	it("keeps native header-carrier pair-dial accepted without a subprotocol echo", async () => {
		const rk = rkFor("native-no-echo");
		const { serviceToken } = await enrollHome();
		const window = await pairOpen("/session/pair-window", { rk, token: serviceToken });
		const incoming = onMessage(window);

		const mobileRes = await pairFetch("/session/pair-dial", { rk });
		expect(mobileRes.headers.get("sec-websocket-protocol")).toBeNull();
		const mobile = await acceptWebSocket(mobileRes);

		const tunnelId = parseIncoming(await incoming);
		const homeTunnel = await pairOpen(`/tunnel/${tunnelId}`, { rk, token: serviceToken });
		const fromMobile = onMessage(homeTunnel);
		mobile.send("native hello");
		expect(await fromMobile).toBe("native hello");

		homeTunnel.close(1000, "test_done");
		mobile.close(1000, "test_done");
		window.close(1000, "test_done");
	});

	it("does not log RK, token, or raw subprotocol during a subprotocol flow", async () => {
		const rk = rkFor("subprotocol-logging");
		const subprotocol = pairSubprotocol(rk);
		const { serviceToken } = await enrollHome();
		const spy = vi.spyOn(console, "log").mockImplementation(() => {});

		try {
			const window = await pairOpen("/session/pair-window", { rk, token: serviceToken });
			const incoming = onMessage(window);
			const mobile = await acceptWebSocket(await pairFetch("/session/pair-dial", { subprotocol }));
			const tunnelId = parseIncoming(await incoming);
			const homeTunnel = await pairOpen(`/tunnel/${tunnelId}`, { rk, token: serviceToken });

			homeTunnel.close(1000, "test_done");
			mobile.close(1000, "test_done");
			window.close(1000, "test_done");

			const lines = spy.mock.calls.map((args) => args.map(String).join(" "));
			for (const line of lines) {
				expect(line).not.toContain(rk);
				expect(line).not.toContain(pairToken(rk));
				expect(line).not.toContain(subprotocol);
				expect(line).not.toContain(serviceToken);
			}
		} finally {
			spy.mockRestore();
		}
	});

	it("parses subprotocol carrier edge cases", () => {
		expect(parsePairSubprotocol(null)).toEqual({
			rk: null,
			offeredV1: false,
			invalid: false,
		});
		expect(parsePairSubprotocol(`${SUBPROTOCOL_V1}, ${pairToken(RK.toUpperCase())}`)).toEqual({
			rk: RK,
			offeredV1: true,
			invalid: false,
		});
		expect(parsePairSubprotocol(`SPL-V1, ${pairToken(RK)}`)).toEqual({
			rk: RK,
			offeredV1: false,
			invalid: true,
		});
		expect(parsePairSubprotocol(`${SUBPROTOCOL_V1}, ${PAIR_TOKEN_PREFIX}nothex`)).toEqual({
			rk: null,
			offeredV1: true,
			invalid: false,
		});
		expect(
			parsePairSubprotocol(`${SUBPROTOCOL_V1}, ${pairToken(RK)}, ${pairToken(ALT_RK)}`),
		).toEqual({
			rk: null,
			offeredV1: true,
			invalid: true,
		});
		expect(
			parsePairSubprotocol(`${SUBPROTOCOL_V1}, ${pairToken(RK)}, ${pairToken(RK.toUpperCase())}`),
		).toEqual({
			rk: RK,
			offeredV1: true,
			invalid: false,
		});
	});
});
