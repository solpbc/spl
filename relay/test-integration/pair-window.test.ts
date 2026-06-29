// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

// Integration tests for RK-addressed pair-window admission. The relay never
// derives or stores RK here; tests use fixed hex strings only as routing inputs.

import { SELF, env, runDurableObjectAlarm, runInDurableObject } from "cloudflare:test";
import { beforeAll, describe, expect, it, vi } from "vitest";
import { mintDeviceToken, mintServiceToken } from "../src/tokens";
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

const VALID_FP = `sha256:${"a".repeat(64)}`;
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

function pairFetch(path: string, options: { rk?: string; token?: string } = {}): Promise<Response> {
	const headers = new Headers({ Upgrade: "websocket" });
	if (options.rk !== undefined) headers.set("Sec-Pair-Key", options.rk);
	if (options.token !== undefined) headers.set("Authorization", `Bearer ${options.token}`);
	return SELF.fetch(`http://spl.test${path}`, { headers });
}

async function pairOpen(path: string, options: { rk: string; token?: string }): Promise<WebSocket> {
	const res = await pairFetch(path, options);
	if (!res.webSocket) {
		throw new Error(`no webSocket on response: status=${res.status} body=${await res.text()}`);
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
		ws.addEventListener("close", (ev) => resolve(ev as CloseEvent), { once: true });
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

describe("pair-window bridge", () => {
	it("brokers without ?instance and relays opaque bytes both ways", async () => {
		const { serviceToken } = await enrollHome();
		const window = await pairOpen("/session/pair-window", { rk: RK, token: serviceToken });
		const incoming = onMessage(window);

		const mobile = await pairOpen("/session/pair-dial", { rk: RK });
		const tunnelId = parseIncoming(await incoming);
		const homeTunnel = await pairOpen(`/tunnel/${tunnelId}`, { rk: RK, token: serviceToken });

		const fromMobile = onMessage(homeTunnel);
		mobile.send("hello from mobile");
		expect(await fromMobile).toBe("hello from mobile");

		const fromHome = onMessage(mobile);
		homeTunnel.send("hello from home");
		expect(await fromHome).toBe("hello from home");

		homeTunnel.close(1000, "test_done");
		mobile.close(1000, "test_done");
		window.close(1000, "test_done");
	});

	it("rejects pair-dial when no window exists", async () => {
		await expectCoarseUnauthorized(
			await pairFetch("/session/pair-dial", { rk: rkFor("no-window") }),
		);
	});

	it("consumes a window after the first successful broker", async () => {
		const rk = rkFor("consume");
		const { serviceToken } = await enrollHome();
		const window = await pairOpen("/session/pair-window", { rk, token: serviceToken });
		const incoming = onMessage(window);
		const mobile = await pairOpen("/session/pair-dial", { rk });
		await incoming;

		await expectCoarseUnauthorized(await pairFetch("/session/pair-dial", { rk }));

		mobile.close(1000, "test_done");
		window.close(1000, "test_done");
	});

	// Rollback-on-send-fail is inspection-covered in handlePairDial: the window is
	// only marked signaled after brokerTunnel returns 101. The harness cannot
	// deterministically force signalIncoming() to throw without replacing runtime
	// WebSocket internals.
	it("requires an enrolled, non-revoked home service token to open a window", async () => {
		const missing = await pairFetch("/session/pair-window", { rk: rkFor("missing-token") });
		await expectCoarseUnauthorized(missing);

		const { instanceId, serviceToken } = await enrollHome();
		const deviceToken = await mintDevice(instanceId);
		const wrongScope = await pairFetch("/session/pair-window", {
			rk: rkFor("wrong-scope"),
			token: deviceToken,
		});
		await expectCoarseUnauthorized(wrongScope);

		const unknownInstance = newInstanceId();
		const unenrolled = await pairFetch("/session/pair-window", {
			rk: rkFor("unenrolled"),
			token: await mintService(unknownInstance),
		});
		await expectCoarseUnauthorized(unenrolled);

		await env.DB.prepare("UPDATE instances SET revoked_at = ? WHERE instance_id = ?")
			.bind(Math.floor(Date.now() / 1000), instanceId)
			.run();
		const revoked = await pairFetch("/session/pair-window", {
			rk: rkFor("revoked"),
			token: serviceToken,
		});
		await expectCoarseUnauthorized(revoked);
	});

	it("rejects pairing tunnel attach unless the service token matches the window instance", async () => {
		const rk = rkFor("tunnel-auth");
		const homeA = await enrollHome();
		const homeB = await enrollHome();
		const window = await pairOpen("/session/pair-window", { rk, token: homeA.serviceToken });
		const incoming = onMessage(window);
		const mobile = await pairOpen("/session/pair-dial", { rk });
		const tunnelId = parseIncoming(await incoming);

		await expectCoarseUnauthorized(
			await pairFetch(`/tunnel/${tunnelId}`, { rk, token: homeB.serviceToken }),
		);

		mobile.close(1000, "test_done");
		window.close(1000, "test_done");
	});

	it("requires RK in the header, not the query string", async () => {
		await expectCoarseUnauthorized(await pairFetch(`/session/pair-dial?rk=${ALT_RK}`));
	});

	it("limits failed empty-window dials and resets the counter on pair-window open", async () => {
		const rk = rkFor("limiter-reset");
		let limitedKey = "";
		for (let i = 0; i < 52; i++) {
			limitedKey = await expectCoarseUnauthorized(await pairFetch("/session/pair-dial", { rk }));
		}
		expect(limitedKey).toContain("401|");

		const { serviceToken } = await enrollHome();
		const window = await pairOpen("/session/pair-window", { rk, token: serviceToken });
		const incoming = onMessage(window);
		const mobile = await pairOpen("/session/pair-dial", { rk });
		await incoming;

		mobile.close(1000, "test_done");
		window.close(1000, "test_done");
	});

	it("returns byte-identical coarse responses for no-window, consumed, and limited dials", async () => {
		const noWindow = await pairFetch("/session/pair-dial", { rk: rkFor("oracle-no-window") });

		const consumedRk = rkFor("oracle-consumed");
		const { serviceToken } = await enrollHome();
		const window = await pairOpen("/session/pair-window", {
			rk: consumedRk,
			token: serviceToken,
		});
		const incoming = onMessage(window);
		const mobile = await pairOpen("/session/pair-dial", { rk: consumedRk });
		await incoming;
		const consumed = await pairFetch("/session/pair-dial", { rk: consumedRk });

		const limitedRk = rkFor("oracle-limited");
		for (let i = 0; i < 51; i++) {
			await expectCoarseUnauthorized(await pairFetch("/session/pair-dial", { rk: limitedRk }));
		}
		const limited = await pairFetch("/session/pair-dial", { rk: limitedRk });

		const keys = await Promise.all([noWindow, consumed, limited].map(coarseKey));
		expect(new Set(keys).size).toBe(1);

		mobile.close(1000, "test_done");
		window.close(1000, "test_done");
	});

	it("does not log RK or token strings during a complete pair-window flow", async () => {
		const rk = rkFor("logging");
		const { serviceToken } = await enrollHome();
		const spy = vi.spyOn(console, "log").mockImplementation(() => {});

		try {
			const window = await pairOpen("/session/pair-window", { rk, token: serviceToken });
			const incoming = onMessage(window);
			const mobile = await pairOpen("/session/pair-dial", { rk });
			const tunnelId = parseIncoming(await incoming);
			const homeTunnel = await pairOpen(`/tunnel/${tunnelId}`, { rk, token: serviceToken });

			homeTunnel.close(1000, "test_done");
			mobile.close(1000, "test_done");
			window.close(1000, "test_done");

			const lines = spy.mock.calls.map((args) => args.map(String).join(" "));
			for (const line of lines) {
				expect(line).not.toContain(rk);
				expect(line).not.toContain(serviceToken);
			}
		} finally {
			spy.mockRestore();
		}
	});

	it("closes a stranded window through the Durable Object alarm", async () => {
		const rk = rkFor("ttl");
		const { serviceToken } = await enrollHome();
		const window = await pairOpen("/session/pair-window", { rk, token: serviceToken });
		const close = onClose(window);
		const id = env.INSTANCE.idFromName(rk);
		const stub = env.INSTANCE.get(id);

		const alarmAt = await runInDurableObject(stub, (_instance, state) => state.storage.getAlarm());
		expect(alarmAt).not.toBeNull();
		expect(await runDurableObjectAlarm(stub)).toBe(true);
		await close;

		await expectCoarseUnauthorized(await pairFetch("/session/pair-dial", { rk }));
	});
});
