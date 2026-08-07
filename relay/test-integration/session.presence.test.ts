// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

// Presence-hold integration tests run under vitest.workers.presence.config.ts
// with PRESENCE_HOLD_ENABLED set at Worker/DO env-bindings load time.

import { SELF, env, runInDurableObject } from "cloudflare:test";
import { beforeAll, describe, expect, it, vi } from "vitest";
import { tagListen, tagTunnelHome, tagTunnelMobile, tagWaiting } from "../src/instance-do";
import { mintDeviceToken, mintServiceToken } from "../src/tokens";
import { applyRelayD1Migrations } from "./apply-migrations";

const VALID_FP = `sha256:${"a".repeat(64)}`;

type LeaseInspectable = {
	attachLeases: Map<string, ReturnType<typeof setTimeout>>;
	pending: Map<string, unknown>;
};

type DrainInspectable = LeaseInspectable & {
	drainPending(tunnelId: string, tag: string, ws: WebSocket, instanceId: string): boolean;
};

interface MobileAttachment {
	tunnel_id?: string;
	paired?: boolean;
	retired?: boolean;
}

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

function logLines(spy: ReturnType<typeof vi.spyOn>): string {
	return spy.mock.calls.map(([arg]) => String(arg)).join("\n");
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

	it("re-offers the same unpaired tunnel id after its listener is replaced", async () => {
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
		const firstIncoming = onMessage(firstHome);
		firstHome.accept();
		const tunnelId = parseIncoming(await firstIncoming);
		firstHome.close(1000, "listener_replaced");

		const replacement = await wsConnect(
			`http://spl.test/session/listen?instance=${instanceId}`,
			listenToken,
		);
		const replacementIncoming = onMessage(replacement);
		replacement.accept();
		expect(parseIncoming(await replacementIncoming)).toBe(tunnelId);

		mobile.close(1000, "test_done");
		replacement.close(1000, "test_done");
	});

	it("re-offers every unpaired held dial exactly once after listener loss", async () => {
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
		const first = await wsConnect(
			`http://spl.test/session/listen?instance=${instanceId}`,
			listenToken,
		);
		const firstOffers = collectMessages(first, mobiles.length);
		first.accept();
		const firstIds = (await firstOffers).map(parseIncoming).sort();
		first.close(1000, "listener_replaced");

		const replacement = await wsConnect(
			`http://spl.test/session/listen?instance=${instanceId}`,
			listenToken,
		);
		const replacementOffers = collectMessages(replacement, mobiles.length);
		replacement.accept();
		expect((await replacementOffers).map(parseIncoming).sort()).toEqual(firstIds);
		await expectNoMessage(replacement);

		for (const mobile of mobiles) mobile.close(1000, "test_done");
		replacement.close(1000, "test_done");
	});

	it("offers an already-open listener once and drains the first opaque bytes", async () => {
		const instanceId = newInstanceId();
		const listenToken = await mintService(instanceId);
		const dialToken = await mintDevice(instanceId);
		const home = await wsOpen(`http://spl.test/session/listen?instance=${instanceId}`, listenToken);
		const incoming = onMessage(home);
		const mobile = await wsHeldDial(
			`http://spl.test/session/dial?instance=${instanceId}`,
			dialToken,
		);
		const tunnelId = parseIncoming(await incoming);
		const noSecondOffer = expectNoMessage(home);
		const opaque = new Uint8Array([0, 255, 17, 42]).buffer;
		mobile.send(opaque);
		const stub = env.INSTANCE.get(env.INSTANCE.idFromName(instanceId));
		await vi.waitFor(async () => {
			expect(
				await runInDurableObject(
					stub,
					(instance) => (instance as unknown as LeaseInspectable).attachLeases.size,
				),
			).toBe(1);
		});
		const homeTunnel = await wsOpen(
			`http://spl.test/tunnel/${tunnelId}?instance=${instanceId}`,
			listenToken,
		);
		const drained = await onMessage(homeTunnel);
		expect(Array.from(new Uint8Array(drained as ArrayBuffer))).toEqual([0, 255, 17, 42]);
		expect(await noSecondOffer).toBeUndefined();
		expect(
			await runInDurableObject(stub, (instance, state) => {
				const mobileServer = state.getWebSockets(tagTunnelMobile(tunnelId))[0];
				return {
					leaseCount: (instance as unknown as LeaseInspectable).attachLeases.size,
					waiting: state.getWebSockets(tagWaiting(instanceId)).length,
					paired: (mobileServer?.deserializeAttachment() as MobileAttachment | undefined)?.paired,
				};
			}),
		).toEqual({ leaseCount: 0, waiting: 1, paired: true });
		homeTunnel.close(1000, "test_done");
		mobile.close(1000, "test_done");
		home.close(1000, "test_done");
	});

	it("does not re-offer a paired id, and re-offers when paired is neutralized", async () => {
		const instanceId = newInstanceId();
		const listenToken = await mintService(instanceId);
		const dialToken = await mintDevice(instanceId);
		const mobile = await wsHeldDial(
			`http://spl.test/session/dial?instance=${instanceId}`,
			dialToken,
		);
		const first = await wsConnect(
			`http://spl.test/session/listen?instance=${instanceId}`,
			listenToken,
		);
		const firstIncoming = onMessage(first);
		first.accept();
		const tunnelId = parseIncoming(await firstIncoming);
		const homeTunnel = await wsOpen(
			`http://spl.test/tunnel/${tunnelId}?instance=${instanceId}`,
			listenToken,
		);
		first.close(1000, "listener_replaced");
		const quietReplacement = await wsConnect(
			`http://spl.test/session/listen?instance=${instanceId}`,
			listenToken,
		);
		const noIncoming = expectNoMessage(quietReplacement);
		quietReplacement.accept();
		await noIncoming;

		const stub = env.INSTANCE.get(env.INSTANCE.idFromName(instanceId));
		await runInDurableObject(stub, (_instance, state) => {
			const server = state.getWebSockets(tagTunnelMobile(tunnelId))[0];
			if (!server) throw new Error("paired mobile missing");
			const attachment = server.deserializeAttachment() as MobileAttachment;
			attachment.paired = false;
			server.serializeAttachment(attachment);
		});
		quietReplacement.close(1000, "listener_replaced");
		const mutatedReplacement = await wsConnect(
			`http://spl.test/session/listen?instance=${instanceId}`,
			listenToken,
		);
		const reoffer = onMessage(mutatedReplacement);
		mutatedReplacement.accept();
		expect(parseIncoming(await reoffer)).toBe(tunnelId);

		homeTunnel.close(1000, "test_done");
		mobile.close(1000, "test_done");
		mutatedReplacement.close(1000, "test_done");
	});

	it("first home attach wins and a second attach is rejected", async () => {
		const instanceId = newInstanceId();
		const listenToken = await mintService(instanceId);
		const dialToken = await mintDevice(instanceId);
		const home = await wsConnect(
			`http://spl.test/session/listen?instance=${instanceId}`,
			listenToken,
		);
		const incoming = onMessage(home);
		home.accept();
		const mobile = await wsHeldDial(
			`http://spl.test/session/dial?instance=${instanceId}`,
			dialToken,
		);
		const tunnelId = parseIncoming(await incoming);
		const first = await wsFetch(
			`http://spl.test/tunnel/${tunnelId}?instance=${instanceId}`,
			listenToken,
		);
		expect(first.status).toBe(101);
		first.webSocket?.accept();
		const loser = await wsFetch(
			`http://spl.test/tunnel/${tunnelId}?instance=${instanceId}`,
			listenToken,
		);
		expect(loser.status).toBe(409);
		expect(await loser.text()).toBe("tunnel already paired");
		first.webSocket?.close(1000, "test_done");
		mobile.close(1000, "test_done");
		home.close(1000, "test_done");
	});

	it("retires an errored unpaired mobile so it cannot be re-offered", async () => {
		const instanceId = newInstanceId();
		const listenToken = await mintService(instanceId);
		const dialToken = await mintDevice(instanceId);
		const mobile = await wsHeldDial(
			`http://spl.test/session/dial?instance=${instanceId}`,
			dialToken,
		);
		const stub = env.INSTANCE.get(env.INSTANCE.idFromName(instanceId));
		const retired = await runInDurableObject(stub, async (instance, state) => {
			const server = state.getWebSockets(tagWaiting(instanceId))[0];
			if (!server) throw new Error("held mobile missing");
			await (
				instance as { webSocketError(ws: WebSocket, error: unknown): Promise<void> }
			).webSocketError(server, new Error("test error"));
			return server.deserializeAttachment() as MobileAttachment;
		});
		expect(retired).toMatchObject({ paired: false, retired: true });
		const home = await wsConnect(
			`http://spl.test/session/listen?instance=${instanceId}`,
			listenToken,
		);
		const noIncoming = expectNoMessage(home);
		home.accept();
		await noIncoming;
		mobile.close(1000, "test_done");
		home.close(1000, "test_done");
	});

	it("emits one dial_open across re-offers without logging sensitive values", async () => {
		const instanceId = newInstanceId();
		const listenToken = await mintService(instanceId);
		const dialToken = await mintDevice(instanceId);
		const payloadCanary = "opaque-payload-canary";
		const spy = vi.spyOn(console, "log").mockImplementation(() => {});
		try {
			const mobile = await wsHeldDial(
				`http://spl.test/session/dial?instance=${instanceId}`,
				dialToken,
			);
			const first = await wsConnect(
				`http://spl.test/session/listen?instance=${instanceId}`,
				listenToken,
			);
			const incoming = onMessage(first);
			first.accept();
			const tunnelId = parseIncoming(await incoming);
			mobile.send(payloadCanary);
			first.close(1000, "listener_replaced");
			const replacement = await wsConnect(
				`http://spl.test/session/listen?instance=${instanceId}`,
				listenToken,
			);
			const reoffer = onMessage(replacement);
			replacement.accept();
			expect(parseIncoming(await reoffer)).toBe(tunnelId);
			const raw = logLines(spy);
			expect(raw.match(/"event":"dial_open"/g)).toHaveLength(1);
			expect(raw).not.toContain(dialToken);
			expect(raw).not.toContain("jti");
			expect(raw).not.toContain("?instance=");
			expect(raw).not.toContain(payloadCanary);
			mobile.close(1000, "test_done");
			replacement.close(1000, "test_done");
		} finally {
			spy.mockRestore();
		}
	});

	it("keeps the held dial when the resident attach lease is neutralized", async () => {
		vi.useFakeTimers();
		const instanceId = newInstanceId();
		const dialToken = await mintDevice(instanceId);
		const spy = vi.spyOn(console, "log").mockImplementation(() => {});
		const mobile = await wsHeldDial(
			`http://spl.test/session/dial?instance=${instanceId}`,
			dialToken,
		);
		const stub = env.INSTANCE.get(env.INSTANCE.idFromName(instanceId));
		try {
			mobile.send("mutation-buffered-byte");
			await vi.advanceTimersByTimeAsync(0);
			const tunnelId = await runInDurableObject(stub, (instance, state) => {
				const server = state.getWebSockets(tagWaiting(instanceId))[0];
				const att = server?.deserializeAttachment() as MobileAttachment | undefined;
				if (!att?.tunnel_id) throw new Error("held mobile missing");
				const leases = (instance as unknown as LeaseInspectable).attachLeases;
				const handle = leases.get(att.tunnel_id);
				if (handle === undefined) throw new Error("lease missing");
				clearTimeout(handle);
				leases.clear();
				return att.tunnel_id;
			});
			await vi.advanceTimersByTimeAsync(20_000);
			expect(logLines(spy)).not.toContain("attach_timeout");
			expect(
				await runInDurableObject(stub, (instance, state) => {
					const held = state.getWebSockets(tagTunnelMobile(tunnelId))[0];
					return {
						leaseCount: (instance as unknown as LeaseInspectable).attachLeases.size,
						pending: (instance as unknown as LeaseInspectable).pending.has(tagTunnelHome(tunnelId)),
						readyState: held?.readyState,
					};
				}),
			).toEqual({ leaseCount: 0, pending: true, readyState: WebSocket.OPEN });
		} finally {
			vi.useRealTimers();
			spy.mockRestore();
			mobile.close(1000, "test_done");
		}
	});

	it("fails closed when a server-closed home socket rejects a pending drain", async () => {
		const instanceId = newInstanceId();
		const listenToken = await mintService(instanceId);
		const dialToken = await mintDevice(instanceId);
		const spy = vi.spyOn(console, "log").mockImplementation(() => {});
		const mobile = await wsHeldDial(
			`http://spl.test/session/dial?instance=${instanceId}`,
			dialToken,
		);
		const stub = env.INSTANCE.get(env.INSTANCE.idFromName(instanceId));
		try {
			mobile.send("first-client-hello-frame");
			mobile.send("second-client-hello-frame");
			const result = await vi.waitFor(async () =>
				runInDurableObject(stub, (instance, state) => {
					const mobileServer = state.getWebSockets(tagWaiting(instanceId))[0];
					const mobileAttachment = mobileServer?.deserializeAttachment() as
						| MobileAttachment
						| undefined;
					if (!mobileAttachment?.tunnel_id) throw new Error("held mobile missing");
					const tunnelId = mobileAttachment.tunnel_id;
					if (!(instance as unknown as LeaseInspectable).pending.has(tagTunnelHome(tunnelId))) {
						throw new Error("pending frames not delivered yet");
					}
					const pair = new WebSocketPair();
					const home = pair[1];
					home.serializeAttachment({
						role: "tunnel_home",
						tunnel_id: tunnelId,
						instance_id: instanceId,
						opened_at: Date.now(),
					});
					state.acceptWebSocket(home, [tagTunnelHome(tunnelId)]);
					home.close(1011, "test closed home");
					const drained = (instance as unknown as DrainInspectable).drainPending(
						tunnelId,
						tagTunnelHome(tunnelId),
						home,
						instanceId,
					);
					return {
						drained,
						leaseCount: (instance as unknown as LeaseInspectable).attachLeases.size,
						homePending: (instance as unknown as LeaseInspectable).pending.has(
							tagTunnelHome(tunnelId),
						),
						mobilePending: (instance as unknown as LeaseInspectable).pending.has(
							tagTunnelMobile(tunnelId),
						),
						paired: (mobileServer?.deserializeAttachment() as MobileAttachment | undefined)?.paired,
					};
				}),
			);
			expect(result).toEqual({
				drained: false,
				leaseCount: 0,
				homePending: false,
				mobilePending: false,
				paired: false,
			});
			expect(logLines(spy)).toContain("pending_drain_failed");
			expect(logLines(spy).match(/pending_drain_failed/g)).toHaveLength(2);

			const home = await wsConnect(
				`http://spl.test/session/listen?instance=${instanceId}`,
				listenToken,
			);
			const incoming = onMessage(home);
			home.accept();
			const fresh = await wsHeldDial(
				`http://spl.test/session/dial?instance=${instanceId}`,
				dialToken,
			);
			const freshTunnelId = parseIncoming(await incoming);
			const freshHome = await wsOpen(
				`http://spl.test/tunnel/${freshTunnelId}?instance=${instanceId}`,
				listenToken,
			);
			const complete = onMessage(freshHome);
			fresh.send("complete-client-hello");
			expect(await complete).toBe("complete-client-hello");
			freshHome.close(1000, "test_done");
			fresh.close(1000, "test_done");
			home.close(1000, "test_done");
		} finally {
			spy.mockRestore();
			mobile.close(1000, "test_done");
		}
	});

	it("holds a dial when the only listener is CLOSING, then re-offers it", async () => {
		const instanceId = newInstanceId();
		const listenToken = await mintService(instanceId);
		const dialToken = await mintDevice(instanceId);
		const first = await wsOpen(
			`http://spl.test/session/listen?instance=${instanceId}`,
			listenToken,
		);
		const stub = env.INSTANCE.get(env.INSTANCE.idFromName(instanceId));
		await runInDurableObject(stub, (_instance, state) => {
			const listener = state.getWebSockets(tagListen(instanceId))[0];
			if (!listener) throw new Error("listener missing");
			listener.close(1000, "test closing listener");
			expect(listener.readyState).toBe(WebSocket.CLOSING);
		});

		// An OPEN listener whose send throws is not inducible here; CLOSING is the observable stale route.
		const mobile = await wsHeldDial(
			`http://spl.test/session/dial?instance=${instanceId}`,
			dialToken,
		);
		const held = await runInDurableObject(stub, (_instance, state) => {
			const waiting = state.getWebSockets(tagWaiting(instanceId));
			const attachment = waiting[0]?.deserializeAttachment() as MobileAttachment | undefined;
			return {
				waiting: waiting.length,
				mobile: state.getWebSockets(tagTunnelMobile(attachment?.tunnel_id ?? "missing")).length,
				paired: attachment?.paired,
				readyState: waiting[0]?.readyState,
			};
		});
		expect(held).toEqual({ waiting: 1, mobile: 1, paired: false, readyState: WebSocket.OPEN });
		const replacement = await wsConnect(
			`http://spl.test/session/listen?instance=${instanceId}`,
			listenToken,
		);
		const incoming = onMessage(replacement);
		replacement.accept();
		expect(parseIncoming(await incoming)).toBeTruthy();
		mobile.close(1000, "test_done");
		replacement.close(1000, "test_done");
		first.close(1000, "test_done");
	});

	it("expires an unpaired held dial exactly twenty seconds after its first buffered byte", async () => {
		// Miniflare does not dispatch this timer-driven server close to the client or update its wrapper.
		vi.useFakeTimers();
		const instanceId = newInstanceId();
		const dialToken = await mintDevice(instanceId);
		const mobile = await wsHeldDial(
			`http://spl.test/session/dial?instance=${instanceId}`,
			dialToken,
		);
		const stub = env.INSTANCE.get(env.INSTANCE.idFromName(instanceId));

		try {
			mobile.send("first buffered byte");
			await vi.advanceTimersByTimeAsync(0);
			await runInDurableObject(stub, (instance, state) => {
				const server = state.getWebSockets(tagWaiting(instanceId))[0];
				expect((instance as unknown as LeaseInspectable).attachLeases.size).toBe(1);
				expect(
					(server?.deserializeAttachment() as { tunnel_id?: string } | undefined)?.tunnel_id,
				).toBeTruthy();
			});
			await vi.advanceTimersByTimeAsync(19_999);
			expect(mobile.readyState).not.toBe(WebSocket.CLOSED);
			await vi.advanceTimersByTimeAsync(1);
			expect(
				await runInDurableObject(
					stub,
					(instance) => (instance as unknown as LeaseInspectable).attachLeases.size,
				),
			).toBe(0);
			vi.useRealTimers();
			const fresh = await wsFetch(`http://spl.test/session/dial?instance=${instanceId}`, dialToken);
			expect(fresh.status).toBe(101);
			fresh.webSocket?.accept();
			fresh.webSocket?.close(1000, "test_done");
		} finally {
			vi.useRealTimers();
			mobile.close(1000, "test_done");
		}
	});
});
