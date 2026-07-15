// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import { SELF, env } from "cloudflare:test";
import { describe, expect, it, vi } from "vitest";
import { mintDeviceToken, mintServiceToken } from "../src/tokens";

const VALID_FP = `sha256:${"a".repeat(64)}`;

interface LogRecord {
	event?: string;
	tunnel_id?: string;
	close_code?: number;
	reason?: string;
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
	const response = await SELF.fetch(url, {
		headers: { Upgrade: "websocket", Authorization: `Bearer ${token}` },
	});
	if (!response.webSocket) throw new Error(`no webSocket on response: status=${response.status}`);
	response.webSocket.accept();
	return response.webSocket;
}

function onMessage(ws: WebSocket): Promise<string | ArrayBuffer> {
	return new Promise((resolve, reject) => {
		const timer = setTimeout(() => reject(new Error("onMessage timeout")), 5000);
		ws.addEventListener(
			"message",
			(event) => {
				clearTimeout(timer);
				resolve(event.data);
			},
			{ once: true },
		);
	});
}

async function pairedTunnel(): Promise<{
	home: WebSocket;
	mobile: WebSocket;
	homeTunnel: WebSocket;
	tunnelId: string;
}> {
	const instanceId = crypto.randomUUID();
	const serviceToken = await mintService(instanceId);
	const deviceToken = await mintDevice(instanceId);
	const home = await wsOpen(`http://spl.test/session/listen?instance=${instanceId}`, serviceToken);
	const incoming = onMessage(home);
	const mobile = await wsOpen(`http://spl.test/session/dial?instance=${instanceId}`, deviceToken);
	const { tunnel_id: tunnelId } = JSON.parse((await incoming) as string) as { tunnel_id: string };
	const homeTunnel = await wsOpen(
		`http://spl.test/tunnel/${tunnelId}?instance=${instanceId}`,
		serviceToken,
	);
	return { home, mobile, homeTunnel, tunnelId };
}

function records(spy: ReturnType<typeof vi.spyOn>): LogRecord[] {
	return spy.mock.calls
		.map(([arg]) => arg)
		.filter((arg): arg is string => typeof arg === "string")
		.map((line) => JSON.parse(line) as LogRecord);
}

async function waitForCloseLog(
	spy: ReturnType<typeof vi.spyOn>,
	tunnelId: string,
	closeCode: number,
): Promise<LogRecord> {
	await vi.waitFor(() => {
		expect(
			records(spy).some(
				(record) =>
					record.event === "tunnel_mobile_close" &&
					record.tunnel_id === tunnelId &&
					record.close_code === closeCode,
			),
		).toBe(true);
	});
	const record = records(spy).find(
		(item) =>
			item.event === "tunnel_mobile_close" &&
			item.tunnel_id === tunnelId &&
			item.close_code === closeCode,
	);
	if (!record) throw new Error("close log disappeared after waitFor");
	return record;
}

describe("close log hygiene", () => {
	it("peer close reason string is never logged", async () => {
		const { home, mobile, homeTunnel, tunnelId } = await pairedTunnel();
		const spy = vi.spyOn(console, "log").mockImplementation(() => {});
		const secret = "leak-canary-8f3a2c-do-not-log";
		try {
			mobile.close(4321, secret);
			const closeLog = await waitForCloseLog(spy, tunnelId, 4321);
			expect(closeLog).toMatchObject({ close_code: 4321, reason: "peer_closed" });
			const raw = spy.mock.calls.map(([arg]) => String(arg)).join("\n");
			expect(raw).not.toContain(secret);
			expect(raw).not.toContain("leak-canary");
			expect(records(spy).some((record) => record.reason === secret)).toBe(false);
		} finally {
			spy.mockRestore();
			homeTunnel.close(1000, "test_done");
			home.close(1000, "test_done");
		}
	});

	it("peer text equal to an allowed literal is still ignored", async () => {
		const { home, mobile, homeTunnel, tunnelId } = await pairedTunnel();
		const spy = vi.spyOn(console, "log").mockImplementation(() => {});
		try {
			mobile.close(4322, "ws_error");
			const closeLog = await waitForCloseLog(spy, tunnelId, 4322);
			expect(closeLog.reason).toBe("peer_closed");
		} finally {
			spy.mockRestore();
			homeTunnel.close(1000, "test_done");
			home.close(1000, "test_done");
		}
	});
});
