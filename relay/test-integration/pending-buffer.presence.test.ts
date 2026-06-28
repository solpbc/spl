// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

// Presence-hold pending-buffer cap test. This exercises the held-before-any-listen
// state; pending-buffer.test.ts covers brokered-but-home-tunnel-not-attached where
// the listen WS is already open.

import { SELF, env } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";
import { mintDeviceToken } from "../src/tokens";
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

async function wsHeldDial(url: string, token: string): Promise<WebSocket> {
	const res = await SELF.fetch(url, {
		headers: { Upgrade: "websocket", Authorization: `Bearer ${token}` },
	});
	expect(res.status).toBe(101);
	if (!res.webSocket) throw new Error(`no webSocket; status=${res.status}`);
	res.webSocket.accept();
	return res.webSocket;
}

describe("presence-held pending buffer overflow closes the tunnel with 1009", () => {
	it("mobile sends > 16 MiB while held before any listen exists; overflow closes", async () => {
		const instanceId = crypto.randomUUID();
		const dialToken = await mintDevice(instanceId);

		const mobile = await wsHeldDial(
			`http://spl.test/session/dial?instance=${instanceId}`,
			dialToken,
		);
		const mobileClose = new Promise<{ code: number; reason: string }>((resolve) => {
			mobile.addEventListener(
				"close",
				(ev) => {
					const ce = ev as CloseEvent;
					resolve({ code: ce.code, reason: ce.reason });
				},
				{ once: true },
			);
		});

		const chunk = new Uint8Array(1024 * 1024);
		for (let i = 0; i < 17; i++) mobile.send(chunk.buffer);

		const ev = await mobileClose;
		expect(ev.code).toBe(1009);
	}, 15000);
});
