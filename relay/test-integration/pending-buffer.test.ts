// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

// Pending-buffer cap test. Proto/session.md §"pending buffer" specifies a
// 16 MiB cap with 1009 close on overflow. Exceeding the cap exercises the
// only payload-sized buffer the DO is allowed to hold, so this is the test
// that protects the blind-by-construction invariant from drift — any code
// change that sneaks unbounded buffering past review will fail here.

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

async function mintAccount(instanceId: string): Promise<string> {
	return (
		await mintAccountToken(env.SIGNING_JWK, {
			instance_id: instanceId,
			ca_fp: "sha256:test",
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
			device_fp: "sha256:test",
			issuer: env.ISSUER,
			ttlSeconds: 300,
		})
	).jwt;
}

async function wsOpen(url: string, token: string): Promise<WebSocket> {
	const res = await SELF.fetch(url, {
		headers: { Upgrade: "websocket", Authorization: `Bearer ${token}` },
	});
	if (!res.webSocket) throw new Error(`no webSocket; status=${res.status}`);
	res.webSocket.accept();
	return res.webSocket;
}

describe("pending buffer overflow closes the tunnel with 1009", () => {
	it("mobile sends > 16 MiB before home attaches; overflow closes", async () => {
		const instanceId = crypto.randomUUID();
		const listenToken = await mintAccount(instanceId);
		const dialToken = await mintDevice(instanceId);

		// Home holds listen WS open but deliberately does NOT attach the
		// /tunnel/<id> side, so mobile writes pile up in the pending buffer.
		const home = await wsOpen(`http://spl.test/session/listen?instance=${instanceId}`, listenToken);
		// Wait for the incoming signal (proves dial succeeded).
		const signal = new Promise<string>((resolve, reject) => {
			const timer = setTimeout(() => reject(new Error("no incoming")), 5000);
			home.addEventListener(
				"message",
				(ev) => {
					clearTimeout(timer);
					resolve(String(ev.data));
				},
				{ once: true },
			);
		});
		const mobile = await wsOpen(`http://spl.test/session/dial?instance=${instanceId}`, dialToken);
		await signal;

		// Mobile observes when the relay closes it.
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

		// Fire 17 × 1 MiB chunks — 17 MiB total, over the 16 MiB cap. The
		// DO uses `message.byteLength` (or string `.length`) to measure, so
		// any datatype the runtime accepts works; Uint8Array is natural.
		const chunk = new Uint8Array(1024 * 1024);
		for (let i = 0; i < 17; i++) mobile.send(chunk.buffer);

		const ev = await mobileClose;
		expect(ev.code).toBe(1009);

		home.close(1000, "test_done");
	}, 15000);
});
