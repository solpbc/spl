// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

// Gate-off integration coverage. Runs under the default Workers config where
// ENTITLEMENT_REQUIRED and GRANT_SECRET are unset.

import { SELF, applyD1Migrations, env } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";
import { mintDeviceToken, mintServiceToken } from "../src/tokens";
import { migrations } from "./migrations";

declare module "cloudflare:test" {
	interface ProvidedEnv {
		DB: D1Database;
		SIGNING_JWK: string;
		JWKS_PUBLIC: string;
		ISSUER: string;
	}
}

const VALID_FP = `sha256:${"a".repeat(64)}`;

beforeAll(async () => {
	await applyD1Migrations(env.DB, migrations);
});

function newInstanceId(): string {
	return crypto.randomUUID();
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

describe("entitlement gate off", () => {
	it("allows listen and dial for an instance with no D1 row", async () => {
		const instanceId = newInstanceId();
		const listenToken = await mintService(instanceId);
		const dialToken = await mintDevice(instanceId);
		const home = await wsOpen(`http://spl.test/session/listen?instance=${instanceId}`, listenToken);
		const incoming = onMessage(home);
		const mobile = await wsOpen(`http://spl.test/session/dial?instance=${instanceId}`, dialToken);
		const signal = JSON.parse(await incoming) as { type: string; tunnel_id: string };

		expect(signal.type).toBe("incoming");
		expect(signal.tunnel_id).toBeTruthy();

		mobile.close(1000, "test_done");
		home.close(1000, "test_done");
	});

	it("returns 503 from grant intake when GRANT_SECRET is unset", async () => {
		const res = await SELF.fetch("http://spl.test/admin/entitlement", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({
				instance_id: newInstanceId(),
				entitled_until: Math.floor(Date.now() / 1000) + 3600,
			}),
		});

		expect(res.status).toBe(503);
	});
});
