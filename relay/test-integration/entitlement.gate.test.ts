// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

// Gate-on integration coverage. Runs under vitest.workers.gate.config.ts with
// load-time GRANT_SECRET and ENTITLEMENT_REQUIRED bindings.

import { SELF, applyD1Migrations, env } from "cloudflare:test";
import { beforeAll, describe, expect, it } from "vitest";
import { mintDeviceToken, mintServiceToken } from "../src/tokens";
import { genCaKeypair } from "../test/fixtures";
import { migrations } from "./migrations";

declare module "cloudflare:test" {
	interface ProvidedEnv {
		DB: D1Database;
		SIGNING_JWK: string;
		JWKS_PUBLIC: string;
		ISSUER: string;
		GRANT_SECRET: string;
		ENTITLEMENT_REQUIRED: string;
	}
}

const VALID_FP = `sha256:${"a".repeat(64)}`;
const CLOSE_CODE_NOT_ENTITLED = "4402";

beforeAll(async () => {
	await applyD1Migrations(env.DB, migrations);
});

function newInstanceId(): string {
	return crypto.randomUUID();
}

async function enrollHome(instanceId: string): Promise<void> {
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

function adminHeaders(bearer = env.GRANT_SECRET): HeadersInit {
	return {
		Authorization: `Bearer ${bearer}`,
		"content-type": "application/json",
	};
}

function postEntitlement(body: unknown, bearer = env.GRANT_SECRET): Promise<Response> {
	return SELF.fetch("http://spl.test/admin/entitlement", {
		method: "POST",
		headers: adminHeaders(bearer),
		body: JSON.stringify(body),
	});
}

function postRawEntitlement(body: string, bearer = env.GRANT_SECRET): Promise<Response> {
	return SELF.fetch("http://spl.test/admin/entitlement", {
		method: "POST",
		headers: adminHeaders(bearer),
		body,
	});
}

function getAdmin(path: string, bearer = env.GRANT_SECRET): Promise<Response> {
	return SELF.fetch(`http://spl.test${path}`, {
		headers: { Authorization: `Bearer ${bearer}` },
	});
}

function wsFetch(url: string, token: string): Promise<Response> {
	return SELF.fetch(url, {
		headers: {
			Upgrade: "websocket",
			Authorization: `Bearer ${token}`,
		},
	});
}

async function wsOpen(url: string, token: string): Promise<WebSocket> {
	const res = await wsFetch(url, token);
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

async function expectNotEntitled(res: Response): Promise<void> {
	expect(res.status).toBe(402);
	expect(res.headers.get("x-close-code")).toBe(CLOSE_CODE_NOT_ENTITLED);
	expect(await res.text()).toBe("not entitled");
}

describe("POST /admin/entitlement", () => {
	it("sets entitled_until for an enrolled instance", async () => {
		const instanceId = newInstanceId();
		await enrollHome(instanceId);
		const until = Math.floor(Date.now() / 1000) + 3600;

		const res = await postEntitlement({ instance_id: instanceId, entitled_until: until + 0.9 });
		expect(res.status).toBe(200);
		expect(await res.json()).toEqual({ ok: true });

		const row = await env.DB.prepare("SELECT entitled_until FROM instances WHERE instance_id = ?")
			.bind(instanceId)
			.first<{ entitled_until: number | null }>();
		expect(row?.entitled_until).toBe(until);
	});

	it("revokes via entitled_until=0", async () => {
		const instanceId = newInstanceId();
		await enrollHome(instanceId);
		const until = Math.floor(Date.now() / 1000) + 3600;
		expect((await postEntitlement({ instance_id: instanceId, entitled_until: until })).status).toBe(
			200,
		);

		const res = await postEntitlement({ instance_id: instanceId, entitled_until: 0 });
		expect(res.status).toBe(200);

		const row = await env.DB.prepare("SELECT entitled_until FROM instances WHERE instance_id = ?")
			.bind(instanceId)
			.first<{ entitled_until: number | null }>();
		expect(row?.entitled_until).toBeNull();
	});

	it("maps non-JSON and missing instance_id bodies to 400", async () => {
		const nonJson = await postRawEntitlement("not json");
		const missingInstance = await postEntitlement({ entitled_until: 123 });

		expect(nonJson.status).toBe(400);
		expect(missingInstance.status).toBe(400);
	});

	it("maps oversized bodies to 400", async () => {
		const res = await postEntitlement({
			instance_id: newInstanceId(),
			padding: "x".repeat(3000),
		});

		expect(res.status).toBe(400);
	});

	it("rejects a bad instance_id with 400", async () => {
		const res = await postEntitlement({
			instance_id: "bad",
			entitled_until: Math.floor(Date.now() / 1000) + 3600,
		});

		expect(res.status).toBe(400);
	});

	it("rejects wrong and missing bearer credentials with 401", async () => {
		const sameLengthWrongBearer = "x".repeat(env.GRANT_SECRET.length);
		expect(sameLengthWrongBearer).not.toBe(env.GRANT_SECRET);
		const body = {
			instance_id: newInstanceId(),
			entitled_until: Math.floor(Date.now() / 1000) + 3600,
		};

		const wrong = await postEntitlement(body, sameLengthWrongBearer);
		const missing = await SELF.fetch("http://spl.test/admin/entitlement", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify(body),
		});

		expect(wrong.status).toBe(401);
		expect(missing.status).toBe(401);
	});

	it("returns 404 for an unknown instance", async () => {
		const res = await postEntitlement({
			instance_id: newInstanceId(),
			entitled_until: Math.floor(Date.now() / 1000) + 3600,
		});

		expect(res.status).toBe(404);
	});
});

describe("GET /admin/instances", () => {
	it("lists instances with correct entitled flags, never exposing pubkey or tokens", async () => {
		const now = Math.floor(Date.now() / 1000);
		const entitledId = newInstanceId();
		await enrollHome(entitledId);
		expect(
			(await postEntitlement({ instance_id: entitledId, entitled_until: now + 3600 })).status,
		).toBe(200);

		const lapsedId = newInstanceId();
		await enrollHome(lapsedId);

		const revokedId = newInstanceId();
		await enrollHome(revokedId);
		expect(
			(await postEntitlement({ instance_id: revokedId, entitled_until: now + 3600 })).status,
		).toBe(200);
		await env.DB.prepare("UPDATE instances SET revoked_at = ? WHERE instance_id = ?")
			.bind(now, revokedId)
			.run();

		const res = await getAdmin("/admin/instances");
		expect(res.status).toBe(200);
		const body = (await res.json()) as { instances: Array<Record<string, unknown>> };
		const byId = new Map(body.instances.map((r) => [r.instance_id, r]));

		expect(byId.get(entitledId)?.entitled).toBe(true);
		expect(byId.get(lapsedId)?.entitled).toBe(false);
		expect(byId.get(revokedId)?.entitled).toBe(false);

		const row = byId.get(entitledId);
		if (!row) throw new Error("entitled row missing from instances list");
		expect(Object.keys(row).sort()).toEqual(
			[
				"instance_id",
				"ca_fp",
				"home_label",
				"created_at",
				"rotated_at",
				"revoked_at",
				"entitled_until",
				"entitled",
			].sort(),
		);
		expect(row).not.toHaveProperty("ca_pubkey_pem");
		expect(row).not.toHaveProperty("service_token_jti");
		expect(row.home_label).toBeNull();
		expect(typeof row.ca_fp).toBe("string");
		expect(row.ca_fp).toMatch(/^sha256:/);

		for (let i = 1; i < body.instances.length; i++) {
			expect(Number(body.instances[i - 1].created_at) >= Number(body.instances[i].created_at)).toBe(
				true,
			);
		}
	});

	it("shows a single instance as a bare object", async () => {
		const now = Math.floor(Date.now() / 1000);
		const id = newInstanceId();
		await enrollHome(id);
		expect((await postEntitlement({ instance_id: id, entitled_until: now + 3600 })).status).toBe(
			200,
		);

		const res = await getAdmin(`/admin/instances/${id}`);
		expect(res.status).toBe(200);
		const body = (await res.json()) as Record<string, unknown>;

		expect(body.instance_id).toBe(id);
		expect(body.entitled).toBe(true);
		expect(body).not.toHaveProperty("instances");
		expect(body).not.toHaveProperty("ca_pubkey_pem");
		expect(body).not.toHaveProperty("service_token_jti");
	});

	it("returns 404 for an unknown instance", async () => {
		const res = await getAdmin(`/admin/instances/${newInstanceId()}`);

		expect(res.status).toBe(404);
		expect(await res.json()).toEqual({ error: "unknown instance_id" });
	});

	it("returns 400 for a malformed id", async () => {
		const malformed = await getAdmin("/admin/instances/bad");
		const empty = await getAdmin("/admin/instances/");

		expect(malformed.status).toBe(400);
		expect(empty.status).toBe(400);
	});

	it("rejects wrong and missing bearer with 401", async () => {
		const sameLengthWrong = "x".repeat(env.GRANT_SECRET.length);
		expect(sameLengthWrong).not.toBe(env.GRANT_SECRET);

		const wrongList = await getAdmin("/admin/instances", sameLengthWrong);
		const wrongShow = await getAdmin(`/admin/instances/${newInstanceId()}`, sameLengthWrong);
		const missingList = await SELF.fetch("http://spl.test/admin/instances");
		const missingShow = await SELF.fetch(`http://spl.test/admin/instances/${newInstanceId()}`);

		expect(wrongList.status).toBe(401);
		expect(wrongShow.status).toBe(401);
		expect(missingList.status).toBe(401);
		expect(missingShow.status).toBe(401);
	});
});

describe("entitlement gate on", () => {
	it("blocks listen and dial when the enrolled instance has no grant", async () => {
		const instanceId = newInstanceId();
		await enrollHome(instanceId);

		const listen = await wsFetch(
			`http://spl.test/session/listen?instance=${instanceId}`,
			await mintService(instanceId),
		);
		const dial = await wsFetch(
			`http://spl.test/session/dial?instance=${instanceId}`,
			await mintDevice(instanceId),
		);

		await expectNotEntitled(listen);
		await expectNotEntitled(dial);
	});

	it("blocks listen for a never-enrolled instance", async () => {
		const instanceId = newInstanceId();
		const res = await wsFetch(
			`http://spl.test/session/listen?instance=${instanceId}`,
			await mintService(instanceId),
		);

		await expectNotEntitled(res);
	});

	it("blocks listen for an expired entitlement", async () => {
		const instanceId = newInstanceId();
		await enrollHome(instanceId);
		const grant = await postEntitlement({
			instance_id: instanceId,
			entitled_until: Math.floor(Date.now() / 1000) - 3600,
		});
		expect(grant.status).toBe(200);

		const res = await wsFetch(
			`http://spl.test/session/listen?instance=${instanceId}`,
			await mintService(instanceId),
		);

		await expectNotEntitled(res);
	});

	it("allows listen and dial with a future entitlement, then blocks fresh listen after revoke", async () => {
		const instanceId = newInstanceId();
		await enrollHome(instanceId);
		const grant = await postEntitlement({
			instance_id: instanceId,
			entitled_until: Math.floor(Date.now() / 1000) + 3600,
		});
		expect(grant.status).toBe(200);

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

		const revoke = await postEntitlement({ instance_id: instanceId, entitled_until: 0 });
		expect(revoke.status).toBe(200);

		const afterRevoke = await wsFetch(
			`http://spl.test/session/listen?instance=${instanceId}`,
			listenToken,
		);
		await expectNotEntitled(afterRevoke);
	});
});
