// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

// Shared retirement acceptance coverage. This file runs once with the
// entitlement gate enabled and once with it unset.

import {
	SELF,
	env,
	listDurableObjectIds,
	runDurableObjectAlarm,
	runInDurableObject,
} from "cloudflare:test";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { fingerprintDer } from "../src/attestation";
import type { InstanceDO } from "../src/instance-do";
import { base64UrlDecode, mintDeviceToken } from "../src/tokens";
import { genCaKeypair, genClientCertDer, mintAttestation } from "../test/fixtures";
import { applyRelayD1Migrations } from "./apply-migrations";

declare module "cloudflare:test" {
	interface ProvidedEnv {
		DB: D1Database;
		GRANT_SECRET: string;
		INSTANCE: DurableObjectNamespace;
		SIGNING_JWK: string;
		JWKS_PUBLIC: string;
		ISSUER: string;
		ENTITLEMENT_REQUIRED: string;
		PRESENCE_HOLD_ENABLED: string;
	}
}

const SUCCESS_KEYS = [
	"devices_revoked",
	"entitlement_cleared",
	"entry_denial_verified",
	"pending_grants_cleared",
	"sockets_closed",
	"state",
	"tombstone_verified",
].sort();
const PARTIAL_KEYS = [
	"devices_revoked",
	"entitlement_cleared",
	"entry_denial_verified",
	"failed_component",
	"pending_grants_cleared",
	"sockets_closed",
	"tombstone_verified",
].sort();
const VALID_FP = `sha256:${"d".repeat(64)}`;

interface EnrolledHome {
	instanceId: string;
	serviceToken: string;
	ca: Awaited<ReturnType<typeof genCaKeypair>>;
}

interface DeviceEnrollment {
	deviceToken: string;
	attestation: string;
	deviceJti: string;
}

interface PairBridge {
	window: WebSocket;
	mobile: WebSocket;
	home: WebSocket;
	tunnelId: string;
}

interface Deferred<T> {
	promise: Promise<T>;
	resolve: (value: T) => void;
}

beforeAll(async () => {
	await applyRelayD1Migrations();
});

afterEach(() => {
	vi.restoreAllMocks();
});

function adminHeaders(): HeadersInit {
	return { Authorization: `Bearer ${env.GRANT_SECRET}` };
}

function onClose(ws: WebSocket): Promise<CloseEvent> {
	return new Promise((resolve) => {
		ws.addEventListener("close", (event) => resolve(event as CloseEvent), { once: true });
	});
}

function deferred<T>(): Deferred<T> {
	let resolve!: (value: T) => void;
	const promise = new Promise<T>((done) => {
		resolve = done;
	});
	return { promise, resolve };
}

function jwtPayload(token: string): Record<string, unknown> {
	return JSON.parse(new TextDecoder().decode(base64UrlDecode(token.split(".")[1]))) as Record<
		string,
		unknown
	>;
}

function postHomeEnroll(
	instanceId: string,
	ca: Awaited<ReturnType<typeof genCaKeypair>>,
): Promise<Response> {
	return SELF.fetch("http://spl.test/enroll/home", {
		method: "POST",
		headers: { "content-type": "application/json" },
		body: JSON.stringify({ instance_id: instanceId, ca_pubkey: ca.pubPem }),
	});
}

async function enrollForTest(): Promise<EnrolledHome> {
	const instanceId = crypto.randomUUID();
	const ca = await genCaKeypair();
	const response = await postHomeEnroll(instanceId, ca);
	expect(response.status).toBe(200);
	const body = (await response.json()) as { service_token: string };
	return { instanceId, serviceToken: body.service_token, ca };
}

async function grantEntitlement(instanceId: string): Promise<void> {
	const response = await SELF.fetch("http://spl.test/admin/entitlement", {
		method: "POST",
		headers: { ...adminHeaders(), "content-type": "application/json" },
		body: JSON.stringify({
			instance_id: instanceId,
			entitled_until: Math.floor(Date.now() / 1000) + 3600,
		}),
	});
	expect(response.status).toBe(200);
}

async function enrollActive(): Promise<EnrolledHome> {
	const enrolled = await enrollForTest();
	await grantEntitlement(enrolled.instanceId);
	return enrolled;
}

async function enrollDeviceForTest(enrolled: EnrolledHome): Promise<DeviceEnrollment> {
	const deviceFp = await fingerprintDer(await genClientCertDer());
	const attestation = await mintAttestation({
		caPrivateKey: enrolled.ca.privateKey,
		instanceId: enrolled.instanceId,
		deviceFp,
	});
	const response = await SELF.fetch("http://spl.test/enroll/device", {
		method: "POST",
		headers: { "content-type": "application/json" },
		body: JSON.stringify({
			instance_id: enrolled.instanceId,
			home_attestation: attestation,
		}),
	});
	expect(response.status).toBe(200);
	const body = (await response.json()) as { device_token: string };
	return {
		deviceToken: body.device_token,
		attestation,
		deviceJti: String(jwtPayload(body.device_token).jti),
	};
}

async function openPairWindow(rk: string, serviceToken: string): Promise<WebSocket> {
	const response = await SELF.fetch("http://spl.test/session/pair-window", {
		headers: {
			Upgrade: "websocket",
			"Sec-Pair-Key": rk,
			Authorization: `Bearer ${serviceToken}`,
		},
	});
	expect(response.status).toBe(101);
	if (!response.webSocket) throw new Error("pair-window response did not contain a WebSocket");
	response.webSocket.accept();
	return response.webSocket;
}

function wsFetch(url: string, token: string): Promise<Response> {
	return SELF.fetch(url, {
		headers: { Upgrade: "websocket", Authorization: `Bearer ${token}` },
	});
}

async function wsOpen(url: string, token: string): Promise<WebSocket> {
	const response = await wsFetch(url, token);
	expect(response.status).toBe(101);
	if (!response.webSocket) throw new Error("upgrade response did not contain a WebSocket");
	response.webSocket.accept();
	return response.webSocket;
}

function pairFetch(path: string, rk: string, token?: string): Promise<Response> {
	const headers = new Headers({ Upgrade: "websocket", "Sec-Pair-Key": rk });
	if (token) headers.set("Authorization", `Bearer ${token}`);
	return SELF.fetch(`http://spl.test${path}`, { headers });
}

function onMessage(ws: WebSocket): Promise<string | ArrayBuffer> {
	return new Promise((resolve, reject) => {
		const timer = setTimeout(() => reject(new Error("message timeout")), 5000);
		ws.addEventListener(
			"message",
			(event) => {
				clearTimeout(timer);
				resolve(event.data);
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

function parseIncoming(message: string | ArrayBuffer): string {
	expect(typeof message).toBe("string");
	const parsed = JSON.parse(String(message)) as { type: string; tunnel_id: string };
	expect(parsed.type).toBe("incoming");
	return parsed.tunnel_id;
}

async function openPairBridge(enrolled: EnrolledHome, rk: string): Promise<PairBridge> {
	const window = await openPairWindow(rk, enrolled.serviceToken);
	const incoming = onMessage(window);
	const dial = await pairFetch("/session/pair-dial", rk);
	expect(dial.status).toBe(101);
	if (!dial.webSocket) throw new Error("pair-dial response did not contain a WebSocket");
	const mobile = dial.webSocket;
	mobile.accept();
	const tunnelId = parseIncoming(await incoming);
	const tunnel = await pairFetch(`/tunnel/${tunnelId}`, rk, enrolled.serviceToken);
	expect(tunnel.status).toBe(101);
	if (!tunnel.webSocket) throw new Error("pairing tunnel response did not contain a WebSocket");
	const home = tunnel.webSocket;
	home.accept();
	return { window, mobile, home, tunnelId };
}

function retireInstance(instanceId: string, bearer = env.GRANT_SECRET): Promise<Response> {
	return SELF.fetch(`http://spl.test/admin/instances/${instanceId}`, {
		method: "DELETE",
		headers: { Authorization: `Bearer ${bearer}` },
	});
}

async function expectRetirementSuccess(
	response: Response,
	state: "retired" | "already_retired" | "absent",
): Promise<Record<string, unknown>> {
	expect(response.status).toBe(200);
	const body = (await response.json()) as Record<string, unknown>;
	expect(Object.keys(body).sort()).toEqual(SUCCESS_KEYS);
	expect(body).toEqual({
		state,
		entry_denial_verified: true,
		sockets_closed: true,
		devices_revoked: true,
		entitlement_cleared: true,
		pending_grants_cleared: true,
		tombstone_verified: true,
	});
	return body;
}

async function expectRetirementFailure(
	response: Response,
	component: string,
): Promise<Record<string, unknown>> {
	expect(response.status).toBe(503);
	const body = (await response.json()) as Record<string, unknown>;
	expect(Object.keys(body).sort()).toEqual(PARTIAL_KEYS);
	expect(body.failed_component).toBe(component);
	expect(body).not.toHaveProperty("state");
	return body;
}

async function pairingOwner(instanceId: string): Promise<{ instance_id: string } | null> {
	return env.DB.prepare("SELECT instance_id FROM pairing_owners WHERE instance_id = ?")
		.bind(instanceId)
		.first<{ instance_id: string }>();
}

async function expectEventually(assertion: () => Promise<void>): Promise<void> {
	let lastError: unknown;
	for (let attempt = 0; attempt < 20; attempt++) {
		try {
			await assertion();
			return;
		} catch (error) {
			lastError = error;
			await new Promise((resolve) => setTimeout(resolve, 5));
		}
	}
	throw lastError;
}

function wrapStatementRun(
	statement: D1PreparedStatement,
	run: (statement: D1PreparedStatement) => Promise<D1Result>,
): D1PreparedStatement {
	return new Proxy(statement, {
		get(target, property) {
			if (property === "bind") {
				return (...values: unknown[]) => wrapStatementRun(target.bind(...values), run);
			}
			if (property === "run") return () => run(target);
			const value = Reflect.get(target, property, target) as unknown;
			return typeof value === "function" ? value.bind(target) : value;
		},
	});
}

function failPreparedRun(fragment: string): { mockRestore(): void } {
	const prepare = env.DB.prepare.bind(env.DB);
	return vi.spyOn(env.DB, "prepare").mockImplementation((query) => {
		const statement = prepare(query);
		if (!query.includes(fragment)) return statement;
		return wrapStatementRun(statement, async () => {
			throw new Error(`injected D1 mutation failure: ${fragment}`);
		});
	});
}

function delayPreparedRun(fragment: string): {
	entered: Promise<void>;
	release: () => void;
	restore: () => void;
} {
	const prepare = env.DB.prepare.bind(env.DB);
	const entered = deferred<void>();
	const released = deferred<void>();
	let intercepted = false;
	const spy = vi.spyOn(env.DB, "prepare").mockImplementation((query) => {
		const statement = prepare(query);
		if (intercepted || !query.includes(fragment)) return statement;
		intercepted = true;
		return wrapStatementRun(statement, async (bound) => {
			const result = await bound.run();
			entered.resolve(undefined);
			await released.promise;
			return result;
		});
	});
	return {
		entered: entered.promise,
		release: () => released.resolve(undefined),
		restore: () => spy.mockRestore(),
	};
}

function delayNextEd25519Verification(): {
	entered: Promise<void>;
	release: () => void;
	restore: () => void;
} {
	const verify = crypto.subtle.verify.bind(crypto.subtle);
	const entered = deferred<void>();
	const released = deferred<void>();
	let intercepted = false;
	const spy = vi
		.spyOn(crypto.subtle, "verify")
		.mockImplementation(async (algorithm, key, signature, data) => {
			const result = await verify(algorithm, key, signature, data);
			const name = typeof algorithm === "string" ? algorithm : algorithm.name;
			if (!intercepted && name === "Ed25519") {
				intercepted = true;
				entered.resolve(undefined);
				await released.promise;
			}
			return result;
		});
	return {
		entered: entered.promise,
		release: () => released.resolve(undefined),
		restore: () => spy.mockRestore(),
	};
}

async function mintUnsignedRowDeviceToken(instanceId: string): Promise<string> {
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

async function expectFreshListenDenied(enrolled: EnrolledHome): Promise<void> {
	const response = await wsFetch(
		`http://spl.test/session/listen?instance=${enrolled.instanceId}`,
		enrolled.serviceToken,
	);
	expect([401, 402]).toContain(response.status);
	expect(response.webSocket).toBeNull();
}

async function countRows(
	table: "devices" | "instances" | "pairing_owners" | "pending_grants",
	id: string,
) {
	const row = await env.DB.prepare(`SELECT COUNT(*) AS count FROM ${table} WHERE instance_id = ?`)
		.bind(id)
		.first<{ count: number }>();
	return row?.count ?? 0;
}

function closeAll(...sockets: Array<WebSocket | undefined>): void {
	for (const socket of sockets) {
		if (socket?.readyState === WebSocket.OPEN) socket.close(1000, "test_done");
	}
}

async function openWaitingDial(instanceId: string, deviceToken: string): Promise<WebSocket> {
	const stub = env.INSTANCE.get(env.INSTANCE.idFromName(instanceId));
	let previous: unknown;
	let hadBinding = false;
	await runInDurableObject(stub, (instance) => {
		const doEnv = Reflect.get(instance, "env") as Record<string, unknown>;
		hadBinding = Object.hasOwn(doEnv, "PRESENCE_HOLD_ENABLED");
		previous = doEnv.PRESENCE_HOLD_ENABLED;
		doEnv.PRESENCE_HOLD_ENABLED = "true";
	});
	try {
		return await wsOpen(`http://spl.test/session/dial?instance=${instanceId}`, deviceToken);
	} finally {
		await runInDurableObject(stub, (instance) => {
			const doEnv = Reflect.get(instance, "env") as Record<string, unknown>;
			if (hadBinding) doEnv.PRESENCE_HOLD_ENABLED = previous;
			else Reflect.deleteProperty(doEnv, "PRESENCE_HOLD_ENABLED");
		});
	}
}

type DoFault =
	| "marker_write"
	| "marker_verification"
	| "socket_discovery"
	| "socket_close"
	| "pending_cleanup"
	| "alarm_cleanup";

async function installDoFault(stub: DurableObjectStub, fault: DoFault): Promise<() => void> {
	let restore = (): void => {};
	await runInDurableObject(stub, (instance, state) => {
		if (fault === "marker_write" || fault === "marker_verification") {
			const sql = state.storage.sql;
			const original = sql.exec.bind(sql);
			Reflect.set(sql, "exec", (query: string, ...bindings: unknown[]) => {
				const result = original(query, ...bindings);
				if (
					(fault === "marker_write" && query.includes("INSERT INTO retired_instances")) ||
					(fault === "marker_verification" && query.includes("SELECT retired_at"))
				) {
					throw new Error(`injected DO ${fault} failure`);
				}
				return result;
			});
			restore = () => {
				Reflect.set(sql, "exec", original);
			};
			return;
		}
		if (fault === "socket_discovery") {
			const original = state.getWebSockets.bind(state);
			Reflect.set(state, "getWebSockets", () => {
				throw new Error("injected DO socket discovery failure");
			});
			restore = () => {
				Reflect.set(state, "getWebSockets", original);
			};
			return;
		}
		if (fault === "socket_close") {
			const socket = state.getWebSockets()[0];
			if (!socket) throw new Error("socket-close fault requires a live socket");
			const original = socket.close.bind(socket);
			Reflect.set(socket, "close", () => {
				throw new Error("injected DO socket close failure");
			});
			restore = () => {
				Reflect.set(socket, "close", original);
			};
			return;
		}
		if (fault === "pending_cleanup") {
			const pending = Reflect.get(instance, "pending") as Map<string, unknown>;
			if (!(pending instanceof Map) || pending.size === 0) {
				throw new Error("pending-cleanup fault requires a buffered frame");
			}
			const original = pending.delete.bind(pending);
			Reflect.set(pending, "delete", () => false);
			restore = () => {
				Reflect.set(pending, "delete", original);
			};
			return;
		}

		const original = state.storage.deleteAlarm.bind(state.storage);
		Reflect.set(state.storage, "deleteAlarm", async () => {
			throw new Error("injected DO alarm cleanup failure");
		});
		restore = () => {
			Reflect.set(state.storage, "deleteAlarm", original);
		};
	});
	return restore;
}

describe("DELETE /admin/instances/<id>", () => {
	it("releases the replaced pair-window owner row at the server-side close", async () => {
		const rk = "a1".repeat(16);
		const first = await enrollForTest();
		const second = await enrollForTest();
		const firstWindow = await openPairWindow(rk, first.serviceToken);
		const firstClosed = onClose(firstWindow);

		const firstOwner = await pairingOwner(first.instanceId);
		expect(firstOwner?.instance_id).toBe(first.instanceId);

		const secondWindow = await openPairWindow(rk, second.serviceToken);
		await firstClosed;

		await expectEventually(async () => {
			expect(await pairingOwner(first.instanceId)).toBeNull();
		});

		secondWindow.close(1000, "test_done");
	});

	it("releases an owner row when retirement closes the final owned socket", async () => {
		const rk = "a2".repeat(16);
		const enrolled = await enrollForTest();
		const pairWindow = await openPairWindow(rk, enrolled.serviceToken);
		const closed = onClose(pairWindow);
		expect((await pairingOwner(enrolled.instanceId))?.instance_id).toBe(enrolled.instanceId);

		const stub = env.INSTANCE.get(env.INSTANCE.idFromName(rk)) as DurableObjectStub<InstanceDO>;
		const result = await stub.retireInstance(enrolled.instanceId, Math.floor(Date.now() / 1000));
		expect(result.socketsClosed).toBe(true);
		const close = await closed;
		expect(close.code).toBe(4403);
		expect(close.reason).toBe("instance_retired");
		await expectEventually(async () => {
			expect(await pairingOwner(enrolled.instanceId)).toBeNull();
		});
	});

	it("retains an owner only until the last pairing bridge socket closes", async () => {
		const enrolled = await enrollForTest();
		const rk = "a3".repeat(16);
		const pair = await openPairBridge(enrolled, rk);
		pair.window.close(1000, "test_done");
		await expectEventually(async () => {
			expect((await pairingOwner(enrolled.instanceId))?.instance_id).toBe(enrolled.instanceId);
		});

		closeAll(pair.mobile, pair.home);
		await expectEventually(async () => {
			expect(await pairingOwner(enrolled.instanceId)).toBeNull();
		});
	});

	it("releases a stranded pair-window owner when its TTL alarm closes it", async () => {
		const enrolled = await enrollForTest();
		const rk = "a4".repeat(16);
		const window = await openPairWindow(rk, enrolled.serviceToken);
		const closed = onClose(window);
		const stub = env.INSTANCE.get(env.INSTANCE.idFromName(rk));
		expect(await runDurableObjectAlarm(stub)).toBe(true);
		await closed;
		await expectEventually(async () => {
			expect(await pairingOwner(enrolled.instanceId)).toBeNull();
		});
	});

	it("retires an enrolled instance, closes its socket, and returns the verified contract", async () => {
		const instanceId = crypto.randomUUID();
		const ca = await genCaKeypair();
		const enroll = await SELF.fetch("http://spl.test/enroll/home", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({ instance_id: instanceId, ca_pubkey: ca.pubPem }),
		});
		expect(enroll.status).toBe(200);
		const { service_token: serviceToken } = (await enroll.json()) as {
			service_token: string;
		};

		const entitledUntil = Math.floor(Date.now() / 1000) + 3600;
		const grant = await SELF.fetch("http://spl.test/admin/entitlement", {
			method: "POST",
			headers: { ...adminHeaders(), "content-type": "application/json" },
			body: JSON.stringify({ instance_id: instanceId, entitled_until: entitledUntil }),
		});
		expect(grant.status).toBe(200);

		const deviceJti = crypto.randomUUID();
		await env.DB.prepare(
			"INSERT INTO devices (device_jti, device_id, instance_id, device_fp, device_label, created_at, revoked_at, attestation_jti) VALUES (?, ?, ?, ?, NULL, ?, NULL, ?)",
		)
			.bind(
				deviceJti,
				crypto.randomUUID(),
				instanceId,
				`sha256:${"b".repeat(64)}`,
				Math.floor(Date.now() / 1000),
				crypto.randomUUID(),
			)
			.run();
		await env.DB.prepare(
			"INSERT INTO pending_grants (instance_id, entitled_until, updated_at) VALUES (?, ?, ?)",
		)
			.bind(instanceId, entitledUntil, Math.floor(Date.now() / 1000))
			.run();

		const listen = await SELF.fetch(`http://spl.test/session/listen?instance=${instanceId}`, {
			headers: {
				Upgrade: "websocket",
				Authorization: `Bearer ${serviceToken}`,
			},
		});
		expect(listen.status).toBe(101);
		if (!listen.webSocket) throw new Error("listen response did not contain a WebSocket");
		const home = listen.webSocket;
		home.accept();
		const closed = onClose(home);

		const retired = await SELF.fetch(`http://spl.test/admin/instances/${instanceId}`, {
			method: "DELETE",
			headers: adminHeaders(),
		});
		expect(retired.status).toBe(200);
		expect(await retired.json()).toEqual({
			state: "retired",
			entry_denial_verified: true,
			sockets_closed: true,
			devices_revoked: true,
			entitlement_cleared: true,
			pending_grants_cleared: true,
			tombstone_verified: true,
		});

		const close = await closed;
		expect(close.code).toBe(4403);
		expect(close.reason).toBe("instance_retired");

		const row = await env.DB.prepare(
			"SELECT created_at, revoked_at, entitled_until FROM instances WHERE instance_id = ?",
		)
			.bind(instanceId)
			.first<{
				created_at: number;
				revoked_at: number | null;
				entitled_until: number | null;
			}>();
		expect(row?.revoked_at).not.toBeNull();
		expect(row?.entitled_until).toBeNull();

		const device = await env.DB.prepare("SELECT revoked_at FROM devices WHERE device_jti = ?")
			.bind(deviceJti)
			.first<{ revoked_at: number | null }>();
		expect(device?.revoked_at).toBe(row?.revoked_at);
		const pending = await env.DB.prepare(
			"SELECT instance_id FROM pending_grants WHERE instance_id = ?",
		)
			.bind(instanceId)
			.first<{ instance_id: string }>();
		expect(pending).toBeNull();

		const show = await SELF.fetch(`http://spl.test/admin/instances/${instanceId}`, {
			headers: adminHeaders(),
		});
		expect(show.status).toBe(200);
		expect(await show.json()).toEqual({
			instance_id: instanceId,
			created_at: row?.created_at,
			revoked_at: row?.revoked_at,
			entitled_until: null,
			entitled: false,
		});
	});

	it("rejects missing, wrong, and malformed authorization without mutating state", async () => {
		const enrolled = await enrollActive();
		const device = await enrollDeviceForTest(enrolled);
		const listen = await wsOpen(
			`http://spl.test/session/listen?instance=${enrolled.instanceId}`,
			enrolled.serviceToken,
		);
		await env.DB.prepare(
			"INSERT INTO pending_grants (instance_id, entitled_until, updated_at) VALUES (?, ?, ?)",
		)
			.bind(enrolled.instanceId, 1234, 1234)
			.run();
		const before = await env.DB.prepare(
			"SELECT revoked_at, entitled_until FROM instances WHERE instance_id = ?",
		)
			.bind(enrolled.instanceId)
			.first<{ revoked_at: number | null; entitled_until: number | null }>();

		const missing = await SELF.fetch(`http://spl.test/admin/instances/${enrolled.instanceId}`, {
			method: "DELETE",
		});
		const wrong = await retireInstance(enrolled.instanceId, "x".repeat(env.GRANT_SECRET.length));
		expect(missing.status).toBe(401);
		expect(wrong.status).toBe(401);
		expect(await missing.json()).toEqual({ error: "unauthorized" });
		expect(await wrong.json()).toEqual({ error: "unauthorized" });
		expect(listen.readyState).toBe(WebSocket.OPEN);
		expect(await countRows("devices", enrolled.instanceId)).toBe(1);
		expect(await countRows("pending_grants", enrolled.instanceId)).toBe(1);
		const afterAuth = await env.DB.prepare(
			"SELECT revoked_at, entitled_until FROM instances WHERE instance_id = ?",
		)
			.bind(enrolled.instanceId)
			.first<{ revoked_at: number | null; entitled_until: number | null }>();
		expect(afterAuth).toEqual(before);

		const idsBefore = (await listDurableObjectIds(env.INSTANCE)).map(String).sort();
		const prepare = vi.spyOn(env.DB, "prepare");
		const malformed = await retireInstance("bad");
		expect(malformed.status).toBe(400);
		expect(await malformed.json()).toEqual({ error: "bad instance_id" });
		expect(prepare).not.toHaveBeenCalled();
		prepare.mockRestore();
		expect((await listDurableObjectIds(env.INSTANCE)).map(String).sort()).toEqual(idsBefore);
		expect(listen.readyState).toBe(WebSocket.OPEN);
		closeAll(listen);
		void device;
	});

	it("returns independently verified absent without creating a tombstone, device, or DO", async () => {
		const instanceId = crypto.randomUUID();
		const namedId = env.INSTANCE.idFromName(instanceId);
		const unusedStub = env.INSTANCE.get(namedId);
		void unusedStub;
		const before = (await listDurableObjectIds(env.INSTANCE)).map(String);
		expect(before).not.toContain(namedId.toString());
		await env.DB.prepare(
			"INSERT INTO pending_grants (instance_id, entitled_until, updated_at) VALUES (?, ?, ?)",
		)
			.bind(instanceId, 1234, 1234)
			.run();

		await expectRetirementSuccess(await retireInstance(instanceId), "absent");
		expect(await countRows("instances", instanceId)).toBe(0);
		expect(await countRows("devices", instanceId)).toBe(0);
		expect(await countRows("pending_grants", instanceId)).toBe(0);
		expect(await countRows("pairing_owners", instanceId)).toBe(0);
		expect((await listDurableObjectIds(env.INSTANCE)).map(String)).not.toContain(
			namedId.toString(),
		);

		await expectRetirementSuccess(await retireInstance(instanceId), "absent");
		expect((await listDurableObjectIds(env.INSTANCE)).map(String)).not.toContain(
			namedId.toString(),
		);
	});

	it("is terminal and idempotent across readback, grant, enrollment, refresh, and every entry path", async () => {
		const enrolled = await enrollActive();
		const device = await enrollDeviceForTest(enrolled);
		const rk = "b1".repeat(16);
		const pair = await openPairBridge(enrolled, rk);
		const listen = await wsOpen(
			`http://spl.test/session/listen?instance=${enrolled.instanceId}`,
			enrolled.serviceToken,
		);
		const incoming = onMessage(listen);
		const dial = await wsOpen(
			`http://spl.test/session/dial?instance=${enrolled.instanceId}`,
			device.deviceToken,
		);
		const tunnelId = parseIncoming(await incoming);
		const tunnel = await wsOpen(
			`http://spl.test/tunnel/${tunnelId}?instance=${enrolled.instanceId}`,
			enrolled.serviceToken,
		);
		const closed = [listen, dial, tunnel, pair.window, pair.mobile, pair.home].map(onClose);

		await expectRetirementSuccess(await retireInstance(enrolled.instanceId), "retired");
		const closeEvents = await Promise.all(closed);
		for (const event of closeEvents) {
			expect(event.code).toBe(4403);
			expect(event.reason).toBe("instance_retired");
		}
		const original = await env.DB.prepare(
			"SELECT created_at, revoked_at, ca_fp, ca_pubkey_pem FROM instances WHERE instance_id = ?",
		)
			.bind(enrolled.instanceId)
			.first<{
				created_at: number;
				revoked_at: number;
				ca_fp: string;
				ca_pubkey_pem: string;
			}>();
		expect(original?.revoked_at).toBeTypeOf("number");
		expect(original?.ca_pubkey_pem).toBe(enrolled.ca.pubPem);

		await expectRetirementSuccess(await retireInstance(enrolled.instanceId), "already_retired");
		const repeated = await env.DB.prepare("SELECT revoked_at FROM instances WHERE instance_id = ?")
			.bind(enrolled.instanceId)
			.first<{ revoked_at: number }>();
		expect(repeated?.revoked_at).toBe(original?.revoked_at);

		const retiredView = {
			instance_id: enrolled.instanceId,
			created_at: original?.created_at,
			revoked_at: original?.revoked_at,
			entitled_until: null,
			entitled: false,
		};
		const show = await SELF.fetch(`http://spl.test/admin/instances/${enrolled.instanceId}`, {
			headers: adminHeaders(),
		});
		expect(await show.json()).toEqual(retiredView);
		const list = await SELF.fetch("http://spl.test/admin/instances", { headers: adminHeaders() });
		const listBody = (await list.json()) as { instances: Array<Record<string, unknown>> };
		expect(listBody.instances.find((row) => row.instance_id === enrolled.instanceId)).toEqual(
			retiredView,
		);

		await env.DB.prepare(
			"INSERT INTO pending_grants (instance_id, entitled_until, updated_at) VALUES (?, ?, ?)",
		)
			.bind(enrolled.instanceId, 9999, 9999)
			.run();
		const grant = await SELF.fetch("http://spl.test/admin/entitlement", {
			method: "POST",
			headers: { ...adminHeaders(), "content-type": "application/json" },
			body: JSON.stringify({ instance_id: enrolled.instanceId, entitled_until: 9999 }),
		});
		expect(grant.status).toBe(409);
		expect(await grant.json()).toEqual({ error: "instance retired" });
		expect(await countRows("pending_grants", enrolled.instanceId)).toBe(0);

		const homeEnroll = await postHomeEnroll(enrolled.instanceId, enrolled.ca);
		expect(homeEnroll.status).toBe(403);
		expect(await homeEnroll.json()).toEqual({ error: "instance retired" });
		const deviceEnroll = await SELF.fetch("http://spl.test/enroll/device", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({
				instance_id: enrolled.instanceId,
				home_attestation: device.attestation,
			}),
		});
		expect(deviceEnroll.status).toBe(403);
		const refresh = await SELF.fetch("http://spl.test/token/refresh", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({ device_token: device.deviceToken }),
		});
		expect(refresh.status).toBe(403);
		expect((await refresh.json()) as Record<string, unknown>).not.toHaveProperty("device_token");

		const entryResponses = await Promise.all([
			wsFetch(
				`http://spl.test/session/listen?instance=${enrolled.instanceId}`,
				enrolled.serviceToken,
			),
			wsFetch(`http://spl.test/session/dial?instance=${enrolled.instanceId}`, device.deviceToken),
			wsFetch(
				`http://spl.test/tunnel/${tunnelId}?instance=${enrolled.instanceId}`,
				enrolled.serviceToken,
			),
			pairFetch("/session/pair-window", "b2".repeat(16), enrolled.serviceToken),
			pairFetch("/session/pair-dial", rk),
			pairFetch(`/tunnel/${pair.tunnelId}`, rk, enrolled.serviceToken),
		]);
		for (const response of entryResponses) {
			expect(response.status).not.toBe(101);
			expect(response.webSocket).toBeNull();
		}
	});

	it("closes normal, waiting, tunneled, and hibernated sockets across two undisclosed RKs without cross-instance damage", async () => {
		const target = await enrollActive();
		const targetDevice = await enrollDeviceForTest(target);
		const unrelated = await enrollActive();
		const unrelatedDevice = await enrollDeviceForTest(unrelated);
		const waiting = await openWaitingDial(target.instanceId, targetDevice.deviceToken);
		const listen = await wsOpen(
			`http://spl.test/session/listen?instance=${target.instanceId}`,
			target.serviceToken,
		);
		const incoming = onMessage(listen);
		const dial = await wsOpen(
			`http://spl.test/session/dial?instance=${target.instanceId}`,
			targetDevice.deviceToken,
		);
		const normalTunnelId = parseIncoming(await incoming);
		const normalTunnel = await wsOpen(
			`http://spl.test/tunnel/${normalTunnelId}?instance=${target.instanceId}`,
			target.serviceToken,
		);

		const rkOne = "c1".repeat(16);
		const rkTwo = "c2".repeat(16);
		const firstPair = await openPairBridge(target, rkOne);
		const secondPair = await openPairBridge(target, rkTwo);
		const unrelatedListen = await wsOpen(
			`http://spl.test/session/listen?instance=${unrelated.instanceId}`,
			unrelated.serviceToken,
		);
		const unrelatedRk = "c3".repeat(16);
		const unrelatedWindow = await openPairWindow(unrelatedRk, unrelated.serviceToken);
		await env.DB.prepare(
			"INSERT INTO pending_grants (instance_id, entitled_until, updated_at) VALUES (?, ?, ?), (?, ?, ?)",
		)
			.bind(target.instanceId, 1111, 1111, unrelated.instanceId, 2222, 2222)
			.run();

		const hibernatedStub = env.INSTANCE.get(env.INSTANCE.idFromName(rkOne));
		await runInDurableObject(hibernatedStub, (instance) => {
			Reflect.set(instance, "__retirementHibernationProbe", true);
		});
		await new Promise((resolve) => setTimeout(resolve, 12_000));
		const reconstructed = await runInDurableObject(hibernatedStub, (instance, state) => ({
			markerPresent: Reflect.has(instance, "__retirementHibernationProbe"),
			socketCount: state.getWebSockets().length,
		}));
		expect(reconstructed.markerPresent).toBe(false);
		expect(reconstructed.socketCount).toBe(3);

		const targetSockets = [
			waiting,
			listen,
			dial,
			normalTunnel,
			firstPair.window,
			firstPair.mobile,
			firstPair.home,
			secondPair.window,
			secondPair.mobile,
			secondPair.home,
		];
		const closeEvents = targetSockets.map(onClose);
		await expectRetirementSuccess(await retireInstance(target.instanceId), "retired");
		for (const close of await Promise.all(closeEvents)) {
			expect(close.code).toBe(4403);
			expect(close.reason).toBe("instance_retired");
		}

		const targetDeviceRow = await env.DB.prepare(
			"SELECT revoked_at FROM devices WHERE device_jti = ?",
		)
			.bind(targetDevice.deviceJti)
			.first<{ revoked_at: number | null }>();
		const unrelatedDeviceRow = await env.DB.prepare(
			"SELECT revoked_at FROM devices WHERE device_jti = ?",
		)
			.bind(unrelatedDevice.deviceJti)
			.first<{ revoked_at: number | null }>();
		expect(targetDeviceRow?.revoked_at).toBeTypeOf("number");
		expect(unrelatedDeviceRow?.revoked_at).toBeNull();
		expect(await countRows("pending_grants", target.instanceId)).toBe(0);
		expect(await countRows("pending_grants", unrelated.instanceId)).toBe(1);
		expect(await countRows("pairing_owners", target.instanceId)).toBe(0);
		expect(await countRows("pairing_owners", unrelated.instanceId)).toBe(1);
		expect(unrelatedListen.readyState).toBe(WebSocket.OPEN);
		expect(unrelatedWindow.readyState).toBe(WebSocket.OPEN);

		const unrelatedIncoming = onMessage(unrelatedListen);
		const unrelatedDial = await wsOpen(
			`http://spl.test/session/dial?instance=${unrelated.instanceId}`,
			unrelatedDevice.deviceToken,
		);
		expect(parseIncoming(await unrelatedIncoming)).toBeTruthy();
		const unrelatedPairIncoming = onMessage(unrelatedWindow);
		const unrelatedPairDial = await pairFetch("/session/pair-dial", unrelatedRk);
		expect(unrelatedPairDial.status).toBe(101);
		if (!unrelatedPairDial.webSocket) throw new Error("unrelated pair dial missing socket");
		unrelatedPairDial.webSocket.accept();
		expect(parseIncoming(await unrelatedPairIncoming)).toBeTruthy();

		for (const [rk, tunnelId] of [
			[rkOne, firstPair.tunnelId],
			[rkTwo, secondPair.tunnelId],
		] as const) {
			const dialDenied = await pairFetch("/session/pair-dial", rk);
			const tunnelDenied = await pairFetch(`/tunnel/${tunnelId}`, rk, target.serviceToken);
			expect(dialDenied.status).toBe(401);
			expect(tunnelDenied.status).toBe(401);
		}

		closeAll(unrelatedDial, unrelatedPairDial.webSocket, unrelatedListen, unrelatedWindow);
	}, 30_000);

	for (const fault of [
		{
			name: "revoked-state write",
			query: "UPDATE instances SET revoked_at = ?",
			component: "retired_state",
			authorityEstablished: false,
		},
		{
			name: "device revocation",
			query: "UPDATE devices SET revoked_at = COALESCE",
			component: "device_revocation",
			authorityEstablished: true,
		},
		{
			name: "entitlement clearing",
			query: "UPDATE instances SET entitled_until = NULL",
			component: "entitlement_clear",
			authorityEstablished: true,
		},
		{
			name: "pending-grant clearing",
			query: "DELETE FROM pending_grants WHERE instance_id = ?",
			component: "pending_grant_clear",
			authorityEstablished: true,
		},
		{
			name: "RK registry deletion",
			query: "DELETE FROM pairing_owners WHERE instance_id = ? AND do_id = ?",
			component: "rk_registry_clear",
			authorityEstablished: true,
		},
	] as const) {
		it(`reports ${fault.name} failure and converges on retry`, async () => {
			const enrolled = await enrollActive();
			await enrollDeviceForTest(enrolled);
			await env.DB.prepare(
				"INSERT INTO pending_grants (instance_id, entitled_until, updated_at) VALUES (?, ?, ?)",
			)
				.bind(enrolled.instanceId, 3333, 3333)
				.run();
			if (fault.component === "rk_registry_clear") {
				const doId = env.INSTANCE.idFromName(`registry-fault-${enrolled.instanceId}`).toString();
				await env.DB.prepare(
					"INSERT INTO pairing_owners (instance_id, do_id, registered_at) VALUES (?, ?, ?)",
				)
					.bind(enrolled.instanceId, doId, 3333)
					.run();
			}

			const spy = failPreparedRun(fault.query);
			await expectRetirementFailure(await retireInstance(enrolled.instanceId), fault.component);
			spy.mockRestore();
			const partialRow = await env.DB.prepare(
				"SELECT revoked_at FROM instances WHERE instance_id = ?",
			)
				.bind(enrolled.instanceId)
				.first<{ revoked_at: number | null }>();
			if (fault.authorityEstablished) {
				expect(partialRow?.revoked_at).toBeTypeOf("number");
				await expectFreshListenDenied(enrolled);
			} else {
				expect(partialRow?.revoked_at).toBeNull();
			}

			await expectRetirementSuccess(
				await retireInstance(enrolled.instanceId),
				fault.authorityEstablished ? "already_retired" : "retired",
			);
			const finalRow = await env.DB.prepare(
				"SELECT revoked_at, entitled_until FROM instances WHERE instance_id = ?",
			)
				.bind(enrolled.instanceId)
				.first<{ revoked_at: number | null; entitled_until: number | null }>();
			if (fault.authorityEstablished) {
				expect(finalRow?.revoked_at).toBe(partialRow?.revoked_at);
			}
			expect(finalRow?.entitled_until).toBeNull();
			expect(await countRows("pending_grants", enrolled.instanceId)).toBe(0);
			expect(await countRows("pairing_owners", enrolled.instanceId)).toBe(0);
		});
	}

	it("fails pair-window registration closed and admits cleanly after the D1 fault is removed", async () => {
		const enrolled = await enrollActive();
		const rk = "d1".repeat(16);
		const spy = failPreparedRun("INSERT INTO pairing_owners");
		let failedResponse: Response | undefined;
		let rejected = false;
		try {
			failedResponse = await pairFetch("/session/pair-window", rk, enrolled.serviceToken);
		} catch {
			rejected = true;
		}
		if (failedResponse) {
			expect(failedResponse.status).toBeGreaterThanOrEqual(500);
			expect(failedResponse.webSocket).toBeNull();
		} else {
			expect(rejected).toBe(true);
		}
		spy.mockRestore();
		expect(await countRows("pairing_owners", enrolled.instanceId)).toBe(0);
		const stub = env.INSTANCE.get(env.INSTANCE.idFromName(rk));
		expect(await runInDurableObject(stub, (_instance, state) => state.getWebSockets().length)).toBe(
			0,
		);

		const window = await openPairWindow(rk, enrolled.serviceToken);
		expect(await countRows("pairing_owners", enrolled.instanceId)).toBe(1);
		closeAll(window);
	});

	for (const fault of [
		"marker_write",
		"marker_verification",
		"socket_discovery",
		"socket_close",
		"pending_cleanup",
		"alarm_cleanup",
	] as const) {
		it(`reports InstanceDO ${fault} failure and converges on retry`, async () => {
			const enrolled = await enrollActive();
			const deviceToken = await mintUnsignedRowDeviceToken(enrolled.instanceId);
			let listen: WebSocket | undefined;
			let dial: WebSocket | undefined;
			if (fault === "socket_close" || fault === "pending_cleanup") {
				listen = await wsOpen(
					`http://spl.test/session/listen?instance=${enrolled.instanceId}`,
					enrolled.serviceToken,
				);
			}
			if (fault === "pending_cleanup") {
				const incoming = onMessage(listen as WebSocket);
				dial = await wsOpen(
					`http://spl.test/session/dial?instance=${enrolled.instanceId}`,
					deviceToken,
				);
				await incoming;
				dial.send("opaque-pending-fault-frame");
				const pendingStub = env.INSTANCE.get(env.INSTANCE.idFromName(enrolled.instanceId));
				await expectEventually(async () => {
					const size = await runInDurableObject(pendingStub, (instance) => {
						const pending = Reflect.get(instance, "pending") as Map<string, unknown>;
						return pending.size;
					});
					expect(size).toBe(1);
				});
			}

			const stub = env.INSTANCE.get(env.INSTANCE.idFromName(enrolled.instanceId));
			const restore = await installDoFault(stub, fault);
			const partial = await expectRetirementFailure(
				await retireInstance(enrolled.instanceId),
				"instance_do_cleanup",
			);
			expect(partial.entry_denial_verified).toBe(
				fault === "socket_close" || fault === "pending_cleanup" || fault === "alarm_cleanup",
			);
			restore();
			const firstRow = await env.DB.prepare(
				"SELECT revoked_at FROM instances WHERE instance_id = ?",
			)
				.bind(enrolled.instanceId)
				.first<{ revoked_at: number }>();
			expect(firstRow?.revoked_at).toBeTypeOf("number");
			await expectFreshListenDenied(enrolled);

			await expectRetirementSuccess(await retireInstance(enrolled.instanceId), "already_retired");
			const finalRow = await env.DB.prepare(
				"SELECT revoked_at FROM instances WHERE instance_id = ?",
			)
				.bind(enrolled.instanceId)
				.first<{ revoked_at: number }>();
			expect(finalRow?.revoked_at).toBe(firstRow?.revoked_at);
			if (fault === "pending_cleanup") {
				const size = await runInDurableObject(stub, (instance) => {
					const pending = Reflect.get(instance, "pending") as Map<string, unknown>;
					return pending.size;
				});
				expect(size).toBe(0);
			}
			closeAll(listen, dial);
		});
	}

	it("reports an RK-DO socket-close failure, keeps its marker authoritative, and converges", async () => {
		const enrolled = await enrollActive();
		const rk = "d2".repeat(16);
		const window = await openPairWindow(rk, enrolled.serviceToken);
		const closed = onClose(window);
		const stub = env.INSTANCE.get(env.INSTANCE.idFromName(rk));
		const restore = await installDoFault(stub, "socket_close");
		const partial = await expectRetirementFailure(
			await retireInstance(enrolled.instanceId),
			"rk_do_cleanup",
		);
		expect(partial.entry_denial_verified).toBe(true);
		expect(window.readyState).toBe(WebSocket.OPEN);
		expect((await pairFetch("/session/pair-dial", rk)).status).toBe(401);
		const firstRow = await env.DB.prepare("SELECT revoked_at FROM instances WHERE instance_id = ?")
			.bind(enrolled.instanceId)
			.first<{ revoked_at: number }>();
		restore();

		await expectRetirementSuccess(await retireInstance(enrolled.instanceId), "already_retired");
		const close = await closed;
		expect(close.code).toBe(4403);
		expect(close.reason).toBe("instance_retired");
		const finalRow = await env.DB.prepare("SELECT revoked_at FROM instances WHERE instance_id = ?")
			.bind(enrolled.instanceId)
			.first<{ revoked_at: number }>();
		expect(finalRow?.revoked_at).toBe(firstRow?.revoked_at);
		expect(await countRows("pairing_owners", enrolled.instanceId)).toBe(0);
	});

	it("denies a pair-window whose real registration committed before the retirement sweep but resumed after it", async () => {
		const enrolled = await enrollActive();
		const rk = "e1".repeat(16);
		const barrier = delayPreparedRun("INSERT INTO pairing_owners");
		const opening = pairFetch("/session/pair-window", rk, enrolled.serviceToken);
		await barrier.entered;

		await expectRetirementSuccess(await retireInstance(enrolled.instanceId), "retired");
		barrier.release();
		const response = await opening;
		barrier.restore();
		expect(response.status).toBe(401);
		expect(response.webSocket).toBeNull();
		expect(await countRows("pairing_owners", enrolled.instanceId)).toBe(0);
		const stub = env.INSTANCE.get(env.INSTANCE.idFromName(rk));
		expect(await runInDurableObject(stub, (_instance, state) => state.getWebSockets().length)).toBe(
			0,
		);
	});

	it("denies an instance-addressed upgrade whose token verification resumes after the sweep", async () => {
		const enrolled = await enrollActive();
		const barrier = delayNextEd25519Verification();
		const opening = wsFetch(
			`http://spl.test/session/listen?instance=${enrolled.instanceId}`,
			enrolled.serviceToken,
		);
		await barrier.entered;

		await expectRetirementSuccess(await retireInstance(enrolled.instanceId), "retired");
		barrier.release();
		const response = await opening;
		barrier.restore();
		expect([401, 402]).toContain(response.status);
		expect(response.webSocket).toBeNull();
	});

	it("converges an entitlement grant whose committed update returns after retirement", async () => {
		const enrolled = await enrollActive();
		const barrier = delayPreparedRun(
			"UPDATE instances SET entitled_until = ? WHERE instance_id = ? AND revoked_at IS NULL",
		);
		const grant = SELF.fetch("http://spl.test/admin/entitlement", {
			method: "POST",
			headers: { ...adminHeaders(), "content-type": "application/json" },
			body: JSON.stringify({
				instance_id: enrolled.instanceId,
				entitled_until: Math.floor(Date.now() / 1000) + 7200,
			}),
		});
		await barrier.entered;

		await expectRetirementSuccess(await retireInstance(enrolled.instanceId), "retired");
		barrier.release();
		expect((await grant).status).toBe(200);
		barrier.restore();
		const row = await env.DB.prepare(
			"SELECT revoked_at, entitled_until FROM instances WHERE instance_id = ?",
		)
			.bind(enrolled.instanceId)
			.first<{ revoked_at: number | null; entitled_until: number | null }>();
		expect(row?.revoked_at).toBeTypeOf("number");
		expect(row?.entitled_until).toBeNull();
		expect(await countRows("pending_grants", enrolled.instanceId)).toBe(0);
	});

	it("converges re-enrollment whose committed rotation returns after retirement", async () => {
		const enrolled = await enrollActive();
		const barrier = delayPreparedRun("UPDATE instances SET ca_fp = ?");
		const reenrollment = postHomeEnroll(enrolled.instanceId, enrolled.ca);
		await barrier.entered;

		await expectRetirementSuccess(await retireInstance(enrolled.instanceId), "retired");
		barrier.release();
		const response = await reenrollment;
		barrier.restore();
		expect(response.status).toBe(200);
		const body = (await response.json()) as { service_token: string };
		const denied = await wsFetch(
			`http://spl.test/session/listen?instance=${enrolled.instanceId}`,
			body.service_token,
		);
		expect([401, 402]).toContain(denied.status);
		expect(await countRows("pending_grants", enrolled.instanceId)).toBe(0);
	});

	it("converges device enrollment whose committed insert returns after retirement", async () => {
		const enrolled = await enrollActive();
		const deviceFp = await fingerprintDer(await genClientCertDer());
		const attestation = await mintAttestation({
			caPrivateKey: enrolled.ca.privateKey,
			instanceId: enrolled.instanceId,
			deviceFp,
		});
		const barrier = delayPreparedRun("INSERT INTO devices");
		const enrollment = SELF.fetch("http://spl.test/enroll/device", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({
				instance_id: enrolled.instanceId,
				home_attestation: attestation,
			}),
		});
		await barrier.entered;

		await expectRetirementSuccess(await retireInstance(enrolled.instanceId), "retired");
		barrier.release();
		const response = await enrollment;
		barrier.restore();
		expect(response.status).toBe(200);
		const body = (await response.json()) as { device_token: string };
		const dial = await wsFetch(
			`http://spl.test/session/dial?instance=${enrolled.instanceId}`,
			body.device_token,
		);
		expect([401, 402]).toContain(dial.status);
		const live = await env.DB.prepare(
			"SELECT device_jti FROM devices WHERE instance_id = ? AND revoked_at IS NULL LIMIT 1",
		)
			.bind(enrolled.instanceId)
			.first<{ device_jti: string }>();
		expect(live).toBeNull();
	});

	it("refuses token refresh when verification resumes after retirement", async () => {
		const enrolled = await enrollActive();
		const device = await enrollDeviceForTest(enrolled);
		const barrier = delayNextEd25519Verification();
		const refresh = SELF.fetch("http://spl.test/token/refresh", {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({ device_token: device.deviceToken }),
		});
		await barrier.entered;

		await expectRetirementSuccess(await retireInstance(enrolled.instanceId), "retired");
		barrier.release();
		const response = await refresh;
		barrier.restore();
		expect(response.status).toBe(403);
		expect((await response.json()) as Record<string, unknown>).not.toHaveProperty("device_token");
		expect(await countRows("pending_grants", enrolled.instanceId)).toBe(0);
	});

	it("converges duplicate retirement around the single conditional tombstone write", async () => {
		const enrolled = await enrollActive();
		const barrier = delayPreparedRun("UPDATE instances SET revoked_at = ?");
		const first = retireInstance(enrolled.instanceId);
		await barrier.entered;

		await expectRetirementSuccess(await retireInstance(enrolled.instanceId), "already_retired");
		const original = await env.DB.prepare("SELECT revoked_at FROM instances WHERE instance_id = ?")
			.bind(enrolled.instanceId)
			.first<{ revoked_at: number }>();
		barrier.release();
		await expectRetirementSuccess(await first, "retired");
		barrier.restore();
		const final = await env.DB.prepare(
			"SELECT revoked_at, entitled_until FROM instances WHERE instance_id = ?",
		)
			.bind(enrolled.instanceId)
			.first<{ revoked_at: number; entitled_until: number | null }>();
		expect(final?.revoked_at).toBe(original?.revoked_at);
		expect(final?.entitled_until).toBeNull();
		expect(await countRows("pending_grants", enrolled.instanceId)).toBe(0);
	});

	it("keeps the active admin projection and active-session behavior unchanged", async () => {
		const enrolled = await enrollActive();
		const device = await enrollDeviceForTest(enrolled);
		const expectedKeys = [
			"ca_fp",
			"created_at",
			"entitled",
			"entitled_until",
			"home_label",
			"instance_id",
			"revoked_at",
			"rotated_at",
		].sort();
		const show = await SELF.fetch(`http://spl.test/admin/instances/${enrolled.instanceId}`, {
			headers: adminHeaders(),
		});
		expect(show.status).toBe(200);
		const showBody = (await show.json()) as Record<string, unknown>;
		expect(Object.keys(showBody).sort()).toEqual(expectedKeys);
		expect(showBody.revoked_at).toBeNull();
		expect(showBody.entitled).toBe(true);
		expect(showBody).not.toHaveProperty("ca_pubkey_pem");
		expect(showBody).not.toHaveProperty("service_token_jti");

		const list = await SELF.fetch("http://spl.test/admin/instances", { headers: adminHeaders() });
		const listBody = (await list.json()) as { instances: Array<Record<string, unknown>> };
		const listed = listBody.instances.find((row) => row.instance_id === enrolled.instanceId);
		expect(Object.keys(listed ?? {}).sort()).toEqual(expectedKeys);

		const listen = await wsOpen(
			`http://spl.test/session/listen?instance=${enrolled.instanceId}`,
			enrolled.serviceToken,
		);
		const incoming = onMessage(listen);
		const dial = await wsOpen(
			`http://spl.test/session/dial?instance=${enrolled.instanceId}`,
			device.deviceToken,
		);
		expect(parseIncoming(await incoming)).toBeTruthy();
		closeAll(dial, listen);
	});

	it("keeps full retirement logs free of RK, payload, token, bearer, and DO-id material", async () => {
		const enrolled = await enrollActive();
		const device = await enrollDeviceForTest(enrolled);
		const rkOne = "f1".repeat(16);
		const rkTwo = "f2".repeat(16);
		const doIds = [rkOne, rkTwo].map((rk) => env.INSTANCE.idFromName(rk).toString());
		const secretFrame = "peer-supplied-S-and-payload-must-not-appear";
		const spy = vi.spyOn(console, "log").mockImplementation(() => {});

		try {
			const listen = await wsOpen(
				`http://spl.test/session/listen?instance=${enrolled.instanceId}`,
				enrolled.serviceToken,
			);
			const incoming = onMessage(listen);
			const dial = await wsOpen(
				`http://spl.test/session/dial?instance=${enrolled.instanceId}`,
				device.deviceToken,
			);
			const tunnelId = parseIncoming(await incoming);
			const tunnel = await wsOpen(
				`http://spl.test/tunnel/${tunnelId}?instance=${enrolled.instanceId}`,
				enrolled.serviceToken,
			);
			const forwarded = onMessage(tunnel);
			dial.send(secretFrame);
			expect(await forwarded).toBe(secretFrame);
			const pairOne = await openPairBridge(enrolled, rkOne);
			const pairTwo = await openPairBridge(enrolled, rkTwo);
			const closes = [
				listen,
				dial,
				tunnel,
				pairOne.window,
				pairOne.mobile,
				pairOne.home,
				pairTwo.window,
				pairTwo.mobile,
				pairTwo.home,
			].map(onClose);

			await expectRetirementSuccess(await retireInstance(enrolled.instanceId), "retired");
			await Promise.all(closes);
			const lines = spy.mock.calls.map((args) => args.map(String).join(" "));
			for (const line of lines) {
				for (const forbidden of [
					rkOne,
					rkTwo,
					enrolled.serviceToken,
					device.deviceToken,
					env.GRANT_SECRET,
					secretFrame,
					...doIds,
				]) {
					expect(line).not.toContain(forbidden);
				}
			}
			expect(lines.some((line) => line.includes('"event":"instance_retire"'))).toBe(true);
		} finally {
			spy.mockRestore();
		}
	});
});
