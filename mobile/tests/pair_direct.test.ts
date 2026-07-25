// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import { describe, expect, test } from "bun:test";
import { X509Certificate } from "node:crypto";

import type { TunnelSession } from "../src/dial";
import { DirectAddressAdmissionError } from "../src/direct_address_policy";
import type { HttpResponse } from "../src/http_client";
import { Multiplexer } from "../src/mux";
import {
	DirectCandidatesExhaustedError,
	type DirectPairDeps,
	type DirectPairInput,
	dedupeDirectCandidates,
	pairDirect,
} from "../src/pair_direct";
import { type DirectPairLink, parsePairLink } from "../src/qr_link";
import { CA_CERT_DER_FP16_HEX, CA_PEM, LEAF_PEM } from "./cert_fixtures";

describe("direct pair candidate preparation", () => {
	test("deduplicates first occurrences and prepares candidates sequentially", async () => {
		const opened: string[] = [];
		const requestedMuxes: Multiplexer[] = [];
		let enrollCalls = 0;
		let saveCalls = 0;
		const selected = controlledSession();

		const result = await pairDirect(
			makeInput({
				candidates: ["10.0.0.1", "10.0.0.1", "192.168.1.2", "10.0.0.1"],
				deps: successfulDeps({
					async openTunnel({ host }) {
						opened.push(host);
						if (host === "10.0.0.1") throw new Error("connect failed");
						return selected.session;
					},
					async request(mux) {
						requestedMuxes.push(mux);
						return validPairResponse();
					},
					async enrollDevice() {
						enrollCalls++;
						return { device_token: "device-token" };
					},
					async savePairing() {
						saveCalls++;
					},
				}),
			}),
		);

		expect(dedupeDirectCandidates(["a", "a", "b", "a"])).toEqual(["a", "b"]);
		expect(opened).toEqual(["10.0.0.1", "192.168.1.2"]);
		expect(requestedMuxes).toEqual([selected.session.mux]);
		expect(enrollCalls).toBe(1);
		expect(saveCalls).toBe(1);
		expect(result.decision).toBe("first-time");
		expect(result.saved).toBe(true);
	});

	test("refuses the published 0x04 vector with zero flow work", async () => {
		const published = "0G0W000258DSX8DJRFAEBXG7308J4CT4ANK7F26YNPZEZJQYQAZ028T5CY4TQKFF";
		const link = parsePairLink(`https://go.solstone.app/p#${published}`);
		expect(link.kind).toBe("direct");
		if (link.kind !== "direct") throw new Error("expected direct link");
		expect(link.addrType).toBe(0x01);
		expect(link.candidates).toEqual(["192.0.2.42"]);
		expect(link.port).toBe(7070);
		expect(link.nonce).toBe("a1b2c3d4e5f607181122334455667788");
		expect(Buffer.from(link.caFp).toString("hex")).toBe("deadbeefcafebabe0123456789abcdef");

		const calls = { open: 0, key: 0, request: 0, enroll: 0, save: 0 };
		const promise = pairDirect(
			makeInput({
				link,
				deps: countingNoWorkDeps(calls),
			}),
		);

		await expect(promise).rejects.toBeInstanceOf(DirectAddressAdmissionError);
		expect(calls).toEqual({ open: 0, key: 0, request: 0, enroll: 0, save: 0 });
	});

	test("refuses a mixed candidate set before key generation or external work", async () => {
		const calls = { open: 0, key: 0, request: 0, enroll: 0, save: 0 };
		const promise = pairDirect(
			makeInput({
				candidates: ["192.168.1.10", "192.0.2.42"],
				deps: countingNoWorkDeps(calls),
			}),
		);

		await expect(promise).rejects.toBeInstanceOf(DirectAddressAdmissionError);
		expect(calls).toEqual({ open: 0, key: 0, request: 0, enroll: 0, save: 0 });
	});

	test("uses one fixed exhaustion error when every opener rejects", async () => {
		let keyCalls = 0;
		let requestCalls = 0;
		let enrollCalls = 0;
		let saveCalls = 0;
		const promise = pairDirect(
			makeInput({
				candidates: ["10.0.0.1", "192.168.1.2"],
				deps: successfulDeps({
					async openTunnel() {
						throw new Error("connect failed");
					},
					async generateKeyPair() {
						keyCalls++;
						throw new Error("must not generate");
					},
					async request() {
						requestCalls++;
						return validPairResponse();
					},
					async enrollDevice() {
						enrollCalls++;
						return { device_token: "device-token" };
					},
					async savePairing() {
						saveCalls++;
					},
				}),
			}),
		);

		await expect(promise).rejects.toEqual(
			expect.objectContaining({
				name: "DirectCandidatesExhaustedError",
				message: "direct candidates exhausted before pairing request",
			}),
		);
		expect(keyCalls).toBe(0);
		expect(requestCalls).toBe(0);
		expect(enrollCalls).toBe(0);
		expect(saveCalls).toBe(0);
	});

	test("waits for a late session teardown before starting the next dial", async () => {
		const firstOpen = deferred<TunnelSession>();
		const late = controlledSession();
		const selected = controlledSession();
		const timers = manualTimers();
		const opened: string[] = [];
		let firstSignal: AbortSignal | undefined;
		let requestCalls = 0;

		const pairing = pairDirect(
			makeInput({
				candidates: ["10.0.0.1", "192.168.1.2"],
				deps: successfulDeps({
					openTunnel({ host, signal }) {
						opened.push(host);
						if (host === "10.0.0.1") firstSignal = signal;
						return host === "10.0.0.1" ? firstOpen.promise : Promise.resolve(selected.session);
					},
					async request() {
						requestCalls++;
						return validPairResponse();
					},
					setTimer: timers.setTimer,
				}),
			}),
		);

		expect(opened).toEqual(["10.0.0.1"]);
		expect(timers.entries[0]?.delayMs).toBe(10_000);
		timers.fire(0);
		await flushMicrotasks();
		expect(firstSignal?.aborted).toBe(true);
		expect(opened).toEqual(["10.0.0.1"]);
		expect(timers.entries[1]?.delayMs).toBe(10_000);

		firstOpen.resolve(late.session);
		await waitFor(() => opened.length === 2);
		expect(late.closeCalls()).toBe(1);
		expect(opened).toEqual(["10.0.0.1", "192.168.1.2"]);

		await pairing;
		expect(requestCalls).toBe(1);
	});

	test("unconfirmed deadline teardown terminates without another dial", async () => {
		const firstOpen = deferred<TunnelSession>();
		const late = controlledSession();
		const timers = manualTimers();
		let firstSignal: AbortSignal | undefined;
		let openCalls = 0;
		let keyCalls = 0;
		let requestCalls = 0;

		const pairing = pairDirect(
			makeInput({
				candidates: ["10.0.0.1", "192.168.1.2"],
				deps: successfulDeps({
					openTunnel({ signal }) {
						openCalls++;
						firstSignal = signal;
						return firstOpen.promise;
					},
					async generateKeyPair() {
						keyCalls++;
						throw new Error("must not generate");
					},
					async request() {
						requestCalls++;
						return validPairResponse();
					},
					setTimer: timers.setTimer,
				}),
			}),
		);

		timers.fire(0);
		await flushMicrotasks();
		expect(firstSignal?.aborted).toBe(true);
		expect(timers.entries[1]?.delayMs).toBe(10_000);
		timers.fire(1);

		await expect(pairing).rejects.toEqual(
			expect.objectContaining({
				name: "DirectCandidatesExhaustedError",
				message: "direct candidates exhausted before pairing request",
			}),
		);
		expect(openCalls).toBe(1);
		expect(keyCalls).toBe(0);
		expect(requestCalls).toBe(0);

		firstOpen.resolve(late.session);
		await waitFor(() => late.closeCalls() === 1);
		expect(requestCalls).toBe(0);
	});
});

describe("direct pair commit and persistence", () => {
	test("commits one request, enrolls once, and saves first-time state once", async () => {
		const session = controlledSession();
		const calls = { request: 0, enroll: 0, save: 0 };
		let savedPath = "";

		const result = await pairDirect(
			makeInput({
				candidates: ["10.0.0.1", "192.168.1.2"],
				deps: successfulDeps({
					async openTunnel() {
						return session.session;
					},
					async request() {
						calls.request++;
						return validPairResponse();
					},
					async enrollDevice() {
						calls.enroll++;
						return { device_token: "device-token" };
					},
					async savePairing(path) {
						calls.save++;
						savedPath = path;
					},
				}),
			}),
		);

		expect(calls).toEqual({ request: 1, enroll: 1, save: 1 });
		expect(savedPath).toBe("/tmp/mobile-state.json");
		expect(result.state.device_token).toBe("device-token");
		expect(result.decision).toBe("first-time");
		expect(result.saved).toBe(true);
	});

	test("preserves already-connected save suppression while enrolling once", async () => {
		let enrollCalls = 0;
		let saveCalls = 0;
		const result = await pairDirect(
			makeInput({
				storedInstanceId: "instance-1",
				deps: successfulDeps({
					async enrollDevice() {
						enrollCalls++;
						return { device_token: "device-token" };
					},
					async savePairing() {
						saveCalls++;
					},
				}),
			}),
		);

		expect(enrollCalls).toBe(1);
		expect(saveCalls).toBe(0);
		expect(result.decision).toBe("already-connected");
		expect(result.saved).toBe(false);
	});

	test("continues enrollment after post-commit teardown is unconfirmed", async () => {
		const session = controlledSession({ confirmClose: false });
		const timers = manualTimers();
		const requestStarted = deferred<void>();
		let enrollCalls = 0;
		let saveCalls = 0;
		const pairing = pairDirect(
			makeInput({
				deps: successfulDeps({
					async openTunnel() {
						return session.session;
					},
					async request() {
						requestStarted.resolve();
						return validPairResponse();
					},
					async enrollDevice() {
						enrollCalls++;
						return { device_token: "device-token" };
					},
					async savePairing() {
						saveCalls++;
					},
					setTimer: timers.setTimer,
				}),
			}),
		);

		await requestStarted.promise;
		await waitFor(() => timers.entries.length >= 2);
		expect(timers.entries[1]?.delayMs).toBe(10_000);
		timers.fire(1);
		await pairing;
		expect(session.closeCalls()).toBe(1);
		expect(enrollCalls).toBe(1);
		expect(saveCalls).toBe(1);
	});

	test("all request and response failures are terminal after one opener", async () => {
		const marker = new Error("terminal request failure");
		const cases: Array<{
			name: string;
			request: DirectPairDeps["request"];
			link?: DirectPairLink;
			expected: string | Error;
		}> = [
			{
				name: "immediate request throw",
				request() {
					throw marker;
				},
				expected: marker,
			},
			{
				name: "reset or timeout rejection",
				request: async () => {
					throw marker;
				},
				expected: marker,
			},
			{
				name: "HTTP 410",
				request: async () => ({ status: 410, reason: "Gone", headers: {}, body: bytes("") }),
				expected: "direct pair failed: HTTP 410",
			},
			{
				name: "malformed JSON",
				request: async () => ({ status: 200, reason: "OK", headers: {}, body: bytes("{") }),
				expected: "direct pair response was malformed",
			},
			{
				name: "missing response fields",
				request: async () => ({ status: 200, reason: "OK", headers: {}, body: bytes("{}") }),
				expected: "direct pair response was malformed",
			},
			{
				name: "pin failure",
				request: async () => validPairResponse(),
				link: directLink(["10.0.0.1"], new Uint8Array(16)),
				expected: "CA cert pin mismatch",
			},
		];

		for (const failure of cases) {
			let openCalls = 0;
			let requestCalls = 0;
			let enrollCalls = 0;
			let saveCalls = 0;
			const session = controlledSession();
			const promise = pairDirect(
				makeInput({
					candidates: ["10.0.0.1", "192.168.1.2"],
					link: failure.link,
					deps: successfulDeps({
						async openTunnel() {
							openCalls++;
							return session.session;
						},
						async request(mux, request) {
							requestCalls++;
							return await failure.request(mux, request);
						},
						async enrollDevice() {
							enrollCalls++;
							return { device_token: "device-token" };
						},
						async savePairing() {
							saveCalls++;
						},
					}),
				}),
			);

			if (typeof failure.expected === "string") {
				await expect(promise).rejects.toThrow(failure.expected);
			} else {
				await expect(promise).rejects.toBe(failure.expected);
			}
			expect(openCalls).toBe(1);
			expect(requestCalls).toBe(1);
			expect(enrollCalls).toBe(0);
			expect(saveCalls).toBe(0);
		}
	});

	test("enrollment and state-save failures are terminal without another candidate", async () => {
		for (const stage of ["enroll", "save"] as const) {
			const marker = new Error(`${stage} failed`);
			let openCalls = 0;
			let requestCalls = 0;
			let enrollCalls = 0;
			let saveCalls = 0;
			const promise = pairDirect(
				makeInput({
					candidates: ["10.0.0.1", "192.168.1.2"],
					deps: successfulDeps({
						async openTunnel() {
							openCalls++;
							return controlledSession().session;
						},
						async request() {
							requestCalls++;
							return validPairResponse();
						},
						async enrollDevice() {
							enrollCalls++;
							if (stage === "enroll") throw marker;
							return { device_token: "device-token" };
						},
						async savePairing() {
							saveCalls++;
							if (stage === "save") throw marker;
						},
					}),
				}),
			);

			await expect(promise).rejects.toBe(marker);
			expect(openCalls).toBe(1);
			expect(requestCalls).toBe(1);
			expect(enrollCalls).toBe(1);
			expect(saveCalls).toBe(stage === "save" ? 1 : 0);
		}
	});
});

function makeInput(options: {
	candidates?: readonly string[];
	link?: DirectPairLink;
	storedInstanceId?: string | null;
	deps?: Partial<DirectPairDeps>;
}): DirectPairInput {
	return {
		link: options.link ?? directLink(options.candidates ?? ["10.0.0.1"]),
		deviceLabel: "test phone",
		relayEndpoint: "https://link.solstone.app/",
		statePath: "/tmp/mobile-state.json",
		storedInstanceId: options.storedInstanceId ?? null,
		deps: options.deps,
	};
}

function directLink(
	candidates: readonly string[],
	caFp = hexToBytes(CA_CERT_DER_FP16_HEX),
): DirectPairLink {
	return {
		kind: "direct",
		addrType: 0x01,
		candidates,
		port: 7070,
		nonce: "a1b2c3d4e5f607181122334455667788",
		caFp,
	};
}

function successfulDeps(overrides: Partial<DirectPairDeps> = {}): Partial<DirectPairDeps> {
	return {
		async openTunnel() {
			return controlledSession().session;
		},
		async request() {
			return validPairResponse();
		},
		async enrollDevice() {
			return { device_token: "device-token" };
		},
		async savePairing() {},
		...overrides,
	};
}

function countingNoWorkDeps(calls: {
	open: number;
	key: number;
	request: number;
	enroll: number;
	save: number;
}): Partial<DirectPairDeps> {
	return {
		async openTunnel() {
			calls.open++;
			throw new Error("must not open");
		},
		async generateKeyPair() {
			calls.key++;
			throw new Error("must not generate");
		},
		async request() {
			calls.request++;
			throw new Error("must not request");
		},
		async enrollDevice() {
			calls.enroll++;
			throw new Error("must not enroll");
		},
		async savePairing() {
			calls.save++;
		},
	};
}

function validPairResponse(): HttpResponse {
	return {
		status: 200,
		reason: "OK",
		headers: { "content-type": "application/json" },
		body: bytes(
			JSON.stringify({
				client_cert: "client-cert",
				ca_chain: [CA_PEM],
				instance_id: "instance-1",
				home_label: "Kitchen Mac",
				home_attestation: "home-attestation",
				fingerprint: "sha256:fingerprint",
			}),
		),
	};
}

function controlledSession(options: { confirmClose?: boolean } = {}): {
	session: TunnelSession;
	closeCalls(): number;
} {
	const confirmClose = options.confirmClose ?? true;
	let closeCalls = 0;
	let resolveClosed = () => {};
	const closed = new Promise<void>((resolve) => {
		resolveClosed = resolve;
	});
	const session: TunnelSession = {
		mux: new Multiplexer(() => {}),
		peerLeaf: new X509Certificate(LEAF_PEM),
		async close() {
			closeCalls++;
			if (confirmClose) resolveClosed();
			await closed;
		},
		closed,
	};
	return { session, closeCalls: () => closeCalls };
}

function manualTimers(): {
	entries: Array<{ delayMs: number; cancelled: boolean; callback: () => void }>;
	setTimer(delayMs: number, callback: () => void): () => void;
	fire(index: number): void;
} {
	const entries: Array<{ delayMs: number; cancelled: boolean; callback: () => void }> = [];
	return {
		entries,
		setTimer(delayMs, callback) {
			const entry = { delayMs, cancelled: false, callback };
			entries.push(entry);
			return () => {
				entry.cancelled = true;
			};
		},
		fire(index) {
			const entry = entries[index];
			if (!entry) throw new Error(`missing timer ${index}`);
			if (!entry.cancelled) entry.callback();
		},
	};
}

function deferred<T>(): {
	promise: Promise<T>;
	resolve(value: T): void;
} {
	let resolve = (_value: T) => {};
	const promise = new Promise<T>((innerResolve) => {
		resolve = innerResolve;
	});
	return { promise, resolve };
}

async function waitFor(predicate: () => boolean): Promise<void> {
	for (let i = 0; i < 100; i++) {
		if (predicate()) return;
		await new Promise<void>((resolve) => setTimeout(resolve, 0));
	}
	throw new Error("condition did not become true");
}

async function flushMicrotasks(): Promise<void> {
	await Promise.resolve();
	await Promise.resolve();
}

function bytes(value: string): Uint8Array {
	return new TextEncoder().encode(value);
}

function hexToBytes(value: string): Uint8Array {
	return new Uint8Array(Buffer.from(value, "hex"));
}
