// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

// Dial WS + tunnel TLS + mux — mobile side.
//
// Opens a single WebSocket to spl-relay /session/dial (with the stored
// device token) — and the *same* socket becomes the tunnel WS once the
// relay has paired with the home tunnel WS. Per proto/session.md §step 2
// this is the single-WS-per-side simplification (prototype finding §11.1).
//
// Inside that byte pipe we run TLS 1.3 as a client (Node's `tls` module
// on an arbitrary Duplex, per prototype finding §11.6 — we plumb all
// Duplex events from the WS into `tls.connect({ socket })` so data/end/
// close/error don't get lost). On top of TLS runs the spl multiplexer,
// and each logical stream speaks HTTP/1.1 to the home's test app.

import type { X509Certificate } from "node:crypto";
import { Duplex } from "node:stream";
import tls from "node:tls";

import { parseJwtClaims, shouldRefreshBeforeDial } from "./device_token";
import { Multiplexer } from "./mux";
import { type PairingState, refreshDeviceToken, savePairing } from "./pair";

export interface DialOptions {
	state: PairingState;
	/** If provided, use this exact token and skip proactive and reactive refresh. */
	deviceToken?: string;
	/** If provided, refreshed tokens are persisted to this pairing-state path. */
	statePath?: string;
	/** Override the relay endpoint (tests). */
	relayEndpoint?: string;
}

export interface TunnelSession {
	mux: Multiplexer;
	peerLeaf?: X509Certificate;
	close(): Promise<void>;
	/** Resolves when the underlying WS disconnects or TLS aborts. */
	closed: Promise<void>;
}

export type TrustMode =
	| { mode: "ca"; caChain: string; cert: string; key: string }
	| { mode: "pin" };

export interface TunnelConfig {
	endpoint: string;
	path: string;
	instanceId: string;
	token: string;
	trust: TrustMode;
}

class DialRejected extends Error {
	constructor() {
		super("WebSocket upgrade rejected");
		this.name = "DialRejected";
	}
}

export class ReconnectRequired extends Error {
	constructor(homeLabel: string) {
		super(`Reconnect required for ${homeLabel}. Re-pair this device to continue.`);
		this.name = "ReconnectRequired";
	}
}

export async function dial(options: DialOptions): Promise<TunnelSession> {
	const { state } = options;
	const endpoint = (options.relayEndpoint ?? state.relay_endpoint).replace(/\/+$/, "");
	const override = options.deviceToken;
	const refreshEnabled = override === undefined;
	let token = override ?? state.device_token;
	let refreshed = false;

	const persist = async (nextToken: string): Promise<void> => {
		state.device_token = nextToken;
		if (options.statePath) await savePairing(options.statePath, state);
	};

	const tunnelConfig = (): TunnelConfig => ({
		endpoint,
		path: "/session/dial",
		instanceId: state.instance_id,
		token,
		trust: {
			mode: "ca",
			caChain: state.ca_chain.join(""),
			cert: state.client_cert,
			key: state.client_key_pem,
		},
	});

	if (refreshEnabled) {
		const claims = parseJwtClaims(token);
		if (claims && shouldRefreshBeforeDial(claims, Math.floor(Date.now() / 1000))) {
			const result = await refreshDeviceToken(endpoint, token);
			if (result.action === "use_new_token" && result.token) {
				token = result.token;
				await persist(token);
				refreshed = true;
			} else if (result.action === "reconnect") {
				throw new ReconnectRequired(state.home_label);
			}
		}
	}

	try {
		return await openTunnel(tunnelConfig());
	} catch (err) {
		if (!(err instanceof DialRejected) || !refreshEnabled || refreshed) throw err;

		const result = await refreshDeviceToken(endpoint, token);
		if (result.action === "use_new_token" && result.token) {
			token = result.token;
			await persist(token);
			return await openTunnel(tunnelConfig());
		}
		if (result.action === "reconnect") throw new ReconnectRequired(state.home_label);
		throw err;
	}
}

export async function openTunnel(config: TunnelConfig): Promise<TunnelSession> {
	const endpoint = config.endpoint.replace(/\/+$/, "");
	const url = toWsUrl(
		`${endpoint}${config.path}?instance=${encodeURIComponent(config.instanceId)}&token=${encodeURIComponent(config.token)}`,
	);

	// Bun 1.1+ exposes a browser-compatible WebSocket global that works
	// against ws:// and wss:// URLs. No third-party dep needed.
	const ws = new WebSocket(url);
	ws.binaryType = "arraybuffer";
	await new Promise<void>((resolve, reject) => {
		let settled = false;
		const cleanup = () => {
			ws.removeEventListener("open", onOpen);
			ws.removeEventListener("error", onRejected);
			ws.removeEventListener("close", onRejected);
		};
		const onOpen = () => {
			if (settled) return;
			settled = true;
			cleanup();
			resolve();
		};
		// Seam: Bun collapses failed relay upgrades for 4401, 4402, and 503 into an
		// opaque failure: CloseEvent.code 1002 with "Expected 101 status code". HTTP
		// status and x-close-code are not exposed. This is a Bun runtime limitation,
		// not a protocol gap: native clients can read that handshake metadata, and
		// classifyDialRejection in device_token.ts encodes the full wire contract for
		// them and for tests. The Bun runtime treats any dial upgrade failure as
		// possibly stale auth and refreshes once; proactive >80%-TTL refresh is the
		// primary mechanism, and this reactive refresh is the backstop.
		const onRejected = (ev: Event) => {
			void ev.type;
			if (settled) return;
			settled = true;
			cleanup();
			reject(new DialRejected());
		};
		ws.addEventListener("open", onOpen, { once: true });
		ws.addEventListener("error", onRejected, { once: true });
		ws.addEventListener("close", onRejected, { once: true });
	});

	const wsDuplex = wsToDuplex(ws);

	const tlsSocket = tls.connect({
		socket: wsDuplex,
		minVersion: "TLSv1.3",
		maxVersion: "TLSv1.3",
		// The home's TLS server cert CN is whatever the home labels it —
		// we're pinned by CA or QR flow, so skip hostname check.
		checkServerIdentity: () => undefined,
		...(config.trust.mode === "ca"
			? {
					ca: [config.trust.caChain],
					cert: config.trust.cert,
					key: config.trust.key,
					rejectUnauthorized: true,
				}
			: {
					rejectUnauthorized: false,
				}),
	});
	let peerLeaf: X509Certificate | undefined;
	await new Promise<void>((resolve, reject) => {
		const onSecureConnect = () => {
			tlsSocket.removeListener("error", onError);
			if (config.trust.mode === "pin") {
				peerLeaf = tlsSocket.getPeerX509Certificate() ?? undefined;
			}
			resolve();
		};
		const onError = (err: Error) => {
			tlsSocket.removeListener("secureConnect", onSecureConnect);
			try {
				tlsSocket.destroy();
			} catch {}
			try {
				ws.close(1011, "tls-error");
			} catch {}
			reject(err);
		};
		tlsSocket.once("secureConnect", onSecureConnect);
		tlsSocket.once("error", onError);
	});

	return buildTunnelSession(tlsSocket, peerLeaf, () => {
		try {
			ws.close(1000, "test_done");
		} catch {}
	});
}

export interface DirectTunnelConfig {
	host: string;
	port: number;
}

// LAN-direct (v0x04) pairing: TLS straight to the home over TCP, no relay WS.
// The home is self-signed, so the handshake is cert-less (rejectUnauthorized
// false); trust is established afterward by pinning the QR CA fingerprint
// against the returned ca_chain and binding it to this captured peer leaf
// (see assertDirectCaPin). Mirrors the relay pin posture, minus the tunnel.
export async function openDirectTunnel(config: DirectTunnelConfig): Promise<TunnelSession> {
	const tlsSocket = tls.connect({
		host: config.host,
		port: config.port,
		minVersion: "TLSv1.3",
		maxVersion: "TLSv1.3",
		checkServerIdentity: () => undefined,
		rejectUnauthorized: false,
	});
	let peerLeaf: X509Certificate | undefined;
	await new Promise<void>((resolve, reject) => {
		const onSecureConnect = () => {
			tlsSocket.removeListener("error", onError);
			peerLeaf = tlsSocket.getPeerX509Certificate() ?? undefined;
			resolve();
		};
		const onError = (err: Error) => {
			tlsSocket.removeListener("secureConnect", onSecureConnect);
			try {
				tlsSocket.destroy();
			} catch {}
			reject(err);
		};
		tlsSocket.once("secureConnect", onSecureConnect);
		tlsSocket.once("error", onError);
	});
	return buildTunnelSession(tlsSocket, peerLeaf, () => {});
}

// Shared mux + session wiring for both the relay tunnel and the LAN-direct
// socket: pump TLS plaintext into the multiplexer, resolve `closed` on
// teardown, and expose `close()` that ends TLS then runs the transport-
// specific `onClose` (relay WS close, or a no-op for a raw socket).
function buildTunnelSession(
	tlsSocket: tls.TLSSocket,
	peerLeaf: X509Certificate | undefined,
	onClose: () => void,
): TunnelSession {
	const mux = new Multiplexer((bytes) => {
		tlsSocket.write(bytes);
	});

	let closedResolver: () => void = () => {};
	const closed = new Promise<void>((resolve) => {
		closedResolver = resolve;
	});

	tlsSocket.on("data", (chunk: Buffer) => {
		mux.feed(new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.byteLength));
	});
	tlsSocket.on("close", () => {
		mux.tearDown();
		closedResolver();
	});
	tlsSocket.on("error", () => {
		mux.tearDown();
		closedResolver();
	});

	return {
		mux,
		peerLeaf,
		async close() {
			try {
				tlsSocket.end();
			} catch {}
			onClose();
			await closed;
		},
		closed,
	};
}

// Adapt a browser-compatible WebSocket to a Node Duplex that carries raw
// binary. Plumbs `message`, `close`, `error` into Duplex events per
// prototype finding §11.6.
function wsToDuplex(ws: WebSocket): Duplex {
	const duplex = new Duplex({
		writableObjectMode: false,
		readableObjectMode: false,
		write(chunk: Buffer | string, _encoding: BufferEncoding, cb: (err?: Error) => void) {
			const buf = typeof chunk === "string" ? Buffer.from(chunk, "utf-8") : chunk;
			try {
				if (ws.readyState !== WebSocket.OPEN) {
					cb(new Error("ws not open"));
					return;
				}
				ws.send(buf);
				cb();
			} catch (err) {
				cb(err as Error);
			}
		},
		read() {
			// push-based; WS message handler feeds `push` below.
		},
		final(cb: (err?: Error) => void) {
			try {
				ws.close(1000, "tls-finish");
				cb();
			} catch (err) {
				cb(err as Error);
			}
		},
		destroy(err: Error | null, cb: (err?: Error | null) => void) {
			try {
				if (ws.readyState === WebSocket.OPEN) ws.close(1011, "tls-destroy");
			} catch {}
			cb(err);
		},
	});
	ws.addEventListener("message", (ev: MessageEvent) => {
		const data = ev.data;
		if (data instanceof ArrayBuffer) {
			duplex.push(Buffer.from(new Uint8Array(data)));
		} else if (ArrayBuffer.isView(data)) {
			duplex.push(Buffer.from(data.buffer, data.byteOffset, data.byteLength));
		} else if (typeof data === "string") {
			duplex.push(Buffer.from(data, "utf-8"));
		}
	});
	ws.addEventListener("close", () => {
		duplex.push(null);
	});
	ws.addEventListener("error", () => {
		duplex.destroy(new Error("ws error"));
	});
	return duplex;
}

function toWsUrl(url: string): string {
	if (url.startsWith("http://")) return `ws://${url.slice(7)}`;
	if (url.startsWith("https://")) return `wss://${url.slice(8)}`;
	return url;
}
