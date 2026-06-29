// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

// InstanceDO — one Durable Object per home solstone instance.
//
// Holds the listen WS open. On each incoming dial, mints a tunnel_id,
// signals the home, pairs the two tunnel WSes, and forwards opaque bytes
// between them until close. Never reads or reasons about payload; never
// stores anything beyond the per-socket attachment and a bounded pending
// buffer.
//
// See proto/session.md for the WebSocket dance contract and the cardinality
// invariants. See AGENTS.md §3 for the blind-by-construction invariant.

import { DurableObject } from "cloudflare:workers";
import type { Env } from "./env";
import { type Direction, log } from "./logging";
import { verifyToken } from "./tokens";

interface Attachment {
	role: "listen" | "dial" | "pair_window" | "tunnel_home" | "tunnel_mobile";
	tunnel_id?: string;
	instance_id: string;
	opened_at: number;
	jti: string;
	// Dedup flag for waiting-dial signaling; mutable post-accept, persisted via serializeAttachment.
	signaled?: boolean;
}

// Pending-buffer cap per tunnel, per peer direction. Bounds memory under a
// misbehaving peer that sends before the other side has attached. See
// proto/session.md §"pending buffer". 16 MiB is generous — a healthy client
// buffers ≤2 KiB (TLS ClientHello).
const PENDING_BUFFER_CAP_BYTES = 16 * 1024 * 1024;

// CF default close code for message-too-big. Proto/session.md §pending buffer
// specifies 1009 on overflow.
const CLOSE_CODE_MESSAGE_TOO_BIG = 1009;

// 1000 is the normal-closure code for peer-driven close propagation.
const CLOSE_CODE_NORMAL = 1000;

// 4401 is the unauthorized-close code per proto/tokens.md §validation.
const CLOSE_CODE_UNAUTHORIZED = 4401;

// 4402 is the not-entitled-close code for the opt-in session gate.
const CLOSE_CODE_NOT_ENTITLED = 4402;

const PAIR_DIAL_FAILED_LIMIT = 50;
const PAIR_WINDOW_TTL_MS = 7 * 60 * 1000;

export class InstanceDO extends DurableObject<Env> {
	// Buffers keyed by WS-tag destination (e.g., `tunnel_home:<id>`).
	private pending: Map<string, PendingBuffer> = new Map();
	private failedDials = 0;

	override async fetch(request: Request): Promise<Response> {
		const url = new URL(request.url);
		const path = url.pathname;
		if (request.headers.get("upgrade")?.toLowerCase() !== "websocket") {
			return new Response("websocket upgrade required", { status: 426 });
		}

		if (path === "/session/pair-window") {
			return this.handlePairWindow(request, url);
		}
		if (path === "/session/pair-dial") {
			return this.handlePairDial(request, url);
		}
		if (path.startsWith("/tunnel/") && request.headers.has("sec-pair-key")) {
			const tunnelId = path.slice("/tunnel/".length);
			if (!tunnelId) return new Response("tunnel_id required", { status: 400 });
			return this.handlePairingTunnel(request, url, tunnelId);
		}

		const instanceId = url.searchParams.get("instance");
		if (!instanceId) {
			return new Response("instance param required", { status: 400 });
		}

		if (path === "/session/listen") {
			return this.handleListen(request, url, instanceId);
		}
		if (path === "/session/dial") {
			return this.handleDial(request, url, instanceId);
		}
		if (path.startsWith("/tunnel/")) {
			const tunnelId = path.slice("/tunnel/".length);
			if (!tunnelId) return new Response("tunnel_id required", { status: 400 });
			return this.handleTunnel(request, url, instanceId, tunnelId);
		}
		return new Response("not found", { status: 404 });
	}

	private async handleListen(request: Request, url: URL, instanceId: string): Promise<Response> {
		const token = extractToken(request, url);
		if (!token) return unauthorizedWithLog("/session/listen", "missing_token", instanceId);

		const result = await verifyToken(token, {
			jwksRaw: this.env.JWKS_PUBLIC,
			expectedIssuer: this.env.ISSUER,
			expectedScope: "session.listen",
		});
		if (!result.ok) return unauthorizedWithLog("/session/listen", result.reason, instanceId);
		if (result.claims.instance_id !== instanceId) {
			return unauthorizedWithLog("/session/listen", "instance_mismatch", instanceId);
		}
		if (this.env.ENTITLEMENT_REQUIRED === "true" && !(await this.isEntitled(instanceId))) {
			log({ event: "not_entitled", route: "/session/listen", instance_id: instanceId });
			return notEntitledResponse();
		}

		// WS-tag cardinality: at most one active listen WS per instance.
		const existing = this.ctx.getWebSockets(tagListen(instanceId));
		for (const ws of existing) {
			try {
				ws.close(CLOSE_CODE_NORMAL, "replaced");
			} catch {}
			log({
				event: "cardinality_violation",
				instance_id: instanceId,
				reason: "listen_replaced",
			});
		}

		const { client, server } = newPair();
		const att: Attachment = {
			role: "listen",
			instance_id: instanceId,
			opened_at: Date.now(),
			jti: result.claims.jti,
		};
		server.serializeAttachment(att);
		this.ctx.acceptWebSocket(server, [tagListen(instanceId)]);
		log({ event: "listen_open", instance_id: instanceId, jti: result.claims.jti });

		if (this.env.PRESENCE_HOLD_ENABLED === "true") {
			// Broker any dials that were held waiting for a home. Tags are
			// immutable, so a paired (still-open) dial also carries tagWaiting;
			// `signaled` dedups so we never re-incoming an already-signaled dial.
			for (const waiting of this.ctx.getWebSockets(tagWaiting(instanceId))) {
				const watt = waiting.deserializeAttachment() as Attachment | null;
				if (!watt || watt.signaled || !watt.tunnel_id) continue;
				if (this.signalIncoming(server, watt.tunnel_id)) {
					watt.signaled = true;
					waiting.serializeAttachment(watt);
					log({
						event: "dial_open",
						instance_id: instanceId,
						tunnel_id: watt.tunnel_id,
						jti: watt.jti,
					});
				}
			}
		}

		return new Response(null, { status: 101, webSocket: client });
	}

	private async handleDial(request: Request, url: URL, instanceId: string): Promise<Response> {
		const token = extractToken(request, url);
		if (!token) return unauthorizedWithLog("/session/dial", "missing_token", instanceId);

		const result = await verifyToken(token, {
			jwksRaw: this.env.JWKS_PUBLIC,
			expectedIssuer: this.env.ISSUER,
			expectedScope: "session.dial",
		});
		if (!result.ok) return unauthorizedWithLog("/session/dial", result.reason, instanceId);
		if (result.claims.instance_id !== instanceId) {
			return unauthorizedWithLog("/session/dial", "instance_mismatch", instanceId);
		}
		if (this.env.ENTITLEMENT_REQUIRED === "true" && !(await this.isEntitled(instanceId))) {
			log({ event: "not_entitled", route: "/session/dial", instance_id: instanceId });
			return notEntitledResponse();
		}

		const listeners = this.ctx.getWebSockets(tagListen(instanceId));
		if (listeners.length === 0) {
			if (this.env.PRESENCE_HOLD_ENABLED === "true") {
				// No home listening: hold the dial open as a waiting dialer. Pre-mint
				// the tunnel_id and tag the socket [waiting, tunnel_mobile] at accept
				// time (tags are immutable). handleListen signals it when a home
				// appears. Relay holds indefinitely; cleanup is reactive on close.
				const tunnelId = crypto.randomUUID();
				const { client } = this.acceptMobileTunnel(instanceId, result.claims.jti, tunnelId, [
					tagWaiting(instanceId),
					tagTunnelMobile(tunnelId),
				]);
				return new Response(null, { status: 101, webSocket: client });
			}
			return new Response("no home listening", { status: 503 });
		}

		return this.brokerTunnel(listeners[0], instanceId, result.claims.jti, "dial_open");
	}

	override async alarm(): Promise<void> {
		for (const ws of this.ctx.getWebSockets(tagPairWindow())) {
			const att = ws.deserializeAttachment() as Attachment | null;
			try {
				ws.close(CLOSE_CODE_NORMAL, "window_expired");
			} catch {}
			log({
				event: "pair_window_close",
				instance_id: att?.instance_id,
				reason: "ttl_expired",
			});
		}
	}

	private async handlePairWindow(request: Request, url: URL): Promise<Response> {
		const token = extractToken(request, url);
		if (!token) return unauthorizedWithLog("/session/pair-window", "missing_token");

		const result = await verifyToken(token, {
			jwksRaw: this.env.JWKS_PUBLIC,
			expectedIssuer: this.env.ISSUER,
			expectedScope: "session.listen",
		});
		if (!result.ok) return unauthorizedWithLog("/session/pair-window", result.reason);

		const instanceId = result.claims.instance_id;
		const row = await this.env.DB.prepare("SELECT revoked_at FROM instances WHERE instance_id = ?")
			.bind(instanceId)
			.first<{ revoked_at: number | null }>();
		if (!row) {
			return unauthorizedWithLog("/session/pair-window", "not_enrolled", instanceId);
		}
		if (row.revoked_at !== null) {
			return unauthorizedWithLog("/session/pair-window", "revoked", instanceId);
		}

		for (const ws of this.ctx.getWebSockets(tagPairWindow())) {
			const existing = ws.deserializeAttachment() as Attachment | null;
			try {
				ws.close(CLOSE_CODE_NORMAL, "replaced");
			} catch {}
			log({
				event: "cardinality_violation",
				instance_id: existing?.instance_id ?? instanceId,
				reason: "pair_window_replaced",
			});
		}

		const { client, server } = newPair();
		const att: Attachment = {
			role: "pair_window",
			instance_id: instanceId,
			opened_at: Date.now(),
			jti: result.claims.jti,
		};
		server.serializeAttachment(att);
		this.ctx.acceptWebSocket(server, [tagPairWindow()]);
		this.failedDials = 0;
		await this.ctx.storage.setAlarm(Date.now() + PAIR_WINDOW_TTL_MS);
		log({ event: "pair_window_open", instance_id: instanceId, jti: result.claims.jti });
		return new Response(null, { status: 101, webSocket: client });
	}

	private async handlePairDial(_request: Request, _url: URL): Promise<Response> {
		if (this.failedDials > PAIR_DIAL_FAILED_LIMIT) {
			log({ event: "pair_dial_rejected", reason: "limited" });
			return unauthorizedResponse();
		}

		const windows = this.ctx.getWebSockets(tagPairWindow());
		if (windows.length === 0) {
			this.failedDials++;
			log({ event: "pair_dial_rejected", reason: "no_window" });
			return unauthorizedResponse();
		}

		const window = windows[0];
		const watt = window.deserializeAttachment() as Attachment | null;
		if (!watt || watt.role !== "pair_window") {
			this.failedDials++;
			log({ event: "pair_dial_rejected", reason: "no_window" });
			return unauthorizedResponse();
		}
		if (watt.signaled) {
			this.failedDials++;
			log({ event: "pair_dial_rejected", instance_id: watt.instance_id, reason: "consumed" });
			return unauthorizedResponse();
		}

		const resp = this.brokerTunnel(window, watt.instance_id, watt.jti, "pair_dial_open");
		if (resp.status === 101) {
			watt.signaled = true;
			window.serializeAttachment(watt);
			return resp;
		}

		this.failedDials++;
		log({ event: "pair_dial_rejected", instance_id: watt.instance_id, reason: "home_dropped" });
		return unauthorizedResponse();
	}

	private async handleTunnel(
		request: Request,
		url: URL,
		instanceId: string,
		tunnelId: string,
	): Promise<Response> {
		const token = extractToken(request, url);
		if (!token) return unauthorizedWithLog("/tunnel", "missing_token", instanceId, tunnelId);

		const result = await verifyToken(token, {
			jwksRaw: this.env.JWKS_PUBLIC,
			expectedIssuer: this.env.ISSUER,
			expectedScope: "session.listen",
		});
		if (!result.ok) return unauthorizedWithLog("/tunnel", result.reason, instanceId, tunnelId);
		if (result.claims.instance_id !== instanceId) {
			return unauthorizedWithLog("/tunnel", "instance_mismatch", instanceId, tunnelId);
		}

		return this.attachHomeTunnel(tunnelId, instanceId, result.claims.jti);
	}

	private async handlePairingTunnel(
		request: Request,
		url: URL,
		tunnelId: string,
	): Promise<Response> {
		const token = extractToken(request, url);
		if (!token) return unauthorizedWithLog("/tunnel", "missing_token", undefined, tunnelId);

		const result = await verifyToken(token, {
			jwksRaw: this.env.JWKS_PUBLIC,
			expectedIssuer: this.env.ISSUER,
			expectedScope: "session.listen",
		});
		if (!result.ok) return unauthorizedWithLog("/tunnel", result.reason, undefined, tunnelId);

		const windows = this.ctx.getWebSockets(tagPairWindow());
		if (windows.length === 0) {
			return unauthorizedWithLog("/tunnel", "no_window", undefined, tunnelId);
		}
		const watt = windows[0].deserializeAttachment() as Attachment | null;
		if (!watt || watt.role !== "pair_window") {
			return unauthorizedWithLog("/tunnel", "no_window", undefined, tunnelId);
		}
		if (result.claims.instance_id !== watt.instance_id) {
			return unauthorizedWithLog(
				"/tunnel",
				"instance_mismatch",
				result.claims.instance_id,
				tunnelId,
			);
		}

		return this.attachHomeTunnel(tunnelId, result.claims.instance_id, result.claims.jti);
	}

	private attachHomeTunnel(tunnelId: string, instanceId: string, jti: string): Response {
		// The mobile side must already be attached — otherwise there's no
		// tunnel to pair into. (If the mobile has disconnected, we refuse the
		// home-side attach; fresh dial mints a new tunnel_id.)
		const mobilePeers = this.ctx.getWebSockets(tagTunnelMobile(tunnelId));
		if (mobilePeers.length === 0) {
			return new Response("no mobile for tunnel_id", { status: 404 });
		}

		// Cardinality: at most one home tunnel WS per tunnel_id.
		const existing = this.ctx.getWebSockets(tagTunnelHome(tunnelId));
		for (const ws of existing) {
			try {
				ws.close(CLOSE_CODE_NORMAL, "replaced");
			} catch {}
			log({
				event: "cardinality_violation",
				instance_id: instanceId,
				tunnel_id: tunnelId,
				reason: "tunnel_home_replaced",
			});
		}

		const { client, server } = newPair();
		const att: Attachment = {
			role: "tunnel_home",
			tunnel_id: tunnelId,
			instance_id: instanceId,
			opened_at: Date.now(),
			jti,
		};
		server.serializeAttachment(att);
		this.ctx.acceptWebSocket(server, [tagTunnelHome(tunnelId)]);

		log({
			event: "tunnel_home_open",
			instance_id: instanceId,
			tunnel_id: tunnelId,
		});
		log({
			event: "pair",
			instance_id: instanceId,
			tunnel_id: tunnelId,
			direction: "meta",
		});

		this.drainPending(tagTunnelHome(tunnelId), server);
		return new Response(null, { status: 101, webSocket: client });
	}

	override async webSocketMessage(ws: WebSocket, message: string | ArrayBuffer): Promise<void> {
		const att = ws.deserializeAttachment() as Attachment | null;
		if (!att) return;

		// listen/dial are signaling surfaces. listen sends nothing v1.
		// dial has already morphed into tunnel_mobile — anything delivered
		// on that WS flows through the forwarding path below via the
		// tunnel_mobile attachment.
		if (att.role === "listen") return;
		if (att.role === "dial") return;
		if (att.role === "pair_window") return;

		if (!att.tunnel_id) return;
		const tunnelId = att.tunnel_id;

		const direction: Direction = att.role === "tunnel_mobile" ? "mobile_to_home" : "home_to_mobile";
		const peerTag =
			att.role === "tunnel_mobile" ? tagTunnelHome(tunnelId) : tagTunnelMobile(tunnelId);
		const peers = this.ctx.getWebSockets(peerTag);
		const byteCount = measure(message);

		if (peers.length === 0) {
			// Peer not yet attached — buffer, enforcing the cap.
			const buf = this.pending.get(peerTag) ?? { frames: [], bytes: 0 };
			if (buf.bytes + byteCount > PENDING_BUFFER_CAP_BYTES) {
				log({
					event: "pending_buffer_overflow",
					tunnel_id: tunnelId,
					instance_id: att.instance_id,
					direction,
					byte_count: byteCount,
					queued_bytes: buf.bytes,
					queued_frames: buf.frames.length,
				});
				this.closeTunnel(tunnelId, CLOSE_CODE_MESSAGE_TOO_BIG, "pending_buffer_overflow");
				this.pending.delete(peerTag);
				return;
			}
			buf.frames.push(message);
			buf.bytes += byteCount;
			this.pending.set(peerTag, buf);
			log({
				event: "pending_buffer",
				tunnel_id: tunnelId,
				instance_id: att.instance_id,
				direction,
				byte_count: byteCount,
				queued_bytes: buf.bytes,
				queued_frames: buf.frames.length,
			});
			return;
		}

		try {
			peers[0].send(message);
		} catch {
			// If forwarding fails, let the close propagation path handle
			// both sides. Do NOT retry — the peer is gone.
			return;
		}

		log({
			event: "fwd",
			tunnel_id: tunnelId,
			instance_id: att.instance_id,
			direction,
			byte_count: byteCount,
		});
	}

	override async webSocketClose(
		ws: WebSocket,
		code: number,
		reason: string,
		_wasClean: boolean,
	): Promise<void> {
		const att = ws.deserializeAttachment() as Attachment | null;
		if (!att) return;

		const durationMs = Date.now() - att.opened_at;
		log({
			event: this.closeEventForRole(att.role),
			instance_id: att.instance_id,
			tunnel_id: att.tunnel_id,
			close_code: code,
			reason,
			duration_ms: durationMs,
		});

		if (att.role === "tunnel_home" || att.role === "tunnel_mobile") {
			const tunnelId = att.tunnel_id;
			if (!tunnelId) return;
			this.closeTunnel(tunnelId, code === 1006 ? CLOSE_CODE_NORMAL : code, "peer_closed", att.role);
		}
	}

	override async webSocketError(ws: WebSocket, _error: unknown): Promise<void> {
		const att = ws.deserializeAttachment() as Attachment | null;
		if (!att) return;
		log({
			event: this.closeEventForRole(att.role),
			instance_id: att.instance_id,
			tunnel_id: att.tunnel_id,
			close_code: 1006,
			reason: "ws_error",
		});
	}

	// Helpers

	private async isEntitled(instanceId: string): Promise<boolean> {
		const now = Math.floor(Date.now() / 1000);
		const row = await this.env.DB.prepare(
			"SELECT entitled_until, revoked_at FROM instances WHERE instance_id = ?",
		)
			.bind(instanceId)
			.first<{ entitled_until: number | null; revoked_at: number | null }>();

		if (!row || row.revoked_at !== null || row.entitled_until === null) return false;
		return row.entitled_until > now;
	}

	private acceptMobileTunnel(
		instanceId: string,
		jti: string,
		tunnelId: string,
		tags: string[],
	): { client: WebSocket; server: WebSocket } {
		const { client, server } = newPair();
		const att: Attachment = {
			role: "tunnel_mobile",
			tunnel_id: tunnelId,
			instance_id: instanceId,
			opened_at: Date.now(),
			jti,
		};
		server.serializeAttachment(att);
		this.ctx.acceptWebSocket(server, tags);
		return { client, server };
	}

	private signalIncoming(listener: WebSocket, tunnelId: string): boolean {
		try {
			listener.send(JSON.stringify({ type: "incoming", tunnel_id: tunnelId }));
			return true;
		} catch {
			return false;
		}
	}

	private brokerTunnel(
		listener: WebSocket,
		instanceId: string,
		jti: string,
		openEvent: "dial_open" | "pair_dial_open",
		onSendFail?: () => void,
	): Response {
		const tunnelId = crypto.randomUUID();
		const { client, server } = this.acceptMobileTunnel(instanceId, jti, tunnelId, [
			tagTunnelMobile(tunnelId),
		]);

		log({
			event: openEvent,
			instance_id: instanceId,
			tunnel_id: tunnelId,
			jti,
		});

		if (!this.signalIncoming(listener, tunnelId)) {
			// If the send fails the home lost its listen — close the dial with 503 semantics.
			try {
				server.close(CLOSE_CODE_NORMAL, "home offline");
			} catch {}
			onSendFail?.();
			return new Response("home unreachable", { status: 503 });
		}

		return new Response(null, { status: 101, webSocket: client });
	}

	private drainPending(tag: string, ws: WebSocket): void {
		const buf = this.pending.get(tag);
		if (!buf || buf.frames.length === 0) {
			this.pending.delete(tag);
			return;
		}
		for (const msg of buf.frames) {
			try {
				ws.send(msg);
			} catch {
				break;
			}
		}
		this.pending.delete(tag);
	}

	private closeTunnel(
		tunnelId: string,
		code: number,
		reason: string,
		originatingRole?: Attachment["role"],
	): void {
		const homeTag = tagTunnelHome(tunnelId);
		const mobileTag = tagTunnelMobile(tunnelId);
		this.pending.delete(homeTag);
		this.pending.delete(mobileTag);

		const toClose = [...this.ctx.getWebSockets(homeTag), ...this.ctx.getWebSockets(mobileTag)];
		for (const ws of toClose) {
			const att = ws.deserializeAttachment() as Attachment | null;
			if (att && att.role === originatingRole) continue;
			try {
				ws.close(code, reason);
			} catch {}
		}
	}

	private closeEventForRole(role: Attachment["role"]): CloseEvent {
		switch (role) {
			case "listen":
				return "listen_close";
			case "dial":
				return "dial_close";
			case "pair_window":
				return "pair_window_close";
			case "tunnel_home":
				return "tunnel_home_close";
			case "tunnel_mobile":
				return "tunnel_mobile_close";
		}
	}
}

type CloseEvent =
	| "listen_close"
	| "dial_close"
	| "pair_window_close"
	| "tunnel_home_close"
	| "tunnel_mobile_close";

interface PendingBuffer {
	frames: Array<string | ArrayBuffer>;
	bytes: number;
}

function measure(message: string | ArrayBuffer): number {
	return typeof message === "string" ? message.length : message.byteLength;
}

function extractToken(request: Request, url: URL): string | null {
	const header = request.headers.get("authorization") ?? "";
	const m = header.match(/^Bearer\s+(.+)$/i);
	if (m) return m[1].trim();
	// WebSocket clients often can't set headers; accept `?token=` as a
	// fallback. This never leaks to logs.
	const q = url.searchParams.get("token");
	return q?.trim() || null;
}

function unauthorizedWithLog(
	route: string,
	reason: string,
	instanceId?: string,
	tunnelId?: string,
): Response {
	log({
		event: "unauthorized",
		route,
		reason,
		instance_id: instanceId,
		tunnel_id: tunnelId,
	});
	return unauthorizedResponse();
}

export function unauthorizedResponse(): Response {
	return new Response("unauthorized", {
		status: 401,
		headers: { "x-close-code": String(CLOSE_CODE_UNAUTHORIZED) },
	});
}

function notEntitledResponse(): Response {
	return new Response("not entitled", {
		status: 402,
		headers: { "x-close-code": String(CLOSE_CODE_NOT_ENTITLED) },
	});
}

function newPair(): { client: WebSocket; server: WebSocket } {
	const pair = new WebSocketPair();
	return { client: pair[0], server: pair[1] };
}

// WS-tag constants. Keep these functions in one place so the tag shape is
// trivially greppable and the cardinality invariants can be audited.
export function tagListen(instanceId: string): string {
	return `listen:${instanceId}`;
}
export function tagWaiting(instanceId: string): string {
	return `waiting_dial:${instanceId}`;
}
export function tagPairWindow(): string {
	return "pair_window";
}
export function tagTunnelHome(tunnelId: string): string {
	return `tunnel_home:${tunnelId}`;
}
export function tagTunnelMobile(tunnelId: string): string {
	return `tunnel_mobile:${tunnelId}`;
}
