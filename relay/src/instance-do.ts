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
import { type CloseReason, type Direction, type LogFields, log } from "./logging";
import { verifyToken } from "./tokens";

interface Attachment {
	role: "listen" | "pair_window" | "tunnel_home" | "tunnel_mobile";
	tunnel_id?: string;
	instance_id: string;
	listener_generation?: number;
	// Pair-window consumption flag; unrelated to recoverable held-dial ownership.
	signaled?: boolean;
	// Present only on recoverable held mobile attachments.
	paired?: boolean;
	// An errored held mobile remains tag-visible until its close handshake ends,
	// but must never be offered again.
	retired?: boolean;
	last_offered_generation?: number;
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

const CLOSE_CODE_TRY_AGAIN_LATER = 1013;
const CLOSE_CODE_INTERNAL_ERROR = 1011;

const ATTACH_LEASE_MS = 20 * 1000;
const LISTENER_GENERATION_KEY = "listener_generation";

const PAIR_DIAL_FAILED_LIMIT = 50;
const PAIR_WINDOW_TTL_MS = 7 * 60 * 1000;

type TunnelCloseReason = CloseReason | "pending_buffer_overflow";

export class InstanceDO extends DurableObject<Env> {
	// Buffers keyed by WS-tag destination (e.g., `tunnel_home:<id>`).
	private pending: Map<string, PendingBuffer> = new Map();
	private attachLeases: Map<string, ReturnType<typeof setTimeout>> = new Map();
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
			return this.handlePairDial();
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
		if (!token) return unauthorizedWithLog("/session/listen", "missing_token");

		const result = await verifyToken(token, {
			jwksRaw: this.env.JWKS_PUBLIC,
			expectedIssuer: this.env.ISSUER,
			expectedScope: "session.listen",
		});
		if (!result.ok) return unauthorizedWithLog("/session/listen", result.reason);
		if (result.claims.instance_id !== instanceId) {
			return unauthorizedWithLog("/session/listen", "instance_mismatch");
		}
		if (this.env.ENTITLEMENT_REQUIRED === "true" && !(await this.isEntitled(instanceId))) {
			return notEntitledResponse();
		}
		const listenerGeneration = await this.nextListenerGeneration();

		// WS-tag cardinality: at most one active listen WS per instance.
		const existing = this.ctx
			.getWebSockets(tagListen(instanceId))
			.filter((ws) => this.isOfferable(ws));
		for (const ws of existing) {
			const attachment = ws.deserializeAttachment() as Attachment | null;
			if (attachment) {
				attachment.retired = true;
				ws.serializeAttachment(attachment);
			}
			try {
				ws.close(CLOSE_CODE_NORMAL, "replaced");
			} catch {}
		}

		const { client, server } = newPair();
		const att: Attachment = {
			role: "listen",
			instance_id: instanceId,
			listener_generation: listenerGeneration,
		};
		server.serializeAttachment(att);
		this.ctx.acceptWebSocket(server, [tagListen(instanceId)]);

		if (this.env.PRESENCE_HOLD_ENABLED === "true") {
			this.offerWaitingDials(server, instanceId, listenerGeneration);
		}

		return new Response(null, { status: 101, webSocket: client });
	}

	private async handleDial(request: Request, url: URL, instanceId: string): Promise<Response> {
		const token = extractToken(request, url);
		if (!token) return unauthorizedWithLog("/session/dial", "missing_token");

		const result = await verifyToken(token, {
			jwksRaw: this.env.JWKS_PUBLIC,
			expectedIssuer: this.env.ISSUER,
			expectedScope: "session.dial",
		});
		if (!result.ok) return unauthorizedWithLog("/session/dial", result.reason);
		if (result.claims.instance_id !== instanceId) {
			return unauthorizedWithLog("/session/dial", "instance_mismatch");
		}
		if (this.env.ENTITLEMENT_REQUIRED === "true" && !(await this.isEntitled(instanceId))) {
			return notEntitledResponse();
		}

		const listeners = this.ctx.getWebSockets(tagListen(instanceId));
		const recoverable = this.env.PRESENCE_HOLD_ENABLED === "true";
		if (recoverable) {
			const listener = this.highestOfferableListener(listeners);
			return this.brokerTunnel(listener, instanceId, true);
		}
		if (listeners.length === 0) {
			return new Response("no home listening", { status: 503 });
		}

		return this.brokerTunnel(listeners[0], instanceId, false);
	}

	override async alarm(): Promise<void> {
		for (const ws of this.ctx.getWebSockets(tagPairWindow())) {
			try {
				ws.close(CLOSE_CODE_NORMAL, "window_expired");
			} catch {}
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
			return unauthorizedWithLog("/session/pair-window", "not_enrolled");
		}
		if (row.revoked_at !== null) {
			return unauthorizedWithLog("/session/pair-window", "revoked");
		}

		for (const ws of this.ctx.getWebSockets(tagPairWindow())) {
			try {
				ws.close(CLOSE_CODE_NORMAL, "replaced");
			} catch {}
		}

		const { client, server } = newPair();
		const att: Attachment = {
			role: "pair_window",
			instance_id: instanceId,
		};
		server.serializeAttachment(att);
		this.ctx.acceptWebSocket(server, [tagPairWindow()]);
		this.failedDials = 0;
		await this.ctx.storage.setAlarm(Date.now() + PAIR_WINDOW_TTL_MS);

		return new Response(null, { status: 101, webSocket: client });
	}

	private async handlePairDial(): Promise<Response> {
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
			log({ event: "pair_dial_rejected", reason: "consumed" });
			return unauthorizedResponse();
		}

		const resp = this.brokerTunnel(window, watt.instance_id, false);
		if (resp.status === 101) {
			watt.signaled = true;
			window.serializeAttachment(watt);
			return resp;
		}

		this.failedDials++;
		log({ event: "pair_dial_rejected", reason: "home_dropped" });
		return unauthorizedResponse();
	}

	private async handleTunnel(
		request: Request,
		url: URL,
		instanceId: string,
		tunnelId: string,
	): Promise<Response> {
		const token = extractToken(request, url);
		if (!token) return unauthorizedWithLog("/tunnel", "missing_token");

		const result = await verifyToken(token, {
			jwksRaw: this.env.JWKS_PUBLIC,
			expectedIssuer: this.env.ISSUER,
			expectedScope: "session.listen",
		});
		if (!result.ok) return unauthorizedWithLog("/tunnel", result.reason);
		if (result.claims.instance_id !== instanceId) {
			return unauthorizedWithLog("/tunnel", "instance_mismatch");
		}

		return this.attachHomeTunnel(tunnelId, instanceId);
	}

	private async handlePairingTunnel(
		request: Request,
		url: URL,
		tunnelId: string,
	): Promise<Response> {
		const token = extractToken(request, url);
		if (!token) return unauthorizedWithLog("/tunnel", "missing_token");

		const result = await verifyToken(token, {
			jwksRaw: this.env.JWKS_PUBLIC,
			expectedIssuer: this.env.ISSUER,
			expectedScope: "session.listen",
		});
		if (!result.ok) return unauthorizedWithLog("/tunnel", result.reason);

		const windows = this.ctx.getWebSockets(tagPairWindow());
		if (windows.length === 0) {
			return unauthorizedWithLog("/tunnel", "no_window");
		}
		const watt = windows[0].deserializeAttachment() as Attachment | null;
		if (!watt || watt.role !== "pair_window") {
			return unauthorizedWithLog("/tunnel", "no_window");
		}
		if (result.claims.instance_id !== watt.instance_id) {
			return unauthorizedWithLog("/tunnel", "instance_mismatch");
		}

		return this.attachHomeTunnel(tunnelId, result.claims.instance_id);
	}

	private attachHomeTunnel(tunnelId: string, instanceId: string): Response {
		// The mobile side must already be attached — otherwise there's no
		// tunnel to pair into. (If the mobile has disconnected, we refuse the
		// home-side attach; fresh dial mints a new tunnel_id.)
		const mobilePeers = this.ctx
			.getWebSockets(tagTunnelMobile(tunnelId))
			.filter((ws) => this.isOfferable(ws));
		if (mobilePeers.length === 0) {
			return new Response("no mobile for tunnel_id", { status: 404 });
		}
		const mobile = mobilePeers[0];
		const mobileAttachment = mobile.deserializeAttachment() as Attachment | null;
		if (mobileAttachment?.paired === true) {
			return new Response("tunnel already paired", { status: 409 });
		}

		// Cardinality: at most one home tunnel WS per tunnel_id.
		const existing = this.ctx.getWebSockets(tagTunnelHome(tunnelId));
		for (const ws of existing) {
			const attachment = ws.deserializeAttachment() as Attachment | null;
			if (attachment) {
				attachment.retired = true;
				ws.serializeAttachment(attachment);
			}
			try {
				ws.close(CLOSE_CODE_NORMAL, "replaced");
			} catch {}
		}

		const { client, server } = newPair();
		const att: Attachment = {
			role: "tunnel_home",
			tunnel_id: tunnelId,
			instance_id: instanceId,
		};
		server.serializeAttachment(att);
		this.ctx.acceptWebSocket(server, [tagTunnelHome(tunnelId)]);
		if (!this.drainPending(tunnelId, tagTunnelHome(tunnelId), server)) {
			return new Response("pending drain failed", { status: 500 });
		}
		if (mobileAttachment?.paired === false) {
			mobileAttachment.paired = true;
			mobile.serializeAttachment(mobileAttachment);
		}
		this.clearAttachLease(tunnelId);

		return new Response(null, { status: 101, webSocket: client });
	}

	override async webSocketMessage(ws: WebSocket, message: string | ArrayBuffer): Promise<void> {
		const att = ws.deserializeAttachment() as Attachment | null;
		if (!att) return;

		// The listen WS is a signaling surface and sends nothing in v1.
		// A dial has already morphed into tunnel_mobile, so anything delivered
		// on it flows through the forwarding path below.
		if (att.role === "listen") return;
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
				log({ event: "pending_buffer_overflow" });
				this.closeTunnel(tunnelId, CLOSE_CODE_MESSAGE_TOO_BIG, "pending_buffer_overflow");
				this.pending.delete(peerTag);
				return;
			}
			buf.frames.push(message);
			buf.bytes += byteCount;
			this.pending.set(peerTag, buf);
			if (
				direction === "mobile_to_home" &&
				att.paired === false &&
				this.env.PRESENCE_HOLD_ENABLED === "true"
			) {
				this.startAttachLease(tunnelId, ws);
			}

			return;
		}

		try {
			peers[0].send(message);
		} catch {
			log({ event: "internal_error", reason: "forward_send_failed" });
			this.closeTunnel(tunnelId, CLOSE_CODE_INTERNAL_ERROR, "forward_send_failed");
			return;
		}
	}

	override async webSocketClose(
		ws: WebSocket,
		code: number,
		_reason: string,
		_wasClean: boolean,
	): Promise<void> {
		const att = ws.deserializeAttachment() as Attachment | null;
		if (!att) return;
		if (att.retired) return;

		if (att.role === "tunnel_home" || att.role === "tunnel_mobile") {
			const tunnelId = att.tunnel_id;
			if (!tunnelId) return;
			this.closeTunnel(tunnelId, code === 1006 ? CLOSE_CODE_NORMAL : code, "peer_closed", att.role);
		}
	}

	override async webSocketError(ws: WebSocket, _error: unknown): Promise<void> {
		const att = ws.deserializeAttachment() as Attachment | null;
		if (!att) return;
		if (att.retired) return;
		if (att.role === "tunnel_mobile" && att.paired === false) {
			att.retired = true;
			ws.serializeAttachment(att);
			if (att.tunnel_id) this.clearAttachLease(att.tunnel_id);
		}
		log({ event: "internal_error", reason: "ws_error" });
		if (att.role === "tunnel_home" || att.role === "tunnel_mobile") {
			const tunnelId = att.tunnel_id;
			if (!tunnelId) return;
			this.closeTunnel(tunnelId, CLOSE_CODE_NORMAL, "ws_error", att.role);
		}
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

	private async nextListenerGeneration(): Promise<number> {
		let next = 0;
		await this.ctx.blockConcurrencyWhile(async () => {
			const current = (await this.ctx.storage.get<number>(LISTENER_GENERATION_KEY)) ?? 0;
			next = current + 1;
			await this.ctx.storage.put(LISTENER_GENERATION_KEY, next);
		});
		return next;
	}

	private isOfferable(ws: WebSocket): boolean {
		return ws.readyState === WebSocket.OPEN;
	}

	private highestOfferableListener(listeners: WebSocket[]): WebSocket | undefined {
		let selected: WebSocket | undefined;
		let generation = -1;
		for (const listener of listeners) {
			if (!this.isOfferable(listener)) continue;
			const att = listener.deserializeAttachment() as Attachment | null;
			if (att?.role !== "listen" || att.listener_generation === undefined) continue;
			if (att.listener_generation > generation) {
				selected = listener;
				generation = att.listener_generation;
			}
		}
		return selected;
	}

	private acceptMobileTunnel(
		instanceId: string,
		tunnelId: string,
		tags: string[],
		recoverable: boolean,
	): { client: WebSocket; server: WebSocket } {
		const { client, server } = newPair();
		const att: Attachment = {
			role: "tunnel_mobile",
			tunnel_id: tunnelId,
			instance_id: instanceId,
			paired: recoverable ? false : undefined,
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
		listener: WebSocket | undefined,
		instanceId: string,
		recoverable: boolean,
	): Response {
		const tunnelId = crypto.randomUUID();
		const tags = recoverable
			? [tagWaiting(instanceId), tagTunnelMobile(tunnelId)]
			: [tagTunnelMobile(tunnelId)];
		const { client, server } = this.acceptMobileTunnel(instanceId, tunnelId, tags, recoverable);

		const listenerAttachment = listener?.deserializeAttachment() as Attachment | null;
		const generation = recoverable ? listenerAttachment?.listener_generation : undefined;
		if (listener && this.offerTunnel(listener, tunnelId, generation)) {
			return new Response(null, { status: 101, webSocket: client });
		}
		if (recoverable) {
			return new Response(null, { status: 101, webSocket: client });
		}
		try {
			server.close(CLOSE_CODE_NORMAL, "home offline");
		} catch {}
		return new Response("home unreachable", { status: 503 });
	}

	private offerWaitingDials(listener: WebSocket, instanceId: string, generation: number): void {
		const waiting = this.ctx
			.getWebSockets(tagWaiting(instanceId))
			.map((ws) => ({ ws, att: ws.deserializeAttachment() as Attachment | null }))
			.filter(
				(entry): entry is { ws: WebSocket; att: Attachment & { tunnel_id: string } } =>
					this.isOfferable(entry.ws) &&
					entry.att?.role === "tunnel_mobile" &&
					entry.att.paired === false &&
					entry.att.retired !== true &&
					typeof entry.att.tunnel_id === "string" &&
					entry.att.last_offered_generation !== generation,
			)
			.sort((a, b) => a.att.tunnel_id.localeCompare(b.att.tunnel_id));
		for (const entry of waiting) {
			if (!this.isHighestListenerGeneration(listener, instanceId, generation)) return;
			if (!this.offerTunnel(listener, entry.att.tunnel_id, generation)) return;
		}
	}

	private isHighestListenerGeneration(
		listener: WebSocket,
		instanceId: string,
		generation: number,
	): boolean {
		const att = listener.deserializeAttachment() as Attachment | null;
		if (!this.isOfferable(listener) || att?.listener_generation !== generation) return false;
		const highest = this.highestOfferableListener(this.ctx.getWebSockets(tagListen(instanceId)));
		return highest === listener;
	}

	private offerTunnel(listener: WebSocket, tunnelId: string, generation?: number): boolean {
		if (!this.isOfferable(listener) || !this.signalIncoming(listener, tunnelId)) {
			try {
				listener.close(CLOSE_CODE_NORMAL, "stale listener");
			} catch {}
			return false;
		}
		if (generation !== undefined) {
			const mobile = this.ctx.getWebSockets(tagTunnelMobile(tunnelId))[0];
			const att = mobile?.deserializeAttachment() as Attachment | null;
			if (mobile && att?.paired === false) {
				att.last_offered_generation = generation;
				mobile.serializeAttachment(att);
			}
		}
		return true;
	}

	private drainPending(tunnelId: string, tag: string, ws: WebSocket): boolean {
		const buf = this.pending.get(tag);
		if (!buf || buf.frames.length === 0) {
			this.pending.delete(tag);
			return true;
		}
		for (const msg of buf.frames) {
			try {
				ws.send(msg);
			} catch {
				this.pending.delete(tag);
				this.clearAttachLease(tunnelId);
				log({ event: "internal_error", reason: "pending_drain_failed" });
				this.closeTunnel(tunnelId, CLOSE_CODE_INTERNAL_ERROR, "pending_drain_failed");
				return false;
			}
		}
		this.pending.delete(tag);
		return true;
	}

	private closeTunnel(
		tunnelId: string,
		code: number,
		reason: TunnelCloseReason,
		originatingRole?: Attachment["role"],
	): void {
		const homeTag = tagTunnelHome(tunnelId);
		const mobileTag = tagTunnelMobile(tunnelId);
		this.clearAttachLease(tunnelId);
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

	private startAttachLease(tunnelId: string, mobile: WebSocket): void {
		if (this.attachLeases.has(tunnelId)) return;
		const handle = setTimeout(
			() => void this.expireAttachLease(tunnelId, mobile, handle),
			ATTACH_LEASE_MS,
		);
		this.attachLeases.set(tunnelId, handle);
	}

	private clearAttachLease(tunnelId: string): void {
		const handle = this.attachLeases.get(tunnelId);
		if (handle !== undefined) clearTimeout(handle);
		this.attachLeases.delete(tunnelId);
	}

	private async expireAttachLease(
		tunnelId: string,
		mobile: WebSocket,
		handle: ReturnType<typeof setTimeout>,
	): Promise<void> {
		await this.ctx.blockConcurrencyWhile(async () => {
			if (this.attachLeases.get(tunnelId) !== handle) return;
			const current = this.ctx
				.getWebSockets(tagTunnelMobile(tunnelId))
				.find((ws) => this.isOfferable(ws));
			const target = current ?? mobile;
			const att = target.deserializeAttachment() as Attachment | null;
			if (!att || att.tunnel_id !== tunnelId || att.paired === true) {
				this.clearAttachLease(tunnelId);
				return;
			}
			this.attachLeases.delete(tunnelId);
			this.pending.delete(tagTunnelHome(tunnelId));
			this.pending.delete(tagTunnelMobile(tunnelId));
			log({ event: "internal_error", reason: "attach_timeout" });
			try {
				target.close(CLOSE_CODE_TRY_AGAIN_LATER, "home attach timeout");
			} catch {}
		});
	}
}

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

function unauthorizedWithLog(route: string, reason: NonNullable<LogFields["reason"]>): Response {
	log({ event: "unauthorized", route, reason });
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
