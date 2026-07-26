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
import { SUBPROTOCOL_V1, parsePairSubprotocol } from "./pair-subprotocol";
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

// 4403 terminates sockets owned by an irreversibly retired instance.
const CLOSE_CODE_INSTANCE_RETIRED = 4403;

const PAIR_DIAL_FAILED_LIMIT = 50;
const PAIR_WINDOW_TTL_MS = 7 * 60 * 1000;

export interface RetireInstanceResult {
	markerVerified: boolean;
	socketsClosed: boolean;
	pendingCleared: boolean;
	alarmCleared: boolean;
	socketCount: number;
}

export class InstanceDO extends DurableObject<Env> {
	// Buffers keyed by WS-tag destination (e.g., `tunnel_home:<id>`).
	private pending: Map<string, PendingBuffer> = new Map();
	private failedDials = 0;
	private retirementClosing = new WeakSet<WebSocket>();

	constructor(ctx: DurableObjectState, env: Env) {
		super(ctx, env);
		this.ctx.storage.sql.exec(`
			CREATE TABLE IF NOT EXISTS retired_instances (
				instance_id TEXT PRIMARY KEY,
				retired_at  INTEGER NOT NULL
			)
		`);
	}

	async retireInstance(instanceId: string, retiredAt: number): Promise<RetireInstanceResult> {
		// The marker is the derived, DO-local enforcement record. It must exist
		// before any socket sweep so an interleaved admission either accepts
		// first and is swept, or observes the marker and refuses synchronously.
		this.ctx.storage.sql.exec(
			"INSERT INTO retired_instances (instance_id, retired_at) VALUES (?, ?) ON CONFLICT(instance_id) DO UPDATE SET retired_at = excluded.retired_at",
			instanceId,
			retiredAt,
		);
		if (!this.hasRetiredMarker(instanceId, retiredAt)) {
			return {
				markerVerified: false,
				socketsClosed: false,
				pendingCleared: false,
				alarmCleared: false,
				socketCount: 0,
			};
		}

		const matching: WebSocket[] = [];
		const tunnelIds = new Set<string>();
		let socketsClosed = true;

		for (const ws of this.ctx.getWebSockets()) {
			let att: Attachment | null;
			try {
				att = ws.deserializeAttachment() as Attachment | null;
			} catch {
				// An unreadable attachment means the ownership sweep cannot be
				// verified, even though cleanup continues for readable sockets.
				socketsClosed = false;
				continue;
			}
			if (!att || att.instance_id !== instanceId) continue;
			matching.push(ws);
			if (att.tunnel_id) tunnelIds.add(att.tunnel_id);
		}

		for (const ws of matching) {
			try {
				this.retirementClosing.add(ws);
				ws.close(CLOSE_CODE_INSTANCE_RETIRED, "instance_retired");
			} catch {
				socketsClosed = false;
			}
		}
		socketsClosed &&= matching.every((ws) => ws.readyState !== WebSocket.OPEN);

		for (const tunnelId of tunnelIds) {
			this.pending.delete(tagTunnelHome(tunnelId));
			this.pending.delete(tagTunnelMobile(tunnelId));
		}
		const pendingCleared = [...tunnelIds].every(
			(tunnelId) =>
				!this.pending.has(tagTunnelHome(tunnelId)) && !this.pending.has(tagTunnelMobile(tunnelId)),
		);

		let alarmCleared = true;
		const matchingSet = new Set(matching);
		const hasOtherPairWindow = this.ctx
			.getWebSockets(tagPairWindow())
			.some((ws) => !matchingSet.has(ws) && ws.readyState === WebSocket.OPEN);
		if (!hasOtherPairWindow) {
			try {
				await this.ctx.storage.deleteAlarm();
			} catch {
				alarmCleared = false;
			}
		}

		return {
			markerVerified: this.hasRetiredMarker(instanceId, retiredAt),
			socketsClosed,
			pendingCleared,
			alarmCleared,
			socketCount: matching.length,
		};
	}

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

		// Load-bearing retirement check: do not insert an await between this
		// synchronous marker read and acceptWebSocket below.
		if (this.hasRetiredMarker(instanceId)) {
			return unauthorizedWithLog("/session/listen", "revoked", instanceId);
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

		// Load-bearing retirement check: do not insert an await between this
		// synchronous marker read and the acceptWebSocket reached below.
		if (this.hasRetiredMarker(instanceId)) {
			return unauthorizedWithLog("/session/dial", "revoked", instanceId);
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
			if (att) await this.releasePairingOwnerIfUnused(att.instance_id, ws);
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
		const registeredAt = Math.floor(Date.now() / 1000);
		const registration = await this.env.DB.prepare(
			"INSERT INTO pairing_owners (instance_id, do_id, registered_at) SELECT instance_id, ?, ? FROM instances WHERE instance_id = ? AND revoked_at IS NULL ON CONFLICT(instance_id, do_id) DO UPDATE SET registered_at = excluded.registered_at",
		)
			.bind(this.ctx.id.toString(), registeredAt, instanceId)
			.run();
		if (registration.meta.changes === 0) {
			// Keep the existing not_enrolled/revoked log distinction only on
			// this cold deny branch; successful admission is one D1 statement.
			const row = await this.env.DB.prepare(
				"SELECT revoked_at FROM instances WHERE instance_id = ?",
			)
				.bind(instanceId)
				.first<{ revoked_at: number | null }>();
			return unauthorizedWithLog(
				"/session/pair-window",
				row ? "revoked" : "not_enrolled",
				instanceId,
			);
		}

		// Load-bearing retirement check: do not insert an await between this
		// synchronous marker read and acceptWebSocket below. A concurrent
		// retirement that won before registration made the upsert a no-op;
		// one that wins after registration writes this marker before sweeping.
		if (this.hasRetiredMarker(instanceId)) {
			await this.releasePairingOwnerIfUnused(instanceId);
			return unauthorizedWithLog("/session/pair-window", "revoked", instanceId);
		}

		for (const ws of this.ctx.getWebSockets(tagPairWindow())) {
			const existing = ws.deserializeAttachment() as Attachment | null;
			let closed = false;
			try {
				ws.close(CLOSE_CODE_NORMAL, "replaced");
				closed = true;
			} catch {}
			if (closed && existing) {
				// Keep this asynchronous: the retirement marker check immediately
				// above must remain adjacent to acceptWebSocket below.
				this.ctx.waitUntil(this.releasePairingOwnerIfUnused(existing.instance_id, ws));
			}
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
		this.ctx.acceptWebSocket(server, [tagPairWindow(), tagPairOwner(instanceId)]);
		this.failedDials = 0;
		await this.ctx.storage.setAlarm(Date.now() + PAIR_WINDOW_TTL_MS);
		log({ event: "pair_window_open", instance_id: instanceId, jti: result.claims.jti });
		return new Response(null, { status: 101, webSocket: client });
	}

	private async handlePairDial(request: Request, _url: URL): Promise<Response> {
		if (this.failedDials > PAIR_DIAL_FAILED_LIMIT) {
			log({ event: "pair_dial_rejected", reason: "limited" });
			return unauthorizedResponse();
		}

		const windows = this.ctx
			.getWebSockets(tagPairWindow())
			.filter((ws) => ws.readyState === WebSocket.OPEN);
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

		const offeredV1 = parsePairSubprotocol(request.headers.get("sec-websocket-protocol")).offeredV1;
		// Load-bearing retirement check: do not insert an await between this
		// synchronous marker read and the acceptWebSocket in brokerTunnel.
		if (this.hasRetiredMarker(watt.instance_id)) {
			return unauthorizedWithLog("/session/pair-dial", "revoked", watt.instance_id);
		}
		const resp = this.brokerTunnel(
			window,
			watt.instance_id,
			watt.jti,
			"pair_dial_open",
			offeredV1,
			[tagPairOwner(watt.instance_id)],
		);
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

		const windows = this.ctx
			.getWebSockets(tagPairWindow())
			.filter((ws) => ws.readyState === WebSocket.OPEN);
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

		return this.attachHomeTunnel(
			tunnelId,
			result.claims.instance_id,
			result.claims.jti,
			result.claims.instance_id,
		);
	}

	private attachHomeTunnel(
		tunnelId: string,
		instanceId: string,
		jti: string,
		pairingOwnerId?: string,
	): Response {
		// The mobile side must already be attached — otherwise there's no
		// tunnel to pair into. (If the mobile has disconnected, we refuse the
		// home-side attach; fresh dial mints a new tunnel_id.)
		const mobilePeers = this.ctx.getWebSockets(tagTunnelMobile(tunnelId));
		if (mobilePeers.length === 0) {
			return new Response("no mobile for tunnel_id", { status: 404 });
		}

		// Load-bearing retirement check for both normal and pairing tunnels:
		// do not insert an await between this synchronous marker read and
		// acceptWebSocket below.
		if (this.hasRetiredMarker(instanceId)) {
			return unauthorizedWithLog("/tunnel", "revoked", instanceId, tunnelId);
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
		const tags = [tagTunnelHome(tunnelId)];
		if (pairingOwnerId) tags.push(tagPairOwner(pairingOwnerId));
		this.ctx.acceptWebSocket(server, tags);

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
		if (this.retirementClosing.has(ws)) return;
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
		_reason: string,
		_wasClean: boolean,
	): Promise<void> {
		const att = ws.deserializeAttachment() as Attachment | null;
		if (!att) return;
		const pairingOwnerSocket = this.ctx.getTags(ws).includes(tagPairOwner(att.instance_id));
		const retirementClose = this.retirementClosing.has(ws);
		const closeReason: CloseReason = retirementClose ? "instance_retired" : "peer_closed";

		const durationMs = Date.now() - att.opened_at;
		log({
			event: this.closeEventForRole(att.role),
			instance_id: att.instance_id,
			tunnel_id: att.tunnel_id,
			close_code: code,
			reason: closeReason,
			duration_ms: durationMs,
		});

		if (att.role === "tunnel_home" || att.role === "tunnel_mobile") {
			const tunnelId = att.tunnel_id;
			if (tunnelId) {
				this.closeTunnel(tunnelId, code === 1006 ? CLOSE_CODE_NORMAL : code, closeReason, att.role);
			}
		}
		if (pairingOwnerSocket && !retirementClose) {
			await this.releasePairingOwnerIfUnused(att.instance_id, ws);
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

	private hasRetiredMarker(instanceId: string, retiredAt?: number): boolean {
		const row = this.ctx.storage.sql
			.exec<{ retired_at: number }>(
				"SELECT retired_at FROM retired_instances WHERE instance_id = ?",
				instanceId,
			)
			.toArray()[0];
		return row !== undefined && (retiredAt === undefined || row.retired_at === retiredAt);
	}

	private async releasePairingOwnerIfUnused(
		instanceId: string,
		leavingSocket?: WebSocket,
	): Promise<void> {
		const hasOwnedSocket = this.ctx
			.getWebSockets(tagPairOwner(instanceId))
			.some((ws) => ws !== leavingSocket && ws.readyState === WebSocket.OPEN);
		if (hasOwnedSocket) return;

		await this.env.DB.prepare("DELETE FROM pairing_owners WHERE instance_id = ? AND do_id = ?")
			.bind(instanceId, this.ctx.id.toString())
			.run();
	}

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
		echoV1 = false,
		additionalTags: string[] = [],
		onSendFail?: () => void,
	): Response {
		const tunnelId = crypto.randomUUID();
		const { client, server } = this.acceptMobileTunnel(instanceId, jti, tunnelId, [
			tagTunnelMobile(tunnelId),
			...additionalTags,
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

		if (echoV1) {
			return new Response(null, {
				status: 101,
				webSocket: client,
				headers: { "Sec-WebSocket-Protocol": SUBPROTOCOL_V1 },
			});
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
	reason: NonNullable<LogFields["reason"]>,
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
export function tagPairOwner(instanceId: string): string {
	return `pair_owner:${instanceId}`;
}
export function tagTunnelHome(tunnelId: string): string {
	return `tunnel_home:${tunnelId}`;
}
export function tagTunnelMobile(tunnelId: string): string {
	return `tunnel_mobile:${tunnelId}`;
}
