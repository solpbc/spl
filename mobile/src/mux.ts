// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

// Multiplex driver — dialer side.
//
// On the dialing side (mobile), we originate odd-numbered stream IDs per
// proto/framing.md §"id allocation". Each stream is a bidirectional
// byte pipe the caller drives via `openStream()` → `{ write, read, close }`.
//
// Kept deliberately spartan: enough to open 10+ concurrent streams, send
// HTTP requests, collect responses, and exercise credit-based flow
// control. The home-side mux is richer (handler dispatch, protocol-error
// RESET on unexpected OPENs, etc.) because it has to accept arbitrary
// peer behavior; the dialer only originates streams we asked for.

import {
	FLAG_CLOSE,
	FLAG_DATA,
	FLAG_OPEN,
	FLAG_RESET,
	FLAG_WINDOW,
	FrameDecoder,
	INITIAL_WINDOW,
	MAX_CONCURRENT_STREAMS,
	ProtocolError,
	RECOMMENDED_CHUNK,
	RESET_INTERNAL_ERROR,
	buildClose,
	buildData,
	buildOpen,
	buildReset,
	buildWindow,
	encodeFrame,
	parseResetReason,
	parseWindowCredit,
} from "./framing";

export interface StreamHandle {
	id: number;
	write(data: Uint8Array): Promise<void>;
	close(): Promise<void>;
	reset(reason?: number): Promise<void>;
	/** Yields bytes as the peer sends DATA frames; ends on CLOSE/RESET. */
	read(): AsyncGenerator<Uint8Array, void, void>;
	/** Convenience: read until EOF into a single buffer. */
	readAll(): Promise<Uint8Array>;
	/** Resolved when the peer sends CLOSE or RESET, or the mux is torn down. */
	closed: Promise<void>;
}

type FrameSink = (bytes: Uint8Array) => void | Promise<void>;

interface StreamState {
	id: number;
	buffered: Uint8Array[];
	waiters: Array<(v: Uint8Array | null) => void>;
	send_credit: number;
	recv_credit: number;
	unacked_recv: number;
	writer_closed: boolean;
	reader_closed: boolean;
	creditWaiters: Array<() => void>;
	closedResolvers: Array<() => void>;
}

export class Multiplexer {
	private decoder = new FrameDecoder();
	private streams = new Map<number, StreamState>();
	private nextLocalId: number;
	private closed = false;

	constructor(
		private send: FrameSink,
		opts?: { isListener?: boolean },
	) {
		this.nextLocalId = opts?.isListener ? 2 : 1;
	}

	/** Feed plaintext bytes from the TLS layer into the framing decoder. */
	feed(plaintext: Uint8Array): void {
		if (!plaintext.byteLength) return;
		this.decoder.feed(plaintext);
		while (true) {
			let frame: ReturnType<FrameDecoder["next"]>;
			try {
				frame = this.decoder.next();
			} catch (err) {
				if (err instanceof ProtocolError) {
					this.tearDown();
					return;
				}
				throw err;
			}
			if (!frame) return;
			this.dispatch(frame);
		}
	}

	async openStream(initial: Uint8Array = new Uint8Array(0)): Promise<StreamHandle> {
		if (this.closed) throw new Error("mux closed");
		if (this.streams.size >= MAX_CONCURRENT_STREAMS) {
			throw new Error("concurrent stream cap reached");
		}
		const id = this.allocLocalId();
		const state: StreamState = {
			id,
			buffered: [],
			waiters: [],
			send_credit: INITIAL_WINDOW,
			recv_credit: INITIAL_WINDOW,
			unacked_recv: 0,
			writer_closed: false,
			reader_closed: false,
			creditWaiters: [],
			closedResolvers: [],
		};
		if (initial.byteLength) {
			state.send_credit -= initial.byteLength;
		}
		this.streams.set(id, state);
		await this.emit(buildOpen(id, initial));
		return this.makeHandle(state);
	}

	tearDown(): void {
		if (this.closed) return;
		this.closed = true;
		for (const state of this.streams.values()) {
			for (const w of state.waiters) w(null);
			state.waiters = [];
			for (const r of state.closedResolvers) r();
			state.closedResolvers = [];
			for (const w of state.creditWaiters) w();
			state.creditWaiters = [];
		}
		this.streams.clear();
	}

	// --- internals ---

	private allocLocalId(): number {
		const id = this.nextLocalId;
		this.nextLocalId += 2;
		return id;
	}

	private makeHandle(state: StreamState): StreamHandle {
		const mux = this;
		return {
			id: state.id,
			async write(data: Uint8Array) {
				if (state.writer_closed) throw new Error(`stream ${state.id} closed`);
				let view = data;
				while (view.byteLength > 0) {
					const chunkLen = Math.min(view.byteLength, RECOMMENDED_CHUNK, state.send_credit);
					if (chunkLen <= 0) {
						await new Promise<void>((resolve) => state.creditWaiters.push(resolve));
						continue;
					}
					const chunk = view.slice(0, chunkLen);
					view = view.slice(chunkLen);
					state.send_credit -= chunkLen;
					await mux.emit(buildData(state.id, chunk));
				}
			},
			async close() {
				if (state.writer_closed) return;
				state.writer_closed = true;
				await mux.emit(buildClose(state.id));
			},
			async reset(reason = RESET_INTERNAL_ERROR) {
				if (state.writer_closed && state.reader_closed) return;
				state.writer_closed = true;
				state.reader_closed = true;
				await mux.emit(buildReset(state.id, reason));
				mux.streams.delete(state.id);
				for (const r of state.closedResolvers) r();
			},
			async *read() {
				while (true) {
					if (state.buffered.length > 0) {
						yield state.buffered.shift() as Uint8Array;
						continue;
					}
					if (state.reader_closed) return;
					const next = await new Promise<Uint8Array | null>((resolve) =>
						state.waiters.push(resolve),
					);
					if (next === null) return;
					yield next;
				}
			},
			async readAll() {
				const parts: Uint8Array[] = [];
				for await (const chunk of this.read()) parts.push(chunk);
				let total = 0;
				for (const p of parts) total += p.byteLength;
				const out = new Uint8Array(total);
				let off = 0;
				for (const p of parts) {
					out.set(p, off);
					off += p.byteLength;
				}
				return out;
			},
			closed: new Promise<void>((resolve) => state.closedResolvers.push(resolve)),
		};
	}

	private dispatch(frame: { stream_id: number; flags: number; payload: Uint8Array }): void {
		if (frame.flags & FLAG_OPEN) {
			// As the dialer we never expect peer OPENs in v1. Spec-conformant
			// behavior is to RESET any stream the peer tries to open.
			void this.emit(buildReset(frame.stream_id, 0x01));
			return;
		}
		const state = this.streams.get(frame.stream_id);
		if (!state) {
			void this.emit(buildReset(frame.stream_id, 0x01));
			return;
		}
		if (frame.flags & FLAG_DATA) {
			if (frame.payload.byteLength > state.recv_credit) {
				void this.emit(buildReset(frame.stream_id, 0x02));
				this.terminate(state);
				return;
			}
			state.recv_credit -= frame.payload.byteLength;
			state.unacked_recv += frame.payload.byteLength;
			if (state.waiters.length > 0) {
				const w = state.waiters.shift() as (v: Uint8Array | null) => void;
				w(frame.payload);
			} else {
				state.buffered.push(frame.payload);
			}
			if (state.unacked_recv >= INITIAL_WINDOW / 2) {
				const grant = state.unacked_recv;
				state.recv_credit += grant;
				state.unacked_recv = 0;
				void this.emit(buildWindow(frame.stream_id, grant));
			}
		}
		if (frame.flags & FLAG_CLOSE) {
			state.reader_closed = true;
			while (state.waiters.length) {
				const w = state.waiters.shift() as (v: Uint8Array | null) => void;
				w(null);
			}
			if (state.writer_closed) this.terminate(state);
			for (const r of state.closedResolvers) r();
			state.closedResolvers = [];
		}
		if (frame.flags & FLAG_WINDOW) {
			try {
				const credit = parseWindowCredit(frame);
				state.send_credit += credit;
			} catch {
				void this.emit(buildReset(frame.stream_id, 0x01));
				this.terminate(state);
				return;
			}
			while (state.creditWaiters.length > 0 && state.send_credit > 0) {
				const w = state.creditWaiters.shift() as () => void;
				w();
			}
		}
		if (frame.flags & FLAG_RESET) {
			try {
				parseResetReason(frame);
			} catch {
				// tolerate unknown reasons per spec
			}
			state.reader_closed = true;
			while (state.waiters.length) {
				const w = state.waiters.shift() as (v: Uint8Array | null) => void;
				w(null);
			}
			this.terminate(state);
		}
	}

	private terminate(state: StreamState): void {
		for (const r of state.closedResolvers) r();
		state.closedResolvers = [];
		for (const w of state.creditWaiters) w();
		state.creditWaiters = [];
		this.streams.delete(state.id);
	}

	private async emit(frame: {
		stream_id: number;
		flags: number;
		payload: Uint8Array;
	}): Promise<void> {
		if (this.closed) return;
		await this.send(encodeFrame(frame));
	}
}
