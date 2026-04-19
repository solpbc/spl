// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

// Structured log helper. ONE responsibility: enforce the log hygiene contract
// from AGENTS.md §3 and proto/session.md §"what spl-relay logs about a session".
//
// Logged fields are an explicit allow-list. Never a payload byte. Never a
// token claim. Never a TLS handshake message. Never an Authorization header.
// Never the bytes inside a relayed frame.
//
// Callers emit events through `log({...})`. The helper refuses unknown fields
// at type-check time so it is impossible to accidentally widen the surface.
// Runtime code that needs to widen the surface must edit this file in a
// reviewable diff; drive-by `console.log` calls elsewhere violate the review
// invariant.

export type LogEvent =
	| "listen_open"
	| "listen_close"
	| "dial_open"
	| "dial_close"
	| "tunnel_home_open"
	| "tunnel_home_close"
	| "tunnel_mobile_open"
	| "tunnel_mobile_close"
	| "pair"
	| "fwd"
	| "pending_buffer"
	| "pending_buffer_overflow"
	| "unauthorized"
	| "cardinality_violation"
	| "enroll_home"
	| "enroll_device"
	| "enroll_home_rotate"
	| "enroll_rejected"
	| "internal_error";

export type Direction = "home_to_mobile" | "mobile_to_home" | "meta";

export interface LogFields {
	event: LogEvent;
	tunnel_id?: string;
	instance_id?: string;
	direction?: Direction;
	byte_count?: number;
	close_code?: number;
	duration_ms?: number;
	reason?: string;
	route?: string;
	jti?: string;
	queued_frames?: number;
	queued_bytes?: number;
}

export function log(fields: LogFields): void {
	console.log(
		JSON.stringify({
			timestamp: Date.now(),
			...fields,
		}),
	);
}
