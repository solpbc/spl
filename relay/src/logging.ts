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

import type { AttestationFailReason } from "./attestation";
import type { VerifyFailReason } from "./tokens";

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
	| "enroll_device_remint"
	| "device_refresh"
	| "enroll_home_rotate"
	| "enroll_rejected"
	| "pair_window_open"
	| "pair_window_close"
	| "pair_dial_open"
	| "pair_dial_rejected"
	| "entitlement_set"
	| "entitlement_pending"
	| "entitlement_revoke"
	| "pending_grant_claimed"
	| "admin_instances_list"
	| "admin_instance_show"
	| "instance_retire"
	| "instance_retire_failed"
	| "not_entitled"
	| "internal_error";

export type Direction = "home_to_mobile" | "mobile_to_home" | "meta";

// Relay-authored close classifications. Distinct from — and a strict subset
// of — the general authored-reason set below. webSocketClose/webSocketError
// emit a FIXED member here; peer close text is never a source.
export type CloseReason = "peer_closed" | "ws_error" | "instance_retired";

export type RetirementComponent =
	| "retired_state"
	| "instance_do_cleanup"
	| "rk_do_cleanup"
	| "device_revocation"
	| "entitlement_clear"
	| "pending_grant_clear"
	| "rk_registry_clear"
	| "verification";

type AuthorizedReason =
	// token verification (forwarded via unauthorizedWithLog)
	| VerifyFailReason
	// attestation failures reach log() only through the enroll.ts template literal
	| `attestation_${AttestationFailReason}`
	// relay-authored close/error classifications
	| CloseReason
	// instance-retirement response/log component vocabulary
	| RetirementComponent
	// route-local auth / routing
	| "missing_token"
	| "instance_mismatch"
	| "not_enrolled"
	| "revoked"
	| "no_window"
	// cardinality + pairing
	| "listen_replaced"
	| "ttl_expired"
	| "pair_window_replaced"
	| "limited"
	| "consumed"
	| "home_dropped"
	| "tunnel_home_replaced"
	// enrollment
	| "body_too_large"
	| "missing_fields"
	| "bad_instance_id"
	| "bad_ca_pubkey"
	| "ca_mismatch"
	| "ca_fp_conflict"
	| "unknown_instance"
	| "instance_revoked"
	| "attestation_replay"
	// entitlement
	| "bad_bearer";

export interface LogFields {
	event: LogEvent;
	tunnel_id?: string;
	instance_id?: string;
	direction?: Direction;
	byte_count?: number;
	count?: number;
	close_code?: number;
	duration_ms?: number;
	reason?: AuthorizedReason;
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
