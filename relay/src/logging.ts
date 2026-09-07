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
	| "enroll_rejected"
	| "internal_error"
	| "owner_purge_expired"
	| "owner_purge_refused"
	| "owner_purge_retryable"
	| "pair_dial_rejected"
	| "pending_buffer_overflow"
	| "unauthorized";

export type Direction = "home_to_mobile" | "mobile_to_home" | "meta";

// Relay-authored close classifications. Distinct from — and a strict subset
// of — the general authored-reason set below. webSocketClose/webSocketError
// emit a FIXED member here; peer close text is never a source.
export type CloseReason = "peer_closed" | "ws_error" | "attach_timeout" | "pending_drain_failed";

type AuthorizedReason =
	// token verification (forwarded via unauthorizedWithLog)
	| VerifyFailReason
	// attestation failures reach log() only through the enroll.ts template literal
	| `attestation_${AttestationFailReason}`
	// relay-authored close/error classifications
	| CloseReason
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
	| "bad_bearer"
	// canonical owner purge
	| "owner_purge_malformed"
	| "owner_purge_bad_integrity"
	| "owner_purge_wrong_service"
	| "owner_purge_digest_mismatch"
	| "owner_purge_instance_limit"
	| "owner_purge_request_lifetime"
	| "owner_purge_attestation_lifetime"
	| "owner_purge_binding_mismatch"
	| "owner_purge_binding_absent"
	| "owner_purge_database_error";

export interface LogFields {
	event: LogEvent;
	reason?: AuthorizedReason;
	route?: string;
}

export function log(fields: LogFields): void {
	// Construct explicitly even if a caller circumvents static typing.
	console.log(JSON.stringify({ event: fields.event, reason: fields.reason, route: fields.route }));
}
