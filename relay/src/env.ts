// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

// Environment bindings shared across the Worker and the Durable Object.

export interface Env {
	// Durable Object namespace — one DO instance per home.
	INSTANCE: DurableObjectNamespace;

	// D1 database — token metadata (instances, devices, revocation). Never
	// payload bytes.
	DB: D1Database;

	// Deployment environment: "development" | "staging" | "production".
	ENVIRONMENT: string;

	// Expected JWT issuer for this deployment. Sol pbc hosted: "spl.solpbc.org".
	// Self-hosted: operator's domain. Tokens whose `iss` claim does not match
	// are rejected.
	ISSUER: string;

	// JWT signing layer secrets — provisioned via `wrangler secret put`.
	// See ../docs/signing-keys.md for the lifecycle and ../proto/tokens.md
	// for the wire format.
	//
	// SIGNING_JWK is the PRIVATE Ed25519 JWK used to mint account/device
	// tokens at the /enroll/* control-plane endpoints.
	//
	// JWKS_PUBLIC is a JSON envelope { "keys": [<public JWK>, ...] } used
	// to verify tokens on every WebSocket upgrade. JWKS supports multi-key
	// rotation via `kid` lookup.
	SIGNING_JWK?: string;
	JWKS_PUBLIC?: string;
}
