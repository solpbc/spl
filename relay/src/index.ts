// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

// Entry point for the spl-relay Worker.
//
// This file is a scaffold placeholder. The real Worker wires up
// /session/listen, /session/dial, /tunnel/<id> routes and hands the
// upgraded WebSockets to the InstanceDO for pairing.
//
// Non-negotiable invariant: this Worker must NEVER read, parse, store,
// or forward the payload of a relayed frame. See ../AGENTS.md §3.

export interface Env {
	INSTANCE: DurableObjectNamespace;
	ENVIRONMENT: string;

	// JWT signing layer secrets — provisioned via `wrangler secret put`.
	// See ../docs/signing-keys.md for the lifecycle (generation, rotation,
	// compromise response) and ../proto/tokens.md for the wire format.
	//
	// SIGNING_JWK is the PRIVATE Ed25519 JWK used to mint account/device
	// tokens at the (not-yet-implemented) /enroll/* control-plane endpoints.
	// JWKS_PUBLIC is a JSON envelope { "keys": [<public JWK>, ...] } used
	// to verify tokens on every WebSocket upgrade. JWKS supports multi-key
	// rotation via the `kid` lookup.
	SIGNING_JWK?: string;
	JWKS_PUBLIC?: string;
}

export default {
	async fetch(request: Request, env: Env): Promise<Response> {
		const url = new URL(request.url);

		// Public JWKS transparency endpoint. Anyone can verify what key the
		// relay is currently signing tokens with — no internal access required.
		// See ../docs/signing-keys.md for the publication contract.
		if (request.method === "GET" && url.pathname === "/.well-known/jwks.json") {
			return jwksResponse(env);
		}

		return new Response("spl-relay — scaffold", {
			status: 200,
			headers: { "content-type": "text/plain; charset=utf-8" },
		});
	},
} satisfies ExportedHandler<Env>;

function jwksResponse(env: Env): Response {
	const raw = env.JWKS_PUBLIC;
	if (!raw) {
		// Without a JWKS the relay cannot validate any token. We return 503
		// (not 404) because the endpoint exists by contract — the relay is
		// just not currently provisioned.
		return new Response(JSON.stringify({ keys: [] }), {
			status: 503,
			headers: jwksHeaders(),
		});
	}

	// Pass through whatever shape was provisioned. We do NOT parse-and-
	// re-emit — that would risk dropping fields a future Worker version
	// added to the JWKS envelope. The provisioning step is responsible
	// for the JSON shape; this endpoint is a transparency mirror.
	return new Response(raw, {
		status: 200,
		headers: jwksHeaders(),
	});
}

function jwksHeaders(): HeadersInit {
	return {
		"content-type": "application/jwk-set+json",
		// 5 minutes — short enough to propagate rotations quickly, long
		// enough to bound load on the Worker. Matches the publication
		// contract documented in ../proto/tokens.md.
		"cache-control": "public, max-age=300",
	};
}

// TODO(mvp): token verification helper.
//
// Will load env.JWKS_PUBLIC, parse the JWKS envelope, look up the kid
// from the JWT JOSE header, verify the EdDSA signature against the
// matched public key (via Web Crypto's Ed25519 import + verify), and
// validate standard claims (aud == "spl-relay", iss == expected issuer for
// this deployment, exp > now, iat <= now + 60s skew, scope matches the
// requested route). Return { ok: true, claims } | { ok: false, reason }.
//
// Called by the /session/listen, /session/dial, /tunnel/<id> route
// handlers before the WebSocket upgrade is accepted.
//
// See ../proto/tokens.md for the validation contract.

// TODO(mvp): token issuance helper.
//
// Will load env.SIGNING_JWK, import as Ed25519 signing key via Web
// Crypto, mint a JWT with the required claims (see ../proto/tokens.md)
// and a fresh jti (UUIDv7), and return the compact-serialized token.
//
// Called only by the /enroll/home and /enroll/device control-plane
// endpoints (HTTPS, not WebSocket). The private key never leaves
// env.SIGNING_JWK; never log it, never echo it, never stack-trace it.
// See ../AGENTS.md §3 + §4 (signing-key safety rail).

// InstanceDO — one Durable Object per home solstone instance.
// Will hold the listen WS and pair incoming dial WSes into blind byte relays.
// Scaffold stub only — the real implementation lands with the MVP build.
export class InstanceDO implements DurableObject {
	constructor(
		_state: DurableObjectState,
		_env: Env,
	) {}

	async fetch(_request: Request): Promise<Response> {
		return new Response("InstanceDO — scaffold", { status: 200 });
	}
}
