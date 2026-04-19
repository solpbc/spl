// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

// Entry point for the spl-relay Worker.
//
// Routes:
//   GET  /.well-known/jwks.json     — transparency mirror of env.JWKS_PUBLIC
//   POST /enroll/home               — mint account token, store CA pubkey
//   POST /enroll/device             — verify home attestation, mint device token
//   GET  /session/listen?instance=  — home holds this open indefinitely
//   GET  /session/dial?instance=    — mobile opens, becomes tunnel WS on pair
//   GET  /tunnel/<id>?instance=     — home opens per `incoming` signal
//
// Blind-by-construction invariant: the Worker NEVER reads, parses, stores,
// or forwards the payload of a relayed frame. The DO holds ArrayBuffers;
// it does not inspect them. See AGENTS.md §3.

import { handleEnrollDevice, handleEnrollHome } from "./enroll";
import type { Env } from "./env";

export { InstanceDO } from "./instance-do";

export default {
	async fetch(request: Request, env: Env): Promise<Response> {
		const url = new URL(request.url);

		if (request.method === "GET" && url.pathname === "/.well-known/jwks.json") {
			return jwksResponse(env);
		}

		if (request.method === "POST" && url.pathname === "/enroll/home") {
			return handleEnrollHome(request, env);
		}
		if (request.method === "POST" && url.pathname === "/enroll/device") {
			return handleEnrollDevice(request, env);
		}

		// WebSocket upgrade surfaces are routed to the Durable Object for the
		// named instance. The DO itself does auth (JWT verify) — doing it here
		// too would just mean double-parsing the same token on every hop.
		if (
			url.pathname === "/session/listen" ||
			url.pathname === "/session/dial" ||
			url.pathname.startsWith("/tunnel/")
		) {
			const instanceId = url.searchParams.get("instance");
			if (!instanceId) {
				return new Response("instance param required", { status: 400 });
			}
			const doId = env.INSTANCE.idFromName(instanceId);
			const stub = env.INSTANCE.get(doId);
			return stub.fetch(request);
		}

		if (request.method === "GET" && url.pathname === "/") {
			return new Response("spl-relay\n", {
				status: 200,
				headers: { "content-type": "text/plain; charset=utf-8" },
			});
		}

		return new Response("not found", { status: 404 });
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
	// Pass through verbatim — see ../proto/tokens.md §JWKS publication. We
	// do NOT parse-and-re-emit; that would risk dropping fields a future
	// Worker version added to the envelope.
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
