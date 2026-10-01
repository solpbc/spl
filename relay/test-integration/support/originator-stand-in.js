// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

// Stand-in for the operator's account portal in the owner-purge suite. Like the
// real portal it is a separate Worker with a default fetch handler and an
// OwnerPurgeOrigin entrypoint. The relay's ORIGINATOR binding names the
// entrypoint; the suite drives the stand-in through a second binding to its
// default handler. It verifies each origin frame independently of the relay's
// own signing code, with the fixture keys. Freshness is not checked here: the
// suite runs the relay on the fixture's clock, and the portal's own suite owns
// its five-minute window.

import { WorkerEntrypoint } from "cloudflare:workers";

const KEYS = { 1: "owner-purge-v1-fixture-test-key", 2: "owner-purge-v2-fixture-test-key" };
const FIELDS = ["version", "key_version", "service", "operation_id", "issued_at", "integrity"];

const state = { originated: new Set(), mode: "portal", frames: [] };

function canonical(value) {
	if (value === null || typeof value !== "object") return JSON.stringify(value);
	const keys = Object.keys(value).sort();
	return `{${keys.map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
}

function lengthPrefixed(bytes) {
	const out = new Uint8Array(8 + bytes.length);
	new DataView(out.buffer).setBigUint64(0, BigInt(bytes.length), false);
	out.set(bytes, 8);
	return out;
}

async function verify(frame) {
	if (!frame || Object.keys(frame).length !== FIELDS.length) return false;
	if (!FIELDS.every((field) => Object.hasOwn(frame, field))) return false;
	const key = KEYS[frame.key_version];
	if (frame.version !== 1 || frame.service !== "relay" || !key) return false;
	const { integrity, ...unsigned } = frame;
	const encoder = new TextEncoder();
	const domain = lengthPrefixed(encoder.encode("solpbc-owner-purge-v1:relay:origin"));
	const body = lengthPrefixed(encoder.encode(canonical(unsigned)));
	const message = new Uint8Array(domain.length + body.length);
	message.set(domain);
	message.set(body, domain.length);
	const hmacKey = await crypto.subtle.importKey(
		"raw",
		encoder.encode(key),
		{ name: "HMAC", hash: "SHA-256" },
		false,
		["sign"],
	);
	const signature = new Uint8Array(await crypto.subtle.sign("HMAC", hmacKey, message));
	const expected = btoa(String.fromCharCode(...signature))
		.replace(/\+/g, "-")
		.replace(/\//g, "_")
		.replace(/=+$/, "");
	return expected === integrity;
}

export class OwnerPurgeOrigin extends WorkerEntrypoint {
	async originated(frame) {
		state.frames.push(frame);
		if (state.mode === "throw") throw new Error("origin check unavailable");
		if (state.mode === "malformed") return { originated: "yes" };
		if (!(await verify(frame))) throw new Error("owner purge origin frame refused");
		return { originated: state.originated.has(frame.operation_id) };
	}
}

export default {
	async fetch(request) {
		const url = new URL(request.url);
		if (url.pathname === "/control/register") {
			state.originated.add((await request.json()).operation_id);
			return new Response(null, { status: 204 });
		}
		if (url.pathname === "/control/mode") {
			state.mode = (await request.json()).mode;
			return new Response(null, { status: 204 });
		}
		if (url.pathname === "/control/frames") return Response.json(state.frames);
		if (url.pathname === "/control/reset") {
			state.originated.clear();
			state.mode = "portal";
			state.frames = [];
			return new Response(null, { status: 204 });
		}
		// Every other path stands for the portal's own routes, which a binding
		// to the OwnerPurgeOrigin entrypoint must never reach.
		return new Response("portal fetch handler", { status: 200 });
	},
};
