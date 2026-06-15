// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

// Admin grant intake for the opt-in session entitlement gate.

import type { Env } from "./env";
import { json, readJson } from "./http";
import { log } from "./logging";

const ROUTE = "/admin/entitlement";
const MAX_ENTITLEMENT_BYTES = 2 * 1024;
const INSTANCE_ID_RE = /^[0-9a-fA-F-]{10,64}$/;

interface EntitlementBody {
	instance_id?: string;
	entitled_until?: number | null;
}

type ResolvedEntitlement = { ok: true; entitledUntil: number | null } | { ok: false };

export async function handleSetEntitlement(request: Request, env: Env): Promise<Response> {
	if (!env.GRANT_SECRET) return json({ error: "relay not provisioned" }, 503);

	if (!hasValidBearer(request, env.GRANT_SECRET)) {
		log({ event: "unauthorized", route: ROUTE, reason: "bad_bearer" });
		return json({ error: "unauthorized" }, 401);
	}

	const read = await readJson<EntitlementBody>(request, MAX_ENTITLEMENT_BYTES);
	if (!read.ok) return json({ error: "bad request" }, 400);

	const body = read.value;
	if (
		typeof body !== "object" ||
		body === null ||
		!body.instance_id ||
		!INSTANCE_ID_RE.test(body.instance_id)
	) {
		return json({ error: "bad instance_id" }, 400);
	}

	const resolved = resolveEntitlement(body.entitled_until);
	if (!resolved.ok) return json({ error: "bad entitled_until" }, 400);

	const result = await env.DB.prepare(
		"UPDATE instances SET entitled_until = ? WHERE instance_id = ?",
	)
		.bind(resolved.entitledUntil, body.instance_id)
		.run();
	if (result.meta.changes === 0) return json({ error: "unknown instance_id" }, 404);

	log({
		event: resolved.entitledUntil === null ? "entitlement_revoke" : "entitlement_set",
		instance_id: body.instance_id,
	});
	return json({ ok: true });
}

function hasValidBearer(request: Request, secret: string): boolean {
	const header = request.headers.get("authorization") ?? "";
	const match = header.match(/^Bearer\s+(.+)$/i);
	if (!match) return false;

	const encoder = new TextEncoder();
	const supplied = encoder.encode(match[1].trim());
	const expected = encoder.encode(secret);
	if (supplied.byteLength !== expected.byteLength) return false;

	return crypto.subtle.timingSafeEqual(supplied, expected);
}

function resolveEntitlement(value: unknown): ResolvedEntitlement {
	if (value === undefined || value === null) return { ok: true, entitledUntil: null };
	if (typeof value !== "number" || !Number.isFinite(value)) return { ok: false };
	if (value <= 0) return { ok: true, entitledUntil: null };
	return { ok: true, entitledUntil: Math.floor(value) };
}
