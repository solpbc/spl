// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

export type ReadResult<T> = { ok: true; value: T } | { ok: false; reason: "too_large" | "invalid" };

export async function readJson<T>(request: Request, maxBytes: number): Promise<ReadResult<T>> {
	const ct = request.headers.get("content-type") ?? "";
	if (!ct.includes("application/json")) return { ok: false, reason: "invalid" };

	// Pre-parse size cap. content-length is the cheap signal for a fixed-length
	// body; the measured byteLength below is the backstop when it is absent or
	// understated. The body stream is consumed exactly once.
	const declared = request.headers.get("content-length");
	if (declared !== null) {
		const n = Number(declared);
		if (Number.isFinite(n) && n > maxBytes) return { ok: false, reason: "too_large" };
	}

	let raw: ArrayBuffer;
	try {
		raw = await request.arrayBuffer();
	} catch {
		return { ok: false, reason: "invalid" };
	}
	if (raw.byteLength > maxBytes) return { ok: false, reason: "too_large" };

	try {
		return { ok: true, value: JSON.parse(new TextDecoder().decode(raw)) as T };
	} catch {
		return { ok: false, reason: "invalid" };
	}
}

export function json(body: unknown, status = 200): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "content-type": "application/json; charset=utf-8" },
	});
}
