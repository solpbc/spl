// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import { b64urlDecode } from "./_csr_internal";

export function parseJwtClaims(token: string): { iat: number; exp: number } | null {
	const parts = token.split(".");
	if (parts.length !== 3) return null;

	try {
		const claims = JSON.parse(new TextDecoder().decode(b64urlDecode(parts[1]))) as {
			iat?: unknown;
			exp?: unknown;
		};
		if (typeof claims.iat !== "number" || !Number.isFinite(claims.iat)) return null;
		if (typeof claims.exp !== "number" || !Number.isFinite(claims.exp)) return null;
		return { iat: claims.iat, exp: claims.exp };
	} catch {
		return null;
	}
}

export function shouldRefreshBeforeDial(
	claims: { iat: number; exp: number },
	nowSeconds: number,
	threshold = 0.8,
): boolean {
	const ttl = claims.exp - claims.iat;
	return ttl > 0 && (nowSeconds - claims.iat) / ttl > threshold;
}

export type RefreshAction = "use_new_token" | "reconnect" | "keep_existing";

export function classifyRefreshOutcome(status: number): RefreshAction {
	if (status === 200) return "use_new_token";
	if (status === 401 || status === 403 || status === 404) return "reconnect";
	return "keep_existing";
}

export type DialRejectionReason = "auth" | "not_entitled" | "no_home" | "transient";

// Native clients can feed WebSocket handshake metadata here. Bun's browser-compatible
// WebSocket exposes neither HTTP status nor x-close-code for failed upgrades, so the
// Bun runtime treats opaque input as transient and handles refresh at the DialRejected seam.
export function classifyDialRejection(o: {
	status?: number;
	xCloseCode?: number;
}): DialRejectionReason {
	if (o.xCloseCode === 4401 || o.status === 401) return "auth";
	if (o.xCloseCode === 4402 || o.status === 402) return "not_entitled";
	if (o.status === 503) return "no_home";
	return "transient";
}
