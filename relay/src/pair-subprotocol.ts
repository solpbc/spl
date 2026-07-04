// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

export const SUBPROTOCOL_V1 = "spl-v1";
export const PAIR_TOKEN_PREFIX = "spl-pair.";

const RK_HEX = /^[0-9a-fA-F]{32}$/;

export function normalizeRk(raw: string | null | undefined): string | null {
	const rk = raw?.trim();
	if (!rk || !RK_HEX.test(rk)) return null;
	return rk.toLowerCase();
}

export function parsePairSubprotocol(headerValue: string | null): {
	rk: string | null;
	offeredV1: boolean;
	invalid: boolean;
} {
	if (!headerValue?.trim()) return { rk: null, offeredV1: false, invalid: false };

	const tokens = headerValue.split(",").map((token) => token.trim());
	const offeredV1 = tokens.some((token) => token === SUBPROTOCOL_V1);
	const rks = new Set<string>();

	for (const token of tokens) {
		if (!token.startsWith(PAIR_TOKEN_PREFIX)) continue;
		const rk = normalizeRk(token.slice(PAIR_TOKEN_PREFIX.length));
		if (rk) rks.add(rk);
	}

	if (rks.size > 1) return { rk: null, offeredV1, invalid: true };

	const rk = rks.values().next().value ?? null;
	return { rk, offeredV1, invalid: rk !== null && !offeredV1 };
}
