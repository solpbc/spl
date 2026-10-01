// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

// Alert on use for the owner-purge endpoint. Every successful purge
// transition writes one key to the operator's signal namespace. The key names
// only the service, the disposition and the time. It has no value, no
// metadata, no operation fingerprint, no request digest and no owner
// association, so it can say that a purge happened but never whose. A refused
// purge the account portal never originated writes a `refused_unoriginated`
// key the same way. Every key expires a fixed seven days after it is written,
// the ceiling of the purge binding's own class. The lifetime is never taken
// from the envelope, because whoever signs the envelope chooses its expiry, and
// a forger must not be able to shorten the record of their own purge. A
// deployment without the binding (any self-hosted relay) writes nothing.

import { log } from "./logging";

export type PurgeSignalDisposition = "complete" | "confirmed" | "refused_unoriginated";

export const PURGE_SIGNAL_TTL_SECONDS = 7 * 24 * 60 * 60;

export function purgeSignalKey(
	service: string,
	disposition: PurgeSignalDisposition,
	nowMs: number,
): string {
	const nonce = Array.from(crypto.getRandomValues(new Uint8Array(4)), (byte) =>
		byte.toString(16).padStart(2, "0"),
	).join("");
	return `${new Date(nowMs).toISOString()}/${service}/${disposition}/${nonce}`;
}

export async function signalPurgeUse(
	kv: KVNamespace | undefined,
	service: string,
	disposition: PurgeSignalDisposition,
	nowMs: number,
): Promise<void> {
	if (!kv) return;
	try {
		await kv.put(purgeSignalKey(service, disposition, nowMs), "", {
			expirationTtl: PURGE_SIGNAL_TTL_SECONDS,
		});
	} catch {
		// A lost signal must not change the disposition: a finished purge cannot
		// be undone, and a refusal stands either way.
		log({ event: "internal_error", reason: "owner_purge_signal_failed" });
	}
}
