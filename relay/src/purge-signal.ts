// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

// Alert on use for the owner-purge endpoint. Every successful purge
// transition writes one key to the operator's signal namespace. The key names
// only the service, the disposition and the time. It has no value, no
// metadata, no operation fingerprint, no request digest and no owner
// association, so it can say that a purge happened but never whose. The key
// expires with the purge binding it reports and never outlives it. A
// deployment without the binding (any self-hosted relay) writes nothing.

import { log } from "./logging";

export type PurgeSignalDisposition = "complete" | "confirmed";

// Workers KV refuses a TTL under 60 seconds.
const MIN_TTL_SECONDS = 60;

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
	bindingExpiresAtMs: number,
	nowMs: number,
): Promise<void> {
	if (!kv) return;
	const expirationTtl = Math.max(MIN_TTL_SECONDS, Math.floor((bindingExpiresAtMs - nowMs) / 1000));
	try {
		await kv.put(purgeSignalKey(service, disposition, nowMs), "", { expirationTtl });
	} catch {
		// The purge already happened and cannot be undone, so a lost signal must
		// not turn a finished purge into a retry.
		log({ event: "internal_error", reason: "owner_purge_signal_failed" });
	}
}
