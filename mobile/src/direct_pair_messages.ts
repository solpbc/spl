// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

export const DIRECT_CANDIDATES_EXHAUSTED_MESSAGE =
	"direct candidates exhausted before pairing request";

export function directPairingAnnouncement(
	deviceLabel: string,
	candidateCount: number,
	port: number,
): string {
	const candidates = candidateCount === 1 ? "1 candidate" : `${candidateCount} candidates`;
	return `pairing from LAN-direct QR as "${deviceLabel}" (${candidates} on port ${port})`;
}
