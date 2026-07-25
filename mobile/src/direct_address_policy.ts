// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

const DIRECT_ADDRESS_REFUSED = "direct pair candidate address is not admitted";

const ALLOWED_IPV4_RANGES: ReadonlyArray<readonly [number, number]> = [
	[0x0a000000, 0x0affffff],
	[0x64400000, 0x647fffff],
	[0x7f000000, 0x7fffffff],
	[0xa9fe0000, 0xa9feffff],
	[0xac100000, 0xac1fffff],
	[0xc0a80000, 0xc0a8ffff],
];

export class DirectAddressAdmissionError extends Error {
	constructor() {
		super(DIRECT_ADDRESS_REFUSED);
		this.name = "DirectAddressAdmissionError";
	}
}

export function assertDirectCandidatesAdmitted(candidates: readonly string[]): void {
	if (candidates.length === 0) throw new DirectAddressAdmissionError();
	for (const candidate of candidates) {
		const address = parseIpv4(candidate);
		if (!ALLOWED_IPV4_RANGES.some(([start, end]) => address >= start && address <= end)) {
			throw new DirectAddressAdmissionError();
		}
	}
}

function parseIpv4(candidate: string): number {
	const parts = candidate.split(".");
	if (parts.length !== 4) throw new DirectAddressAdmissionError();

	let address = 0;
	for (const part of parts) {
		if (!/^(0|[1-9][0-9]{0,2})$/.test(part)) throw new DirectAddressAdmissionError();
		const octet = Number(part);
		if (octet > 255) throw new DirectAddressAdmissionError();
		address = address * 256 + octet;
	}
	return address;
}
