// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

// Pair-link parser for solstone QR payloads. Dispatch on the decoded version
// byte first so relay and direct layouts cannot cross-read one another.

import { decode } from "./crockford32";

export interface RelayPairLink {
	kind: "relay";
	instanceId: string;
	totp: string;
	nonce: string;
	caFpTag: number;
	caFp: Uint8Array;
	relayOrigin: string | null;
}

export interface DirectPairLink {
	kind: "direct";
	addrType: number;
	ipv4: string;
	port: number;
	nonce: string;
	caFp: Uint8Array;
}

export type PairLink = RelayPairLink | DirectPairLink;

export function looksLikePairLink(s: string): boolean {
	try {
		const url = new URL(s);
		return (
			url.protocol === "https:" &&
			url.hostname === "link.solpbc.org" &&
			url.pathname === "/p" &&
			url.hash.length > 1
		);
	} catch {
		return false;
	}
}

export function parsePairLink(s: string): PairLink {
	const url = new URL(s);
	const fragment = url.hash.slice(1);
	if (!fragment) throw new Error("pair link missing fragment");

	const bytes = decode(fragment);
	if (bytes.byteLength === 0) throw new Error("pair link payload is empty");

	const version = bytes[0];
	if (version === 0x03) return parseRelay(bytes);
	if (version === 0x02) return parseDirect(bytes);
	throw new Error(`unsupported pair-link version: 0x${version.toString(16).padStart(2, "0")}`);
}

function parseRelay(bytes: Uint8Array): RelayPairLink {
	if (bytes.byteLength < 54) {
		throw new Error(
			`malformed relay pair link: expected at least 54 bytes, got ${bytes.byteLength}`,
		);
	}

	const selector = bytes[53];
	const expectedLength = selector === 0 ? 54 : 54 + selector;
	if (bytes.byteLength !== expectedLength) {
		throw new Error(
			`malformed relay pair link: selector ${selector} requires ${expectedLength} bytes, got ${bytes.byteLength}`,
		);
	}

	const totpInt = (bytes[17] << 16) | (bytes[18] << 8) | bytes[19];
	return {
		kind: "relay",
		instanceId: uuidFromRaw(bytes.slice(1, 17)),
		totp: String(totpInt).padStart(6, "0"),
		nonce: hex(bytes.slice(20, 36)),
		caFpTag: bytes[36],
		caFp: bytes.slice(37, 53),
		relayOrigin: selector === 0 ? null : new TextDecoder().decode(bytes.slice(54, 54 + selector)),
	};
}

function parseDirect(bytes: Uint8Array): DirectPairLink {
	if (bytes.byteLength !== 32) {
		throw new Error(`malformed direct pair link: expected 32 bytes, got ${bytes.byteLength}`);
	}
	return {
		kind: "direct",
		addrType: bytes[1],
		ipv4: Array.from(bytes.slice(2, 6)).join("."),
		port: (bytes[6] << 8) | bytes[7],
		nonce: hex(bytes.slice(8, 16)),
		caFp: bytes.slice(16, 32),
	};
}

function uuidFromRaw(bytes: Uint8Array): string {
	if (bytes.byteLength !== 16) {
		throw new Error(`raw UUID must be 16 bytes, got ${bytes.byteLength}`);
	}
	const h = hex(bytes);
	return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

function hex(bytes: Uint8Array): string {
	return Buffer.from(bytes).toString("hex");
}
