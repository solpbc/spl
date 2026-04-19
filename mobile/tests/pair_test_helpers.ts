// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

// Test-only scaffolding that exposes the CSR-building path from pair.ts
// without pulling in the full network-side code.

import { webcrypto } from "node:crypto";

// Re-export the internal helpers by importing a stripped-down clone —
// pair.ts's builders are private to that module, so we replay them here.
// Keeping parallel copies is cheap because the real code is also CSR-
// generation boilerplate; if we ever extract a shared asn1/csr helper,
// both sides will delete their copy.

import { buildCsr } from "../src/_csr_internal";

export async function buildCsrForTest(commonName: string): Promise<string> {
	const { publicKey, privateKey } = (await webcrypto.subtle.generateKey(
		{ name: "ECDSA", namedCurve: "P-256" },
		true,
		["sign", "verify"],
	)) as CryptoKeyPair;
	const publicJwk = (await webcrypto.subtle.exportKey("jwk", publicKey)) as Record<string, string>;
	return buildCsr(commonName, publicJwk, privateKey);
}
