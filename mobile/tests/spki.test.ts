// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

import { describe, expect, test } from "bun:test";
import { X509Certificate } from "node:crypto";

import { PinningError, assertCaPin, caCertSpkiFp16, spkiFp16 } from "../src/spki";

const CA_FP16_HEX = "616a75b8113d89062796b4f591d1165f";
const CA_SPKI_DER_HEX =
	"3059301306072a8648ce3d020106082a8648ce3d030107034200043ed1477e38da335b5fc5e2257cdc28961b7b0a8ce45a7a2994df6cfcb1a877ac470fdf1db556f7e4e673cd7614afe9f01b999590f72f9235ad00d6a7e57d8807";

const CA_PEM = `-----BEGIN CERTIFICATE-----
MIIBlTCCATqgAwIBAgIUfKlYE6B2qxmra+k2J7iWWJ2kpxkwCgYIKoZIzj0EAwIw
FjEUMBIGA1UEAwwLc3BsIHRlc3QgQ0EwHhcNMjYwNTI5MjIyNzQ2WhcNMzYwNTI2
MjIyNzQ2WjAWMRQwEgYDVQQDDAtzcGwgdGVzdCBDQTBZMBMGByqGSM49AgEGCCqG
SM49AwEHA0IABD7RR3442jNbX8XiJXzcKJYbewqM5Fp6KZTfbPyxqHesRw/fHbVW
9+Tmc812FK/p8BuZlZD3L5I1rQDWp+V9iAejZjBkMB0GA1UdDgQWBBT6oNZSm87v
mF+mS8LrALDVpG8CbjAfBgNVHSMEGDAWgBT6oNZSm87vmF+mS8LrALDVpG8CbjAS
BgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAKBggqhkjOPQQDAgNJ
ADBGAiEAiMuPXJ4AWSLHls2dX2EBw92vrCweZQzcT6Vk+M5gkagCIQDoyty1PMLo
tuFhRDjMMfuXgxtvMkzBcGbl6QQJvLYE8w==
-----END CERTIFICATE-----`;

const LEAF_PEM = `-----BEGIN CERTIFICATE-----
MIIBuzCCAWKgAwIBAgIUXYQC9Em3OCbZ+iZlR0lyNtK7b1kwCgYIKoZIzj0EAwIw
FjEUMBIGA1UEAwwLc3BsIHRlc3QgQ0EwHhcNMjYwNTI5MjIyNzQ2WhcNMzYwNTI2
MjIyNzQ2WjAYMRYwFAYDVQQDDA1zcGwgdGVzdCBsZWFmMFkwEwYHKoZIzj0CAQYI
KoZIzj0DAQcDQgAEtbxGIKnsCz9SyYNb7lya1CntPWV8O3qGC8Y78NjjKw8K6Ev9
wz4X1lJBtF71j615BR4Uh1Ngqrn1QLxSSlGFWqOBizCBiDAMBgNVHRMBAf8EAjAA
MA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDATATBgNVHREEDDAK
gghzcGwudGVzdDAdBgNVHQ4EFgQUSceTG+MKGkFke2ziiFkzxBD3d8UwHwYDVR0j
BBgwFoAU+qDWUpvO75hfpkvC6wCw1aRvAm4wCgYIKoZIzj0EAwIDRwAwRAIgAxPd
KBRhue43NQfOFWINyStjDM3RIY1kuOMQbxOEpikCIEoGdekJk3R4wcixNxxWR1gf
OO+yAjdv9Xa0dS+RlQ2o
-----END CERTIFICATE-----`;

const OTHER_PEM = `-----BEGIN CERTIFICATE-----
MIIBkDCCATagAwIBAgIUY7EBjiURm3clg8F1yDA8evEnMaowCgYIKoZIzj0EAwIw
FDESMBAGA1UEAwwJc3BsIG90aGVyMB4XDTI2MDUyOTIyMjc0NloXDTM2MDUyNjIy
Mjc0NlowFDESMBAGA1UEAwwJc3BsIG90aGVyMFkwEwYHKoZIzj0CAQYIKoZIzj0D
AQcDQgAEgpEJm2ZuYFwXcjaD1xAWctp4asnXSM5E1d1NnzAUWVzqD0q5aMtfXqq0
Zo0v/s4R9bJBfSiZwUQjiClwqwzh16NmMGQwHQYDVR0OBBYEFGaYsjRy4JFe4kWb
0ql3LNBa5pCqMB8GA1UdIwQYMBaAFGaYsjRy4JFe4kWb0ql3LNBa5pCqMBIGA1Ud
EwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMCA0gAMEUC
IAbi3RV63AAMmZU/Xe3CzbwSjjxa8pmef3nWmncW4Xz7AiEA2+LBauywQpqbZGge
moxtYtbu52dSrQUiI3VWBY3CeMM=
-----END CERTIFICATE-----`;

describe("SPKI pinning", () => {
	test("computes CA cert SPKI fingerprint", () => {
		expect(hex(caCertSpkiFp16(CA_PEM))).toBe(CA_FP16_HEX);
	});

	test("spkiFp16 works on raw SPKI DER", () => {
		expect(hex(spkiFp16(hexToBytes(CA_SPKI_DER_HEX)))).toBe(CA_FP16_HEX);
	});

	test("assertCaPin accepts a leaf signed by the pinned CA", () => {
		expect(() =>
			assertCaPin({
				caPem: CA_PEM,
				expectedFp16: hexToBytes(CA_FP16_HEX),
				peerLeaf: new X509Certificate(LEAF_PEM),
			}),
		).not.toThrow();
	});

	test("assertCaPin rejects a wrong SPKI fingerprint", () => {
		expect(() =>
			assertCaPin({
				caPem: CA_PEM,
				expectedFp16: hexToBytes("00000000000000000000000000000000"),
				peerLeaf: new X509Certificate(LEAF_PEM),
			}),
		).toThrow(PinningError);
	});

	test("assertCaPin rejects a leaf not signed by the pinned CA", () => {
		expect(() =>
			assertCaPin({
				caPem: CA_PEM,
				expectedFp16: hexToBytes(CA_FP16_HEX),
				peerLeaf: new X509Certificate(OTHER_PEM),
			}),
		).toThrow(PinningError);
	});
});

function hex(bytes: Uint8Array): string {
	return Buffer.from(bytes).toString("hex");
}

function hexToBytes(s: string): Uint8Array {
	return new Uint8Array(Buffer.from(s, "hex"));
}
