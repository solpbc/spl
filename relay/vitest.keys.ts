// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

export async function genSigningKeypair(): Promise<{
	privateJwkRaw: string;
	jwksPublicRaw: string;
}> {
	const pair = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
		"sign",
		"verify",
	])) as CryptoKeyPair;
	const pub = (await crypto.subtle.exportKey("jwk", pair.publicKey)) as unknown as Record<
		string,
		string
	>;
	const priv = (await crypto.subtle.exportKey("jwk", pair.privateKey)) as unknown as Record<
		string,
		string
	>;
	const kid = "test-kid-1";
	const publicJwk = {
		kty: "OKP",
		crv: "Ed25519",
		kid,
		x: pub.x,
		alg: "EdDSA",
		use: "sig",
	};
	const privateJwk = { ...publicJwk, d: priv.d };
	return {
		privateJwkRaw: JSON.stringify(privateJwk),
		jwksPublicRaw: JSON.stringify({ keys: [publicJwk] }),
	};
}
