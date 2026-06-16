// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

// LAN-direct (v0x04) pair flow. The home runs the spl framed-mux protocol over
// a cert-less TLS 1.3 socket on the LAN, so we connect straight to <ip>:<port>
// from the pair link, run the multiplexer, and POST /app/link/pair?token=. Like
// the relay flow, Bun's node:tls exposes only the peer leaf after a cert-less
// handshake, so we pin after /pair returns ca_chain: verify the QR's embedded
// CA cert-DER fingerprint against the returned CA and bind that CA to the live
// peer leaf. We cannot pin before sending the one-use nonce; pin-before-nonce
// is the production native client's job (see mobile/README.md).

import { webcrypto } from "node:crypto";

import { buildCsr, jwkToPkcs8Pem } from "./_csr_internal";
import { openDirectTunnel } from "./dial";
import { httpRequest } from "./http_client";
import { type PairingState, enrollDevice } from "./pair";
import type { DirectPairLink } from "./qr_link";
import { assertDirectCaPin } from "./spki";

export interface DirectPairInput {
	link: DirectPairLink;
	deviceLabel: string;
	relayEndpoint: string;
}

export async function pairDirect(input: DirectPairInput): Promise<{ state: PairingState }> {
	const relay = input.relayEndpoint.replace(/\/+$/, "");
	const { ipv4, port, nonce, caFp } = input.link;

	const session = await openDirectTunnel({ host: ipv4, port });

	let pairJson: PairResponse;
	let clientKeyPem: string;
	try {
		const { publicKey, privateKey } = (await webcrypto.subtle.generateKey(
			{ name: "ECDSA", namedCurve: "P-256" },
			true,
			["sign", "verify"],
		)) as CryptoKeyPair;
		const publicJwk = (await webcrypto.subtle.exportKey("jwk", publicKey)) as Record<
			string,
			string
		>;
		const privateJwk = (await webcrypto.subtle.exportKey("jwk", privateKey)) as Record<
			string,
			string
		>;

		clientKeyPem = jwkToPkcs8Pem(privateJwk);
		const csrPem = await buildCsr(input.deviceLabel, publicJwk, privateKey);

		const pairResponse = await httpRequest(session.mux, {
			method: "POST",
			path: `/app/link/pair?token=${encodeURIComponent(nonce)}`,
			headers: { "content-type": "application/json" },
			body: JSON.stringify({ csr: csrPem, device_label: input.deviceLabel }),
		});
		if (pairResponse.status !== 200) {
			throw new Error(`direct pair failed: HTTP ${pairResponse.status}`);
		}
		pairJson = JSON.parse(new TextDecoder().decode(pairResponse.body)) as PairResponse;
		if (!Array.isArray(pairJson.ca_chain) || typeof pairJson.ca_chain[0] !== "string") {
			throw new Error("pair response missing ca_chain");
		}
		assertDirectCaPin({
			caPem: pairJson.ca_chain[0],
			expectedFp16: caFp,
			peerLeaf: session.peerLeaf,
		});
	} catch (err) {
		try {
			await session.close();
		} catch {}
		throw err;
	}

	await session.close();
	const { device_token } = await enrollDevice(relay, {
		instance_id: pairJson.instance_id,
		home_attestation: pairJson.home_attestation,
	});

	return {
		state: {
			instance_id: pairJson.instance_id,
			home_label: pairJson.home_label,
			relay_endpoint: relay,
			ca_chain: pairJson.ca_chain,
			client_cert: pairJson.client_cert,
			client_key_pem: clientKeyPem,
			device_token,
			fingerprint: pairJson.fingerprint,
		},
	};
}

interface PairResponse {
	client_cert: string;
	ca_chain: string[];
	instance_id: string;
	home_label: string;
	home_attestation: string;
	fingerprint: string;
}
