// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

// Relay-addressed (off-LAN) pair flow. Bun 1.3.10 cannot expose the presented
// CA certificate chain from node:tls after the cert-less handshake, so this
// reference CLI pins after /pair returns ca_chain and binds that CA to the live
// leaf certificate. It cannot pin before sending the one-use nonce; active-MITM
// resistance during pairing is the production iOS client's responsibility. See
// mobile/README.md.

import { webcrypto } from "node:crypto";

import { buildCsr, jwkToPkcs8Pem } from "./_csr_internal";
import { openTunnel } from "./dial";
import { httpRequest } from "./http_client";
import { type PairingState, enrollDevice, httpsPost } from "./pair";
import type { RelayPairLink } from "./qr_link";
import { assertCaPin } from "./spki";

export interface RelayPairInput {
	link: RelayPairLink;
	deviceLabel: string;
	relayEndpoint: string;
}

export async function pairRelay(input: RelayPairInput): Promise<{ state: PairingState }> {
	const relay = input.relayEndpoint.replace(/\/+$/, "");
	const { instanceId, totp, nonce, caFp } = input.link;

	const ticketResponse = await httpsPost(
		`${relay}/session/pair-ticket?instance=${encodeURIComponent(instanceId)}`,
		JSON.stringify({ instance_id: instanceId, totp }),
		{},
	);
	if (ticketResponse.status !== 200) {
		throw new Error(`pair-ticket failed: HTTP ${ticketResponse.status}: ${ticketResponse.body}`);
	}
	const ticketJson = JSON.parse(ticketResponse.body) as { pair_ticket?: string };
	if (typeof ticketJson.pair_ticket !== "string" || !ticketJson.pair_ticket) {
		throw new Error("pair-ticket response missing pair_ticket");
	}

	const session = await openTunnel({
		endpoint: relay,
		path: "/session/pair-dial",
		instanceId,
		token: ticketJson.pair_ticket,
		trust: { mode: "pin" },
	});

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
			throw new Error(`relay pair failed: HTTP ${pairResponse.status}`);
		}
		pairJson = JSON.parse(new TextDecoder().decode(pairResponse.body)) as PairResponse;
		if (!Array.isArray(pairJson.ca_chain) || typeof pairJson.ca_chain[0] !== "string") {
			throw new Error("pair response missing ca_chain");
		}
		assertCaPin({ caPem: pairJson.ca_chain[0], expectedFp16: caFp, peerLeaf: session.peerLeaf });
		if (pairJson.instance_id !== instanceId) {
			throw new Error("instance_id mismatch between QR and /pair response");
		}
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
