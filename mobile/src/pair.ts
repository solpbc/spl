// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

// Pair flow — mobile side.
//
// 1. Generate an ECDSA-P256 keypair locally (mode 0600 on the private-key file).
// 2. Build a CSR carrying the public key.
// 3. POST to the home's local HTTPS pair URL, pinning the home's self-signed
//    CA cert (pin fingerprint optionally provided out-of-band).
// 4. Receive { client_cert, ca_chain, instance_id, home_label, home_attestation }.
// 5. Forward the client_cert + home_attestation to spl-relay /enroll/device and
//    store the resulting device_token alongside the local keypair.

import { webcrypto } from "node:crypto";
import { chmod, readFile, writeFile } from "node:fs/promises";

import { buildCsr, jwkToPkcs8Pem } from "./_csr_internal";

export interface PairingState {
	instance_id: string;
	home_label: string;
	relay_endpoint: string;
	ca_chain: string[];
	client_cert: string;
	client_key_pem: string;
	device_token: string;
	fingerprint: string;
}

export async function loadPairing(path: string): Promise<PairingState> {
	const raw = await readFile(path, "utf-8");
	return JSON.parse(raw) as PairingState;
}

export async function savePairing(path: string, state: PairingState): Promise<void> {
	await writeFile(path, `${JSON.stringify(state, null, 2)}\n`);
	await chmod(path, 0o600);
}

export interface PairInput {
	lanUrl: string;
	deviceLabel: string;
	relayEndpoint: string;
	/** Optional: SHA-256 fingerprint of the home's self-signed TLS cert (hex). */
	caFingerprint?: string;
	/** Test-only: bypass TLS verification for the LAN call. Never in production. */
	insecureSkipLanVerify?: boolean;
}

export interface PairResult {
	state: PairingState;
}

export async function pair(input: PairInput): Promise<PairResult> {
	const nonce = new URL(input.lanUrl).searchParams.get("token");
	if (!nonce) throw new Error(`pair URL missing ?token=: ${input.lanUrl}`);

	const { publicKey, privateKey } = (await webcrypto.subtle.generateKey(
		{ name: "ECDSA", namedCurve: "P-256" },
		true,
		["sign", "verify"],
	)) as CryptoKeyPair;
	const publicJwk = (await webcrypto.subtle.exportKey("jwk", publicKey)) as Record<string, string>;
	const privateJwk = (await webcrypto.subtle.exportKey("jwk", privateKey)) as Record<
		string,
		string
	>;

	const clientKeyPem = jwkToPkcs8Pem(privateJwk);
	const csrPem = await buildCsr(input.deviceLabel, publicJwk, privateKey);

	const body = JSON.stringify({
		nonce,
		csr: csrPem,
		device_label: input.deviceLabel,
	});
	const pairResponse = await httpsPost(input.lanUrl, body, {
		caFingerprint: input.caFingerprint,
		insecureSkipVerify: input.insecureSkipLanVerify,
	});
	if (pairResponse.status !== 200) {
		throw new Error(`pair failed: HTTP ${pairResponse.status}: ${pairResponse.body}`);
	}
	const pairJson = JSON.parse(pairResponse.body) as {
		client_cert: string;
		ca_chain: string[];
		instance_id: string;
		home_label: string;
		home_attestation: string;
		fingerprint: string;
	};

	const enroll = await httpsPost(
		`${input.relayEndpoint.replace(/\/+$/, "")}/enroll/device`,
		JSON.stringify({
			instance_id: pairJson.instance_id,
			client_cert: pairJson.client_cert,
			home_attestation: pairJson.home_attestation,
		}),
		{},
	);
	if (enroll.status !== 200) {
		throw new Error(`/enroll/device failed: HTTP ${enroll.status}: ${enroll.body}`);
	}
	const enrollJson = JSON.parse(enroll.body) as { device_token: string };

	const state: PairingState = {
		instance_id: pairJson.instance_id,
		home_label: pairJson.home_label,
		relay_endpoint: input.relayEndpoint.replace(/\/+$/, ""),
		ca_chain: pairJson.ca_chain,
		client_cert: pairJson.client_cert,
		client_key_pem: clientKeyPem,
		device_token: enrollJson.device_token,
		fingerprint: pairJson.fingerprint,
	};
	return { state };
}

interface HttpsOpts {
	caFingerprint?: string;
	insecureSkipVerify?: boolean;
}

interface HttpResponse {
	status: number;
	body: string;
}

async function httpsPost(url: string, body: string, opts: HttpsOpts): Promise<HttpResponse> {
	const https = await import("node:https");
	const http = await import("node:http");
	const crypto = await import("node:crypto");

	return new Promise((resolve, reject) => {
		const parsed = new URL(url);
		const isHttps = parsed.protocol === "https:";
		const client = isHttps ? https : http;
		const options = {
			method: "POST",
			hostname: parsed.hostname,
			port: parsed.port || (isHttps ? 443 : 80),
			path: parsed.pathname + parsed.search,
			headers: {
				"content-type": "application/json",
				"content-length": Buffer.byteLength(body).toString(),
			},
			...(isHttps
				? {
						rejectUnauthorized: !(opts.caFingerprint !== undefined || opts.insecureSkipVerify),
						checkServerIdentity: opts.caFingerprint
							? (_: string, cert: { raw: Buffer }) => {
									const digest = crypto.createHash("sha256").update(cert.raw).digest("hex");
									if (digest.toLowerCase() !== opts.caFingerprint?.toLowerCase()) {
										return new Error(
											`CA fingerprint mismatch: got ${digest}, pinned ${opts.caFingerprint}`,
										);
									}
									return undefined;
								}
							: undefined,
					}
				: {}),
		};
		const req = client.request(options, (res) => {
			const chunks: Buffer[] = [];
			res.on("data", (c: Buffer) => chunks.push(c));
			res.on("end", () => {
				resolve({
					status: res.statusCode ?? 0,
					body: Buffer.concat(chunks).toString("utf-8"),
				});
			});
		});
		req.on("error", reject);
		req.write(body);
		req.end();
	});
}
