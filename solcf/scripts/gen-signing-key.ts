// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

// Self-host generator for the spl JWT signing key.
//
// Run via: `npm run gen-key` (or `npm run gen-key -- --out <path>`).
// Generates an Ed25519 keypair in JWK format, writes it to disk with
// 0600 perms, and prints the exact `wrangler secret put` commands the
// operator must run next.
//
// This is the root of trust for token signing. See ../docs/signing-keys.md
// for the full lifecycle (rotation, compromise response, layer separation).

import { mkdir, writeFile, chmod } from "node:fs/promises";
import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { homedir } from "node:os";
import { argv, exit, stdout } from "node:process";
import { webcrypto as crypto } from "node:crypto";

interface PublicJwk {
	kty: "OKP";
	crv: "Ed25519";
	kid: string;
	x: string;
	alg: "EdDSA";
	use: "sig";
}

interface PrivateJwk extends PublicJwk {
	d: string;
}

interface KeypairFile {
	kid: string;
	created_at: string;
	publicKey: PublicJwk;
	privateKey: PrivateJwk;
}

function parseArgs(args: string[]): { out: string; force: boolean } {
	let out = `${homedir()}/.spl/signing-keypair.json`;
	let force = false;
	for (let i = 0; i < args.length; i++) {
		const arg = args[i];
		if (arg === "--out" || arg === "-o") {
			const next = args[i + 1];
			if (!next) {
				console.error("error: --out requires a path argument");
				exit(2);
			}
			out = next;
			i++;
		} else if (arg === "--force" || arg === "-f") {
			force = true;
		} else if (arg === "--help" || arg === "-h") {
			printHelp();
			exit(0);
		} else {
			console.error(`error: unknown argument: ${arg}`);
			printHelp();
			exit(2);
		}
	}
	return { out: resolve(out), force };
}

function printHelp(): void {
	stdout.write(
		[
			"gen-signing-key — generate an Ed25519 JWK keypair for solcf JWT signing",
			"",
			"usage:",
			"  npm run gen-key                        write to ~/.spl/signing-keypair.json",
			"  npm run gen-key -- --out <path>        write to a custom path",
			"  npm run gen-key -- --force             overwrite an existing file",
			"",
			"output:",
			"  A JSON file with { kid, created_at, publicKey, privateKey } in JWK format.",
			"  File mode is 0600. The private key is the root of trust — protect it.",
			"",
			"see docs/signing-keys.md for rotation, compromise response, and the layer",
			"separation between this JWT signing key (Ed25519) and the mTLS layer (ECDSA-P256).",
			"",
		].join("\n"),
	);
}

// UUIDv7: 48-bit unix-millis timestamp, 4-bit version=7, 12 bits random,
// 2-bit variant=10, 62 bits random. crypto.randomUUID() is v4 — implement v7 inline.
function uuidv7(): string {
	const bytes = new Uint8Array(16);
	crypto.getRandomValues(bytes);

	const ms = BigInt(Date.now());
	bytes[0] = Number((ms >> 40n) & 0xffn);
	bytes[1] = Number((ms >> 32n) & 0xffn);
	bytes[2] = Number((ms >> 24n) & 0xffn);
	bytes[3] = Number((ms >> 16n) & 0xffn);
	bytes[4] = Number((ms >> 8n) & 0xffn);
	bytes[5] = Number(ms & 0xffn);

	bytes[6] = (bytes[6] & 0x0f) | 0x70; // version 7
	bytes[8] = (bytes[8] & 0x3f) | 0x80; // variant 10

	const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
	return [
		hex.slice(0, 8),
		hex.slice(8, 12),
		hex.slice(12, 16),
		hex.slice(16, 20),
		hex.slice(20, 32),
	].join("-");
}

async function generateKeypair(): Promise<{ publicJwk: PublicJwk; privateJwk: PrivateJwk; kid: string }> {
	const kid = uuidv7();

	const keypair = await crypto.subtle.generateKey(
		{ name: "Ed25519" },
		true, // extractable — we need both halves to write the JWK
		["sign", "verify"],
	);

	const pubExport = (await crypto.subtle.exportKey("jwk", keypair.publicKey)) as {
		kty: string;
		crv: string;
		x: string;
	};
	const privExport = (await crypto.subtle.exportKey("jwk", keypair.privateKey)) as {
		kty: string;
		crv: string;
		x: string;
		d: string;
	};

	if (pubExport.kty !== "OKP" || pubExport.crv !== "Ed25519") {
		throw new Error(
			`unexpected JWK shape from Web Crypto: kty=${pubExport.kty} crv=${pubExport.crv}`,
		);
	}

	const publicJwk: PublicJwk = {
		kty: "OKP",
		crv: "Ed25519",
		kid,
		x: pubExport.x,
		alg: "EdDSA",
		use: "sig",
	};
	const privateJwk: PrivateJwk = { ...publicJwk, d: privExport.d };
	return { publicJwk, privateJwk, kid };
}

function jwksEnvelope(publicJwk: PublicJwk): { keys: PublicJwk[] } {
	return { keys: [publicJwk] };
}

async function main(): Promise<void> {
	const { out, force } = parseArgs(argv.slice(2));

	if (existsSync(out) && !force) {
		console.error(
			`error: ${out} already exists. Pass --force to overwrite (this is destructive — back up the existing key first).`,
		);
		exit(1);
	}

	const { publicJwk, privateJwk, kid } = await generateKeypair();

	const file: KeypairFile = {
		kid,
		created_at: new Date().toISOString(),
		publicKey: publicJwk,
		privateKey: privateJwk,
	};

	await mkdir(dirname(out), { recursive: true });
	await writeFile(out, `${JSON.stringify(file, null, 2)}\n`, { mode: 0o600 });
	await chmod(out, 0o600); // belt-and-suspenders for environments where mode in writeFile isn't honored

	const signingJwkPayload = JSON.stringify(privateJwk);
	const jwksPayload = JSON.stringify(jwksEnvelope(publicJwk));

	stdout.write(
		[
			"",
			`Wrote keypair to ${out}`,
			`  kid: ${kid}`,
			`  alg: EdDSA (Ed25519)`,
			"",
			"⚠  This file is the root of trust for your tunnel.",
			"   Lose it and every paired device must re-enroll.",
			"   Back it up offline (paper, hardware token, encrypted USB — never a cloud drive).",
			"",
			"Provision the secrets to your solcf Worker. Make sure you are using the GLOBAL",
			"wrangler binary (npx wrangler loses the OAuth session and breaks secret put).",
			"",
			"For production:",
			"",
			`  echo '${signingJwkPayload}' | wrangler secret put SIGNING_JWK --env production`,
			`  echo '${jwksPayload}' | wrangler secret put JWKS_PUBLIC --env production`,
			"",
			"For staging (use a separate keypair — re-run with --out):",
			"",
			`  echo '${signingJwkPayload}' | wrangler secret put SIGNING_JWK --env staging`,
			`  echo '${jwksPayload}' | wrangler secret put JWKS_PUBLIC --env staging`,
			"",
			"After provisioning, your solcf will serve the public JWKS at",
			"  https://<your-solcf-host>/.well-known/jwks.json",
			"",
			"Rotation: see docs/signing-keys.md. Default cadence is 12 months with a 30-day overlap.",
			"",
		].join("\n"),
	);
}

main().catch((err) => {
	console.error("error:", err instanceof Error ? err.message : err);
	exit(1);
});
