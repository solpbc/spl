#!/usr/bin/env bun
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

// spl-mobile CLI.
//
//   spl-mobile pair <lan-url> <device-label> [--relay <endpoint>] [--pin <sha256-hex>] [--state <path>]
//   spl-mobile dial [--state <path>]
//   spl-mobile test [--state <path>] [--n <int>]
//
// The MVP equivalent of the iOS app — a command-line harness that
// exercises the home's pair flow, dials through spl-relay, and runs
// the test scenarios.

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

import { dial } from "./dial";
import { httpRequest } from "./http_client";
import { loadPairing, pair, savePairing } from "./pair";

const DEFAULT_STATE = join(homedir(), ".spl", "mobile", "state.json");
const DEFAULT_RELAY = "https://spl.solpbc.org";

async function main(argv: string[]): Promise<number> {
	const [cmd, ...rest] = argv;
	switch (cmd) {
		case "pair":
			return await cmdPair(rest);
		case "dial":
			return await cmdDial(rest);
		case "test":
			return await cmdTest(rest);
		case "help":
		case "--help":
		case "-h":
		case undefined:
			printHelp();
			return cmd === undefined ? 2 : 0;
		default:
			console.error(`unknown command: ${cmd}`);
			printHelp();
			return 2;
	}
}

function printHelp(): void {
	console.log(
		[
			"spl-mobile — example mobile CLI for sol private link",
			"",
			"usage:",
			"  spl-mobile pair <lan-url> <device-label> [options]",
			"  spl-mobile dial [options]",
			"  spl-mobile test [options]",
			"",
			"options:",
			"  --state <path>    pairing-state file (default: ~/.spl/mobile/state.json)",
			"  --relay <url>     spl-relay endpoint (default: https://spl.solpbc.org)",
			"  --pin <sha256>    home TLS cert fingerprint (hex) for LAN pair",
			"  --insecure        test-only: skip LAN TLS verification (never in prod)",
			"  --n <int>         test: request size / count (default 16)",
			"",
		].join("\n"),
	);
}

interface Options {
	state: string;
	relay: string;
	pin?: string;
	insecure?: boolean;
	n?: number;
}

function parseOptions(args: string[]): { positional: string[]; opts: Options } {
	const positional: string[] = [];
	const opts: Options = { state: DEFAULT_STATE, relay: DEFAULT_RELAY };
	for (let i = 0; i < args.length; i++) {
		const arg = args[i];
		if (arg === "--state") opts.state = expect(args, ++i);
		else if (arg === "--relay") opts.relay = expect(args, ++i);
		else if (arg === "--pin") opts.pin = expect(args, ++i);
		else if (arg === "--insecure") opts.insecure = true;
		else if (arg === "--n") opts.n = Number.parseInt(expect(args, ++i), 10);
		else positional.push(arg);
	}
	return { positional, opts };
}

function expect(args: string[], i: number): string {
	if (i >= args.length) throw new Error(`flag ${args[i - 1]} requires a value`);
	return args[i];
}

async function cmdPair(args: string[]): Promise<number> {
	const { positional, opts } = parseOptions(args);
	const [lanUrl, deviceLabel] = positional;
	if (!lanUrl || !deviceLabel) {
		console.error("usage: spl-mobile pair <lan-url> <device-label>");
		return 2;
	}
	console.log(`pairing with ${lanUrl} as "${deviceLabel}"`);
	const { state } = await pair({
		lanUrl,
		deviceLabel,
		relayEndpoint: opts.relay,
		caFingerprint: opts.pin,
		insecureSkipLanVerify: opts.insecure,
	});
	await savePairing(opts.state, state);
	console.log(`Paired with ${state.home_label} (instance ${state.instance_id}).`);
	console.log(`  fingerprint: ${state.fingerprint}`);
	console.log(`  state saved to: ${opts.state}`);
	return 0;
}

async function cmdDial(args: string[]): Promise<number> {
	const { opts } = parseOptions(args);
	const state = await loadPairing(opts.state);
	console.log(`dialing ${state.home_label} through ${state.relay_endpoint}`);
	const session = await dial({ state });
	console.log("tunnel established. close with ctrl-c.");
	await session.closed;
	return 0;
}

async function cmdTest(args: string[]): Promise<number> {
	const { opts } = parseOptions(args);
	const n = opts.n ?? 16;
	const state = await loadPairing(opts.state);
	const session = await dial({ state });

	try {
		// 1. /echo
		const echo = await httpRequest(session.mux, {
			method: "GET",
			path: `/echo?n=${n}`,
		});
		if (echo.status !== 200) {
			throw new Error(`/echo returned ${echo.status}`);
		}
		if (echo.body.byteLength !== n) {
			throw new Error(`/echo body length ${echo.body.byteLength} != ${n}`);
		}
		if (!bytesMatchDeterministic(echo.body, n)) {
			throw new Error("/echo body mismatch at byte-level");
		}
		console.log(`✓ /echo n=${n} OK`);

		// 2. /stream
		const sse = await httpRequest(session.mux, {
			method: "GET",
			path: "/stream?n=5&ms=0",
		});
		if (sse.status !== 200) throw new Error(`/stream returned ${sse.status}`);
		const text = new TextDecoder().decode(sse.body);
		const events = text.split("\n\n").filter((s) => s.startsWith("data: "));
		if (events.length !== 5) {
			throw new Error(`/stream expected 5 events, got ${events.length}`);
		}
		console.log("✓ /stream 5 events OK");

		// 3. /upload
		const payload = new Uint8Array(Math.max(1, n) * 16);
		for (let i = 0; i < payload.byteLength; i++) payload[i] = i & 0xff;
		const expectedDigest = createHash("sha256").update(payload).digest("hex");
		const upload = await httpRequest(session.mux, {
			method: "POST",
			path: "/upload",
			headers: { "content-type": "application/octet-stream" },
			body: payload,
		});
		if (upload.status !== 200) throw new Error(`/upload returned ${upload.status}`);
		const parsed = JSON.parse(new TextDecoder().decode(upload.body)) as {
			sha256: string;
			length: number;
		};
		if (parsed.sha256 !== expectedDigest) {
			throw new Error(`/upload sha256 mismatch: got ${parsed.sha256}, expected ${expectedDigest}`);
		}
		if (parsed.length !== payload.byteLength) {
			throw new Error(
				`/upload length mismatch: got ${parsed.length}, expected ${payload.byteLength}`,
			);
		}
		console.log(`✓ /upload ${payload.byteLength} bytes, sha256 matches`);

		// 4. Concurrent multiplex: 10 /echo in parallel, all must succeed.
		const concurrent = 10;
		const results = await Promise.all(
			Array.from({ length: concurrent }, (_, i) =>
				httpRequest(session.mux, {
					method: "GET",
					path: `/echo?n=${64 * (i + 1)}`,
				}),
			),
		);
		for (const [i, r] of results.entries()) {
			if (r.status !== 200) throw new Error(`concurrent[${i}] status ${r.status}`);
			if (r.body.byteLength !== 64 * (i + 1)) {
				throw new Error(`concurrent[${i}] wrong length ${r.body.byteLength}`);
			}
		}
		console.log(`✓ ${concurrent} concurrent multiplexed streams OK`);

		return 0;
	} finally {
		await session.close();
	}
}

function bytesMatchDeterministic(body: Uint8Array, n: number): boolean {
	for (let i = 0; i < n; i++) {
		if (body[i] !== i % 256) return false;
	}
	return true;
}

// Unused but imported for the side-effect of ensuring deps resolve cleanly.
void readFileSync;

const code = await main(process.argv.slice(2));
process.exit(code);
