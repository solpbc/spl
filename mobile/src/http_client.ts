// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc

// Minimal HTTP/1.1 client over a mux stream. Writes a request, reads the
// response head + body (Content-Length or Transfer-Encoding: chunked).
// Only what's needed to hit the test app's /echo, /stream, /upload.

import type { StreamHandle } from "./mux";

export interface HttpRequest {
	method: string;
	path: string;
	headers?: Record<string, string>;
	body?: Uint8Array | string;
}

export interface HttpResponse {
	status: number;
	reason: string;
	headers: Record<string, string>;
	body: Uint8Array;
}

export async function httpRequest(
	mux: { openStream: (initial?: Uint8Array) => Promise<StreamHandle> },
	request: HttpRequest,
): Promise<HttpResponse> {
	const bodyBytes =
		typeof request.body === "string"
			? new TextEncoder().encode(request.body)
			: (request.body ?? new Uint8Array(0));

	const headers: Record<string, string> = { host: "spl.local", ...request.headers };
	if (bodyBytes.byteLength > 0 && !headers["content-length"]) {
		headers["content-length"] = String(bodyBytes.byteLength);
	}
	if (bodyBytes.byteLength === 0 && request.method !== "GET" && !headers["content-length"]) {
		headers["content-length"] = "0";
	}
	if (!headers["content-length"] && request.method === "GET") {
		headers["content-length"] = "0";
	}

	const head = `${request.method} ${request.path} HTTP/1.1\r\n${Object.entries(headers)
		.map(([k, v]) => `${k}: ${v}\r\n`)
		.join("")}\r\n`;
	const headBytes = new TextEncoder().encode(head);

	const reqBytes = new Uint8Array(headBytes.byteLength + bodyBytes.byteLength);
	reqBytes.set(headBytes, 0);
	reqBytes.set(bodyBytes, headBytes.byteLength);

	const stream = await mux.openStream(reqBytes);
	await stream.close();

	const all = await stream.readAll();
	return parseResponse(all);
}

function parseResponse(all: Uint8Array): HttpResponse {
	const eoh = findDoubleCrlf(all);
	if (eoh < 0) {
		throw new Error("response missing header terminator");
	}
	const headText = new TextDecoder().decode(all.slice(0, eoh));
	const bodyRaw = all.slice(eoh + 4);

	const [statusLine, ...headerLines] = headText.split("\r\n");
	const m = statusLine.match(/^HTTP\/\d\.\d\s+(\d{3})\s*(.*)$/);
	if (!m) throw new Error(`bad status line: ${statusLine}`);
	const status = Number.parseInt(m[1], 10);
	const reason = m[2] ?? "";
	const headers: Record<string, string> = {};
	for (const line of headerLines) {
		if (!line) continue;
		const idx = line.indexOf(":");
		if (idx < 0) continue;
		headers[line.slice(0, idx).trim().toLowerCase()] = line.slice(idx + 1).trim();
	}

	let body: Uint8Array;
	if (headers["transfer-encoding"] === "chunked") {
		body = dechunk(bodyRaw);
	} else {
		const len = Number.parseInt(headers["content-length"] ?? "0", 10);
		body = bodyRaw.slice(0, Number.isFinite(len) ? len : bodyRaw.byteLength);
	}
	return { status, reason, headers, body };
}

function findDoubleCrlf(bytes: Uint8Array): number {
	for (let i = 0; i + 3 < bytes.byteLength; i++) {
		if (
			bytes[i] === 0x0d &&
			bytes[i + 1] === 0x0a &&
			bytes[i + 2] === 0x0d &&
			bytes[i + 3] === 0x0a
		) {
			return i;
		}
	}
	return -1;
}

function dechunk(raw: Uint8Array): Uint8Array {
	const chunks: Uint8Array[] = [];
	let i = 0;
	while (i < raw.byteLength) {
		const lineEnd = findCrlf(raw, i);
		if (lineEnd < 0) break;
		const sizeStr = new TextDecoder().decode(raw.slice(i, lineEnd)).trim();
		const size = Number.parseInt(sizeStr.split(";")[0], 16);
		i = lineEnd + 2;
		if (!Number.isFinite(size) || size <= 0) break;
		chunks.push(raw.slice(i, i + size));
		i += size + 2; // skip chunk bytes and trailing CRLF
	}
	let total = 0;
	for (const c of chunks) total += c.byteLength;
	const out = new Uint8Array(total);
	let off = 0;
	for (const c of chunks) {
		out.set(c, off);
		off += c.byteLength;
	}
	return out;
}

function findCrlf(bytes: Uint8Array, start: number): number {
	for (let i = start; i + 1 < bytes.byteLength; i++) {
		if (bytes[i] === 0x0d && bytes[i + 1] === 0x0a) return i;
	}
	return -1;
}
