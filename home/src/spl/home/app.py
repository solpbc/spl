# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc

"""Minimal test HTTP app served inside the tunnel.

Endpoints — all one-shot request/response per stream, no Keep-Alive needed:

  GET  /echo?n=<int>              returns n bytes of deterministic content
  GET  /stream?n=<int>&ms=<int>   SSE-shape: n events, ms apart
  POST /upload                    returns SHA-256 of the request body

A real home app (convey) replaces this at integration time. For MVP this
is enough to exercise request/response, SSE, and bulk transfer — the three
patterns the integration tests hit.
"""

from __future__ import annotations

import asyncio
import hashlib
from dataclasses import dataclass
from typing import Any


@dataclass
class Request:
    method: str
    path: str
    query: dict[str, str]
    headers: dict[str, str]
    body: bytes

    @property
    def content_length(self) -> int:
        try:
            return int(self.headers.get("content-length", "0"))
        except ValueError:
            return 0


async def read_request(
    reader: asyncio.StreamReader, *, max_body: int = 64 * 1024 * 1024
) -> Request:
    """Parse an HTTP/1.1 request from a stream reader. Returns the full Request.

    Expects requests to end after the body — no Keep-Alive / pipelining.
    Callers should close the stream after responding.
    """
    raw_line = await reader.readline()
    line = raw_line.decode("latin-1").rstrip("\r\n")
    parts = line.split(" ", 2)
    if len(parts) != 3:
        raise ValueError(f"bad request line: {line!r}")
    method, target, _version = parts
    path, _, query_str = target.partition("?")
    query = _parse_query(query_str)
    headers: dict[str, str] = {}
    while True:
        raw = await reader.readline()
        if raw in (b"\r\n", b"\n", b""):
            break
        header_line = raw.decode("latin-1").rstrip("\r\n")
        if ":" not in header_line:
            raise ValueError(f"bad header: {header_line!r}")
        name, _, value = header_line.partition(":")
        headers[name.strip().lower()] = value.strip()
    cl_raw = headers.get("content-length", "0")
    try:
        cl = int(cl_raw)
    except ValueError as exc:
        raise ValueError(f"bad content-length: {cl_raw}") from exc
    if cl < 0 or cl > max_body:
        raise ValueError(f"content-length out of bounds: {cl}")
    body = await reader.readexactly(cl) if cl else b""
    return Request(method=method, path=path, query=query, headers=headers, body=body)


async def handle(request: Request, writer: ResponseWriter) -> None:
    """Route a request to a handler. Writer is a stream-oriented response API."""
    if request.method == "GET" and request.path == "/echo":
        await _echo(request, writer)
    elif request.method == "GET" and request.path == "/stream":
        await _stream(request, writer)
    elif request.method == "POST" and request.path == "/upload":
        await _upload(request, writer)
    else:
        await writer.send_status(404, "not found")
        await writer.send_headers({"content-type": "text/plain", "content-length": "10"})
        await writer.send_body(b"not found\n")


class ResponseWriter:
    """Incremental HTTP/1.1 response writer over a plain byte sink."""

    def __init__(self, send: Any) -> None:
        self._send = send
        self._status_sent = False

    async def send_status(self, code: int, reason: str) -> None:
        if self._status_sent:
            raise RuntimeError("status already sent")
        self._status_sent = True
        await self._send(f"HTTP/1.1 {code} {reason}\r\n".encode("ascii"))

    async def send_headers(self, headers: dict[str, str]) -> None:
        lines = "".join(f"{k}: {v}\r\n" for k, v in headers.items())
        await self._send((lines + "\r\n").encode("latin-1"))

    async def send_body(self, body: bytes) -> None:
        await self._send(body)


# --- handlers ---


async def _echo(request: Request, writer: ResponseWriter) -> None:
    n = _int_query(request.query, "n", 16)
    body = _deterministic_bytes(n)
    await writer.send_status(200, "ok")
    await writer.send_headers(
        {
            "content-type": "application/octet-stream",
            "content-length": str(len(body)),
        },
    )
    await writer.send_body(body)


async def _stream(request: Request, writer: ResponseWriter) -> None:
    n = _int_query(request.query, "n", 5)
    ms = _int_query(request.query, "ms", 100)
    await writer.send_status(200, "ok")
    # Use chunked transfer encoding so the client can see events as they arrive.
    await writer.send_headers(
        {
            "content-type": "text/event-stream",
            "transfer-encoding": "chunked",
            "cache-control": "no-cache",
        },
    )
    for i in range(n):
        event = f"data: event-{i}\n\n".encode()
        chunk = f"{len(event):x}\r\n".encode("ascii") + event + b"\r\n"
        await writer.send_body(chunk)
        if i < n - 1 and ms > 0:
            await asyncio.sleep(ms / 1000.0)
    await writer.send_body(b"0\r\n\r\n")


async def _upload(request: Request, writer: ResponseWriter) -> None:
    digest = hashlib.sha256(request.body).hexdigest()
    body = f'{{"sha256":"{digest}","length":{len(request.body)}}}\n'.encode()
    await writer.send_status(200, "ok")
    await writer.send_headers(
        {
            "content-type": "application/json",
            "content-length": str(len(body)),
        },
    )
    await writer.send_body(body)


def _parse_query(q: str) -> dict[str, str]:
    out: dict[str, str] = {}
    if not q:
        return out
    for pair in q.split("&"):
        if not pair:
            continue
        name, _, value = pair.partition("=")
        out[name] = value
    return out


def _int_query(query: dict[str, str], name: str, default: int) -> int:
    raw = query.get(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _deterministic_bytes(n: int) -> bytes:
    """n bytes of deterministic content. Stable across languages."""
    if n <= 0:
        return b""
    # Repeating 0..255 pattern — easy to verify bytewise on the client.
    full = bytes(range(256))
    q, r = divmod(n, 256)
    return full * q + full[:r]
