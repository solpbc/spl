# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc

"""End-to-end test of the inline HTTP app against the mux writer plumbing."""

from __future__ import annotations

import asyncio
import hashlib
import json

import pytest

from spl.home import app as test_app


class _BufferWriter:
    def __init__(self) -> None:
        self.buf = bytearray()
        self.closed = False

    async def write(self, data: bytes) -> None:
        self.buf.extend(data)

    async def close(self) -> None:
        self.closed = True


async def _drive(request_bytes: bytes) -> bytes:
    reader = asyncio.StreamReader()
    reader.feed_data(request_bytes)
    reader.feed_eof()
    request = await test_app.read_request(reader)
    writer = _BufferWriter()
    response = test_app.ResponseWriter(writer.write)
    await test_app.handle(request, response)
    return bytes(writer.buf)


@pytest.mark.asyncio
async def test_echo_returns_n_deterministic_bytes() -> None:
    resp = await _drive(b"GET /echo?n=128 HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n")
    head, _, body = resp.partition(b"\r\n\r\n")
    assert b"200" in head
    assert b"content-length: 128" in head.lower()
    assert len(body) == 128


@pytest.mark.asyncio
async def test_upload_returns_sha256_of_body() -> None:
    payload = b"the quick brown fox jumps over the lazy dog"
    digest = hashlib.sha256(payload).hexdigest()
    request = (
        b"POST /upload HTTP/1.1\r\n"
        b"Host: x\r\n"
        b"Content-Type: application/octet-stream\r\n"
        b"Content-Length: " + str(len(payload)).encode("ascii") + b"\r\n\r\n" + payload
    )
    resp = await _drive(request)
    _, _, body = resp.partition(b"\r\n\r\n")
    parsed = json.loads(body)
    assert parsed == {"sha256": digest, "length": len(payload)}


@pytest.mark.asyncio
async def test_stream_emits_n_chunked_events() -> None:
    resp = await _drive(
        b"GET /stream?n=3&ms=0 HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n",
    )
    head, _, body = resp.partition(b"\r\n\r\n")
    assert b"transfer-encoding: chunked" in head.lower()
    # Count chunks — each ends with "\r\n"; terminator is "0\r\n\r\n".
    events = [line for line in body.split(b"data: ") if line.startswith(b"event-")]
    assert len(events) == 3
    assert body.endswith(b"0\r\n\r\n")


@pytest.mark.asyncio
async def test_unknown_route_is_404() -> None:
    resp = await _drive(b"GET /unknown HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n")
    head, _, _ = resp.partition(b"\r\n\r\n")
    assert b"404" in head
