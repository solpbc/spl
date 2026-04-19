# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc

"""Multiplexer — open/data/close and echo handler on multiple concurrent streams."""

from __future__ import annotations

import asyncio

import pytest

from spl.home.framing import (
    FLAG_CLOSE,
    FLAG_DATA,
    FLAG_OPEN,
    FrameDecoder,
    build_close,
    build_data,
    build_open,
)
from spl.home.mux import Multiplexer


@pytest.mark.asyncio
async def test_open_with_initial_payload_hits_handler() -> None:
    handler_seen: dict[int, bytes] = {}

    async def handler(reader: asyncio.StreamReader, writer) -> None:  # type: ignore[no-untyped-def]
        data = await reader.readuntil(b"\n")
        handler_seen[1] = data
        await writer.write(b"ack\n")
        await writer.close()

    sent: list[bytes] = []

    async def send(data: bytes) -> None:
        sent.append(data)

    mux = Multiplexer(send, handler, is_listener=True)
    # Dialer opens odd stream 1 with initial bytes then closes.
    open_frame = build_open(1, b"hello\n")
    close_frame = build_close(1)
    await mux.feed(open_frame.encode() + close_frame.encode())
    # Give the handler task a tick to complete.
    for _ in range(20):
        await asyncio.sleep(0.005)
        if handler_seen.get(1):
            break
    assert handler_seen.get(1) == b"hello\n"

    # Sent frames: a DATA with "ack\n" and a CLOSE on the same stream.
    decoder = FrameDecoder()
    for chunk in sent:
        decoder.feed(chunk)
    frames = decoder.drain()
    flags = [f.flags for f in frames]
    assert any(f & FLAG_DATA for f in flags)
    assert any(f & FLAG_CLOSE for f in flags)
    data_payload = b"".join(f.payload for f in frames if f.flags & FLAG_DATA)
    assert data_payload == b"ack\n"


@pytest.mark.asyncio
async def test_wrong_parity_stream_id_gets_reset() -> None:
    sent: list[bytes] = []

    async def send(data: bytes) -> None:
        sent.append(data)

    async def handler(*_: object) -> None:
        pytest.fail("handler should not be reached on protocol-error parity")

    mux = Multiplexer(send, handler, is_listener=True)
    # As the listener, we expect peer (dialer) to use odd stream IDs. 2 is
    # even → protocol error → RESET.
    await mux.feed(build_open(2).encode())
    decoder = FrameDecoder()
    for chunk in sent:
        decoder.feed(chunk)
    frames = decoder.drain()
    assert any(f.stream_id == 2 and f.flags & 0x08 for f in frames)  # RESET


@pytest.mark.asyncio
async def test_unknown_stream_data_gets_reset() -> None:
    sent: list[bytes] = []

    async def send(data: bytes) -> None:
        sent.append(data)

    async def handler(*_: object) -> None:
        return

    mux = Multiplexer(send, handler, is_listener=True)
    # DATA on a stream that was never OPENed → RESET.
    await mux.feed(build_data(99, b"x").encode())
    decoder = FrameDecoder()
    for chunk in sent:
        decoder.feed(chunk)
    frames = decoder.drain()
    # Stream 99 is odd — parity is OK — but the stream isn't open. Expect RESET.
    assert any(f.stream_id == 99 and f.flags & 0x08 for f in frames)


@pytest.mark.asyncio
async def test_concurrent_streams_do_not_interfere() -> None:
    """Open 5 streams simultaneously, each echoes; responses go to each peer."""
    responses: dict[int, bytes] = {}

    async def handler(reader: asyncio.StreamReader, writer) -> None:  # type: ignore[no-untyped-def]
        payload = await reader.readuntil(b"\n")
        await writer.write(payload)
        await writer.close()

    sent: list[bytes] = []

    async def send(data: bytes) -> None:
        sent.append(data)

    mux = Multiplexer(send, handler, is_listener=True)
    # Open 5 odd streams with payloads.
    bulk = bytearray()
    for sid in (1, 3, 5, 7, 9):
        bulk.extend(build_open(sid, f"stream-{sid}\n".encode()).encode())
        bulk.extend(build_close(sid).encode())
    await mux.feed(bytes(bulk))
    for _ in range(50):
        await asyncio.sleep(0.005)
        decoder = FrameDecoder()
        for chunk in sent:
            decoder.feed(chunk)
        frames = decoder.drain()
        for f in frames:
            if f.flags & FLAG_DATA:
                responses.setdefault(f.stream_id, b"")
                responses[f.stream_id] += f.payload
        if all(sid in responses for sid in (1, 3, 5, 7, 9)):
            break
    for sid in (1, 3, 5, 7, 9):
        assert responses.get(sid) == f"stream-{sid}\n".encode()


@pytest.mark.asyncio
async def test_validates_open_reopen_is_protocol_error() -> None:
    sent: list[bytes] = []

    async def send(data: bytes) -> None:
        sent.append(data)

    async def handler(reader: asyncio.StreamReader, writer) -> None:  # type: ignore[no-untyped-def]
        # Block forever so the stream stays open.
        await asyncio.sleep(3600)

    mux = Multiplexer(send, handler, is_listener=True)
    await mux.feed(build_open(1).encode())
    await asyncio.sleep(0.01)
    # Reopen of an already-open stream is a protocol violation.
    await mux.feed(build_open(1).encode())
    decoder = FrameDecoder()
    for chunk in sent:
        decoder.feed(chunk)
    frames = decoder.drain()
    assert any(f.stream_id == 1 and f.flags & 0x08 for f in frames)
    await mux.close()


_ = FLAG_OPEN  # keep import for readability
