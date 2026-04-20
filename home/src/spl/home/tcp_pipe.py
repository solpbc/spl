# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc

"""Per-stream TCP byte pipe.

For each tunnel stream the relay client hands us a mux ``StreamReader`` /
``StreamWriter`` pair. This module opens a plain TCP connection to the
local home-app port and pumps bytes bidirectionally — no HTTP parsing,
no protocol introspection. The tunnel layer sits *below* HTTP.

Privacy invariant: NO payload bytes appear in logs. Only rendezvous
metadata (tunnel_id, stream_id, direction, byte counts) is eligible for
logging. That invariant becomes structural here: the pipe reads bytes
and writes bytes, and that is the full extent of its interaction with
stream contents.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .mux import StreamWriter as MuxStreamWriter

log = logging.getLogger("spl.home.tcp_pipe")

_CHUNK = 64 * 1024


@dataclass
class PipeMetadata:
    """Per-stream rendezvous metadata — safe to log (no payload)."""

    tunnel_id: str | None
    stream_id: int | None
    bytes_in: int = 0  # tunnel → TCP
    bytes_out: int = 0  # TCP → tunnel
    closed_reason: str | None = None


async def pipe_stream(
    reader: asyncio.StreamReader,
    writer: MuxStreamWriter,
    *,
    target_host: str,
    target_port: int,
    tunnel_id: str | None = None,
    stream_id: int | None = None,
) -> PipeMetadata:
    """Pipe one tunnel stream to a local TCP port and back.

    Returns metadata for the debug log. Never raises to the caller on
    peer-caused errors — closes the tunnel stream (CLOSE on EOF, RESET on
    socket error) and returns.
    """
    meta = PipeMetadata(tunnel_id=tunnel_id, stream_id=stream_id)
    try:
        tcp_reader, tcp_writer = await asyncio.open_connection(target_host, target_port)
    except (ConnectionRefusedError, OSError) as exc:
        log.debug("tunnel %s stream %s: TCP connect refused: %s", tunnel_id, stream_id, exc)
        meta.closed_reason = "refused"
        from .framing import RESET_INTERNAL_ERROR

        with contextlib.suppress(Exception):
            await writer.reset(RESET_INTERNAL_ERROR)
        return meta

    async def tunnel_to_tcp() -> None:
        try:
            while True:
                chunk = await reader.read(_CHUNK)
                if not chunk:
                    # Tunnel peer half-closed — send FIN to TCP upstream.
                    with contextlib.suppress(OSError, AttributeError):
                        tcp_writer.write_eof()
                    return
                tcp_writer.write(chunk)
                await tcp_writer.drain()
                meta.bytes_in += len(chunk)
        except (ConnectionError, OSError) as exc:
            log.debug("tunnel %s stream %s: tunnel→tcp error: %s", tunnel_id, stream_id, exc)
            raise

    async def tcp_to_tunnel() -> None:
        try:
            while True:
                chunk = await tcp_reader.read(_CHUNK)
                if not chunk:
                    # TCP peer closed — signal tunnel CLOSE.
                    await writer.close()
                    return
                await writer.write(chunk)
                meta.bytes_out += len(chunk)
        except (ConnectionError, OSError) as exc:
            log.debug("tunnel %s stream %s: tcp→tunnel error: %s", tunnel_id, stream_id, exc)
            raise

    t_in = asyncio.create_task(tunnel_to_tcp(), name=f"pipe-in-{stream_id}")
    t_out = asyncio.create_task(tcp_to_tunnel(), name=f"pipe-out-{stream_id}")
    try:
        done, pending = await asyncio.wait({t_in, t_out}, return_when=asyncio.FIRST_EXCEPTION)
        # If either side errored, RESET the tunnel stream. Otherwise it's a
        # clean half-close completing the pair.
        errored = any(t.exception() for t in done)
        if errored:
            meta.closed_reason = "error"
            from .framing import RESET_INTERNAL_ERROR

            with contextlib.suppress(Exception):
                await writer.reset(RESET_INTERNAL_ERROR)
        else:
            meta.closed_reason = meta.closed_reason or "eof"
        for task in pending:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task
    finally:
        with contextlib.suppress(Exception):
            tcp_writer.close()
            await tcp_writer.wait_closed()
    return meta
