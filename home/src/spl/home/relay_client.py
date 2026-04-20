# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc

"""Listen WS + tunnel WS orchestrator.

On startup:
  1. If no account_token stored, POST /enroll/home to mint one (idempotent).
  2. Open listen WS to spl-relay with the account token.
  3. Loop: wait for {"type":"incoming","tunnel_id":...} control message.
     On each signal, spawn a tunnel task that opens /tunnel/<id>, drives
     pyOpenSSL TLS 1.3 in memory-BIO mode, and pipes each multiplexed
     stream to a local TCP connection on ``target_host:target_port``.
  4. On disconnect, reconnect with exponential backoff (1s → 60s, ±25%).

The link layer is a dumb byte pipe: it does not parse HTTP, WebSocket,
or any other application-layer protocol. That is the blind-by-construction
invariant made structural — every stream is ``socket.read`` / ``socket.write``
and nothing else.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import random
import ssl
import urllib.parse
from dataclasses import dataclass
from typing import Any

import websockets
from websockets.asyncio.client import ClientConnection as _WsConnection
from websockets.exceptions import ConnectionClosed

from .auth import AuthorizedClients
from .ca import LoadedCa
from .config import Config
from .mux import Multiplexer, StreamWriter
from .tcp_pipe import pipe_stream
from .tls_adapter import (
    TlsError,
    build_server_context,
    drive_tls,
    issue_server_cert,
    new_server,
)

log = logging.getLogger("spl.home.relay_client")

_RECONNECT_MIN = 1.0
_RECONNECT_MAX = 60.0


@dataclass
class EnrollResult:
    account_token: str


class RelayClient:
    def __init__(
        self,
        config: Config,
        ca: LoadedCa,
        authorized: AuthorizedClients,
        *,
        target_host: str,
        target_port: int,
    ) -> None:
        self._config = config
        self._ca = ca
        self._authorized = authorized
        self._target_host = target_host
        self._target_port = target_port
        self._running = False
        # Shared TLS context — contains the home's server cert + CA +
        # verify callback that pins on authorized_clients.json.
        server_cert, server_key_pem = issue_server_cert(
            ca,
            common_name=config.tunnel_server_cert_cn,
        )
        self._tls_ctx = build_server_context(
            ca=ca,
            server_cert=server_cert,
            server_key=server_key_pem,
            authorized=authorized,
        )

    async def enroll_if_needed(self) -> None:
        if self._config.account_token:
            return
        endpoint = f"{self._config.relay_endpoint}/enroll/home"
        body = {
            "instance_id": self._config.instance_id,
            "ca_pubkey": self._ca.pubkey_spki_pem,
            "home_label": self._config.home_label,
        }
        log.info("enrolling home with relay at %s", endpoint)
        account_token = await _post_json(endpoint, body)
        token = account_token.get("account_token")
        if not isinstance(token, str) or not token:
            raise RuntimeError("relay returned no account_token")
        self._config.account_token = token

    async def run(self) -> None:
        self._running = True
        delay = _RECONNECT_MIN
        while self._running:
            try:
                await self._run_once()
                delay = _RECONNECT_MIN
            except ConnectionClosed as exc:
                log.warning("listen WS closed: code=%s reason=%s", exc.code, exc.reason)
            except Exception as exc:  # noqa: BLE001
                log.exception("listen loop error: %s", exc)
            if not self._running:
                return
            jitter = delay * 0.25
            wait = delay + random.uniform(-jitter, jitter)  # noqa: S311 — jitter only, not security-sensitive
            log.info("reconnecting in %.1fs", wait)
            await asyncio.sleep(wait)
            delay = min(_RECONNECT_MAX, delay * 2.0)

    async def stop(self) -> None:
        self._running = False

    # --- internals ---

    async def _run_once(self) -> None:
        await self.enroll_if_needed()
        listen_url = self._url_for("/session/listen", token=self._config.account_token)
        headers = _auth_header(self._config.account_token)
        log.info("opening listen WS to %s", _redact(listen_url))
        async with websockets.connect(
            listen_url,
            additional_headers=headers,
            max_size=None,
        ) as ws:
            log.info("listen WS open — waiting for incoming")
            async for message in ws:
                data = _parse_control(message)
                if data is None:
                    continue
                tunnel_id = data.get("tunnel_id")
                if data.get("type") == "incoming" and isinstance(tunnel_id, str):
                    log.info("incoming tunnel_id=%s", tunnel_id)
                    asyncio.create_task(
                        self._handle_tunnel(tunnel_id),
                        name=f"spl-tunnel-{tunnel_id}",
                    )

    async def _handle_tunnel(self, tunnel_id: str) -> None:
        assert self._config.account_token is not None
        url = self._url_for(f"/tunnel/{tunnel_id}", token=self._config.account_token)
        headers = _auth_header(self._config.account_token)
        try:
            async with websockets.connect(
                url,
                additional_headers=headers,
                max_size=None,
            ) as ws:
                await self._pump_tunnel(ws, tunnel_id)
        except ConnectionClosed as exc:
            log.info("tunnel %s closed: code=%s reason=%s", tunnel_id, exc.code, exc.reason)
        except TlsError as exc:
            log.info("tunnel %s TLS rejected: %s", tunnel_id, exc)
        except Exception as exc:  # noqa: BLE001
            log.exception("tunnel %s error: %s", tunnel_id, exc)

    async def _pump_tunnel(self, ws: _WsConnection, tunnel_id: str) -> None:
        tls = new_server(self._tls_ctx)
        send_queue: asyncio.Queue[bytes] = asyncio.Queue()

        async def send_frame(frame: bytes) -> None:
            send_queue.put_nowait(frame)

        async def handle_stream(
            reader: asyncio.StreamReader,
            writer: StreamWriter,
        ) -> None:
            meta = await pipe_stream(
                reader,
                writer,
                target_host=self._target_host,
                target_port=self._target_port,
                tunnel_id=tunnel_id,
            )
            log.debug(
                "tunnel %s stream %s: in=%s out=%s (%s)",
                meta.tunnel_id,
                meta.stream_id,
                meta.bytes_in,
                meta.bytes_out,
                meta.closed_reason,
            )

        mux = Multiplexer(send_frame, handle_stream, is_listener=True)

        async def ws_reader() -> None:
            try:
                async for frame in ws:
                    inbound = frame if isinstance(frame, bytes) else frame.encode("utf-8")
                    outbound, plaintext = drive_tls(tls, inbound=inbound)
                    if outbound:
                        await ws.send(outbound)
                    if plaintext:
                        await mux.feed(plaintext)
                    # Drain any app-side writes that got queued while we
                    # were driving the TLS pump.
                    await _drain_send_queue(tls, ws, send_queue)
            except ConnectionClosed:
                return

        async def app_writer() -> None:
            try:
                while True:
                    data = await send_queue.get()
                    outbound = _encrypt(tls, data)
                    if outbound:
                        await ws.send(outbound)
            except ConnectionClosed:
                return

        reader_task = asyncio.create_task(ws_reader(), name=f"ws-reader-{tunnel_id}")
        writer_task = asyncio.create_task(app_writer(), name=f"app-writer-{tunnel_id}")
        try:
            await reader_task
        finally:
            writer_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await writer_task
            await mux.close()

    def _url_for(self, path: str, *, token: str | None = None) -> str:
        base = _to_ws(self._config.relay_endpoint) + path
        q = {"instance": self._config.instance_id}
        if token:
            q["token"] = token
        return base + "?" + urllib.parse.urlencode(q)


def _encrypt(tls: Any, plaintext: bytes) -> bytes:
    outbound, _ = drive_tls(tls, inbound=b"", plaintext_out=plaintext)
    return outbound


async def _drain_send_queue(
    tls: Any,
    ws: _WsConnection,
    queue: asyncio.Queue[bytes],
) -> None:
    drained: list[bytes] = []
    while not queue.empty():
        try:
            drained.append(queue.get_nowait())
        except asyncio.QueueEmpty:
            break
    if not drained:
        return
    for chunk in drained:
        outbound = _encrypt(tls, chunk)
        if outbound:
            await ws.send(outbound)


async def _post_json(url: str, body: dict[str, Any]) -> dict[str, Any]:
    # Lazily import aiohttp-free — use urllib in a thread for simplicity.
    import urllib.request

    def sync() -> dict[str, Any]:
        data = json.dumps(body).encode("utf-8")
        # URL comes from config (sol pbc relay endpoint); scheme is http/https only.
        # Cloudflare's edge rejects UA-less requests with 403 on some zones;
        # send a stable client identifier so staging + prod both accept us.
        req = urllib.request.Request(  # noqa: S310 — URL scheme validated below
            url,
            data=data,
            headers={
                "content-type": "application/json",
                "user-agent": "spl.home/0.1",
            },
            method="POST",
        )
        ctx = ssl.create_default_context()
        if url.startswith("http://"):
            ctx = None  # type: ignore[assignment]  # local Miniflare dev
        elif not url.startswith("https://"):
            raise ValueError(f"unsupported url scheme: {url!r}")
        with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:  # noqa: S310
            payload = resp.read()
            parsed: dict[str, Any] = json.loads(payload)
            return parsed

    return await asyncio.to_thread(sync)


def _to_ws(endpoint: str) -> str:
    if endpoint.startswith("http://"):
        return "ws://" + endpoint[len("http://") :]
    if endpoint.startswith("https://"):
        return "wss://" + endpoint[len("https://") :]
    return endpoint


def _parse_control(message: str | bytes) -> dict[str, Any] | None:
    if isinstance(message, bytes):
        try:
            text = message.decode("utf-8")
        except UnicodeDecodeError:
            return None
    else:
        text = message
    try:
        out = json.loads(text)
    except json.JSONDecodeError:
        return None
    return out if isinstance(out, dict) else None


def _auth_header(token: str | None) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"} if token else {}


def _redact(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    q = urllib.parse.parse_qs(parsed.query)
    if "token" in q:
        q["token"] = ["<redacted>"]
    new_query = urllib.parse.urlencode(q, doseq=True)
    return urllib.parse.urlunparse(parsed._replace(query=new_query))
