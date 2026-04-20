# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc

"""Minimal test HTTP server served on a loopback port inside the tunnel process.

The spl.home relay client opens a plain TCP connection to this server for
every tunnel stream and pipes bytes bidirectionally. The link layer itself
never parses HTTP — this server does, via Python's stdlib
``http.server.ThreadingHTTPServer``. That keeps the tunnel "dumb byte pipe"
shape honest: the reference implementation demonstrates the same pattern a
real home app (convey, etc.) uses.

Endpoints — all one-shot request/response per stream, no Keep-Alive needed:

  GET  /echo?n=<int>              returns n bytes of deterministic content
  GET  /stream?n=<int>&ms=<int>   SSE-shape: n events, ms apart (chunked)
  POST /upload                    returns SHA-256 of the request body
"""

from __future__ import annotations

import hashlib
import logging
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

log = logging.getLogger("spl.home.app")


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:
        log.debug(
            "test-app %s:%s %s", self.client_address[0], self.client_address[1], format % args
        )

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(parsed.query)
        if parsed.path == "/echo":
            self._echo(query)
        elif parsed.path == "/stream":
            self._stream(query)
        else:
            self._not_found()

    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/upload":
            self._upload()
        else:
            self._not_found()

    def _echo(self, query: dict[str, list[str]]) -> None:
        n = _int_query(query, "n", 16)
        body = _deterministic_bytes(n)
        self.send_response(200)
        self.send_header("content-type", "application/octet-stream")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _stream(self, query: dict[str, list[str]]) -> None:
        n = _int_query(query, "n", 5)
        ms = _int_query(query, "ms", 100)
        self.send_response(200)
        self.send_header("content-type", "text/event-stream")
        self.send_header("transfer-encoding", "chunked")
        self.send_header("cache-control", "no-cache")
        self.end_headers()
        import time

        for i in range(n):
            event = f"data: event-{i}\n\n".encode()
            chunk = f"{len(event):x}\r\n".encode("ascii") + event + b"\r\n"
            self.wfile.write(chunk)
            self.wfile.flush()
            if i < n - 1 and ms > 0:
                time.sleep(ms / 1000.0)
        self.wfile.write(b"0\r\n\r\n")
        self.wfile.flush()

    def _upload(self) -> None:
        try:
            length = int(self.headers.get("content-length", "0"))
        except ValueError:
            length = 0
        body = self.rfile.read(length) if length > 0 else b""
        digest = hashlib.sha256(body).hexdigest()
        payload = f'{{"sha256":"{digest}","length":{len(body)}}}\n'.encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _not_found(self) -> None:
        body = b"not found\n"
        self.send_response(404)
        self.send_header("content-type", "text/plain")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class AppServer:
    """Loopback ``ThreadingHTTPServer`` wrapper.

    Starts a background serve loop on an ephemeral port; the caller retrieves
    the port and points the relay client at it. Stops cleanly on ``close()``.
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 0) -> None:
        self._server = ThreadingHTTPServer((host, port), _Handler)
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name="spl-home-app",
            daemon=True,
        )

    @property
    def host(self) -> str:
        host = self._server.server_address[0]
        if isinstance(host, (bytes, bytearray)):
            return host.decode("ascii")
        return host

    @property
    def port(self) -> int:
        return int(self._server.server_address[1])

    def start(self) -> None:
        self._thread.start()

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)


def _int_query(query: dict[str, list[str]], name: str, default: int) -> int:
    values = query.get(name)
    if not values:
        return default
    try:
        return int(values[0])
    except ValueError:
        return default


def _deterministic_bytes(n: int) -> bytes:
    """n bytes of deterministic content. Stable across languages."""
    if n <= 0:
        return b""
    full = bytes(range(256))
    q, r = divmod(n, 256)
    return full * q + full[:r]
