# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc

"""Tests for the reference home-app HTTP server.

The server is a plain stdlib ``ThreadingHTTPServer`` bound on loopback.
These tests exercise the three test endpoints over real TCP — the same
path the tunnel takes at runtime.
"""

from __future__ import annotations

import hashlib
import http.client
import json

import pytest

from spl.home.app import AppServer


@pytest.fixture
def server():
    s = AppServer(host="127.0.0.1", port=0)
    s.start()
    try:
        yield s
    finally:
        s.close()


def _request(server, method: str, path: str, body: bytes = b""):
    conn = http.client.HTTPConnection(server.host, server.port, timeout=5)
    headers = {"content-length": str(len(body))} if body or method == "POST" else {}
    try:
        conn.request(method, path, body=body, headers=headers)
        resp = conn.getresponse()
        return resp.status, {k.lower(): v for k, v in resp.getheaders()}, resp.read()
    finally:
        conn.close()


def test_echo_returns_n_deterministic_bytes(server):
    status, headers, body = _request(server, "GET", "/echo?n=128")
    assert status == 200
    assert headers["content-length"] == "128"
    assert len(body) == 128
    expected = bytes(range(256))[:128]
    assert body == expected


def test_upload_returns_sha256_of_body(server):
    payload = b"the quick brown fox jumps over the lazy dog"
    digest = hashlib.sha256(payload).hexdigest()
    status, _, body = _request(server, "POST", "/upload", body=payload)
    assert status == 200
    parsed = json.loads(body)
    assert parsed == {"sha256": digest, "length": len(payload)}


def test_stream_emits_n_chunked_events(server):
    status, headers, body = _request(server, "GET", "/stream?n=3&ms=0")
    assert status == 200
    # http.client de-chunks the transfer encoding automatically; inspect the
    # decoded body for the three SSE events.
    events = [seg for seg in body.split(b"data: ") if seg.startswith(b"event-")]
    assert len(events) == 3


def test_unknown_route_is_404(server):
    status, _, _ = _request(server, "GET", "/unknown")
    assert status == 404
