# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc

"""Local HTTPS pair server.

Listens on `config.pair_host:pair_port` with the home's self-signed TLS
cert (signed by the CA). Mobile pins the CA fingerprint from the QR/URL
out-of-band, so there's no trust leap on the LAN.

POST /pair body:
    { "nonce": "<hex>", "csr": "<PEM>", "device_label": "<string>" }

Response:
    200 { client_cert, ca_chain, instance_id, home_label, home_attestation }
    410 if nonce expired or used
    400 if CSR malformed

The pair ceremony is completed by:
  1. validating the nonce (single-use, 5-min TTL) against the shared nonces file
  2. signing the CSR with the CA
  3. writing the new fingerprint into authorized_clients.json
  4. minting a home_attestation JWT (ES256, per proto/tokens.md) for the mobile
     to forward to spl-relay /enroll/device
"""

from __future__ import annotations

import datetime as dt
import json
import ssl
import tempfile
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from typing import Any

from cryptography.hazmat.primitives import serialization

from .auth import AuthorizedClients
from .ca import LoadedCa, cert_fingerprint, mint_attestation, sign_csr
from .nonces import NonceStore


class PairServer:
    """Threaded HTTPS server — runs in a dedicated thread, not the event loop."""

    def __init__(
        self,
        *,
        host: str,
        port: int,
        instance_id: str,
        home_label: str,
        ca: LoadedCa,
        authorized: AuthorizedClients,
        nonces: NonceStore,
    ) -> None:
        self._host = host
        self._port = port
        self._instance_id = instance_id
        self._home_label = home_label
        self._ca = ca
        self._authorized = authorized
        self._nonces = nonces
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: Thread | None = None
        self._cert_paths: tuple[Path, Path] | None = None

    def start(self) -> None:
        if self._httpd is not None:
            return
        # Mint a server cert signed by the CA for the pair listener.
        from .tls_adapter import issue_server_cert

        server_cert, server_key = issue_server_cert(self._ca, common_name=self._home_label)
        tmpdir = Path(tempfile.mkdtemp(prefix="spl-home-pair-"))
        cert_path = tmpdir / "pair.crt"
        key_path = tmpdir / "pair.key"
        cert_path.write_bytes(server_cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(server_key)
        cert_path.chmod(0o600)
        key_path.chmod(0o600)
        self._cert_paths = (cert_path, key_path)

        handler = _make_handler(
            instance_id=self._instance_id,
            home_label=self._home_label,
            ca=self._ca,
            authorized=self._authorized,
            nonces=self._nonces,
        )
        httpd = ThreadingHTTPServer((self._host, self._port), handler)
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ssl_ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
        httpd.socket = ssl_ctx.wrap_socket(httpd.socket, server_side=True)
        self._httpd = httpd
        self._thread = Thread(
            target=httpd.serve_forever,
            name="spl-home-pair",
            daemon=True,
        )
        self._thread.start()

    @property
    def bound_port(self) -> int:
        if self._httpd is None:
            return self._port
        return self._httpd.server_port

    def stop(self) -> None:
        if self._httpd is None:
            return
        self._httpd.shutdown()
        self._httpd.server_close()
        self._httpd = None
        if self._thread is not None:
            self._thread.join(timeout=5)
        if self._cert_paths:
            for p in self._cert_paths:
                try:
                    p.unlink()
                except OSError:
                    pass


def _make_handler(
    *,
    instance_id: str,
    home_label: str,
    ca: LoadedCa,
    authorized: AuthorizedClients,
    nonces: NonceStore,
) -> type[BaseHTTPRequestHandler]:
    # The BaseHTTPRequestHandler pattern uses a class per server; we bake
    # the closures via a factory.
    class Handler(BaseHTTPRequestHandler):
        server_version = "spl-home-pair/0.1"

        def log_message(self, *_args: Any, **_kwargs: Any) -> None:  # noqa: ANN401
            # Quiet by default — the relay does structured logging; this
            # pair server runs on loopback and is only active during the
            # 5-min ceremony window.
            return

        def do_POST(self) -> None:  # noqa: N802 — stdlib requires this name
            if self.path != "/pair":
                self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
                return
            length_raw = self.headers.get("Content-Length", "0")
            try:
                length = int(length_raw)
            except ValueError:
                self._json(HTTPStatus.BAD_REQUEST, {"error": "bad content-length"})
                return
            if length < 0 or length > 1 << 20:
                self._json(HTTPStatus.BAD_REQUEST, {"error": "body too large"})
                return
            body = self.rfile.read(length) if length else b""
            try:
                payload = json.loads(body)
            except json.JSONDecodeError:
                self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid json"})
                return

            nonce = payload.get("nonce")
            csr_pem = payload.get("csr")
            device_label = payload.get("device_label") or "unnamed device"
            if not isinstance(nonce, str) or not isinstance(csr_pem, str):
                self._json(HTTPStatus.BAD_REQUEST, {"error": "missing fields"})
                return

            consumed = nonces.consume(nonce)
            if consumed is None:
                self._json(HTTPStatus.GONE, {"error": "nonce expired or used"})
                return

            try:
                client_cert_pem, fingerprint = sign_csr(ca, csr_pem, device_label)
            except Exception as exc:  # noqa: BLE001
                self._json(HTTPStatus.BAD_REQUEST, {"error": f"bad csr: {exc}"})
                return

            authorized.add(
                fingerprint=fingerprint,
                device_label=device_label,
                instance_id=instance_id,
                paired_at=dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            )
            attestation = mint_attestation(ca, instance_id, fingerprint)
            ca_chain = [
                ca.cert.public_bytes(serialization.Encoding.PEM).decode("ascii"),
            ]
            response = {
                "client_cert": client_cert_pem,
                "ca_chain": ca_chain,
                "instance_id": instance_id,
                "home_label": home_label,
                "home_attestation": attestation,
                "fingerprint": fingerprint,
            }
            # Double-check: fingerprint in the response matches
            # cert_fingerprint(response.client_cert) — invariant test
            # scaffolding relies on it.
            assert cert_fingerprint(client_cert_pem) == fingerprint, "fingerprint drift"
            self._json(HTTPStatus.OK, response)

        def _json(self, status: HTTPStatus, payload: dict[str, Any]) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status.value, status.phrase)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return Handler
