# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc

"""pyOpenSSL memory-BIO adapter: TLS 1.3 over non-socket byte streams.

The home runs TLS inside the spl-relay tunnel, which is an opaque
WebSocket — not a real socket. pyOpenSSL's `SSL.Connection` supports
memory-BIO mode (no socket): the caller pushes ciphertext in with
`bio_write`, pulls ciphertext out with `bio_read`, and reads/writes
plaintext with `recv`/`send`.

This module wraps that state machine with a simple byte-oriented API that
the relay-client and mux loops can drive. It also installs the pinned
verify callback — the load-bearing reason we use pyOpenSSL and not stdlib
`ssl` (stdlib doesn't expose a handshake-time callback that can reject a
cert with a clean TLS alert; see proto/pairing.md §revocation).
"""

from __future__ import annotations

from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from OpenSSL import SSL, crypto

from .auth import AuthorizedClients
from .ca import LoadedCa


class TlsError(RuntimeError):
    """Raised when the TLS handshake is aborted (e.g., fingerprint rejected)."""


@dataclass
class TlsServerState:
    conn: SSL.Connection
    handshake_done: bool = False
    peer_fingerprint: str | None = None


def build_server_context(
    ca: LoadedCa,
    server_cert: x509.Certificate,
    server_key: bytes,
    authorized: AuthorizedClients,
) -> SSL.Context:
    """Build a TLS 1.3 server context with the pinned verify callback.

    `server_cert` is the home's self-signed TLS cert (signed by the CA).
    `server_key` is its PEM-encoded private key.
    """
    ctx = SSL.Context(SSL.TLS_METHOD)
    ctx.set_min_proto_version(SSL.TLS1_3_VERSION)
    ctx.set_max_proto_version(SSL.TLS1_3_VERSION)
    ctx.use_certificate(
        crypto.X509.from_cryptography(server_cert),
    )
    ctx.use_privatekey(crypto.load_privatekey(crypto.FILETYPE_PEM, server_key))
    ctx.add_extra_chain_cert(crypto.X509.from_cryptography(ca.cert))
    # Trust only certs signed by this CA — chain validation happens below
    # the fingerprint check.
    store = ctx.get_cert_store()
    assert store is not None, "pyOpenSSL context must expose a cert store"
    store.add_cert(crypto.X509.from_cryptography(ca.cert))

    def verify_cb(
        _conn: SSL.Connection,
        cert: crypto.X509,
        _errno: int,
        depth: int,
        preverify_ok: int,
    ) -> bool:
        # Chain validation runs first; we only get called with depth==0 for
        # the leaf. Reject if chain failed *or* the leaf fingerprint isn't
        # in authorized_clients.json. Either way the handshake aborts with
        # a clean TLS alert — which is the whole point of doing this in
        # the callback rather than post-handshake.
        if not preverify_ok:
            return False
        if depth != 0:
            return True
        der = cert.to_cryptography().public_bytes(serialization.Encoding.DER)
        import hashlib

        fp = f"sha256:{hashlib.sha256(der).hexdigest()}"
        return authorized.is_authorized(fp)

    ctx.set_verify(
        SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT,
        verify_cb,
    )
    return ctx


def new_server(ctx: SSL.Context) -> TlsServerState:
    """Fresh memory-BIO connection in accept state."""
    conn = SSL.Connection(ctx, None)  # None socket → memory BIO
    conn.set_accept_state()
    return TlsServerState(conn=conn)


def drive_tls(
    state: TlsServerState,
    *,
    inbound: bytes,
    plaintext_out: bytes = b"",
) -> tuple[bytes, bytes]:
    """Push ciphertext in + plaintext out; return (ciphertext_to_send, plaintext_received).

    This is a single pass through the TLS state machine. The caller loops
    this while progressing handshake / draining app bytes.
    """
    if inbound:
        state.conn.bio_write(inbound)
    if plaintext_out:
        try:
            state.conn.send(plaintext_out)
        except SSL.WantReadError:
            # Will retry when more ciphertext is available.
            pass

    if not state.handshake_done:
        try:
            state.conn.do_handshake()
            state.handshake_done = True
            peer = state.conn.get_peer_certificate()
            if peer is not None:
                import hashlib

                der = peer.to_cryptography().public_bytes(
                    serialization.Encoding.DER,
                )
                state.peer_fingerprint = f"sha256:{hashlib.sha256(der).hexdigest()}"
        except SSL.WantReadError:
            pass
        except SSL.Error as exc:
            raise TlsError(f"handshake failed: {exc}") from exc

    plaintext_in = bytearray()
    if state.handshake_done:
        while True:
            try:
                chunk = state.conn.recv(16 * 1024)
            except SSL.WantReadError:
                break
            except SSL.ZeroReturnError:
                break
            if not chunk:
                break
            plaintext_in.extend(chunk)

    outbound = bytearray()
    while True:
        try:
            chunk = state.conn.bio_read(16 * 1024)
        except SSL.WantReadError:
            break
        if not chunk:
            break
        outbound.extend(chunk)
    return bytes(outbound), bytes(plaintext_in)


def issue_server_cert(
    ca: LoadedCa,
    common_name: str = "spl home",
) -> tuple[x509.Certificate, bytes]:
    """Mint a server cert (signed by the CA) + its PEM-encoded private key.

    Regenerated on each start — server-side TLS material doesn't need to
    survive restarts since the mobile pins the *CA* fingerprint, not the
    server cert.
    """
    import datetime as dt

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]),
        )
        .issuer_name(ca.cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .sign(ca.private_key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return cert, key_pem


# Re-export for relay_client convenience.
__all__ = [
    "TlsError",
    "TlsServerState",
    "build_server_context",
    "drive_tls",
    "issue_server_cert",
    "new_server",
]
