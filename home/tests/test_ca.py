# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc

"""CA generation + CSR signing + attestation minting."""

from __future__ import annotations

import base64
import json
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from spl.home.ca import (
    cert_fingerprint,
    generate_ca,
    load_ca,
    load_or_generate_ca,
    mint_attestation,
    sign_csr,
)


def test_generate_and_reload(tmp_path: Path) -> None:
    ca_path = tmp_path / "ca"
    ca1 = generate_ca(ca_path, "pass-word")
    ca2 = load_ca(ca_path, "pass-word")
    assert ca1.fingerprint_sha256() == ca2.fingerprint_sha256()
    # Encrypted private key file should not contain the plaintext key.
    raw = (ca_path.with_suffix(".key.pem")).read_bytes()
    assert b"ENCRYPTED" in raw


def test_load_or_generate_is_idempotent(tmp_path: Path) -> None:
    ca_path = tmp_path / "ca"
    first = load_or_generate_ca(ca_path, "pw")
    second = load_or_generate_ca(ca_path, "pw")
    assert first.fingerprint_sha256() == second.fingerprint_sha256()


def test_sign_csr_produces_valid_cert_chained_to_ca(tmp_path: Path) -> None:
    ca = generate_ca(tmp_path / "ca", "pw")
    # Mobile-side: generate ECDSA-P256 keypair + CSR.
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "Jer's iPhone")]),
        )
        .sign(key, hashes.SHA256())
    )
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode("ascii")

    cert_pem, fp = sign_csr(ca, csr_pem, "Jer's iPhone")
    assert fp.startswith("sha256:")
    assert cert_fingerprint(cert_pem) == fp

    # Cert must chain to the CA — verify the CA's signature over the new cert.
    cert = x509.load_pem_x509_certificate(cert_pem.encode("ascii"))
    ca.cert.public_key().verify(
        cert.signature,
        cert.tbs_certificate_bytes,
        ec.ECDSA(cert.signature_hash_algorithm),  # type: ignore[arg-type]
    )


def test_attestation_signed_by_ca_verifies(tmp_path: Path) -> None:
    ca = generate_ca(tmp_path / "ca", "pw")
    instance_id = "deadbeef-dead-beef-dead-beefdeadbeef"
    device_fp = "sha256:" + "aa" * 32
    jwt = mint_attestation(ca, instance_id, device_fp)
    header_b64, payload_b64, sig_b64 = jwt.split(".")
    header = json.loads(_b64dec(header_b64))
    payload = json.loads(_b64dec(payload_b64))
    assert header == {"alg": "ES256", "typ": "home-attest"}
    assert payload["iss"] == f"home:{instance_id}"
    assert payload["aud"] == "spl-relay"
    assert payload["scope"] == "device.enroll"
    assert payload["device_fp"] == device_fp
    assert payload["instance_id"] == instance_id
    assert payload["exp"] > payload["iat"]
    assert 0 < payload["exp"] - payload["iat"] <= 300  # matches relay cap

    # Signature is raw IEEE P1363 (r||s, 64 bytes for P-256); verify against CA pubkey.
    raw_sig = _b64dec(sig_b64)
    assert len(raw_sig) == 64
    r = int.from_bytes(raw_sig[:32], "big")
    s = int.from_bytes(raw_sig[32:], "big")
    der_sig = encode_dss_signature(r, s)
    ca.cert.public_key().verify(  # type: ignore[union-attr]
        der_sig,
        f"{header_b64}.{payload_b64}".encode("ascii"),
        ec.ECDSA(hashes.SHA256()),
    )


def _b64dec(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)
