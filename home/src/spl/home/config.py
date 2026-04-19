# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc

"""Home config — persisted state between `start` and `pair` invocations.

The config file lives at `<state_dir>/config.json` and is the source of
truth for: instance_id, home_label, relay endpoint, account token, paths
to the CA key/cert, authorized_clients.json, and the nonces file used by
the pair ceremony.

First-run bootstrap creates the CA, registers with the relay via
/enroll/home, stores the account token, and writes the config. Subsequent
runs load it. If the relay invalidates the token (rotation, reinstall),
`start` re-registers idempotently.
"""

from __future__ import annotations

import dataclasses
import json
import os
import uuid
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Config:
    instance_id: str
    home_label: str
    relay_endpoint: str  # e.g. "https://spl.example.org" — trailing slash stripped
    account_token: str | None
    ca_path: Path  # base path; actual files are <ca_path>.crt.pem + <ca_path>.key.pem
    ca_passphrase_file: Path
    authorized_clients_path: Path
    nonces_path: Path
    pair_host: str  # e.g. "127.0.0.1" or LAN IP
    pair_port: int  # bound by pair server
    tunnel_server_port: int  # local port the inner TLS server listens on
    tunnel_server_cert_cn: str  # CN of the home's TLS server cert

    @staticmethod
    def path_for(state_dir: Path) -> Path:
        return state_dir / "config.json"

    @classmethod
    def load(cls, state_dir: Path) -> Config:
        path = cls.path_for(state_dir)
        raw = json.loads(path.read_text("utf-8"))
        return cls(
            instance_id=raw["instance_id"],
            home_label=raw["home_label"],
            relay_endpoint=raw["relay_endpoint"].rstrip("/"),
            account_token=raw.get("account_token"),
            ca_path=Path(raw["ca_path"]),
            ca_passphrase_file=Path(raw["ca_passphrase_file"]),
            authorized_clients_path=Path(raw["authorized_clients_path"]),
            nonces_path=Path(raw["nonces_path"]),
            pair_host=raw["pair_host"],
            pair_port=int(raw["pair_port"]),
            tunnel_server_port=int(raw["tunnel_server_port"]),
            tunnel_server_cert_cn=raw.get("tunnel_server_cert_cn", "spl home"),
        )

    def save(self, state_dir: Path) -> None:
        path = self.path_for(state_dir)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            **dataclasses.asdict(self),
            "ca_path": str(self.ca_path),
            "ca_passphrase_file": str(self.ca_passphrase_file),
            "authorized_clients_path": str(self.authorized_clients_path),
            "nonces_path": str(self.nonces_path),
        }
        tmp = path.with_suffix(".json.tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)


def default_config(
    state_dir: Path,
    *,
    relay_endpoint: str,
    home_label: str = "spl home",
    pair_host: str = "127.0.0.1",
    pair_port: int = 8443,
    tunnel_server_port: int = 9443,
) -> Config:
    state_dir.mkdir(parents=True, exist_ok=True)
    return Config(
        instance_id=str(uuid.uuid4()),
        home_label=home_label,
        relay_endpoint=relay_endpoint.rstrip("/"),
        account_token=None,
        ca_path=state_dir / "ca",
        ca_passphrase_file=state_dir / "ca.pass",
        authorized_clients_path=state_dir / "authorized_clients.json",
        nonces_path=state_dir / "nonces.json",
        pair_host=pair_host,
        pair_port=pair_port,
        tunnel_server_port=tunnel_server_port,
        tunnel_server_cert_cn="spl home",
    )


def ensure_passphrase(path: Path) -> str:
    """Return the passphrase at `path`, creating a random one if absent."""
    if path.exists():
        return path.read_text("utf-8").strip()
    import secrets

    passphrase = secrets.token_urlsafe(32)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(passphrase + "\n", encoding="utf-8")
    path.chmod(0o600)
    return passphrase
