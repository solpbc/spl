# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc

"""AuthorizedClients — add/remove/reload semantics."""

from __future__ import annotations

import json
import time
from pathlib import Path

from spl.home.auth import AuthorizedClients


def test_empty_file_is_empty(tmp_path: Path) -> None:
    store = AuthorizedClients(tmp_path / "auth.json")
    assert not store.is_authorized("sha256:abc")


def test_add_and_authorized(tmp_path: Path) -> None:
    store = AuthorizedClients(tmp_path / "auth.json")
    store.add("sha256:abc", "Jer's phone", "inst-1")
    assert store.is_authorized("sha256:abc")
    assert not store.is_authorized("sha256:xyz")


def test_remove(tmp_path: Path) -> None:
    store = AuthorizedClients(tmp_path / "auth.json")
    store.add("sha256:abc", "Jer", "inst-1")
    assert store.remove("sha256:abc") is True
    assert not store.is_authorized("sha256:abc")
    assert store.remove("sha256:abc") is False


def test_external_edit_reloads_on_mtime_change(tmp_path: Path) -> None:
    path = tmp_path / "auth.json"
    store = AuthorizedClients(path)
    store.add("sha256:abc", "Jer", "inst-1")
    assert store.is_authorized("sha256:abc")

    # Simulate an external convey "Unpair" writing the file directly —
    # wait enough for mtime_ns to differ, then rewrite with no entries.
    time.sleep(0.02)
    path.write_text(json.dumps([]))
    # reload_if_stale returns True; is_authorized reflects the new state.
    assert store.reload_if_stale() is True
    assert not store.is_authorized("sha256:abc")


def test_is_authorized_reloads_automatically(tmp_path: Path) -> None:
    path = tmp_path / "auth.json"
    store = AuthorizedClients(path)
    time.sleep(0.02)
    path.write_text(
        json.dumps(
            [
                {
                    "fingerprint": "sha256:zzz",
                    "device_label": "external",
                    "paired_at": "2026-04-19T00:00:00Z",
                    "instance_id": "inst-1",
                },
            ],
        ),
    )
    # No explicit reload — is_authorized must pick up the fresh file.
    assert store.is_authorized("sha256:zzz")


def test_snapshot_returns_entries(tmp_path: Path) -> None:
    store = AuthorizedClients(tmp_path / "auth.json")
    store.add("sha256:a", "d1", "inst-1")
    store.add("sha256:b", "d2", "inst-1")
    snap = store.snapshot()
    fps = sorted(e.fingerprint for e in snap)
    assert fps == ["sha256:a", "sha256:b"]
