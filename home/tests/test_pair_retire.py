# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc

"""Pair-server same-label re-pair retirement semantics."""

from __future__ import annotations

from pathlib import Path

from spl.home.auth import AuthorizedClients, ClientEntry
from spl.home.pair_server import (
    _UNNAMED_DEVICE,
    _retire_superseded,
    _superseded_fingerprints,
)


def test_repair_same_label_collapses_to_newest(tmp_path: Path) -> None:
    store = AuthorizedClients(tmp_path / "auth.json")
    store.add("sha256:fp1", "Jer's iPhone", "inst-1")
    store.add("sha256:fp2", "Jer's iPhone", "inst-1")

    _retire_superseded(store, "sha256:fp2", "Jer's iPhone")

    assert not store.is_authorized("sha256:fp1")
    assert store.is_authorized("sha256:fp2")
    assert len(store.snapshot()) == 1


def test_accrued_same_label_entries_collapse_to_newest(tmp_path: Path) -> None:
    store = AuthorizedClients(tmp_path / "auth.json")
    store.add("sha256:fp1", "Jer's iPhone", "inst-1")
    store.add("sha256:fp2", "Jer's iPhone", "inst-1")
    store.add("sha256:fp3", "Jer's iPhone", "inst-1")
    store.add("sha256:fp4", "Jer's iPhone", "inst-1")

    _retire_superseded(store, "sha256:fp4", "Jer's iPhone")

    remaining = [e.fingerprint for e in store.snapshot() if e.device_label == "Jer's iPhone"]
    assert remaining == ["sha256:fp4"]
    assert len(store.snapshot()) == 1


def test_different_labels_are_not_collapsed(tmp_path: Path) -> None:
    store = AuthorizedClients(tmp_path / "auth.json")
    store.add("sha256:fp1", "Jer's iPhone", "inst-1")
    store.add("sha256:fp2", "Jer's iPad", "inst-1")
    store.add("sha256:fp3", "Jer's iPhone", "inst-1")

    _retire_superseded(store, "sha256:fp3", "Jer's iPhone")

    assert not store.is_authorized("sha256:fp1")
    assert store.is_authorized("sha256:fp2")
    assert store.is_authorized("sha256:fp3")
    assert len(store.snapshot()) == 2


def test_sentinel_and_empty_labels_are_never_collapsed(tmp_path: Path) -> None:
    store = AuthorizedClients(tmp_path / "auth.json")
    store.add("sha256:fp1", _UNNAMED_DEVICE, "inst-1")
    store.add("sha256:fp2", _UNNAMED_DEVICE, "inst-1")
    store.add("sha256:fp3", "", "inst-1")
    store.add("sha256:fp4", _UNNAMED_DEVICE, "inst-1")

    _retire_superseded(store, "sha256:fp4", _UNNAMED_DEVICE)

    assert store.is_authorized("sha256:fp1")
    assert store.is_authorized("sha256:fp2")
    assert store.is_authorized("sha256:fp3")
    assert store.is_authorized("sha256:fp4")


def test_retire_failure_does_not_fail_pair(tmp_path: Path) -> None:
    class FailingRemoveAuthorizedClients(AuthorizedClients):
        def remove(self, fingerprint: str) -> bool:
            raise RuntimeError("remove failed")

    store = FailingRemoveAuthorizedClients(tmp_path / "auth.json")
    store.add("sha256:fp1", "Jer's iPhone", "inst-1")
    store.add("sha256:fp2", "Jer's iPhone", "inst-1")

    _retire_superseded(store, "sha256:fp2", "Jer's iPhone")

    assert store.is_authorized("sha256:fp1")
    assert store.is_authorized("sha256:fp2")


def test_superseded_fingerprints_selects_prior_explicit_exact_label() -> None:
    snapshot = [
        ClientEntry("sha256:old", "Jer's iPhone", "2026-04-19T00:00:00Z", "inst-1"),
        ClientEntry("sha256:new", "Jer's iPhone", "2026-04-19T00:00:01Z", "inst-1"),
        ClientEntry("sha256:ipad", "Jer's iPad", "2026-04-19T00:00:02Z", "inst-1"),
        ClientEntry("sha256:empty", "", "2026-04-19T00:00:03Z", "inst-1"),
        ClientEntry(
            "sha256:unnamed",
            _UNNAMED_DEVICE,
            "2026-04-19T00:00:04Z",
            "inst-1",
        ),
    ]

    assert _superseded_fingerprints(
        snapshot,
        "sha256:new",
        "Jer's iPhone",
    ) == ["sha256:old"]
    assert (
        _superseded_fingerprints(
            snapshot,
            "sha256:new-unnamed",
            _UNNAMED_DEVICE,
        )
        == []
    )
