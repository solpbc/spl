# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc

"""NonceStore — single-use consume, TTL, GC."""

from __future__ import annotations

from pathlib import Path

from spl.home.nonces import NONCE_TTL_SECONDS, NonceStore


def test_add_and_consume(tmp_path: Path) -> None:
    store = NonceStore(tmp_path / "nonces.json")
    store.add("abc123", "Jer's phone", now=1000)
    entry = store.consume("abc123", now=1001)
    assert entry is not None
    assert entry.device_label == "Jer's phone"


def test_consume_is_single_use(tmp_path: Path) -> None:
    store = NonceStore(tmp_path / "nonces.json")
    store.add("abc123", "d", now=1000)
    assert store.consume("abc123", now=1001) is not None
    assert store.consume("abc123", now=1002) is None


def test_expired_nonce_rejected(tmp_path: Path) -> None:
    store = NonceStore(tmp_path / "nonces.json")
    store.add("abc123", "d", now=1000)
    assert store.consume("abc123", now=1000 + NONCE_TTL_SECONDS + 1) is None


def test_unknown_nonce_returns_none(tmp_path: Path) -> None:
    store = NonceStore(tmp_path / "nonces.json")
    assert store.consume("never-added") is None


def test_gc_removes_expired_and_used(tmp_path: Path) -> None:
    store = NonceStore(tmp_path / "nonces.json")
    # Insert a used-but-live entry and another live one; after consume,
    # gc should reap the used one.
    store.add("live", "d", now=1000)
    store.add("used", "d", now=1000)
    store.consume("used", now=1001)
    removed = store.gc(now=1001)
    assert removed == 1
    assert len(store.snapshot()) == 1
    # A stand-alone expired entry gets reaped on any mutating call — add()
    # and consume() both GC under the lock. That's the safety property we
    # actually need (store never grows unbounded); explicit gc() is only
    # necessary on a quiescent store.
    store.add("fresh", "d", now=2000)
    store.add("also_expired", "d", now=2000 - NONCE_TTL_SECONDS - 10)
    store.gc(now=2000)
    # only "live" remains — but its entry was added at now=1000 so it's
    # still within TTL at 1001; at now=2000 it's stale too.
    # Adjust expectation: at now=2000, anything added at 1000 or earlier
    # with TTL=300 is expired. Ensure only "fresh" survives.
    snapshot = {n.value for n in store.snapshot()}
    assert snapshot == {"fresh"}


def test_persistence_across_store_instances(tmp_path: Path) -> None:
    path = tmp_path / "nonces.json"
    s1 = NonceStore(path)
    s1.add("shared", "d", now=1000)
    s2 = NonceStore(path)
    entry = s2.consume("shared", now=1001)
    assert entry is not None
