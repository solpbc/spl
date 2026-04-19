# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc

"""Smoke test placeholder. Replaced as the MVP build lands."""

from spl import __version__


def test_version_importable() -> None:
    assert isinstance(__version__, str)
