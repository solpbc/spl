#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc

"""End-to-end integration harness for spl.

Spins up a local wrangler-dev spl-relay, a spl.home process, and a
spl-mobile test run, asserting the full scenario matrix. Prints a
pass/fail line per scenario and exits with an aggregate status code.

See ./README.md for the step-by-step orchestration and prerequisites.
"""

from __future__ import annotations

import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
RELAY = REPO / "relay"
HOME = REPO / "home"
MOBILE = REPO / "mobile"

# Colors — keep it simple; terminals that don't support ANSI see the codes.
GREEN = "\033[32m"
RED = "\033[31m"
RESET = "\033[0m"


class RunError(Exception):
    pass


def main() -> int:
    for tool in ("wrangler", "uv", "bun"):
        if shutil.which(tool) is None:
            print(f"error: {tool} not on PATH; see tests/e2e/README.md", file=sys.stderr)
            return 2

    workspace = Path(tempfile.mkdtemp(prefix="spl-e2e-"))
    print(f"workspace: {workspace}")

    results: list[tuple[str, bool, str]] = []
    relay_proc: subprocess.Popen[bytes] | None = None
    home_proc: subprocess.Popen[bytes] | None = None
    relay_logs = workspace / "relay.log"

    try:
        # 1. Mint a throwaway signing keypair.
        keypair_path = workspace / "signing.json"
        _gen_keypair(keypair_path)
        jwks_public, signing_jwk = _split_keypair(keypair_path)

        # 2. Start wrangler dev on a free port.
        relay_port = _free_port()
        dev_vars = workspace / "relay.dev.vars"
        dev_vars.write_text(
            f'SIGNING_JWK={json.dumps(signing_jwk)}\n'
            f'JWKS_PUBLIC={json.dumps(jwks_public)}\n'
            'ISSUER=spl.local\n',
            encoding="utf-8",
        )
        # wrangler dev reads `.dev.vars` from the Worker's directory. Copy
        # ours in place (non-destructively — back up any existing one).
        dev_vars_live = RELAY / ".dev.vars"
        backup = None
        if dev_vars_live.exists():
            backup = RELAY / ".dev.vars.e2e-backup"
            dev_vars_live.replace(backup)
        shutil.copy(dev_vars, dev_vars_live)

        try:
            relay_proc = _start_relay(relay_port, relay_logs)
            _wait_http(f"http://127.0.0.1:{relay_port}/.well-known/jwks.json", timeout=60)

            # 3. Start spl.home against the dev relay.
            home_state = workspace / "home-state"
            home_proc = _start_home(
                relay=f"http://127.0.0.1:{relay_port}",
                state_dir=home_state,
                log_path=workspace / "home.log",
            )
            _wait_for_home_enroll(workspace / "home.log", timeout=30)

            # 4. Mint a pair nonce.
            pair_out = subprocess.run(
                [
                    "uv", "run", "python", "-m", "spl.home", "pair",
                    "--state-dir", str(home_state),
                    "--device-label", "e2e",
                ],
                cwd=HOME,
                capture_output=True,
                check=True,
                text=True,
            )
            lan_url = _extract_pair_url(pair_out.stdout)

            # 5. Run spl-mobile pair.
            mobile_state = workspace / "mobile-state.json"
            subprocess.run(
                [
                    "bun", "run", "src/index.ts",
                    "pair",
                    lan_url,
                    "e2e-device",
                    "--state", str(mobile_state),
                    "--relay", f"http://127.0.0.1:{relay_port}",
                    "--insecure",
                ],
                cwd=MOBILE,
                check=True,
            )
            results.append(("pair", True, "OK"))

            # 6. Run spl-mobile test.
            test_run = subprocess.run(
                [
                    "bun", "run", "src/index.ts",
                    "test",
                    "--state", str(mobile_state),
                    "--n", "128",
                ],
                cwd=MOBILE,
                capture_output=True,
                check=False,
                text=True,
            )
            if test_run.returncode != 0:
                results.append(("scenarios", False, f"mobile test exit {test_run.returncode}: {test_run.stdout}\n{test_run.stderr}"))
            else:
                results.append(("scenarios", True, "echo + stream + upload + 10x concurrent"))

            # 7. Revocation — edit authorized_clients.json to remove the fp.
            auth_file = home_state / "authorized_clients.json"
            authorized = json.loads(auth_file.read_text("utf-8"))
            removed_fp = None
            if isinstance(authorized, list) and authorized:
                removed_fp = authorized[0].get("fingerprint")
            auth_file.write_text(json.dumps([]) + "\n")
            time.sleep(0.75)  # mtime poll
            rev_run = subprocess.run(
                [
                    "bun", "run", "src/index.ts", "test",
                    "--state", str(mobile_state),
                    "--n", "16",
                ],
                cwd=MOBILE,
                capture_output=True,
                check=False,
                text=True,
            )
            if rev_run.returncode == 0:
                results.append(("revocation", False, "mobile test succeeded after revocation — unexpected"))
            else:
                results.append(("revocation", True, f"rejected at TLS (fp={removed_fp})"))

            # 8. Reconnect — restore the authorized entry, kill home, start,
            # verify fresh test succeeds.
            if removed_fp:
                auth_file.write_text(
                    json.dumps(authorized, indent=2) + "\n",
                    encoding="utf-8",
                )
            home_proc.send_signal(signal.SIGTERM)
            home_proc.wait(timeout=10)
            home_proc = _start_home(
                relay=f"http://127.0.0.1:{relay_port}",
                state_dir=home_state,
                log_path=workspace / "home2.log",
            )
            _wait_for_home_enroll(workspace / "home2.log", timeout=30)
            reconnect_run = subprocess.run(
                [
                    "bun", "run", "src/index.ts", "test",
                    "--state", str(mobile_state),
                    "--n", "16",
                ],
                cwd=MOBILE,
                capture_output=True,
                check=False,
                text=True,
            )
            if reconnect_run.returncode != 0:
                results.append(("reconnect", False, f"mobile test failed after home restart: {reconnect_run.stderr[-400:]}"))
            else:
                results.append(("reconnect", True, "tunnel reestablished"))

            # 9. Blindness — grep collected logs for payload / token leakage.
            blindness_ok, blindness_msg = _blindness_check(relay_logs, signing_jwk, jwks_public)
            results.append(("blindness", blindness_ok, blindness_msg))

        finally:
            if home_proc and home_proc.poll() is None:
                home_proc.send_signal(signal.SIGTERM)
                home_proc.wait(timeout=5)
            if relay_proc and relay_proc.poll() is None:
                relay_proc.send_signal(signal.SIGINT)
                relay_proc.wait(timeout=10)
            dev_vars_live.unlink(missing_ok=True)
            if backup is not None and backup.exists():
                backup.replace(dev_vars_live)
    finally:
        pass

    # Summary
    print()
    print("=" * 72)
    failures = 0
    for name, ok, detail in results:
        tag = f"{GREEN}PASS{RESET}" if ok else f"{RED}FAIL{RESET}"
        print(f"  {tag}  {name:12s}  {detail}")
        if not ok:
            failures += 1
    print("=" * 72)
    if failures:
        print(f"{RED}FAILED: {failures} of {len(results)}{RESET}")
        return 1
    print(f"{GREEN}SUCCESS: {len(results)} scenarios passed.{RESET}")
    return 0


def _gen_keypair(out: Path) -> None:
    # Use the relay's gen-signing-key script — already tested, emits the
    # exact JWK shape the Worker expects.
    subprocess.run(
        ["bun", "run", "scripts/gen-signing-key.ts", "--out", str(out), "--force"],
        cwd=RELAY,
        check=True,
    )


def _split_keypair(path: Path) -> tuple[str, str]:
    raw = json.loads(path.read_text("utf-8"))
    public = raw["publicKey"]
    private = raw["privateKey"]
    return json.dumps({"keys": [public]}), json.dumps(private)


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _start_relay(port: int, log_path: Path) -> subprocess.Popen[bytes]:
    log_f = open(log_path, "wb", buffering=0)
    return subprocess.Popen(
        [
            "wrangler", "dev",
            "--ip", "127.0.0.1",
            "--port", str(port),
            "--local",
        ],
        cwd=RELAY,
        stdout=log_f,
        stderr=subprocess.STDOUT,
        env={**os.environ, "NO_COLOR": "1"},
    )


def _wait_http(url: str, timeout: float) -> None:
    start = time.monotonic()
    while time.monotonic() - start < timeout:
        try:
            with urllib.request.urlopen(url, timeout=2) as resp:
                if resp.status == 200:
                    return
        except Exception:
            pass
        time.sleep(0.5)
    raise RunError(f"timed out waiting for {url}")


def _start_home(
    relay: str, state_dir: Path, log_path: Path,
) -> subprocess.Popen[bytes]:
    state_dir.mkdir(parents=True, exist_ok=True)
    log_f = open(log_path, "wb", buffering=0)
    return subprocess.Popen(
        [
            "uv", "run", "python", "-m", "spl.home", "start",
            "--state-dir", str(state_dir),
            "--relay", relay,
            "--home-label", "e2e home",
            "--pair-host", "127.0.0.1",
            "--pair-port", str(_free_port()),
            "-vv",
        ],
        cwd=HOME,
        stdout=log_f,
        stderr=subprocess.STDOUT,
        env=os.environ.copy(),
    )


def _wait_for_home_enroll(log_path: Path, timeout: float) -> None:
    start = time.monotonic()
    while time.monotonic() - start < timeout:
        if log_path.exists():
            text = log_path.read_text("utf-8", errors="replace")
            if "listen WS open" in text:
                return
        time.sleep(0.3)
    raise RunError("timed out waiting for home listen WS")


def _extract_pair_url(stdout: str) -> str:
    for line in stdout.splitlines():
        line = line.strip()
        if line.startswith("https://") and "/pair?token=" in line:
            return line
    raise RunError(f"couldn't find pair URL in:\n{stdout}")


def _blindness_check(
    relay_log: Path, signing_jwk: str, jwks_public: str,
) -> tuple[bool, str]:
    if not relay_log.exists():
        return False, "relay log not found"
    text = relay_log.read_text("utf-8", errors="replace")
    # Any of these strings in the relay log would be a serious privacy
    # regression. Secrets shouldn't be logged; Authorization headers
    # shouldn't be logged; Bearer token prefixes shouldn't either.
    bad_substrings = [
        "BEGIN CERTIFICATE",
        "BEGIN PRIVATE",
        "-----BEGIN",
        "Bearer eyJ",  # JWT prefix
        "Authorization:",
        "content-length: ",  # we log byte_count, not raw HTTP headers
    ]
    hits = [s for s in bad_substrings if s in text]
    # Also search for chunks of the signing key and JWKS — should never show up in logs.
    signing_private = json.loads(signing_jwk).get("d", "")
    if signing_private and signing_private in text:
        hits.append("signing_jwk d")
    if jwks_public and jwks_public in text:
        hits.append("jwks_public raw")
    if hits:
        return False, f"log contains: {', '.join(hits)}"
    return True, "no payload / token / header leakage found"


if __name__ == "__main__":
    sys.exit(main())
