# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc

"""CLI entry point — `python -m spl.home <command>`.

Two commands:

  start   long-running; opens listen WS + pair HTTPS listener. Reconnects
          on disconnect. Sig-terms cleanly.

  pair    one-shot; mints a fresh pair nonce into the shared nonces file
          and prints the LAN URL to stdout. Requires a running `start` on
          the same machine (both processes read/write the nonces file).
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import signal
import sys
from pathlib import Path

from .app import AppServer
from .auth import AuthorizedClients
from .ca import generate_nonce, load_or_generate_ca
from .config import Config, default_config, ensure_passphrase
from .nonces import NonceStore
from .pair_server import PairServer
from .relay_client import RelayClient

DEFAULT_STATE_DIR = Path.home() / ".spl" / "home"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="spl.home")
    parser.add_argument(
        "--state-dir",
        type=Path,
        default=DEFAULT_STATE_DIR,
        help="persistent state directory (default: ~/.spl/home)",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="count",
        default=0,
        help="increase log verbosity",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    start = sub.add_parser("start", help="run the tunnel module")
    start.add_argument(
        "--relay",
        default="https://spl.solpbc.org",
        help="spl-relay endpoint (defaults to sol pbc hosted)",
    )
    start.add_argument("--home-label", default="spl home")
    start.add_argument("--pair-host", default="127.0.0.1")
    start.add_argument("--pair-port", type=int, default=8443)

    pair = sub.add_parser("pair", help="mint a fresh pair nonce")
    pair.add_argument("--device-label", required=True)

    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG
        if args.verbose >= 2
        else logging.INFO
        if args.verbose == 1
        else logging.WARNING,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )

    if args.command == "start":
        return _cmd_start(args)
    if args.command == "pair":
        return _cmd_pair(args)
    parser.error(f"unknown command: {args.command}")
    return 2


def _cmd_start(args: argparse.Namespace) -> int:
    state_dir: Path = args.state_dir
    config_path = Config.path_for(state_dir)
    if config_path.exists():
        config = Config.load(state_dir)
    else:
        config = default_config(
            state_dir,
            relay_endpoint=args.relay,
            home_label=args.home_label,
            pair_host=args.pair_host,
            pair_port=args.pair_port,
        )
        config.save(state_dir)

    passphrase = ensure_passphrase(config.ca_passphrase_file)
    ca = load_or_generate_ca(config.ca_path, passphrase)
    authorized = AuthorizedClients(config.authorized_clients_path)
    nonces = NonceStore(config.nonces_path)

    pair_server = PairServer(
        host=config.pair_host,
        port=config.pair_port,
        instance_id=config.instance_id,
        home_label=config.home_label,
        ca=ca,
        authorized=authorized,
        nonces=nonces,
    )
    pair_server.start()

    app_server = AppServer(host="127.0.0.1", port=0)
    app_server.start()

    relay_client = RelayClient(
        config,
        ca,
        authorized,
        target_host=app_server.host,
        target_port=app_server.port,
    )

    async def run() -> None:
        await relay_client.enroll_if_needed()
        config.save(state_dir)  # persist the account_token after enroll
        stop_event = asyncio.Event()
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, stop_event.set)
        run_task = asyncio.create_task(relay_client.run())
        await stop_event.wait()
        await relay_client.stop()
        run_task.cancel()
        try:
            await run_task
        except asyncio.CancelledError:
            pass

    try:
        asyncio.run(run())
    finally:
        app_server.close()
        pair_server.stop()
    return 0


def _cmd_pair(args: argparse.Namespace) -> int:
    state_dir: Path = args.state_dir
    config_path = Config.path_for(state_dir)
    if not config_path.exists():
        print(
            "error: home not initialized — run `python -m spl.home start` first.",
            file=sys.stderr,
        )
        return 1
    config = Config.load(state_dir)
    nonces = NonceStore(config.nonces_path)
    value = generate_nonce()
    nonces.add(value, args.device_label)
    url = f"https://{config.pair_host}:{config.pair_port}/pair?token={value}"
    print(
        f"Pair URL (valid 5 min, single-use):\n  {url}\n"
        f"Nonce:       {value}\n"
        f"Device:      {args.device_label}\n"
        f"Instance ID: {config.instance_id}\n",
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
