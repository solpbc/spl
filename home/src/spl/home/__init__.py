# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc

"""Home-side spl tunnel module.

The home is the long-held endpoint. On startup it opens a listen WebSocket to
spl-relay and waits for the relay to signal an incoming dial. For each dial
the home opens a fresh tunnel WebSocket, runs TLS 1.3 *inside* that tunnel
against the mobile's pinned client cert, and hands the decrypted stream to a
small test HTTP app.

See ../../proto/session.md for the WS dance, ../../proto/pairing.md for the
LAN pair ceremony, ../../proto/framing.md for the multiplex wire format.
"""

__version__ = "0.1.0"
