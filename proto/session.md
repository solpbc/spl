# session

The lifecycle of a tunnel: how the home's listen WebSocket, the mobile's dial WebSocket, and the relay's pairing logic come together to make opaque bytes flow between two endpoints.

This document is the contract for the WebSocket dance — what each side opens, when, in what order, and how disconnects are handled. It does not define the bytes that flow inside the tunnel (that's [`framing.md`](framing.md)) or the credentials that authorize the dance (that's [`tokens.md`](tokens.md), [`pairing.md`](pairing.md)).

## actors and surfaces

Three WebSocket endpoints on `solcf`:

- `GET /session/listen` — home upgrades to WS; carries an account-token bearer. One per home, held open indefinitely.
- `GET /session/dial` — mobile upgrades to WS; carries a device-token bearer. One per mobile dial; **becomes** the mobile-side tunnel WS once paired.
- `GET /tunnel/<id>` — home upgrades to WS; carries the account-token plus a `tunnel_id` minted by the relay. One per active tunnel on the home side; opened in response to a pair signal.

The asymmetry is deliberate. The mobile opens **one** WebSocket per dial (the dial WS becomes the tunnel WS — single-WS-per-side, prototype finding §11.1, saves ~40-80 ms per cold request). The home opens **one** persistent listen WS plus **one** transient tunnel WS per active tunnel.

## endpoint shapes

### listen — home → solcf

```
GET /session/listen HTTP/1.1
Host: spl.solpbc.org
Upgrade: websocket
Connection: Upgrade
Authorization: Bearer <account_token>
Sec-WebSocket-Key: ...
```

Response:

```
HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: ...
```

After upgrade, the WebSocket is held open. The home sends nothing on this socket in v1. The relay sends control messages — only one in v1: `incoming` (see *pair signal* below).

Reconnect: see *home reconnect* below.

### dial — mobile → solcf

```
GET /session/dial?instance=<paired_instance_id> HTTP/1.1
Host: spl.solpbc.org
Upgrade: websocket
Connection: Upgrade
Authorization: Bearer <device_token>
Sec-WebSocket-Key: ...
```

Query parameter `instance` names the home this dial targets; must match the `instance_id` claim on the device token.

After upgrade, this **same WebSocket** becomes the mobile-side tunnel WS once the relay has paired it with a home tunnel WS. There is no second WS open from the mobile. The mobile waits for the relay to attach the home side, then begins TLS 1.3 over this WS toward the home.

### tunnel — home → solcf

```
GET /tunnel/<tunnel_id> HTTP/1.1
Host: spl.solpbc.org
Upgrade: websocket
Connection: Upgrade
Authorization: Bearer <account_token>
Sec-WebSocket-Key: ...
```

`<tunnel_id>` is the value the relay sent on the home's listen WS via the `incoming` control message. The home opens this WS in response to the signal; the relay matches it to the waiting mobile-side dial WS by `tunnel_id`.

The home opens one tunnel WS per concurrent tunnel. The listen WS stays open across many tunnels.

## the dance, step by step

```
home                          solcf                              mobile
----                          -----                              ------

(1) listen WS open ─────────▶ validate account token
                              hold WS open, register as
                              ready for instance_id

                                                                 (2) dial WS open ─────▶
                                                                     validate device token
                              mint tunnel_id
                              record (tunnel_id, mobile_ws)

(3) ◀── ctrl: incoming
        { tunnel_id }
                              ◀── (4) tunnel WS open
                                       /tunnel/<tunnel_id>

                              (5) DO.pair(tunnel_id) — match
                                  home's tunnel WS to mobile's
                                  (already-open) dial-turned-tunnel WS

                              ──── opaque byte pipe ────
                              (6) frames flow blindly

(7) TLS 1.3 handshake          ◀── frames forwarded ───▶            TLS 1.3 client
    server presents cert            in both directions               presents paired cert
    verify_callback checks
    fingerprint against
    authorized_clients.json
    OK → handshake completes
    BAD → TLS alert, drop

(8) framed HTTP/SSE/WS         ◀── frames forwarded ───▶            mobile UX
    inside the tunnel
```

Numbered steps:

### 1. listen — home opens at solstone startup

The home's `spl.tunnel` task opens `GET /session/listen` to `solcf` immediately on solstone startup. It carries the account token in the `Authorization` header. The relay validates the token (see [`tokens.md`](tokens.md)), records this WS as the ready listen socket for the home's `instance_id`, and holds the WS open. The home sends no further bytes on this WS — it only reads.

### 2. dial — mobile opens when the user opens the app

When the user opens the solstone mobile app and the app foregrounds, the mobile opens `GET /session/dial?instance=<id>` to `solcf`, carrying the device token. The relay validates the token and the matching `instance_id`, mints a `tunnel_id`, and records the mobile's WS as one half of the (not yet complete) tunnel.

### 3. pair signal — relay tells the home

The relay sends a single control frame on the home's listen WS:

```json
{ "type": "incoming", "tunnel_id": "<uuidv7>" }
```

This is a structured JSON message in a WebSocket text frame. It is the **only** message the home receives on its listen WS in v1. Future versions may add control messages (e.g., revoke notifications); the home parses defensively and ignores unknown message types.

### 4. tunnel — home opens on the signal

The home reacts to the `incoming` signal by opening `GET /tunnel/<tunnel_id>` to `solcf`, carrying the account token and the `tunnel_id` from the signal. The relay matches the WS against the recorded entry by `tunnel_id`.

### 5. pair — relay matches the two WSes

In the relay's Durable Object, both halves of the tunnel are now attached. The DO's pairing logic uses `getWebSockets("tunnel_home:" + tunnel_id)` and `getWebSockets("tunnel_mobile:" + tunnel_id)` to retrieve them, asserts cardinality (see *cardinality* below), and begins forwarding.

### 6. relay — opaque byte pump

From this point, the relay is a pure byte pump. Bytes received on the home WS are forwarded to the mobile WS unchanged; bytes received on the mobile WS are forwarded to the home WS unchanged. The relay does not parse, does not reframe, does not buffer beyond what's necessary to handle one side's send-while-other-side-not-yet-attached (see *pending buffer* below).

### 7. inner TLS handshake

With the byte pipe open, the mobile initiates TLS 1.3 toward the home. The mobile presents the paired client cert (from Keychain). The home's TLS server presents its self-signed cert (from the local CA). The home's `verify_callback` (pyOpenSSL — stdlib `ssl` doesn't expose this cleanly) validates the SHA-256 fingerprint of the client cert against `authorized_clients.json` **inside the handshake**. A non-match aborts the handshake with a clean TLS alert; the mobile observes it as a specific handshake failure and surfaces `LITERAL: "This device was unpaired from your solstone."`.

`authorized_clients.json` is mtime-polled at 0.5s; revocation propagates within a second of the file edit (see [`pairing.md`](pairing.md) for the revocation flow).

### 8. application traffic

After TLS, the mobile speaks HTTP (with multiplexed streams per [`framing.md`](framing.md)) to the home's convey Flask app via WSGI test-client (or an internal socket). Image loads, SSE feeds, WS upgrades all flow through the same tunnel WS, multiplexed by stream id.

## hibernation

Cloudflare hibernates idle Hibernatable WebSockets after ~10 seconds of inactivity. This is aggressive but cheap:

- **Listen WS:** hibernates between dials. Wake on next `incoming` signal pre-empt or on the WebSocket library's own ping (see *no app heartbeat* below).
- **Tunnel WS:** hibernates between bursts. Every mobile request after ≥10 s of inactivity pays wake cost.
- **Wake cost is low and flat across idle duration.** Prototype measurements (§3): 1-min idle p50 = 157 ms, 5-min idle p50 = 37 ms. Both well under the 500 ms criterion. There is no growing tax on longer idle periods (§11.2).

The 30-min and 2-hr profiles weren't measured in the prototype session; the 30+ min listen WS held open without app heartbeats is observational evidence that hibernation works at those durations too. Confirmed measurements of the 2-hr profile remain a v1 alpha follow-up (not blocking).

## no app heartbeat

v1 ships **no application-level heartbeat.** Both sides rely on:

- The WebSocket library's built-in ping (typically every 20-30 s for `websockets` in python and Apple's `URLSessionWebSocketTask` on iOS).
- Cloudflare's auto ping/pong response from the Hibernatable WebSocket runtime (does not wake the DO).

Prototype §9: the listen WS held open across 30+ min idle without any application-level heartbeat, with only the `websockets` library's default ping. Cost implication: this halves wake-billing frequency vs. the cost simulation's 1/min heartbeat assumption.

If alpha reveals idle disconnects beyond 30 min in real-world conditions, we revisit. v1 ships without.

## reconnect semantics

### home reconnect — listen WS

The listen WS may disconnect for any reason — network flap on the home machine, `solcf` deploy, transient CF edge churn, etc. The home reconnects with **exponential backoff**:

- Initial delay: 1 s.
- Multiplier: 2× each failed attempt.
- Cap: 60 s.
- Reset to 1 s on a successful reconnect.
- Jitter: ±25% on each delay to avoid synchronized reconnect storms after a CF deploy.

While the listen WS is down, the home cannot receive `incoming` signals. New dials from a paired mobile will fail at the relay (the DO marks the home as not-ready and the dial returns 503). The mobile's reconnect logic handles this; the user sees `LITERAL: "Reconnecting…"` for the brief outage and `LITERAL: "Offline — check your connection."` if it persists past a small grace window.

### mobile reconnect — dial WS / tunnel WS

The mobile dial-turned-tunnel WS disconnects on:

- App backgrounding (iOS suspends after 20 s grace, per the extro-phone lifecycle; the WS naturally drops).
- Network change (wifi ↔ cellular).
- TLS-handshake failure (revocation).
- `solcf` deploy.

For non-revocation disconnects, the mobile reconnects on next user-visible activity (foreground, scroll, tap). Backoff is: 1 s, then 5 s, then 10 s, capped at 30 s, with the same ±25% jitter. The mobile's UX handles "Reconnecting…" / "Offline" banners.

For TLS-handshake failure (revocation), the mobile does **not** retry automatically — it presents the unpaired error and requires the user to re-pair through convey.

## deploy-disconnect

Every `solcf` Worker redeploy disconnects every WebSocket. This is a CF property of the Hibernatable WebSocket API — the new code version cannot inherit live sockets from the old version.

Behavior:

- Both sides observe a clean WebSocket close (typically code 1006 abnormal closure or 1012 service restart).
- Both sides reconnect per the backoff rules above.
- **Pair state is not preserved.** All in-flight `tunnel_id`s are invalidated. The mobile's next dial mints a new `tunnel_id`; the home opens a fresh tunnel WS in response to the new `incoming`.
- **Pairing material is preserved.** The home's CA, the mobile's client cert, the device tokens, and the account tokens all survive — they live in their respective stores, not in the Worker. **No re-enrollment is required.**

Acceptance criterion (per spec): clients reconnect within 10 seconds of a Worker redeploy without requiring re-pair. Prototype did not measure this directly (§7); MVP test suite covers it.

Operational implication: deploy cadence on `solcf` is low. We don't ship features weekly. Every deploy is a customer-visible blip; only ship when it's worth that.

## cardinality

The DO uses `getWebSockets(tag)` to look up sockets by tag. The relay tags sockets as:

- `home:<instance_id>` for the listen WS.
- `tunnel_home:<tunnel_id>` for the home tunnel WS.
- `tunnel_mobile:<tunnel_id>` for the mobile dial-turned-tunnel WS.

Each tag MUST resolve to exactly one WebSocket. If a duplicate WS attaches under any of these tags (e.g., a home reconnects without the previous WS having been observed as closed), the relay closes the duplicate and keeps the most recently attached. Prototype finding §11.4 — the API doesn't enforce cardinality, the application must.

## pending buffer

Between the moment one tunnel side has attached (e.g., mobile dial completed, `tunnel_id` minted) and the moment the other side attaches (home opens `/tunnel/<id>` in response to `incoming`), the relay buffers any frames sent by the attached side in memory. In practice this window is ~100-200 ms and the buffered content is the TLS ClientHello (~1-2 KB).

The buffer is **capped at 16 MiB per tunnel**. If the cap is exceeded:

- The relay logs a structured `pending_buffer_overflow` event with `tunnel_id`, `direction`, and `byte_count`. **No payload bytes.**
- The relay closes both sides of the (incomplete) tunnel with WebSocket close code `1009` (message too big).
- The DO frees the buffer and the `tunnel_id` is retired.

Sixteen MiB is generous; a healthy v1 client will buffer ≤2 KiB. The cap exists to bound memory under a misbehaving or attacking peer that opens a dial WS, sends a flood, and never connects the home side.

Once both sides are paired, the buffer is drained and the relay reverts to direct forwarding. From that point, backpressure is the WebSocket layer's job (via TCP and the framing-layer credit windows — see [`framing.md`](framing.md)).

## clean disconnect

Both sides may close at any time. The relay propagates close events across the pair:

- Home tunnel WS closes → relay closes mobile tunnel WS with the same close code.
- Mobile tunnel WS closes → relay closes home tunnel WS with the same close code.

The listen WS closing does **not** close active tunnel WSes — those continue until either side hangs up. The relay does, however, refuse new dials while the listen WS is down.

## what `solcf` logs about a session

For audit and debugging, the Worker emits structured log events at session boundaries. Logged fields are an exhaustive list:

- `tunnel_id` (uuid)
- `instance_id` (uuid)
- `direction` (one of `home → mobile`, `mobile → home`, or `meta`)
- `event` (one of `pair`, `close`, `pending_buffer_overflow`, `unauthorized`, `cardinality_violation`)
- `byte_count` (when applicable)
- `close_code` (when applicable)
- `duration_ms` (on close events)
- `timestamp`

**Never** a payload byte. **Never** a token claim. **Never** a TLS handshake message. **Never** a `Authorization` header value. This is enforced by code review; the framework does not protect us from a sloppy `console.log`.

## related

- [`framing.md`](framing.md) — what flows inside the tunnel after the session is established.
- [`tokens.md`](tokens.md) — what authorizes the listen and dial WSes.
- [`pairing.md`](pairing.md) — how the device cert and device token come into being.
- [`../docs/architecture.md`](../docs/architecture.md) — trust boundaries, blind-by-construction invariant.
