# session

The lifecycle of a tunnel: how the home's listen WebSocket, the mobile's dial WebSocket, and the relay's pairing logic come together to make opaque bytes flow between two endpoints.

This document is the contract for the WebSocket dance — what each side opens, when, in what order, and how disconnects are handled. It does not define the bytes that flow inside the tunnel (that's [`framing.md`](framing.md)) or the credentials that authorize the dance (that's [`tokens.md`](tokens.md), [`pairing.md`](pairing.md)).

## actors and surfaces

Five WebSocket endpoints on `spl-relay`:

- `GET /session/listen` — home upgrades to WS; carries a service-token bearer. One per home, held open indefinitely.
- `GET /session/dial` — mobile upgrades to WS; carries a device-token bearer. One per mobile dial; **becomes** the mobile-side tunnel WS once paired.
- `GET /session/pair-window` — home upgrades to WS; carries a service-token bearer and `RK` in `Sec-Pair-Key`. Home-opened off-LAN pairing window; no `?instance=`.
- `GET /session/pair-dial` — mobile upgrades to WS; carries `RK` in `Sec-Pair-Key`, anonymously, with no token and no `?instance=`. Routes to the RK-addressed DO and **becomes** the mobile-side tunnel WS once paired, exactly like `/session/dial`.
- `GET /tunnel/<id>` — home upgrades to WS; carries the service-token plus a `tunnel_id` minted by the relay. One per active tunnel on the home side; opened in response to a pair signal.

Pair-window admission is specified in [`pair-window.md`](pair-window.md).

The asymmetry is deliberate. The mobile opens **one** WebSocket per dial (the dial WS becomes the tunnel WS — single-WS-per-side, prototype finding §11.1, saves ~40-80 ms per cold request). The home opens **one** persistent listen WS plus **one** transient tunnel WS per active tunnel.

## endpoint shapes

### listen — home → spl-relay

```
GET /session/listen HTTP/1.1
Host: link.solstone.app
Upgrade: websocket
Connection: Upgrade
Authorization: Bearer <service_token>
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

### dial — mobile → spl-relay

```
GET /session/dial?instance=<paired_instance_id> HTTP/1.1
Host: link.solstone.app
Upgrade: websocket
Connection: Upgrade
Authorization: Bearer <device_token>
Sec-WebSocket-Key: ...
```

Query parameter `instance` names the home this dial targets; must match the `instance_id` claim on the device token.

After upgrade, this **same WebSocket** becomes the mobile-side tunnel WS once the relay has paired it with a home tunnel WS. There is no second WS open from the mobile. The mobile waits for the relay to attach the home side, then begins TLS 1.3 over this WS toward the home.

### pair-window — home → spl-relay

```
GET /session/pair-window HTTP/1.1
Host: link.solstone.app
Upgrade: websocket
Connection: Upgrade
Authorization: Bearer <service_token>
Sec-Pair-Key: <RK hex>
Sec-WebSocket-Key: ...
```

`RK` is accepted in the `Sec-Pair-Key` header only, never `?rk=`, and there is no `?instance=`. The relay routes to the RK-addressed DO; the DO records the `instance_id` from the service token for admission/logging.

### pair-dial — mobile → spl-relay

```
GET /session/pair-dial HTTP/1.1
Host: link.solstone.app
Upgrade: websocket
Connection: Upgrade
Sec-Pair-Key: <RK hex>
Sec-WebSocket-Key: ...
```

After upgrade, this **same WebSocket** becomes the mobile-side tunnel WS once the relay has paired it with a home tunnel WS. It is byte-for-byte the same relay tunnel shape as `/session/dial`; only the admission surface differs.

### tunnel — home → spl-relay

```
GET /tunnel/<tunnel_id> HTTP/1.1
Host: link.solstone.app
Upgrade: websocket
Connection: Upgrade
Authorization: Bearer <service_token>
Sec-WebSocket-Key: ...
```

`<tunnel_id>` is the value the relay sent on the home's listen WS via the `incoming` control message. The home opens this WS in response to the signal; the relay matches it to the waiting mobile-side dial WS by `tunnel_id`.

The home opens one tunnel WS per concurrent tunnel. The listen WS stays open across many tunnels.

## the dance, step by step

```
home                          spl-relay                              mobile
----                          -----                              ------

(1) listen WS open ─────────▶ validate service token
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
    home checks fingerprint
    against authorized_clients.json
    in the file  → completes
    not in it    → alert 49, drop
    unreadable   → alert 46, drop

(8) framed HTTP/SSE/WS         ◀── frames forwarded ───▶            mobile UX
    inside the tunnel
```

Numbered steps:

### 1. listen — home opens at solstone startup

The home's `spl.tunnel` task opens `GET /session/listen` to `spl-relay` immediately on solstone startup. It carries the service token in the `Authorization` header. The relay validates the token (see [`tokens.md`](tokens.md)), records this WS as the ready listen socket for the home's `instance_id`, and holds the WS open. The home sends no further bytes on this WS — it only reads.

### 2. dial — mobile opens when the owner opens the app

When the owner opens the solstone mobile app and the app foregrounds, the mobile opens `GET /session/dial?instance=<id>` to `spl-relay`, carrying the device token. The relay validates the token and the matching `instance_id`, mints a `tunnel_id`, and records the mobile's WS as one half of the (not yet complete) tunnel.

### 3. pair signal — relay tells the home

The relay sends a single control frame on the home's listen WS:

```json
{ "type": "incoming", "tunnel_id": "<uuidv4>" }
```

This is a structured JSON message in a WebSocket text frame. It is the **only** message the home receives on its listen WS, and per *WS-layer minimality* (below) any future addition at this layer is bounded to TLS-establishment-related signaling — endpoint-to-endpoint application data does not belong here. The home parses defensively and ignores unknown message types.

### 4. tunnel — home opens on the signal

The home reacts to the `incoming` signal by opening `GET /tunnel/<tunnel_id>` to `spl-relay`, carrying the service token and the `tunnel_id` from the signal. The relay matches the WS against the recorded entry by `tunnel_id`.

### 5. pair — relay matches the two WSes

In the relay's Durable Object, both halves of the tunnel are now attached. The DO's pairing logic uses `getWebSockets("tunnel_home:" + tunnel_id)` and `getWebSockets("tunnel_mobile:" + tunnel_id)` to retrieve them, asserts cardinality (see *cardinality* below), and begins forwarding.

### 6. relay — opaque byte pump

From this point, the relay is a pure byte pump. Bytes received on the home WS are forwarded to the mobile WS unchanged; bytes received on the mobile WS are forwarded to the home WS unchanged. The relay does not parse, does not reframe, does not buffer beyond what's necessary to handle one side's send-while-other-side-not-yet-attached (see *pending buffer* below).

### 7. inner TLS handshake

With the byte pipe open, the mobile initiates TLS 1.3 toward the home. The mobile presents the paired client cert (from Keychain). The home's TLS server presents its self-signed cert (from the local CA). The home checks the SHA-256 fingerprint of the client cert against `authorized_clients.json` **inside the handshake**, so an unauthorized device never reaches the application.

Three outcomes at a home implementing this section, and the two that abort carry different alerts:

- **The fingerprint is in the file.** The handshake completes and application traffic begins.
- **The home read the file and the fingerprint is not in it** — the device was unpaired, or was never paired. Alert `access_denied` (49).
- **The home could not read the file** — it is unreadable, or its contents do not parse. Alert `certificate_unknown` (46).

An unreadable `authorized_clients.json` authorizes nobody, so refusing is the same act in both cases; only the alert code differs. There is nowhere else for the difference to travel, because the handshake fails before any application byte and there is no response body to put it in. On a single alert for both, a home whose file is briefly unreadable tells every device that connects during that window it was unpaired, and each one discards a working credential and walks its owner through a re-pair that nothing required.

This section assigns two codes, and both are new, so no home in the field sends either one. A home predating this section refuses an unauthorized device with whatever its TLS stack produces for a failed authorization callback: OpenSSL's is `internal_error` (80).

A client MUST discriminate on the alert code. Two codes carry the meanings above; every other code is one rule:

- `access_denied` (49) — unpaired. Present `LITERAL: "This device was unpaired from your solstone."`, require a re-pair, and stop retrying.
- `certificate_unknown` (46) — retry on the schedule under *mobile reconnect* and keep the credential. Present no unpaired message; the reconnect banners there still apply. ⚠ This branch is deliberately unbounded, unlike the one below: the credential is still valid and the home is expected to recover, so there is nothing for the owner to do and nothing to warn them about.
- **every other code** — retry on that same schedule, and once refusals under this branch have continued long enough, present the unpaired message and stop retrying.

Three things about that last branch decide whether two clients agree, so they are stated rather than left to be inferred:

- **Only a completed handshake clears the state.** A refusal never clears it, whatever code it carries.
- **A `certificate_unknown` (46) neither advances nor clears it.** It belongs to the unbounded branch, so counting it in would eventually tell an owner they were unpaired because their home's file was briefly unreadable — the harm this whole section exists to prevent. Letting it clear the state would let a home alternating 46 with another code retry forever, which is the same defect from the other side.
- ⛔ **Do not key it on one code repeating.** A home alternating its refusal code with an occasional transport error would reset a per-code counter forever, leaving an unpaired owner retrying with no re-pair ever offered.

⚠ **How long, or how many refusals, is owned by the client — but the measure only advances while attempts are actually being refused.** A client that is simply offline is not being refused: a phone that took one refusal and then spent two days without a network must not come back to an unpaired message and a discarded credential.

The catch-all is deliberately one rule rather than a table, because it has to be right without knowing which home it is talking to. `internal_error` (80) lands here, so a device unpaired by a home predating this section is still told, eventually. A transient chain or transport error also lands here and resolves before it can persist. And a *persistent* certificate problem — a home that regenerated its CA, a corrupted keychain entry — lands here too, where a re-pair is the remedy anyway. ⛔ **Do not narrow this to a set of recognized codes.** A client that treats unrecognized codes as transient forever leaves an unpaired owner with no re-pair affordance, which is worse than not implementing the split at all.

⚠ **`internal_error` (80) is deliberately not the code for the unreadable-file case**, even though it is the natural reading of a server that cannot consult its own configuration. It is what a home predating this section already sends, so reusing it would collapse the new transient case into the legacy one.

**A home MUST NOT signal an authorization outcome with `unknown_ca` (48) or `bad_certificate` (42).** Those describe the certificate or its chain. A paired device's cert is signed by the home's own CA and matches during chain validation, so a chain error means something else went wrong; authorization sits above the chain, and reporting a chain error for an authorization outcome points the client at the wrong layer.

`authorized_clients.json` is mtime-polled at 0.5 s; revocation propagates within a second of the file edit (see [`pairing.md`](pairing.md) for the revocation flow).

### 8. application traffic

After TLS, the mobile speaks HTTP (with multiplexed streams per [`framing.md`](framing.md)) toward the home's app — convey on solstone, or any other HTTP server the operator runs.

The link service on the home side is a **dumb byte pipe**. For each incoming stream it opens a plain TCP connection to `127.0.0.1:<app_port>` and pumps bytes bidirectionally:

```
tunnel stream reader ──► socket writer
socket reader        ──► tunnel stream writer
```

No HTTP parsing, no WSGI environ, no internal hand-off through a framework's request object. Half-close on the tunnel stream (stream CLOSE) translates to `shutdown(SHUT_WR)` on the TCP socket, and half-close on the TCP socket (EOF) translates to stream CLOSE. A stream RESET closes the socket abruptly; a socket error RESETs the stream with `INTERNAL_ERROR`.

This choice is load-bearing. Image loads, SSE feeds, and **WebSocket upgrades** all flow through the same tunnel WS, multiplexed by stream id, because the tunnel layer sits below HTTP. Frameworks that hijack the underlying socket to service a protocol upgrade (`flask-sock`, `starlette`'s WebSocket endpoints, `Hypercorn` / `uvicorn` with HTTP/2 push, chunked-transfer responses) work without special cases in the link service — they would not work through a WSGI callable, which cannot surrender a socket.

## off-LAN pairing (pair-window + pair-dial)

Off-LAN pairing reuses the same relay tunnel shape. The relay's role is limited to brokering an ordinary tunnel through a home-opened pairing window. The authoritative contract is [`pair-window.md`](pair-window.md).

Flow at the relay boundary:

1. The home opens `GET /session/pair-window` with `Sec-Pair-Key: <RK hex>` and a service token. `RK = HKDF(S)` is derived from the home-side pairing nonce `S`.
2. The phone scans the pair link, derives the same `RK` from `S`, and opens `GET /session/pair-dial` with `Sec-Pair-Key: <RK hex>`. The dial is anonymous: no token and no `?instance=`.
3. The relay routes both sockets to the RK-addressed DO, brokers an ordinary tunnel, and consumes the one-use window on successful broker. First dial wins; later dials get the same coarse unauthorized response.
4. The home receives the byte-identical control message it gets for a normal dial:

```json
{ "type": "incoming", "tunnel_id": "<uuidv4>" }
```

There is no new WebSocket message type.

The relay-side TTL backstop closes a stranded pair-window. No-window, closed-window, consumed-window, and limiter cases return a uniform coarse `401` to the pair-dial client.

The home admits the cert-less tunnel and runs its pairing handshake (`/pair` + `/enroll/device`) inside the inner TLS. That handshake is home-side and out of scope for `spl-relay`.

### blindness is structural

The link service on the home side never parses, interprets, or transforms the application-layer protocol (HTTP, WS, SSE, HTTP/2, raw bytes) flowing through it. Its only two operations on stream contents are `socket.read` and `socket.write`. This is the blindness invariant made structural, not promise-based:

- The relay cannot see TLS plaintext because it holds no key.
- The link service cannot see application semantics because its code contains no parser.

A code reviewer looking at either layer can verify blindness by reading a small amount of code — not by auditing every commit for "did someone add logging that includes payload bytes?" The shape of the pipe prevents the class of mistake.

## WS-layer minimality

Cloudflare terminates the outer TLS connection on each WebSocket between an endpoint and `spl-relay`. Anything written at the WebSocket protocol layer — JSON control messages, header values, framing metadata — is plaintext to CF the operator and to anyone with subpoena access to CF, regardless of how the worker code chooses to handle it. The relay's blindness about the inner TLS payload (above) is a property of cryptographic layering. Blindness about everything else has to be a property of **what bytes can structurally exist at the WS layer at all.**

The discipline:

> The WebSocket protocol surface between endpoints (home, mobile) and `spl-relay` exists **solely** to broker inner-TLS tunnel establishment.

**Acceptable at the WS layer:**

- Dial signaling — the HTTP+upgrade exchanges on `/session/listen`, `/session/dial`, `/session/pair-window`, `/session/pair-dial`, `/tunnel/<id>` and their required rendezvous headers (`Authorization` where token-authenticated, `Sec-Pair-Key` where RK-addressed).
- The `incoming` / `tunnel_id` control message from relay to home (above, §3).
- Opaque ciphertext payload of inner-TLS records, framed as binary WS messages.
- WebSocket transport keepalive (RFC 6455 Ping/Pong; see *no app heartbeat* below).

Pair-dial deliberately reuses the existing `incoming` control message and adds no new WS-layer message type. The operator gate for this surface was cleared 2026-05-29.

**Not acceptable at the WS layer:**

Any application-layer or device-to-device data, however small, however framed as "opaque to the relay code." This includes — but is not limited to:

- LAN endpoint advertisements (the originating motivating case — the LAN-direct path)
- Capability or version hints
- Presence signals
- Key fingerprints or instance metadata beyond what's already inside the bearer tokens
- Owner identifiers
- Any field whose presence or contents would describe runtime state of the home or the mobile

Such data carries **inside the inner TLS** — as ordinary application traffic to convey on the home, or to a future explicit mux-level control stream below the application protocol (see [`framing.md`](framing.md)). The home and the mobile have a private encrypted channel; that's the only legitimate venue for endpoint-to-endpoint negotiation.

This is the same shape of move as *blindness is structural* (above): we make the privacy property a property of the transport rather than a property of how the relay code is written. A reviewer can verify the property by enumerating the small set of message types accepted at WS-message handlers — they don't have to audit "did someone add a control-message type that captures the contents of a new field?"

The discipline also rules out a class of leak by construction: a coding-agent or contributor extending the wire protocol cannot accidentally add an endpoint-to-endpoint feature at the WS layer, because the rule against doing so is at the design layer, not buried in privacy-review checklists.

**Gate.** A new control-message type at the WS layer requires explicit operator review — the same gate as adding a listening port to the home's `link` service.

**Origin.** The first design pass for the LAN-direct path proposed an `endpoint_advertisement` JSON message at the WS layer ("opaque to relay code"). The operator caught the leak: even with the relay code declining to parse the field, CF terminates the outer TLS and could log, store, or be subpoenaed for the contents. The corrected design moves the advertisement into a convey API call inside the inner TLS. This invariant generalizes the lesson so future spl features don't re-tread the same path. Established 2026-05-10.

## hibernation

Cloudflare hibernates idle Hibernatable WebSockets after ~10 seconds of inactivity. This is aggressive but cheap. The Hibernation API answers Ping automatically, does not invoke `webSocketMessage` for control frames, and does not interrupt hibernation; control frames never enter the forwarding or pending-buffer path:

- **Listen WS:** hibernates between dials. Wake on the next `incoming` signal pre-empt; transport Ping/Pong control frames do not wake it (see *no app heartbeat* below).
- **Tunnel WS:** hibernates between bursts. Every mobile request after ≥10 s of inactivity pays wake cost.
- **Wake cost is low and flat across idle duration.** Prototype measurements (§3): 1-min idle p50 = 157 ms, 5-min idle p50 = 37 ms. Both well under the 500 ms criterion. There is no growing tax on longer idle periods (§11.2).

The 30-min and 2-hr profiles weren't measured in the prototype session; the 30+ min listen WS held open without app heartbeats is observational evidence that hibernation works at those durations too. Confirmed measurements of the 2-hr profile remain a v1 alpha follow-up (not blocking).

## no app heartbeat

v1 ships **no application-level heartbeat** and no heartbeat alarm. The home uses only RFC 6455 control frames:

- home -> relay: RFC 6455 Ping with exactly 8 opaque random bytes
- relay -> home: RFC 6455 Pong with the identical 8 bytes
- home interval: 30 seconds; home acknowledgement timeout: 10 seconds

CF's Hibernation API answers Ping automatically, does not invoke `webSocketMessage` for control frames, and does not interrupt hibernation. Control frames never enter the forwarding or pending-buffer path. No heartbeat payload is persisted.

## reconnect semantics

### home reconnect — listen WS

The listen WS may disconnect for any reason — network flap on the home machine, `spl-relay` deploy, transient CF edge churn, etc. The home reconnects with **exponential backoff**:

- Initial delay: 1 s.
- Multiplier: 2× each failed attempt.
- Cap: 60 s.
- Reset to 1 s only after the reconnected listen WS remains established without transport failure for 60 s. Connection establishment alone does not reset backoff; a connection that fails before the stability interval advances to the next delay.
- Jitter: ±25% on each delay to avoid synchronized reconnect storms after a CF deploy.

While the listen WS is down, the home cannot receive `incoming` signals. By default (`PRESENCE_HOLD_ENABLED` off), new dials from a paired mobile fail at the relay (the DO marks the home as not-ready and the dial returns 503). With `PRESENCE_HOLD_ENABLED` enabled, the relay holds the dial WS open and brokers it when the home's listen WS reconnects. The mobile's reconnect logic handles this; the owner sees `LITERAL: "Reconnecting…"` for the brief outage and `LITERAL: "Offline — check your connection."` if it persists past a small grace window.

### mobile reconnect — dial WS / tunnel WS

The mobile dial-turned-tunnel WS disconnects on:

- App backgrounding (iOS suspends after 20 s grace; the WS naturally drops).
- Network change (wifi ↔ cellular).
- TLS-handshake failure.
- `spl-relay` deploy.

Except where § 7 says to stop retrying, the mobile reconnects on next owner-visible activity (foreground, scroll, tap). Backoff is: 1 s, then 5 s, then 10 s, capped at 30 s, with the same ±25% jitter. Connection establishment alone does not reset backoff. The dialer retains its current attempt until a tunnel generation remains connected without transport or keepalive failure for 60 s; only then does the next automatic reconnect start again at 1 s. An explicit owner-initiated start or stop begins a fresh backoff sequence. The home and mobile use different delay schedules, but the same demonstrated-stability reset condition. The mobile's UX handles "Reconnecting…" / "Offline" banners.

§ 7 owns which handshake refusals stop retrying and what the mobile presents; that is not restated here, because two normative lists would drift. This section owns only the schedule they run on, above.

### waiting-dial lifecycle (presence-hold)

Presence-hold is flag-gated and default-off. When `PRESENCE_HOLD_ENABLED` is enabled, the relay accepts a mobile dial as a waiting dialer (`101 Switching Protocols`) and tags it for both waiting-dial discovery and its tunnel. An idle held dial has no timer and no alarm. The first buffered mobile-to-home byte starts one in-memory, per-tunnel 20-second home-attach lease. Successful attach and drain clear the lease; expiry frees pending state, logs the existing `tunnel_mobile_close` event with `attach_timeout`, and closes the mobile with 1013 / `home attach timeout`.

When a home listen WS appears, the relay sends the existing `incoming` control message once for each unpaired, non-retired waiting dial in that listener generation. A later listener generation may re-offer the same still-unpaired tunnel ID; a paired tunnel is never re-offered. A `retired` attachment is an error-cleanup marker, distinct from `paired` ownership, and is never eligible for another offer. Presence-hold adds no new WS-layer message type. The home then opens `/tunnel/<tunnel_id>` exactly as in the normal session flow, and any pending mobile bytes drain through the existing pending-buffer path.

The waiting-phase timeout is owned by the client and is out of scope for the relay. If the dialer gives up, the network drops, a deploy disconnects sockets, or Cloudflare reaps a dead peer, the close path frees the socket state and any pending buffer for that tunnel.

## deploy-disconnect

Every `spl-relay` Worker redeploy disconnects every WebSocket. This is a CF property of the Hibernatable WebSocket API — the new code version cannot inherit live sockets from the old version.

Behavior:

- Both sides observe a clean WebSocket close (typically code 1006 abnormal closure or 1012 service restart).
- Both sides reconnect per the backoff rules above.
- **Pair state is not preserved.** All in-flight `tunnel_id`s are invalidated. The mobile's next dial mints a new `tunnel_id`; the home opens a fresh tunnel WS in response to the new `incoming`.
- **Pairing material is preserved.** The home's CA, the mobile's client cert, the device tokens, and the service tokens all survive — they live in their respective stores, not in the Worker. **No re-enrollment is required.**

Acceptance criterion (per spec): clients reconnect within 10 seconds of a Worker redeploy without requiring re-pair. Prototype did not measure this directly (§7); MVP test suite covers it.

Operational implication: deploy cadence on `spl-relay` is low. We don't ship features weekly. Every deploy is a customer-visible blip; only ship when it's worth that.

## cardinality

The DO uses `getWebSockets(tag)` to look up sockets by tag. The relay tags sockets as:

- `listen:<instance_id>` for the listen WS.
- `tunnel_home:<tunnel_id>` for the home tunnel WS.
- `tunnel_mobile:<tunnel_id>` for the mobile dial-turned-tunnel WS.

Each tag MUST resolve to exactly one offerable WebSocket. CLOSING sockets returned by `getWebSockets()` are not offerable. Listen attachments carry a persisted, strictly increasing generation; only the highest offerable generation may offer or re-offer an unpaired held tunnel ID. If a duplicate WS attaches under any of these tags (e.g., a home reconnects without the previous WS having been observed as closed), the relay closes the duplicate and keeps the most recently attached. Prototype finding §11.4 — the API doesn't enforce cardinality, the application must.

Presence-hold also uses `waiting_dial:<instance_id>` as a many-valued discovery tag for held dials. It is intentionally excluded from the exact-one cardinality invariant: one instance may have N waiting dials.

## pending buffer

Between the moment one tunnel side has attached (e.g., mobile dial completed, `tunnel_id` minted) and the moment the other side attaches (home opens `/tunnel/<id>` in response to `incoming`), the relay buffers any frames sent by the attached side in memory. In practice this window is ~100-200 ms and the buffered content is the TLS ClientHello (~1-2 KB).

The buffer is **capped at 16 MiB per tunnel**. If the cap is exceeded:

- The relay logs a structured `pending_buffer_overflow` event with `tunnel_id`, `direction`, and `byte_count`. **No payload bytes.**
- The relay closes both sides of the (incomplete) tunnel with WebSocket close code `1009` (message too big).
- The DO frees the buffer and the `tunnel_id` is retired.

Sixteen MiB is generous; a healthy v1 client will buffer ≤2 KiB. The cap exists to bound memory under a misbehaving or attacking peer that opens a dial WS, sends a flood, and never connects the home side.

Once both sides are paired, the buffer is drained and the relay reverts to direct forwarding. A drain send failure closes both halves with 1011, clears the remaining buffer and any attach lease, and never leaves a paired tunnel established from a partial drain. From that point, backpressure is the WebSocket layer's job (via TCP and the framing-layer credit windows — see [`framing.md`](framing.md)).

## clean disconnect

Both sides may close at any time. The relay propagates close events across the pair:

- Home tunnel WS closes → relay closes mobile tunnel WS with the same close code.
- Mobile tunnel WS closes → relay closes home tunnel WS with the same close code.

The listen WS closing does **not** close active tunnel WSes — those continue until either side hangs up. The relay does, however, refuse new dials while the listen WS is down.

## what `spl-relay` logs about a session

For audit and debugging, the Worker emits structured log events at session boundaries. Logged fields are an exhaustive list:

- `tunnel_id` (uuid)
- `instance_id` (uuid)
- `direction` (one of `home_to_mobile`, `mobile_to_home`, or `meta`)
- `event` (one of `listen_open`, `listen_close`, `dial_open`, `dial_close`, `tunnel_home_open`, `tunnel_home_close`, `tunnel_mobile_open`, `tunnel_mobile_close`, `pair`, `fwd`, `pending_buffer`, `pending_buffer_overflow`, `unauthorized`, `cardinality_violation`, `enroll_home`, `enroll_device`, `enroll_device_remint`, `device_refresh`, `enroll_home_rotate`, `enroll_rejected`, `pair_window_open`, `pair_window_close`, `pair_dial_open`, `pair_dial_rejected`, `entitlement_set`, `entitlement_pending`, `entitlement_revoke`, `pending_grant_claimed`, `admin_instances_list`, `admin_instance_show`, `not_entitled`, `internal_error`)
- `byte_count` (when applicable)
- `close_code` (when applicable)
- `reason` (on close/error events; a relay-authored classification drawn from a fixed closed set)
- `duration_ms` (on close events)
- `timestamp`

**Never** a payload byte. **Never** a token claim. **Never** a TLS handshake message. **Never** an `Authorization` header value. **Never** `S`, `RK`, the pair-link fragment, a token value, or the home-side nonce. This is enforced by code review; the framework does not protect us from a sloppy `console.log`.
The peer-supplied WebSocket close-reason string is never logged and cannot select
the relay-authored close classification.
Server-driven attach expiry uses `attach_timeout`; a failed pending drain uses `pending_drain_failed`. Both are fixed relay-authored classifications, and the relay explicitly emits their close events because server-initiated closes do not invoke the close callback.

## related

- [`framing.md`](framing.md) — what flows inside the tunnel after the session is established.
- [`tokens.md`](tokens.md) — what authorizes the token-authenticated listen, dial, and pair-window home-side WSes.
- [`pairing.md`](pairing.md) — how the device cert and device token come into being.
- [`../docs/architecture.md`](../docs/architecture.md) — trust boundaries, blind-by-construction invariant.
