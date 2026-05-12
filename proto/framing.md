# framing

The wire format that lets one tunnel WebSocket carry many concurrent logical streams. Lives between the TLS 1.3 record layer and whatever application-layer bytes the endpoints decide to send through it.

This is the SSH-channel-style multiplex. The prototype (tracked in sol pbc's internal engineering notes, §13.1) ran one request per tunnel — fine for vetting the relay, TLS, and hibernation paths, but not what v1 ships. v1 needs to load a journal page that pulls images, holds a server-sent-event stream, and opens a WebSocket for live updates concurrently. All of that has to multiplex onto the single WebSocket each side holds open through `spl-relay`.

This document is the contract between the home python module (`home/src/spl/framing.py`), the iOS client (`ios/Sources/SPLTunnel/Framing.swift`), and any future port (Android, browser bridge, etc.). The relay (`spl-relay`) does not parse frames — it forwards opaque bytes — so the contract is **between the two endpoints only**. That is the load-bearing fact: any framing change is a coordinated endpoint upgrade. The relay does not need a deploy.

The framing layer is **application-layer agnostic**. A `stream_id` is a labelled byte channel; it carries whatever bytes the endpoints agreed to send — HTTP/1.1 today, WebSocket frames after an upgrade, SSE events inside a long-lived HTTP response, or anything else. The framing code does not parse the payload; the home's link service pipes stream bytes into a local TCP connection, and the mobile side does the same at the app boundary. Blindness is not a property we enforce at the framing layer; it is a property we get for free because the layer above framing never inspects payload contents either.

## frame layout

Every frame has an 8-byte header followed by zero or more bytes of payload (`stream_id` u32 + `flags` u8 + `length` u24).

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          stream_id                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     flags     |                    length                     |
+-+-+-+-+-+-+-+-+                                               +
|                                                               |
+                          payload (length bytes)               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| field      | bytes | meaning |
|-----------|-------|---------|
| `stream_id` | 4 | unsigned big-endian; identifies one logical stream within the tunnel |
| `flags`     | 1 | bitfield (see below) |
| `length`    | 3 | unsigned big-endian; payload byte count, 0 ≤ length ≤ 16 777 215 |
| `payload`   | `length` | opaque application bytes (TLS-decrypted at this layer; the endpoints decide what protocol rides here — HTTP/WS/SSE in v1; framing doesn't care) |

Maximum frame payload is 16 MiB minus 1. In practice frames are much smaller — see *fragmentation* below.

### flags

Bit 0 is the low-order bit.

| bit | name      | meaning |
|----:|-----------|---------|
| 0   | `OPEN`    | this frame opens `stream_id`. payload may be empty or carry initial bytes. |
| 1   | `DATA`    | this frame carries application bytes for `stream_id`. set on every data frame. |
| 2   | `CLOSE`   | sender will write no more bytes on this stream; payload may be empty or carry final bytes. half-close. |
| 3   | `RESET`   | this stream is aborted; both sides drop pending buffers. payload is a 1-byte reason code (see below). |
| 4   | `WINDOW`  | this frame is a window-update for `stream_id`; payload is a 4-byte big-endian unsigned credit count. carries no data. |
| 5   | `PING`    | tunnel-level keepalive probe. `stream_id` MUST be 0. payload is an 8-byte nonce. see *control frames* below. |
| 6   | `PONG`    | matching reply to a `PING`. `stream_id` MUST be 0. payload is the same 8-byte nonce verbatim. |
| 7   | reserved  | must be zero on send; receiver MUST reject a frame with bit 7 set. |

**Valid combinations.** Exactly one of `OPEN | DATA | CLOSE | RESET | WINDOW | PING | PONG` MUST be set, except that `OPEN | DATA` MAY appear together (open with initial bytes) and `DATA | CLOSE` MAY appear together (last data frame also closes the writer). `PING` and `PONG` are mutually exclusive with each other and with every other flag — neither MAY be combined with `OPEN | DATA | CLOSE | RESET | WINDOW`. Any other combination is a protocol violation and the receiver MUST `RESET` the offending stream with reason `PROTOCOL_ERROR` (or, for malformed control frames on `stream_id = 0`, tear the tunnel down — control errors have no stream to reset on).

**Reset reason codes** (1-byte, in the `RESET` payload):

| code | name | meaning |
|-----:|------|---------|
| `0x01` | `PROTOCOL_ERROR` | malformed frame, illegal flag combination, unknown stream |
| `0x02` | `FLOW_CONTROL_ERROR` | peer sent more data than the window allowed |
| `0x03` | `STREAM_LIMIT_EXCEEDED` | peer opened more concurrent streams than the agreed cap |
| `0x04` | `INTERNAL_ERROR` | endpoint-local failure unrelated to the peer |
| `0x05` | `CANCEL` | application-initiated abort (e.g., user navigated away) |
| `0xff` | `UNSPECIFIED` | reserved fallback; senders SHOULD prefer a specific code |

Receivers MUST tolerate unknown reason codes (treat as `UNSPECIFIED`) — this lets the codes evolve without coordinated upgrades.

## stream lifecycle

```
  (none)
    │
    │  send/recv frame with OPEN flag
    ▼
  open
    │  ────► send/recv DATA frames freely
    │  ────► send/recv WINDOW frames to grant credit
    │
    ├─── send CLOSE ────► local-half-closed
    │                       │  recv CLOSE ────► closed
    │                       │  recv RESET ────► closed
    │
    ├─── recv CLOSE ────► remote-half-closed
    │                       │  send CLOSE ────► closed
    │                       │  send RESET ────► closed
    │
    └─── send/recv RESET ─► closed
```

A stream is half-close-aware: each side independently signals it is done writing. A stream is fully closed when both directions have CLOSE'd, or when either side RESET's. After close, the `stream_id` is free for reuse — but see *id allocation* for why we don't immediately reuse.

### id allocation

`stream_id` is allocated per-side, not per-tunnel. This avoids open/open races without a coordination round-trip:

- The **dialing side** (mobile) MUST use **odd** stream ids: `1, 3, 5, …`.
- The **listening side** (home) MUST use **even** stream ids: `2, 4, 6, …`. Home rarely opens streams unprompted in v1, but the convention is reserved so future server-push features (e.g., notifications) don't collide.
- `stream_id = 0` is reserved for tunnel-level control frames. v1 defines two: `PING` and `PONG` (see *control frames* below). It is illegal to OPEN, DATA, CLOSE, RESET, or WINDOW on `stream_id = 0` — receivers MUST treat such frames as a tunnel-fatal protocol error.
- Allocation is monotonic per side. **Do not reuse a closed `stream_id`** until at least 2² = 4 active streams have separated it from any in-flight RESET frames the peer may still emit. In practice: increment, never recycle. The 32-bit space is large enough that v1 will not exhaust it.

If a peer opens a `stream_id` outside its assigned parity, RESET with `PROTOCOL_ERROR`.

### concurrent stream cap

Either side MAY enforce a maximum number of concurrent open streams. If the peer attempts to OPEN beyond the cap, RESET that stream immediately with `STREAM_LIMIT_EXCEEDED`.

v1 default cap: **256 concurrent streams per direction.** This is generous for a journal app (a heavy page rarely exceeds 30) and tight enough to bound memory under a misbehaving peer. The cap is a local policy, not negotiated; future versions MAY add a SETTINGS exchange.

## flow control and backpressure

Without per-stream flow control, one fat upload would head-of-line block every other stream sharing the tunnel. The framing layer fixes this with a credit-based window per direction per stream, mirroring HTTP/2 and SSH semantics.

- When a stream OPENs, **each side starts with 1 MiB of send credit toward the other**. Total in-flight bytes on a stream cannot exceed the credit the sender holds.
- The receiver returns credit by sending a `WINDOW` frame whose 4-byte payload is an unsigned big-endian count of bytes to grant.
- The sender adds the granted credit to its remaining window. If credit ever exceeds 2³¹ − 1, RESET with `FLOW_CONTROL_ERROR` (this would only happen on a buggy peer).
- A sender with zero credit MUST NOT send DATA. It MAY send `CLOSE` (carrying no payload) or `RESET` regardless of credit.

The 1 MiB initial window is sized so a single TLS record (typically ≤16 KiB after fragmentation) never blocks waiting for a window update on an uncongested tunnel. For a streaming upload, the receiver's policy SHOULD grant credit as it drains the application — typical implementation: grant whatever is consumed every 64 KiB or every 100 ms, whichever comes first.

There is **no tunnel-wide credit window in v1.** The relay enforces no flow control across streams; the underlying WebSocket and TCP carry the only tunnel-level backpressure. This is sufficient because both endpoints are TLS terminators, and TLS handles record-level backpressure naturally. If a future version surfaces tunnel-wide head-of-line blocking, a tunnel-level WINDOW (`stream_id = 0`) is the obvious extension point.

## control frames

`stream_id = 0` is the tunnel-level control channel. v1 defines two control frames, `PING` and `PONG`, used to detect a silently-dead direct-mode TLS path so the client can re-dial with relay-preferred candidates.

### PING

| field | value |
|-------|-------|
| `stream_id` | `0` (MUST) |
| `flags` | `PING` (`0x20`) only |
| `length` | `8` |
| `payload` | 8-byte nonce, opaque to the wire; sender SHOULD use cryptographically-random bytes |

### PONG

| field | value |
|-------|-------|
| `stream_id` | `0` (MUST) |
| `flags` | `PONG` (`0x40`) only |
| `length` | `8` |
| `payload` | the nonce from the `PING` being acknowledged, copied verbatim |

### responder behavior

When a peer receives a valid `PING`, it MUST reply with a `PONG` carrying the same 8-byte nonce. The reply MUST be emitted promptly — implementations SHOULD treat the reply as higher priority than queued DATA frames on application streams. The reply is opaque at the framing layer; it does not interact with stream credit, the concurrent-stream cap, or stream lifecycle.

A peer MUST tolerate stray `PONG` frames it did not solicit (e.g., a `PONG` arriving after the side that sent the matching `PING` has already torn the keepalive down). Stray `PONG`s MUST be silently dropped, not treated as a protocol error.

### initiator behavior

v1 is asymmetric: the **dialing side** (mobile) drives keepalive on a direct-mode tunnel; the **listening side** (home) responds. Concretely:

- The mobile client opens a keepalive task immediately after the mux is established on a direct-mode candidate, and pings at a fixed cadence of **500 ms**.
- Each outstanding `PING` is tracked by its nonce. A `PONG` whose payload matches the outstanding nonce clears the pending state.
- If **3 consecutive pings** elapse without a matching `PONG` (≈1.5 s of silence), the client treats the direct TLS path as lost and tears it down, then re-dials with relay-preferred candidates.

These cadences are mobile-side policy; the framing layer does not encode them. A future version MAY change the cadence or add SETTINGS-style negotiation. Receivers MUST tolerate `PING` at any cadence — including bursts — without rate-limiting.

### why streamID==0 ping/pong, not HTTP HEAD

A direct-mode TLS path can go dark with no FIN, no RST, and no TLS alert — e.g., NAT rebinding on a backgrounded mobile foregrounding into Wi-Fi, or a flaky router silently dropping ESTABLISHED state. The TLS state machine has no application-layer liveness signal of its own, so we need one inside the tunnel. `PING/PONG` on `stream_id = 0` rides inside the inner TLS record stream, so it exercises the exact same wire that user requests will: a `PONG` round-trip is positive proof the direct TLS path is alive end-to-end.

The alternative — an HTTP `HEAD` to a sentinel route — also works, but it allocates a fresh mux stream every 500ms, churns server-side request logs, and conflates application-layer health with transport-layer liveness. A framing-layer ping has neither cost.

### tunnel-wide WINDOW extension point

The framing layer keeps `stream_id = 0` as the obvious extension point for a future tunnel-wide WINDOW frame (see *flow control*). `WINDOW` on stream 0 is reserved for that purpose and is currently a protocol error.

## ordering guarantees

- **Within a stream:** strict FIFO. The receiver's bytes arrive in the order the sender wrote them. This is what TLS over WebSocket gives us; the framing layer does not reorder.
- **Across streams:** no ordering guarantee. Two frames on different streams may interleave on the wire in either order.
- **Frame atomicity:** a frame is delivered as a unit. The receiver never sees a partial frame; the WebSocket layer's message boundaries are not relied on (we treat the WS as a byte stream and re-frame ourselves).

A sender MAY freely interleave frames from different streams to keep small streams responsive while a large stream is uploading. The recommended policy: emit at most one frame per stream before scheduling another stream — round-robin, not greedy.

## fragmentation

Application writes do not map 1:1 to frames. The framing layer fragments large writes and may coalesce small writes:

- **Fragmentation:** a write larger than the implementation's chunk size (recommended: 64 KiB) MUST be split into multiple DATA frames on the same stream. Each frame's `length` field reflects the chunk, not the total write.
- **Coalescing:** small writes MAY be coalesced into one DATA frame, provided ordering within the stream is preserved.
- **Empty DATA frames** (length = 0) are legal and MAY be used as a heartbeat-style nudge, but SHOULD be rare. Receivers MUST tolerate them.

64 KiB is the recommended max chunk because it matches the TLS record size cap (after fragmentation) and avoids surprising the WebSocket layer with a single very large message. Larger chunks are legal up to the 16 MiB hard limit.

## relationship to the relay

The relay (`spl-relay`) carries opaque bytes. It does not parse frames. It does not enforce credit. It does not enforce stream caps. It does not validate flag combinations. **All framing semantics are between the two TLS endpoints.**

This is load-bearing for the blind-by-construction claim. If `spl-relay` had to inspect frames to enforce flow control, it would have to decrypt the TLS record stream, which would defeat the whole architecture. The bytes the relay sees are TLS records — `framing` lives inside TLS.

The relay does enforce one thing relevant to framing: a per-tunnel pending-buffer cap (16 MiB, see [`session.md`](session.md)). This is independent of the framing window and exists only to bound the in-process buffer between the moment one side has attached and the moment the other side has. Once both sides are paired, the relay is a pure pump.

## evolution

The framing format is versioned implicitly by the JWT-authenticated tunnel session — both endpoints already trust the same sol pbc deployment, so format negotiation is a future feature, not a v1 concern. v1 ships the format above.

If the format changes incompatibly in a future version:

- Bit 7 (the remaining reserved flag bit, after `PING`/`PONG` took bits 5 and 6 in the streamID==0 control-frame addition) is the hook for an explicit version negotiation frame.
- Reset codes are extensible without coordinated upgrades (unknown codes degrade to `UNSPECIFIED`).
- Either side detecting a peer that violates v1 semantics MUST RESET the offending stream and SHOULD log a structured `framing_protocol_violation` event (with `tunnel_id`, `stream_id`, `flags`, `length` only — never payload).

## related

- [`session.md`](session.md) — the lifecycle of the tunnel WS that carries these frames.
- [`tokens.md`](tokens.md) — what authorizes a side to open the tunnel WS in the first place.
- [`pairing.md`](pairing.md) — how a mobile device first becomes able to dial a particular home.
- [`../docs/architecture.md`](../docs/architecture.md) — the trust boundaries that explain *why* framing is between endpoints, not at the relay.
