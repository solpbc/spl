# pair-window — relay-form pairing admission (v2)

**Status:** active contract (2026-06-29). **Supersedes** the TOTP / `current_totp` / `pair_ticket` mechanism in [`tokens.md`](tokens.md) and the `0x03` relay QR form in [`pairing.md`](pairing.md). This is a **hard cutover**: relays and clients implement `0x06` only — there is no `0x03`/TOTP fallback.

This document specifies how a relay decides to bridge an off-LAN pairing dial to a home, replacing the rotating TOTP with a **home-opened pairing window** keyed by a single short-lived nonce. The home-side pairing nonce, the inner pinned-TLS ceremony, the CSR/cert exchange, `home_attestation`, and the device-token issuance are **unchanged** (see [`pairing.md`](pairing.md) steps 4–8 and [`tokens.md`](tokens.md) `/enroll/device`).

## model

Two trust boundaries, one nonce.

- **`S`** — an 8-byte (64-bit) single-use pairing nonce minted by the home per pairing. It is the home-side gate (the home verifies `S` over the inner TLS, exactly as the old nonce). Short-lived: 5-minute window.
- **`RK = HKDF-SHA256(IKM=S, salt="", info="spl-pair-window-v1", L=16)`** — the relay-side gate. The home registers `RK` with the relay; the client derives `RK` from `S` and presents it. The relay only ever sees `RK`. Because HKDF is one-way, a party holding `RK` cannot recover `S`, so the relay (or anyone who learns `RK`) cannot pass the home's `S` check → the relay stays **blind** and cannot forge a pairing.

`S` is the only secret in the link. `instance_id` is **not** in the link — the client learns it from the inner TLS (below).

### HKDF parameters (normative)

- HKDF per RFC 5869, hash = SHA-256.
- `IKM` = `S` (the 8 raw bytes).
- `salt` = empty → HKDF-Extract uses 32 zero bytes.
- `info` = ASCII `spl-pair-window-v1` (18 bytes, no terminator).
- `L` = 16 → `RK` is 16 bytes.

## pair-link wire format — version `0x06`

`https://go.solstone.app/p#<uppercase Crockford base32 of the blob>`. Form is discriminated by the first decoded byte (`version`), never by URL path.

| Offset | Len | Field | Encoding |
|--------|-----|-------|----------|
| 0 | 1 | version | `0x06` |
| 1 | 8 | `S` | 64-bit single-use pairing nonce |
| 9 | 1 | ca_fp_tag | `0x01` = SHA-256 over CA DER SPKI, first 16 bytes |
| 10 | 16 | ca_fp_spki | first 16 bytes of SHA-256 over the CA DER SubjectPublicKeyInfo |
| 26 | 1 | relay_origin_selector | `0x00` = well-known default relay; `N` (`1..255`) = custom origin byte length |
| 27 | N | relay_origin | UTF-8 bytes of the custom origin; omitted when selector is `0x00` |

Base size **27 bytes** (selector `0x00`). `ca_fp` is the SHA-256-over-SPKI pin (tag `0x01`), identical in meaning to the `0x03` form — parsers MUST key the pin algorithm off `version` + `ca_fp_tag`. The well-known default relay origin is `https://link.solstone.app`.

### conformance vectors (normative — byte-identity gate)

Fixed inputs: `S = 0123456789abcdef`, `ca_fp_spki = deadbeefcafebabe0123456789abcdef`.

```
S            = 0123456789abcdef
info         = "spl-pair-window-v1"
salt         = "" (-> 32 zero bytes)
RK (L=16)    = e34481a4cde647ba9c9fb29a59e18271
```

Default relay (`relay_origin = None`, selector `0x00`):

```
blob (hex) = 060123456789abcdef01deadbeefcafebabe0123456789abcdef00
fragment   = 0R0J6HB7H6NWVVR1VTPVXVYAZTXBW0938NKRKAYDXW00
link       = https://go.solstone.app/p#0R0J6HB7H6NWVVR1VTPVXVYAZTXBW0938NKRKAYDXW00
```

Custom relay (`relay_origin = https://relay.example`):

```
blob (hex) = 060123456789abcdef01deadbeefcafebabe0123456789abcdef1568747470733a2f2f72656c61792e6578616d706c65
fragment   = 0R0J6HB7H6NWVVR1VTPVXVYAZTXBW0938NKRKAYDXWAPGX3ME1SKMBSFE9JPRRBS5SJQGRBDE1P6A
link       = https://go.solstone.app/p#0R0J6HB7H6NWVVR1VTPVXVYAZTXBW0938NKRKAYDXWAPGX3ME1SKMBSFE9JPRRBS5SJQGRBDE1P6A
```

Every client parser + the journal encoder MUST reproduce these bytes exactly. Inline these vectors verbatim into each implementing lode's tests; gate on byte-identity post-ship.

## relay endpoints

### `GET /session/pair-window` (home → relay)

The home opens this WebSocket when the owner starts a pairing, **authenticated by its `service_token`** (`Authorization: Bearer …`, scope `session.listen`, `instance_id` claim). It carries `RK` (as the first control frame, never in the URL — see logging).

- Routing: addressed by **`RK`** → `idFromName(SHA256(RK))` (keep raw `RK` out of the DO namespace). This is an **ephemeral pairing DO**, distinct from the home's per-instance DO.
- The pairing DO verifies the `service_token` statelessly (JWKS), confirms it is an enrolled home, and records `(RK, home pair-window socket)` plus the `instance_id` from the token claims (logging/optional entitlement only). **Only an enrolled home may open a window for a given `RK`.**
- The **window's lifetime is this socket's lifetime** (close → window gone). A relay-side **TTL backstop** (≥ 5 min, ≤ ~10 min) closes a stranded half-open window.
- One open window per `RK`.

### `GET /session/pair-dial` (client → relay)

The client derives `RK = HKDF(S, …)` and opens this WebSocket presenting `RK` (first control frame). No JWT.

- Routing: addressed by the same **`RK`** → same ephemeral pairing DO.
- The DO **constant-time matches** the presented `RK` to an open pair-window socket. On match: broker the tunnel to that socket (reuse the existing `brokerTunnel` / `signalIncoming` / `/tunnel/<id>` machinery), then **consume** the window (one-use; remove `RK`). On no match / expired / closed: coarse `401`; a detailed reason is returned only after a structurally-valid `RK` for the window (see oracle-safety).
- A **failed-attempt limiter** (per pairing DO) bounds repeated bad-`RK` traffic.

### `/tunnel/<id>` (pairing)

Routed by `RK` to the same pairing DO; bridges the client's pair-dial socket to the home's `/tunnel/<id>` socket. Unchanged in mechanics from the existing tunnel bridge — only the addressing key is `RK`, not `instance_id`.

### what stays on the per-instance DO

`/enroll/device`, `/session/listen`, `/session/dial`, entitlement, and revocation remain addressed by **`instance_id`**. The client reaches `/enroll/device` *after* it has learned `instance_id` from the inner TLS.

## client learns `instance_id` from the inner TLS

The pair-link carries no `instance_id`. After the inner pinned-TLS handshake (pinned to `ca_fp_spki` from the link), the home returns `instance_id` in the inner `PairResponse` (as today). Because the inner channel is cryptographically bound to the pinned CA, that value is trustworthy. The client:

1. takes `instance_id` from the `PairResponse`,
2. **SHOULD verify** `instance_id == jid_from_spki(pinned CA)` as an integrity check,
3. uses it for `/enroll/device` and for storing the dial address.

## failure reasons & oracle-safety

The relay distinguishes `window_closed` / `revoked` / `bad_rk` / `malformed` internally, but returns them to the client **only after** a structurally-valid `RK` is presented for an open window. Unknown / malformed / no-window cases return a **coarse `401`**; precise reasons go to logs (`instance_id` + reason only). This reconciles friendlier client errors with not leaking instance/window state to an `RK`-less probe.

## logging contract

Never log `S`, `RK`, the pair-link fragment, or the inner nonce. Log only `instance_id` (when known from the token) + reason + window event type.

## what is deleted (hard cutover)

- The `current_totp` field in the QR; the `0x03` relay form entirely.
- The relay `totp_secret` column + `verifyTotp` + the `pair_ticket` JWT (scope `session.pair`) + `/session/pair-ticket` + the `pair_jti_consumed` / `pair_rate` tables.
- The home `totp.json` + `compute_current_totp` + `generate/load/save_totp_secret` + the `totp_secret` field on `/enroll/home`.

## related

- [`pairing.md`](pairing.md) — the full ceremony; steps 4–8 (inner TLS, CSR, cert, attestation) are unchanged.
- [`tokens.md`](tokens.md) — service/device tokens + `home_attestation` (unchanged); the pair-ticket sections are superseded by this doc.
- [`session.md`](session.md) — the tunnel/bridge lifecycle reused here.
