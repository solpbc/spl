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

**Addressing — the DO identity is the rendezvous match.** Both endpoints carry `RK` **in the upgrade request** (a request header, e.g. `Sec-Pair-Key: <RK hex>` — *not* the URL query, to keep `RK` out of edge access logs; routing happens at the HTTP layer, before any WS frame). `RK` MUST be accepted via the header only — no `?rk=` query fallback (the existing `?token=` fallback for service/device tokens must not be extended to `RK`). The Worker routes by `idFromName(RK_hex)` → a **distinct DO instance** addressed by `RK`. **Reuse the existing per-instance DO class** (it already carries the bridge machinery) addressed by `idFromName(RK)` rather than introducing a new DO class/binding; the RK-addressed instance is the ephemeral "pairing DO". Home and client presenting the same `RK` land in the **same DO instance** — that *is* the match. The relay performs **no `RK` value comparison** and stores no `RK` secret; it routes and bridges whoever is in the DO. The pairing endpoints (`/session/pair-window`, `/session/pair-dial`, and the pairing `/tunnel/<id>`) carry **no `?instance=`** — the Worker's instance-param guard must not apply to them. `RK` is never logged (log `instance_id` from the home's token + reason only).

### `GET /session/pair-window` (home → relay)

The home opens this WebSocket when the owner starts a pairing, **authenticated by its `service_token`** (`Authorization: Bearer …`, scope `session.listen`, `instance_id` claim), carrying `RK` in the upgrade header.

- The pairing DO verifies the `service_token` statelessly (JWKS) and confirms it is an enrolled, non-revoked home before accepting the socket — **only an enrolled home may open a window** (this gates window squatting). It records the home pair-window socket + the `instance_id` from the token (logging / optional entitlement only).
- The **window's lifetime is this socket's lifetime** (close → window gone). A relay-side **TTL backstop** (≥ 5 min, ≤ ~10 min) closes a stranded half-open window. One open window per DO (a second pair-window for the same `RK` replaces or is rejected).

### `GET /session/pair-dial` (client → relay)

The client derives `RK = HKDF(S, …)` and opens this WebSocket carrying `RK` in the upgrade header. No JWT.

- Routes to the same pairing DO. If a home pair-window socket is present: broker the tunnel to it (reuse the existing `brokerTunnel` / `signalIncoming` / `/tunnel/<id>` machinery) and **consume the window** (one-use; first dial wins, subsequent dials get a coarse `401`). If no home socket present: coarse `401`.
- A **failed-attempt limiter** (per pairing DO) bounds repeated dials to an empty/closed window.
- Oracle-safety: client-visible responses for the no-window / closed / not-yet-open cases are a **uniform coarse `401`**; any finer reason is logs-only.

### `/tunnel/<id>` (pairing)

Carries `RK` in the upgrade header, routes to the same pairing DO; bridges the client's pair-dial socket to the home's `/tunnel/<id>` socket. **Home-side attach is authenticated:** because `RK` is known to the *client* (it derived it), the home side of the bridge must NOT be occupiable by anyone presenting `RK` + `tunnel_id`. The existing per-instance tunnel attach gates the home on `service_token` (scope `session.listen`) **AND** `instance_id === routingKey`; that equality cannot hold here (routing key is `RK`). Replace it: the pairing `/tunnel/<id>` home attach MUST present a valid, non-revoked `service_token` whose `instance_id` **matches the `instance_id` that opened this DO's pair-window**. The client (pair-dial) side stays anonymous (gated downstream by the inner `ca_fp`/`S`). Reuse the existing `incoming{tunnel_id}` signal — no new WS-layer control type.

**Consume on success only:** the window is consumed (one-use) only when the broker actually succeeds. If the home pair-window socket is present at dial time but the `incoming` signal send fails (home just dropped), the window is **rolled back** (not consumed) so a legitimate retry can still broker — mirroring the existing `onSendFail` rollback.

### what stays on the per-instance DO

`/enroll/device`, `/session/listen`, `/session/dial`, entitlement, and revocation remain addressed by **`instance_id`**. The client reaches `/enroll/device` *after* it has learned `instance_id` from the inner TLS.

## client learns `instance_id` from the inner TLS

The pair-link carries no `instance_id`. After the inner pinned-TLS handshake (pinned to `ca_fp_spki` from the link), the home returns `instance_id` in the inner `PairResponse` (as today). Because the inner channel is cryptographically bound to the pinned CA, that value is trustworthy. The client:

1. takes `instance_id` from the `PairResponse`,
2. **SHOULD verify** `instance_id == jid_from_spki(pinned CA)` as an integrity check,
3. uses it for `/enroll/device` and for storing the dial address.

## failure reasons & oracle-safety

Because routing is by DO identity, a `pair-dial` either lands in a DO with a live home pair-window socket (→ broker) or it does not (→ **uniform coarse `401`**, covering no-window / closed / consumed / not-yet-open alike). The client cannot distinguish these, so an `RK`-less probe — or an `RK`-holder probing window state — learns nothing. Finer detail (which case, `instance_id` from the home's token) is **logs-only**. The home side, by contrast, *can* surface honest reasons over the inner TLS (e.g. nonce expired) since that channel is authenticated to the owner.

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
