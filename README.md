# sol private link (spl)

**Blind byte-relay rendezvous service.** Two paired endpoints meet through Cloudflare's edge without Cloudflare — or sol pbc — ever seeing inside the tunnel.

> spl is blind by construction. Cloudflare and sol pbc hold no key that could decrypt traffic inside the tunnel. Revocation is local. Open source so you can verify.

## what it is

spl gives two paired endpoints (today: a solstone home server and a paired mobile app) a way to reach each other over the public internet without exposing either to it. Cloudflare holds two WebSockets and shovels opaque bytes between them. Inside the tunnel, the endpoints run TLS 1.3 end-to-end; the server authenticates the rendezvous, never the payload.

- **Operator:** sol pbc (hosted `spl-relay` relay at `link.solstone.app`). Or run your own — the whole server is in this repo.
- **License:** [AGPL-3.0-only](LICENSE).
- **Status:** pre-MVP, closed alpha approaching. Architecture vetted end-to-end by prototype (2026-04-18). See the [roadmap](https://github.com/solpbc/spl/blob/main/docs/roadmap.md) when published.

## architecture

```
solstone (home, python)          sol-pbc CF ("spl-relay")            mobile app (swift/kotlin)
-----------------------          --------------------            ------------------------
POST /session/listen ────────▶   Workers: validate
  Authorization: service_token     service token
                                  DO.setReady(instance_id)
                              ◀── hold-open WS (the "listen" socket)

                                                         POST /session/dial ────────────────▶
                                                            target: <instance_id>
                                                            Authorization: device_token
                                                         DO: mint tunnel_id + dial_ticket
                                                         ◀── { tunnel_id, dial_ticket }

                              ◀── DO pushes "incoming"
                                  { tunnel_id } on listen WS
Open WS /tunnel/<id> ────────▶                                ◀── Open WS /tunnel/<id>
                                 DO.pair(a, b)                     with dial_ticket

                              ══════════ blind byte pipe ══════════

TLS server(cert, mTLS)  ◀─── DO forwards opaque frames ───▶   TLS client(paired_cert)
mTLS verify against
  authorized_clients.json

encrypted http/ws/sse   ◀─── DO forwards opaque frames ───▶   encrypted traffic
```

Key invariants:

- `spl-relay` holds **no key** that can decrypt the inner stream. It authenticates the rendezvous, not the payload.
- mTLS with a self-signed CA lives **at the home endpoint**, not at CF. Authorized-keys-file pattern for revocation — edit a file, device is out.
- The inner protocol is TLS 1.3 with an SSH-channel-style multiplexing frame (`stream_id | flags | length | payload`). One tunnel WebSocket carries many concurrent HTTP/WS/SSE connections.

## repo layout

| Directory | What's here |
|-----------|-------------|
| [`proto/`](proto/) | The protocol: wire documents, plus [`proto/definition/`](proto/definition/) — a machine-readable definition and conformance-vector corpus every implementation can check itself against. |
| [`relay/`](relay/) | CF Worker + Durable Object (TypeScript). The relay. |
| [`docs/`](docs/) | Architecture, self-host guide, signing-key lifecycle, client-implementation audit. |

## implementations

**This repository holds the protocol and the relay. It deliberately ships no client or home implementation.** It used to carry a Python home module and a TypeScript example client; both drifted behind the protocol they were meant to demonstrate — one implemented a pairing form the spec had retired, the other could not complete a pairing against its own server. A reference that lies is worse than no reference, so they were removed in favour of pointing at the real thing.

Every implementation below is open source and in production use. Read these instead:

| Role | Language | Repository |
|---|---|---|
| Shared client library | Rust | [`solpbc/spl-rust`](https://github.com/solpbc/spl-rust) |
| Shared client library | Swift | [`solpbc/spl-swift`](https://github.com/solpbc/spl-swift) |
| Home (journal) | Python | [`solpbc/solstone-journal`](https://github.com/solpbc/solstone-journal) |
| Client — iOS, watchOS, macOS | Swift | [`solpbc/solstone-swift`](https://github.com/solpbc/solstone-swift) · [`solpbc/solstone-macos`](https://github.com/solpbc/solstone-macos) |
| Client — Android | Kotlin | [`solpbc/solstone-android`](https://github.com/solpbc/solstone-android) |
| Client — Windows | Rust | [`solpbc/solstone-windows`](https://github.com/solpbc/solstone-windows) |

If you are writing a new implementation, start with the documents in [`proto/`](proto/) and check yourself against [`proto/definition/`](proto/definition/); then read the closest existing client above. [`docs/client-implementation-audit.json`](docs/client-implementation-audit.json) records what each in-repo component actually implements, with evidence.

## install

Clone, then:

```sh
make install
```

Installs the relay toolchain (`make relay-install` is the same thing).

Prerequisites:

- **bun 1.2+** for `relay/`
- **Python 3.11+** for the protocol-definition gate (standard library only — no packages to install)

## run

**spl-relay locally** (Miniflare):

```sh
make relay-dev
```

See [`relay/README.md`](relay/README.md) for the full story on the relay, and [`docs/self-host.md`](docs/self-host.md) for running your own.

## test

```sh
make test
```

`make ci` runs the full pre-commit gate locally: the protocol-definition gate (`make definition-ci`) plus the relay's format, lint, type check, and tests.

## self-host

Running your own `spl-relay` instance is a supported path — not an afterthought. See [`docs/self-host.md`](docs/self-host.md).

## license

[AGPL-3.0-only](LICENSE). Built by [sol pbc](https://solpbc.org), a public benefit corporation.
