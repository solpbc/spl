# sol private link (spl)

**Blind byte-relay rendezvous service.** Two paired endpoints meet through Cloudflare's edge without Cloudflare — or sol pbc — ever seeing inside the tunnel.

> spl is blind by construction. Cloudflare and sol pbc hold no key that could decrypt traffic inside the tunnel. Revocation is local. Open source so you can verify.

## what it is

spl gives two paired endpoints (today: a solstone home server and a paired mobile app) a way to reach each other over the public internet without exposing either to it. Cloudflare holds two WebSockets and shovels opaque bytes between them. Inside the tunnel, the endpoints run TLS 1.3 end-to-end; the server authenticates the rendezvous, never the payload.

- **Operator:** sol pbc (hosted `solcf` relay at [solpbc.org](https://solpbc.org)). Or run your own — the whole server is in this repo.
- **License:** [AGPL-3.0-only](LICENSE).
- **Status:** pre-MVP, closed alpha approaching. Architecture vetted end-to-end by prototype (2026-04-18). See the [roadmap](https://github.com/solpbc/spl/blob/main/docs/roadmap.md) when published.

## architecture

```
solstone (home, python)          sol-pbc CF ("solcf")            mobile app (swift/kotlin)
-----------------------          --------------------            ------------------------
POST /session/listen ────────▶   Workers: validate
  Authorization: account_token     account token
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

- `solcf` holds **no key** that can decrypt the inner stream. It authenticates the rendezvous, not the payload.
- mTLS with a self-signed CA lives **at the home endpoint**, not at CF. Authorized-keys-file pattern for revocation — edit a file, device is out.
- The inner protocol is TLS 1.3 with an SSH-channel-style multiplexing frame (`stream_id | flags | length | payload`). One tunnel WebSocket carries many concurrent HTTP/WS/SSE connections.

## repo layout

| Directory | What's here |
|-----------|-------------|
| [`solcf/`](solcf/) | CF Worker + Durable Object (TypeScript). The relay. |
| [`home/`](home/) | Python tunnel module. Embeddable in solstone. |
| [`ios/`](ios/) | iOS client. Stub — lineage is the solstone mobile app. |
| [`proto/`](proto/) | Shared protocol spec (framing, pairing, token shape). |
| [`docs/`](docs/) | Architecture, self-host guide, decision log. |

## install

Clone, then:

```sh
make install
```

Orchestrates per-component installs (`solcf/` → npm, `home/` → uv/pip). Per-component targets are also available: `make solcf-install`, `make home-install`.

Prerequisites:

- **Node 20+** and **bun** or **npm** for `solcf/`
- **Python 3.11+** and **uv** (or **pip**) for `home/`

## run

**solcf locally** (Miniflare):

```sh
make solcf-dev
```

**home locally** (against a running `solcf`):

```sh
cd home && make dev
```

See each component's `README.md` for the full story.

## test

```sh
make test
```

Per-component: `make solcf-test`, `make home-test`. `make ci` runs the full pre-commit gate (format + lint + type check + test) locally.

## self-host

Running your own `solcf` instance is a supported path — not an afterthought. See [`docs/self-host.md`](docs/self-host.md).

## license

[AGPL-3.0-only](LICENSE). Built by [sol pbc](https://solpbc.org), a public benefit corporation.
