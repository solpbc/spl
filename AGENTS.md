# spl Developer Guide

This file is the developer guide for the `spl` repository. Read it before writing code.

`CLAUDE.md` at the repo root is a symlink to this file — one source of truth for human and agent contributors.

Build conventions follow `cto/standards/project-conventions.md`; engineering philosophy follows `cto/standards/engineering-principles.md`. Those live in the sol pbc internal ops repo; the principles that matter in *this* codebase are distilled below.

## 1. What spl is

A blind rendezvous service. Two paired endpoints meet through Cloudflare's edge without Cloudflare — or sol pbc — ever seeing inside the tunnel. See [`README.md`](README.md) for the architecture diagram and product framing.

Read the architecture section of the README before writing code. If the change you're making wouldn't survive reading that section out loud to a user, it's the wrong change.

## 2. Repo layout

| Directory | Purpose | Go here when |
|-----------|---------|--------------|
| [`solcf/`](solcf/) | CF Worker + Durable Object — the relay. TypeScript. | Editing the relay server, wrangler config, migrations. |
| [`home/`](home/) | Python tunnel module. Embeds in solstone. | Editing the home-side listen/TLS/pairing code. |
| [`ios/`](ios/) | iOS client (stub). Lineage: extro-phone. | Once the iOS build lands — not yet. |
| [`proto/`](proto/) | Shared protocol spec (framing, pairing, token shape). | Changing the wire format or token shape — both sides must agree. |
| [`docs/`](docs/) | Architecture notes, self-host guide, decision log. | Reference lookups; never the first stop. |

Each component has its own `README.md` and `Makefile`. The top-level `Makefile` is an orchestrator — it delegates to the per-component Makefiles.

## 3. Non-negotiable invariants

These are architectural, not aspirational. A PR that violates any of them is declined regardless of how small it looks.

### blind by construction

- `solcf` (the relay) must hold **no key** that can decrypt the inner stream.
- `solcf` must have **no code path** that reads the contents of a relayed frame. The DO holds `ArrayBuffer`s. It does not parse them.
- `solcf` must **not store** relayed bytes anywhere — not in D1, not in R2, not in KV, not in memory beyond the in-process pairing table that lives only for the socket's lifetime.
- mTLS with the self-signed CA terminates **at the home endpoint**, never at CF. An earlier architecture considered CF Access edge mTLS; it was rejected because that shape would show CF the plaintext.
- There is **no key escrow, ever**. No path by which sol pbc can reconstruct a past or present session.

### no payload in logs, ever

- Every log statement that touches tunnel data must log metadata only: `timestamp`, `tunnel_id`, `direction`, `byte_count`. Never a payload byte. Never a header. Never a token value. Never a TLS handshake message.
- No analytics libraries. No tracking pixels. No behavioral telemetry. No third-party error-reporting SDK that could capture a payload on a stack trace. Adding one is a fail-stop change — cut it in code review.
- Operational error tracking for `solcf` bugs is fine *if* it captures Worker stack traces that do not include user frames. Be specific about what goes upstream; default-deny anything ambiguous.

### open source is the product

- Everything that runs in production is in this repo, under [AGPL-3.0-only](LICENSE).
- Self-hosting `solcf` against a clean CF account must produce a working tunnel by following a README. A contributor running it on their own infra is not a second-class path — they are the product in a different hosting mode.
- No hidden dependencies on sol-pbc-proprietary infrastructure, closed SaaS, or internal services. If you reach for one, stop; there's a wrong turn upstream.

### minimum-delta MVP

- This repo starts as scaffolding, not ported prototype code. Prototype learnings (see [`vpe/workspace/spl-prototype-report.md`](https://github.com/solpbc/spl) — internal) inform structure, not contents.
- v1 is one use case: solstone mobile ↔ home convey, iOS-only, LAN-pair only. Not two platforms. Not off-LAN pairing. Not observer-over-tunnel. See `cpo/specs/shipped/spl-v1-tunnel-mvp.md` once it graduates.
- When in doubt, ship less. A reviewer who pushes back with "is this v1 scope?" is doing the right thing.

## 4. Safety rails — what an agent must never do here

- **Never** write a code path in `solcf` that reads, parses, stores, forwards, or reasons about the payload of a relayed frame. Opaque bytes in, opaque bytes out.
- **Never** add an analytics / tracking / telemetry / behavioral-insight library. Not as a dep, not as a middleware, not as a debug tool. This is fail-stop.
- **Never** commit a secret — tokens, signing keys, CF API tokens, wrangler OAuth sessions, `authorized_clients.json` entries, `.dev.vars` contents. Secrets go in `.env.local` (gitignored) for dev and `wrangler secret put` for prod.
- **Signing keys (`SIGNING_JWK`, `JWKS_PUBLIC`) are JWT-layer secrets — never confuse them with mTLS cert keys.** They live in two different layers with two different algorithms: this layer is **Ed25519 / EdDSA** for JWT signing; the mTLS layer (home CA + mobile client cert) is separately **ECDSA-P256**. They authorize different things — JWTs authorize the rendezvous WebSocket open; mTLS authorizes the actual byte exchange. The private signing key (`env.SIGNING_JWK`) MUST NOT appear in the repo, in commit history, in any log line, in any error message, in any `console.*` call, in any HTTP response body, or in any thrown exception's `.message`. It exists only at `env.SIGNING_JWK` at runtime and at the operator's local keypair file. See [`docs/signing-keys.md`](docs/signing-keys.md) for the full lifecycle and [`proto/tokens.md`](proto/tokens.md) for the wire format.
- **Never** run `wrangler deploy` from CI or from any unattended process. Production deploys are run by an authenticated operator on their local machine. A deploy disconnects every live tunnel; it is not a routine event.
- **Never** push to `main` without review once the project has external contributors. During bootstrap, push directly as normal.
- **Never** add a "trust us" bit. If the trust claim rests on "sol pbc decided not to look," the design is wrong. Rework it so there is nothing to look *at*.

## 5. Local conventions

### file headers (AGPL SPDX)

Every TypeScript and Python source file starts with:

**TypeScript:**
```typescript
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 sol pbc
```

**Python:**
```python
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
```

Headers go immediately after any shebang. Do not add them to docs, configs, generated files, or vendored dependencies.

### build system

Top-level `Makefile` orchestrates. Per-component Makefiles live in `solcf/` and `home/`. Required targets at each level:

| Target | Does |
|--------|------|
| `make install` | Set up the dev environment |
| `make test` | Run the test suite |
| `make ci` | Format check + lint + type check + test |
| `make format` | Auto-fix formatting |
| `make clean` | Remove build artifacts |

Additional targets (`make dev`, `make deploy` in `solcf/`) are fine. These five are the contract.

### secrets

- **Dev:** `.env.local` at the component root. Gitignored. Load via the language's dotenv library.
- **solcf prod:** `wrangler secret put <NAME>`. Encrypted server-side by CF. Read via `env.NAME` in the Worker.
- **Signing keys** (account-token / device-token signing): live in sol pbc's vault. Install into `solcf` via `wrangler secret put SIGNING_KEY < key.pem`. Never written to the repo, never echoed to logs, never returned in an API response.

### testing

- Tests live under each component's `tests/` directory.
- Unit tests run without network or CF resources.
- Integration tests against Miniflare (solcf) or a running local `solcf` (home) are marked separately and not gated by default CI.
- The build gate is `make ci`. It must pass before commit.

### git

- Small, focused commits. If the commit message needs "and," it's probably two commits.
- Push immediately after commit — keep the remote in sync.
- No force-push to `main`. If something is wrong, new commit.
- No deploy pipeline on push. Production deploys happen manually by an authenticated operator.

## 6. Working the MVP

The v1 build is a future phase. This repo is scaffolded, not implemented. When MVP work begins:

- Spec lives in `cpo/specs/in-flight/spl-v1-tunnel-mvp.md` (sol pbc internal). Acceptance criteria in that spec are the contract the build delivers against.
- VPE will issue one or more hopper lodes per spec section. Review them against spec acceptance criteria; ship when they match.
- Cross-office dependencies (paid CF resources, production DNS, token signing keys, ToS, brand) are tracked separately — see `cpo/workspace/spl-cross-office-dependencies.md` and scope them through VPE/CTO before they block MVP work.

## 7. If something's off

If a proposed change feels like it drifts from *blind by construction*, stop. Write the concern out in the PR description. The author may have caught a real architectural tension — better to resolve it in review than ship it.

Prototype findings folded into the spec are where the concrete lessons live. Re-read them before architecting anything new. Don't re-derive what's already been measured.
