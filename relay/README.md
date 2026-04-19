# spl-relay

The Cloudflare Worker + Durable Object that relays opaque bytes between two paired endpoints.

`spl-relay` is the hosted server component of spl. sol pbc runs it at the canonical endpoint; you can run your own against a clean Cloudflare account by following the steps below. That self-host path is first-class — we ship `spl-relay` with the same trust claim as the hosted relay because *the code is the claim*.

## status

MVP build — Worker + Durable Object implement the full v1 protocol surface:

- `/enroll/home` and `/enroll/device` control-plane endpoints with Ed25519 JWT issuance and ES256 home-attestation verification (see [`../proto/tokens.md`](../proto/tokens.md))
- `/session/listen`, `/session/dial`, `/tunnel/<id>` WebSocket routes with JWT verify, WS-tag cardinality, and 16 MiB pending-buffer cap with 1009 close on overflow
- `/.well-known/jwks.json` transparency mirror
- D1 schema (`migrations/0001_init.sql`) for instance + device metadata — no payload bytes, ever
- Blind forwarding: the DO holds `ArrayBuffer`s and forwards them without parsing; no code path reads a relayed frame

**What's not built yet:** the Python home (`spl/home/`) and Bun mobile (`spl/mobile/`) MVP programs that exercise the relay end-to-end. Those are the next chunk of the MVP scope.

## what it is

A Cloudflare Worker (TypeScript, Hono) that routes `/session/listen`, `/session/dial`, and `/tunnel/<id>` WebSocket upgrades into an `InstanceDO` Durable Object. The DO pairs a home-side listen WS with a mobile-side dial WS and forwards opaque frames between them. It does not parse frames. It does not store frames. It logs tunnel metadata and nothing else.

See [`../README.md`](../README.md#architecture) for the diagram and [`../AGENTS.md`](../AGENTS.md) §3 for the invariants this component must preserve.

## prerequisites

- **Node 20+** (tested on 20.x and 22.x)
- **wrangler 4+** installed **globally** for any operation that touches a real CF account (`npm install -g wrangler` or `bun add -g wrangler`). `npx wrangler` is acceptable for local Miniflare dev only; do not use it for deploy or for any command that needs your OAuth session (R2, D1, secret put, tail).
- A Cloudflare account (free tier is fine for local development; production needs Workers Paid, ~$5/mo)

## install

```sh
make install
```

## develop

```sh
make dev
```

Runs the Worker under Miniflare. No CF account required. Secrets can be set in a gitignored `.dev.vars` file at this component root (`HOME_TOKEN=...`, `MOBILE_TOKEN=...`).

## test

```sh
make test
```

Two suites. Unit tests (`test/`, vitest + node) cover the pure crypto helpers — JWT verify/mint, attestation verify, fingerprinting. Integration tests (`test-integration/`, vitest + `@cloudflare/vitest-pool-workers`) spin up the real Worker under Miniflare with D1 and InstanceDO bindings and exercise the full request path, WebSocket pairing, cardinality enforcement, and pending-buffer overflow.

A fresh Ed25519 signing keypair is minted at config-load time in `vitest.workers.config.ts`; no keys are committed. Full CI (`make ci`) runs typecheck + biome + both suites.

## deploy

Production deploys are manual and run by an authenticated sol pbc operator from their local machine:

```sh
make deploy
```

This invokes the **global** `wrangler deploy`. The operator must have run `wrangler login` at least once. Do not use `npx wrangler` for this — it installs a temporary binary that loses the authenticated OAuth session and has been observed to cause R2/D1 visibility bugs.

A deploy disconnects every live tunnel. It is not routine. Only deploy when the change is worth the customer-visible blip.

### account context — `account_id`

The checked-in `wrangler.toml` deliberately contains **no `account_id`**. This avoids two problems: leaking sol pbc's CF account identifier into a public repo, and inviting paste errors from self-hosters who would otherwise have to remember to delete a line before deploying.

`wrangler` resolves the account context from one of three sources, checked in this order. Pick whichever fits your environment:

1. **OAuth session (recommended).** Run `wrangler login` once on this workstation. wrangler stores account context in `~/.wrangler/config/` (outside the repo) and uses it for every subsequent invocation. If the session is bound to a single CF account, you're done; if it's bound to multiple, wrangler will prompt the first time and remember.
2. **Environment variable.** Export `CLOUDFLARE_ACCOUNT_ID=<your-account-id>` in your shell profile, or set it in a local `.env.local` (gitignored) and source it before deploying.
3. **Per-invocation flag.** Pass `--account-id=<your-account-id>` on every `wrangler deploy`. Verbose, but explicit.

For sol pbc operators: option 1 is the standard. The founder workstation is already authenticated.

For self-hosters: any of the three is fine. Option 1 is the cleanest and matches the way wrangler is designed to work.

Do **not** edit `wrangler.toml` to add an `account_id` line. The pattern is: the checked-in config has no account binding; the invocation context supplies it.

## secrets

Never commit a secret. For production:

```sh
# Private Ed25519 signing JWK (JSON; the private half used to mint
# account/device tokens):
echo "$PRIVATE_JWK_JSON" | wrangler secret put SIGNING_JWK --env production

# Public JWKS envelope (JSON; the public half the Worker verifies against —
# supports multi-key rotation via kid):
echo "$JWKS_ENVELOPE_JSON" | wrangler secret put JWKS_PUBLIC --env production
```

Read in the Worker via `env.SIGNING_JWK` and `env.JWKS_PUBLIC`. The private key is the root of trust; see [`../docs/signing-keys.md`](../docs/signing-keys.md) for the full lifecycle (generation, rotation, compromise response).

Run `npm run gen-key` to mint a self-host keypair — it writes to `~/.spl/signing-keypair.json` with mode 0600 and prints the exact `wrangler secret put` commands.

## configuration

`wrangler.toml` is checked in and contains no secrets. The top-level block is a dev-only placeholder; `[env.staging]` and `[env.production]` hold the real deploy targets. Fill in each env's `database_id` (from `wrangler d1 create ...`) before deploying. Signing keys and tokens are secrets, provisioned via `wrangler secret put`.

## logging policy

Every log statement that touches tunnel data logs metadata only: `timestamp`, `tunnel_id`, `direction`, `byte_count`. No payload byte ever. No token value ever. This is enforced by code review, not by a library — be deliberate about what you log.

See [`../AGENTS.md`](../AGENTS.md) §3 for the full policy.
