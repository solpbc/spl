# solcf

The Cloudflare Worker + Durable Object that relays opaque bytes between two paired endpoints.

`solcf` is the hosted server component of spl. sol pbc runs it at the canonical endpoint; you can run your own against a clean Cloudflare account by following the steps below. That self-host path is first-class — we ship `solcf` with the same trust claim as the hosted relay because *the code is the claim*.

## status

Scaffold only. The MVP build lands in a later phase; see [`../AGENTS.md`](../AGENTS.md) §6.

## what it is

A Cloudflare Worker (TypeScript, Hono) that routes `/session/listen`, `/session/dial`, and `/tunnel/<id>` WebSocket upgrades into an `InstanceDO` Durable Object. The DO pairs a home-side listen WS with a mobile-side dial WS and forwards opaque frames between them. It does not parse frames. It does not store frames. It logs tunnel metadata and nothing else.

See [`../README.md`](../README.md#architecture) for the diagram and [`../AGENTS.md`](../AGENTS.md) §3 for the invariants this component must preserve.

## prerequisites

- **Node 20+** (tested on 20.x and 22.x)
- **wrangler 4+** (installed globally or via the local dev dependency)
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

Unit tests run under Miniflare. Integration tests require a live `solcf` and are marked separately.

## deploy

Production deploys are manual and run by an authenticated sol pbc operator from their local machine:

```sh
make deploy
```

This invokes `wrangler deploy`. The operator must have run `wrangler login` at least once and be working from the global `wrangler` binary (not `npx wrangler` — that loses the OAuth session).

A deploy disconnects every live tunnel. It is not routine. Only deploy when the change is worth the customer-visible blip.

## secrets

Never commit a secret. For production:

```sh
wrangler secret put HOME_TOKEN < /path/to/token
wrangler secret put MOBILE_TOKEN < /path/to/token
wrangler secret put SIGNING_KEY < /path/to/key.pem
```

Read in the Worker via `env.HOME_TOKEN`, `env.SIGNING_KEY`, etc.

## configuration

`wrangler.toml` is checked in and contains no secrets. Database IDs and account IDs are not secrets; signing keys and auth tokens are.

## logging policy

Every log statement that touches tunnel data logs metadata only: `timestamp`, `tunnel_id`, `direction`, `byte_count`. No payload byte ever. No token value ever. This is enforced by code review, not by a library — be deliberate about what you log.

See [`../AGENTS.md`](../AGENTS.md) §3 for the full policy.
