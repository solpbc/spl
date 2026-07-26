# spl-relay

The Cloudflare Worker + Durable Object that relays opaque bytes between two paired endpoints.

`spl-relay` is the hosted server component of spl. sol pbc runs it at the canonical endpoint `https://link.solstone.app`; you can run your own against a clean Cloudflare account by following the steps below. That self-host path is first-class — we ship `spl-relay` with the same trust claim as the hosted relay because *the code is the claim*.

## status

MVP build — Worker + Durable Object implement the full v1 protocol surface:

- `/enroll/home` and `/enroll/device` control-plane endpoints with Ed25519 JWT issuance and ES256 home-attestation verification (see [`../proto/tokens.md`](../proto/tokens.md))
- `/session/listen`, `/session/dial`, `/tunnel/<id>` WebSocket routes with JWT verify, WS-tag cardinality, and 16 MiB pending-buffer cap with 1009 close on overflow
- `/.well-known/jwks.json` transparency mirror
- D1 schema (`migrations/`) for instance, device, grant, and ephemeral pairing-owner metadata — no payload bytes, ever
- Blind forwarding: the DO holds `ArrayBuffer`s and forwards them without parsing; no code path reads a relayed frame

**Endpoint implementations live in their own repositories** — see the root README's implementations table. This repository holds the protocol and the relay only.

## what it is

A Cloudflare Worker (TypeScript, Hono) that routes `/session/listen`, `/session/dial`, and `/tunnel/<id>` WebSocket upgrades into an `InstanceDO` Durable Object. The DO pairs a home-side listen WS with a mobile-side dial WS and forwards opaque frames between them. It does not parse frames. It does not store frames. It logs tunnel metadata and nothing else.

See [`../README.md`](../README.md#architecture) for the diagram and [`../AGENTS.md`](../AGENTS.md) §3 for the invariants this component must preserve.

## prerequisites

- **bun 1.2+** — the toolchain for this component (install, typecheck, lint, test, local dev). The relay runs `bun install` rather than `npm install`: bun's installer cleanly resolves the platform-prebuilt native binaries that wrangler/miniflare pull in transitively, where npm currently falls back to a broken source build on modern hosts.
- **wrangler 4+** installed **globally** for any operation that touches a real CF account (`bun add -g wrangler`). The project-local wrangler (`bun run wrangler`) is acceptable for local Miniflare dev only; do not use it for deploy or for any command that needs your OAuth session (R2, D1, secret put, tail).
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

Unit tests plus four Workers configurations run via `bun run test` (vitest, driven by bun). Unit tests (`test/`) cover the pure crypto helpers. Integration tests (`test-integration/`, `@cloudflare/vitest-pool-workers`) run the real Worker under Miniflare in the default, entitlement-gated, retirement-without-entitlement-gate, and presence-hold configurations with D1 and InstanceDO bindings.

Every Workers config imports `vitest.keys.ts`, which mints a fresh in-memory Ed25519 signing keypair at config-load time; no key file is written or committed. Full CI (`make ci`) runs typecheck, biome, and all five vitest invocations.

## deploy

Production deploys are manual and run by an authenticated sol pbc operator from their local machine:

```sh
wrangler deploy --env production
```

`make deploy` runs the same command. The operator must have run `wrangler login` at least once. Do not run the project-local wrangler (`bun run wrangler` / `npx wrangler`) for this — it loses the authenticated OAuth session and has been observed to cause R2/D1 visibility bugs.

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
# service/device tokens):
echo "$PRIVATE_JWK_JSON" | wrangler secret put SIGNING_JWK --env production

# Public JWKS envelope (JSON; the public half the Worker verifies against —
# supports multi-key rotation via kid):
echo "$JWKS_ENVELOPE_JSON" | wrangler secret put JWKS_PUBLIC --env production
```

Read in the Worker via `env.SIGNING_JWK` and `env.JWKS_PUBLIC`. The private key is the root of trust; see [`../docs/signing-keys.md`](../docs/signing-keys.md) for the full lifecycle (generation, rotation, compromise response).

Run `bun run gen-key` to mint a self-host keypair — it writes to `~/.spl/signing-keypair.json` with mode 0600 and prints the exact `wrangler secret put` commands.

## configuration

`wrangler.toml` is checked in and contains no secrets. The top-level block is a dev-only placeholder; `[env.production]` is sol pbc's hosted deploy target. It deploys Worker `spl-relay`, D1 database `spl-relay`, and custom domain `link.solstone.app`. Fill in the target env's `database_id` (from `wrangler d1 create ...`) before deploying your own copy. Signing keys and tokens are secrets, provisioned via `wrangler secret put`.

## admin API

All admin endpoints require `Authorization: Bearer <GRANT_SECRET>`. Provision `GRANT_SECRET` with `wrangler secret put GRANT_SECRET --env production`; an unprovisioned relay returns 503, and a missing or incorrect bearer returns 401.

- `POST /admin/entitlement` sets or clears `entitled_until` for an instance. A grant received before home enrollment is held in `pending_grants`; a retired instance returns 409 and any stale pending grant for it is deleted.
- `GET /admin/instances` lists instance metadata.
- `GET /admin/instances/<id>` returns one instance or 404.
- `DELETE /admin/instances/<id>` irreversibly retires an instance. There is no reactivation endpoint, soft mode, or rollback.

For example, with the secret held in the shell environment:

```sh
curl -X DELETE \
  -H "Authorization: Bearer ${GRANT_SECRET}" \
  https://relay.example/admin/instances/018f6b79-9a7c-7d31-a021-4b91c02c7a10
```

A complete retirement returns HTTP 200 with exactly this shape:

```json
{
  "state": "retired",
  "entry_denial_verified": true,
  "sockets_closed": true,
  "devices_revoked": true,
  "entitlement_cleared": true,
  "pending_grants_cleared": true,
  "tombstone_verified": true
}
```

`state` is `retired` when this request established the tombstone, `already_retired` when a prior request established it, or `absent` when an independent post-cleanup read proved that neither a live instance row nor a tombstone exists. The `absent` path still clears a pre-enrollment pending grant, but creates no instance row, device row, tombstone, or Durable Object.

The six booleans attest separate postconditions:

- `entry_denial_verified`: D1 contains the terminal revoked state and every discovered instance-addressed or RK-addressed Durable Object contains its derived synchronous denial marker.
- `sockets_closed`: all discovered sockets and associated DO cleanup completed; already accepted sockets close with code 4403 and reason `instance_retired`.
- `devices_revoked`: the device mutation completed and no unrevoked device row remains for the instance.
- `entitlement_cleared`: the mutation completed and `instances.entitled_until` reads back as null.
- `pending_grants_cleared`: the mutation completed and no pending grant reads back for the instance.
- `tombstone_verified`: for a known instance, the original `revoked_at` and empty RK-owner registry read back successfully; for `absent`, a separate read proved no instance or tombstone exists.

After `revoked_at` commits, cleanup is best-effort and continues across independent components. If any component cannot be verified, the endpoint returns HTTP 503, omits `state`, returns the same six booleans with their current verified values, and adds exactly one `failed_component` field. Its value is one of `retired_state`, `instance_do_cleanup`, `rk_do_cleanup`, `device_revocation`, `entitlement_clear`, `pending_grant_clear`, `rk_registry_clear`, or `verification`. Retry the authenticated DELETE until it returns 200; retries preserve the original `revoked_at`, repeat and re-verify cleanup, and never reactivate the instance. A malformed id returns 400 before any D1 write or Durable Object invocation.

Retirement uses projection-only tombstones. D1 retains the original `ca_fp`, `ca_pubkey_pem`, `home_label`, and service-token metadata so the same CA cannot be registered again, but retired list/show responses expose exactly `instance_id`, `created_at`, `revoked_at`, `entitled_until: null`, and `entitled: false`. The retained CA public material is not secret and confers no live capability; all enrollment, refresh, session, tunnel, and pairing entry paths refuse the retired instance.

To find RK-addressed sockets without retaining `RK`, D1 temporarily records `(instance_id, do_id, registered_at)` in `pairing_owners`. `do_id` is the opaque 64-hex result of `idFromName(RK)`, not `RK`; it cannot be reversed to recover `RK`, and public routes accept only `RK`, never a DO id. Someone with D1 read access learns that an instance has an active pairing-owned DO and its opaque address, but gains neither the RK nor authority to pair or attach through the public router. Close, replacement, and alarm paths release rows best-effort when the last owned socket leaves. A transient D1 failure can leave opaque residue; retirement discovers through and clears any residual row.

## logging policy

Every log statement that touches tunnel data logs metadata only: `timestamp`, `tunnel_id`, `direction`, `byte_count`. No payload byte ever. No token value ever. This is enforced by code review, not by a library — be deliberate about what you log.

See [`../AGENTS.md`](../AGENTS.md) §3 for the full policy.
