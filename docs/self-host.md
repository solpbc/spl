# self-hosting solcf

Running your own `solcf` relay against a clean Cloudflare account is a first-class path. The hosted relay at `solpbc.org` is a convenience; the code is the claim.

## status

Scaffold only. The full walk-through lands with the MVP build. The intent for this document is to get a reader from *clean CF account* to *working tunnel* without having to read the source.

## shape of the path

Approximate steps, subject to revision as the MVP lands:

1. **Clone the repo.** `git clone https://github.com/solpbc/spl && cd spl`
2. **Prerequisites.** Node 20+ for `solcf/`, Python 3.11+ for `home/`. `make install` covers both. Also install **wrangler globally** (`npm install -g wrangler` or `bun add -g wrangler`) — `npx wrangler` is acceptable for local Miniflare dev only; it loses the OAuth session and breaks R2/D1 commands. The deploy target in `solcf/Makefile` invokes the global binary.
3. **Cloudflare account.** Workers Paid plan (~$5/mo) is required — the free tier's Durable Object allocations do not cover production shape.
4. **Account context.** Run `wrangler login` once. wrangler stores your account binding in `~/.wrangler/config/` (outside the repo) and uses it for every subsequent invocation. The checked-in `wrangler.toml` deliberately omits `account_id` — do not add it; let your local OAuth session supply it.

   Alternatives if `wrangler login` doesn't fit your environment: set `CLOUDFLARE_ACCOUNT_ID=<your-account-id>` in your shell profile or a local `.env.local`, or pass `--account-id=<id>` on every `wrangler` command. All three work; OAuth is cleanest.
5. **Wrangler config.** Edit `solcf/wrangler.toml` — `name`, `routes`. Create the D1 database and update `database_id`. **Leave `account_id` unset** (see step 4).
6. **Signing key.** Generate an Ed25519 keypair for account/device token signing using the bundled generator: `cd solcf && npm run gen-key`. The script writes a JWK keypair to `~/.spl/signing-keypair.json` and prints the exact `wrangler secret put SIGNING_JWK` and `wrangler secret put JWKS_PUBLIC` commands to run. The private key is the root of trust for your tunnel — lose it and every paired device must re-enroll. See [`signing-keys.md`](signing-keys.md) for the full lifecycle (rotation, compromise response, why Ed25519 here vs. ECDSA at the mTLS layer).
7. **Auth tokens.** Decide the account-token and device-token issuance story for your deployment. The production sol pbc flow mints these through a control-plane service inside the Worker; a self-host can hand-issue them for personal use.
8. **Deploy.** `cd solcf && make deploy` (which calls `wrangler deploy` from the global binary). Your relay is live at the route you configured.
9. **Home side.** Point your solstone install at your relay by setting `SOLCF_ENDPOINT` in `home/.env.local` and bootstrapping with an account token signed by your key.
10. **Mobile.** Update the app's `AppConfig` with the new relay endpoint and public signing key (or rebuild against them). Pair on LAN as usual.

## placeholder sections

Once MVP ships, this doc will cover:

- Concrete wrangler.toml diffs for self-host
- Token issuance patterns (manual, scripted, control-plane)
- Logging and observability checklist
- How to prove to yourself that the relay is blind (packet capture walkthrough, code review pointers)
- Migration between relay hosts (rotate account tokens, re-pair devices, etc.)

If you're eager to self-host before this document catches up, read [`../AGENTS.md`](../AGENTS.md) in full and open an issue describing your target environment.
