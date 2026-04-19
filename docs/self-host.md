# self-hosting solcf

Running your own `solcf` relay against a clean Cloudflare account is a first-class path. The hosted relay at `solpbc.org` is a convenience; the code is the claim.

## status

Scaffold only. The full walk-through lands with the MVP build. The intent for this document is to get a reader from *clean CF account* to *working tunnel* without having to read the source.

## shape of the path

Approximate steps, subject to revision as the MVP lands:

1. **Clone the repo.** `git clone https://github.com/solpbc/spl && cd spl`
2. **Prerequisites.** Node 20+ for `solcf/`, Python 3.11+ for `home/`. `make install` covers both.
3. **Cloudflare account.** Workers Paid plan (~$5/mo) is required — the free tier's Durable Object allocations do not cover production shape.
4. **Wrangler config.** Edit `solcf/wrangler.toml` — `name`, `routes`, `account_id`. Create the D1 database and update `database_id`.
5. **Signing key.** Generate an ECDSA-P256 keypair for account/device token signing. Store the private key as a wrangler secret: `wrangler secret put SIGNING_KEY < key.pem`. Publish the public key wherever your home clients will fetch it.
6. **Auth tokens.** Decide the account-token and device-token issuance story for your deployment. The production sol pbc flow mints these through a control-plane service; a self-host can hand-issue them for personal use.
7. **Deploy.** `cd solcf && wrangler deploy`. Your relay is live at the route you configured.
8. **Home side.** Point your solstone install at your relay by setting `SOLCF_ENDPOINT` in `home/.env.local` and bootstrapping with an account token signed by your key.
9. **Mobile.** Update the app's `AppConfig` with the new relay endpoint and public signing key (or rebuild against them). Pair on LAN as usual.

## placeholder sections

Once MVP ships, this doc will cover:

- Concrete wrangler.toml diffs for self-host
- Token issuance patterns (manual, scripted, control-plane)
- Logging and observability checklist
- How to prove to yourself that the relay is blind (packet capture walkthrough, code review pointers)
- Migration between relay hosts (rotate account tokens, re-pair devices, etc.)

If you're eager to self-host before this document catches up, read [`../AGENTS.md`](../AGENTS.md) in full and open an issue describing your target environment.
