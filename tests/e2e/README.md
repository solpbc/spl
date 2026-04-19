# spl end-to-end integration tests

A Python harness that spins up all three spl components locally and
exercises the full protocol.

The orchestrator (`run.py`) does this in order:

1. **Generate a throwaway Ed25519 signing keypair** via
   `relay/scripts/gen-signing-key.ts`. Written to a temp file; never
   committed. `SIGNING_JWK` + `JWKS_PUBLIC` are passed to wrangler dev via
   a temp `.dev.vars` file.
2. **Start `wrangler dev`** (Miniflare) from `relay/`. Waits until
   `GET /.well-known/jwks.json` returns the provisioned envelope.
3. **Start `python -m spl.home start`** pointed at the local relay with
   state rooted in a temp dir. Waits for enroll + listen WS to open
   (detected by a log line).
4. **Run `python -m spl.home pair --device-label e2e`** to mint a nonce.
5. **Run `spl-mobile pair ... --insecure`** against the emitted LAN URL
   plus `--relay http://localhost:<port>`.
6. **Run `spl-mobile test`** and assert:
   * `/echo` returns byte-for-byte correct content
   * `/stream` emits 5 SSE events
   * `/upload` SHA-256 matches a client-side digest
   * 10 concurrent multiplexed streams all succeed
7. **Revocation test** — edit authorized_clients.json to remove the fp,
   re-run `spl-mobile test`, expect a TLS handshake failure at the
   client.
8. **Reconnect test** — kill home, restart, wait for listen WS, re-run
   `spl-mobile test`, expect success.
9. **Blindness assertion** — grep the collected wrangler stdout for any
   byte of payload / token / Authorization header / TLS record prefix.
   Any hit fails the test.

## prerequisites

- `bun` on PATH (for `wrangler dev` and `spl-mobile`)
- `uv` on PATH (for `python -m spl.home`)
- `wrangler` global install (not `npx wrangler`) — matches the convention
  in `relay/README.md`

## run

From the top of the repo:

```sh
make integration-test
```

Or directly:

```sh
cd tests/e2e && python run.py
```

Outputs a per-scenario pass/fail summary and a final SUCCESS/FAILURE
exit code.

## status

**Harness complete, not yet exercised in CI.** The full top-level
`make integration-test` requires all three toolchains present and
currently must be run manually. Wire-up to CI is a post-MVP follow-up
once staging is stood up.
