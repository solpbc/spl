# security policy

## reporting a vulnerability

Please email **`security@solpbc.org`**. We target a **48-hour acknowledgement** and will keep you updated as we investigate.

If you cannot reach that address for any reason, email `jer@solpbc.org` directly.

**Do not open a public GitHub issue** for a suspected security vulnerability. Open disclosure helps attackers more than it helps users.

## scope

spl's core trust claim is that `solcf` (the relay) is **blind by construction**: it holds no key that could decrypt the inner TLS 1.3 stream, and no code path in the Worker or Durable Object reads the contents of a relayed frame.

In scope for disclosure:

- Any bug, misconfiguration, or design flaw that breaks (or appears to break) the blindness invariant.
- Any code path in `solcf` that reads, parses, stores, logs, or forwards tunnel payload.
- Authentication bypass (account-token or device-token issuance, validation, or replay).
- Pairing ceremony flaws (nonce reuse, TTL bypass, CSR signing misuse).
- Revocation bypass (a fingerprint removed from `authorized_clients.json` is not enforced at TLS).
- Memory exhaustion or resource abuse in `solcf` that could be used as a denial-of-service.
- Supply-chain concerns (tampered dependencies, compromised build artifacts).

Out of scope:

- Vulnerabilities in Cloudflare's platform itself (report to Cloudflare).
- Vulnerabilities in third-party dependencies — please report upstream; we track and upgrade.
- Denial-of-service requiring sustained high-volume traffic (we rate-limit at CF, but don't offer a bounty on exhaustion).

## what we commit to

- Acknowledge within 48 hours.
- Investigate in good faith and tell you what we find.
- Credit you in the release notes for the fix (unless you prefer not).
- No legal action against good-faith researchers acting within this policy.

## what we don't offer

- A formal bug bounty program. sol pbc is a small public benefit corporation; we're building a trust story, not a bounty program. If you find something significant, we'll do right by you.

## when disclosure happens

We prefer coordinated disclosure: give us a reasonable window to ship a fix (typically ≤90 days, sooner for critical issues), then you and we can discuss public disclosure together.

Thank you for helping keep the people who use sol pbc products safe.
