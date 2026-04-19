# contributing to spl

Thanks for looking. spl is the first piece of infrastructure sol pbc operates on behalf of customers, and we want the code that runs it to be as trustworthy in public as in private. Contributions that sharpen that trust are welcome.

## the invariants are non-negotiable

Before you open a PR, read [`AGENTS.md`](AGENTS.md) §3–§4. The short version:

- **Blind by construction.** No code path in `solcf` may read, parse, store, or forward the payload of a relayed frame. The relay sees opaque bytes, and so does its source.
- **No payload in logs, ever.** Metadata (timestamp, tunnel_id, direction, byte_count) is fine. A byte from a user's stream is not.
- **No analytics, tracking, or telemetry vendors.** Adding one is a fail-stop change in review. We do not have an allowlist.
- **Open source is the product.** No hidden dependencies on proprietary infrastructure. If you'd need to be inside sol pbc to make it work, the design is wrong.

PRs that touch the byte-relay path or the pairing/TLS layer will get extra scrutiny. That's not distrust — it's the shape of the trust claim. The cost of reviewing carefully is always lower than the cost of losing the claim.

## how to work

1. **Open an issue first** for anything bigger than a typo or small bug fix. Alignment on direction before code saves both of us time.
2. **Fork the repo, branch from `main`**, build locally, commit small and focused changes.
3. **`make ci` must pass** before you open the PR.
4. **Push, then open a PR.** Link the issue if there is one.
5. sol pbc reviews. We may decline PRs that dilute the blind-by-construction invariant, introduce tracking vendors, or widen scope beyond what the issue established. We'll tell you why.

## local development

See [`README.md`](README.md) for per-component setup. In short: `make install` at the repo root gets both components ready; `make ci` runs the full gate.

## licensing

spl is licensed [AGPL-3.0-only](LICENSE). By submitting a pull request, you agree that your contribution is licensed under the same license and that you have the right to submit it.

We do not require a separate CLA. A commit-by-commit Signed-off-by (the Developer Certificate of Origin, `git commit -s`) is not required but is welcome.

## reporting security issues

Please **do not** open a public issue for a security vulnerability. See [`SECURITY.md`](SECURITY.md) for the disclosure path.

## code of conduct

We follow the [Contributor Covenant 2.1](CODE_OF_CONDUCT.md). Be good to each other.
