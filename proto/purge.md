# portal purge contract v1

This document defines the service-to-service owner-purge contract between the
portal and spl-relay. It is not a browser API. It carries no portal-account
identifier, and spl-relay must not resolve or persist such an association.

The contract removes relay rows only: for every admitted relay instance_id, it
deletes devices, then pending_grants, then instances. It never carries or
authorizes access to tunnel payload bytes.

## endpoints and service authentication

The portal sends JSON over HTTPS to:

- POST /internal/purge to submit or retry a purge operation.
- POST /internal/purge/confirm to confirm a durably recorded complete result.

Both requests require Authorization: Bearer <PURGE_SECRET> and
Content-Type: application/json. Submit uses this body shape:

```json
{ "envelope": "<compact EdDSA JWT>" }
```

Confirmation uses this body shape:

```json
{
  "envelope": "<original compact EdDSA purge JWT>",
  "confirmation": "<compact EdDSA purge-confirm JWT>"
}
```

PURGE_SECRET is a portal-to-relay service credential. It is separate from the
operator grant credential and is never a browser credential.

## portal signing key

The portal signs compact JWTs with Ed25519 / EdDSA. The relay verifies them
against PORTAL_JWKS_PUBLIC, a JWKS envelope with Ed25519 public keys selected by
protected-header kid. The protected header MUST contain alg: "EdDSA" and a kid.
The relay verifies the compact-JWT signature before trusting payload claims.

All iat and exp values are safe-integer Unix seconds. The relay requires
iat <= relay_now, exp > relay_now, and exp > iat. There is no future-issued
clock-skew allowance in this internal contract.

## purge envelope

A submit payload requires:

| Claim | Value |
|---|---|
| iss | "spl-portal" |
| aud | "spl-relay-purge" |
| ver | string "1" |
| typ | string "purge" |
| op | opaque nonempty portal operation ID, at most 256 UTF-8 bytes |
| instances | array of relay instance-ID strings |
| iat | issue time |
| exp | expiry; exp - iat MUST be at most 604800 seconds |

A confirmation payload requires:

| Claim | Value |
|---|---|
| iss | "spl-portal" |
| aud | "spl-relay-purge" |
| ver | string "1" |
| typ | string "purge-confirm" |
| op | operation ID from the completed purge |
| snapshot_digest | `sha256:<64 lowercase hexadecimal digits>` for the canonical target snapshot |
| state | string "complete" |
| iat | issue time |
| exp | independent expiry; exp - iat MUST be at most 300 seconds |

The required payload typ separates submit from confirmation authority. A purge
JWT can never be accepted at the confirmation endpoint and vice versa.

The portal MUST choose a globally fresh op for every new purge operation. It
MUST NOT reissue an op after it has been confirmed, hard-deleted, or expired
while incomplete. A retry uses the unchanged operation and target set while the
original envelope remains valid.

## canonical target snapshot

Every instances entry MUST match ^[0-9a-fA-F-]{10,64}$. Case is significant.
The relay validates every entry, deduplicates exact strings, and sorts unique
values ascending in ASCII string order. It rejects more than 100 unique IDs; an
empty list is valid.

Let canonical be the sorted unique array. Its canonical snapshot text is exactly
JSON.stringify(canonical), without whitespace. The snapshot digest is SHA-256
over its UTF-8 bytes rendered sha256:<64 lowercase hexadecimal digits>.

The relay hashes raw op UTF-8 bytes the same way. It stores only that operation
hash and the snapshot digest; it never stores/logs raw op or target IDs.

## submit results and binding lifetime

Authenticated outcomes are JSON { "ver": "1", "disposition": "<value>" }.

The submit endpoint returns complete only after every named row has been
deleted. Repeating the same fresh completed envelope returns complete without
work. A D1 failure returns retryable; retrying the same still-valid envelope is
safe. A changed canonical snapshot for the same operation returns
altered_replay without mutation. Expired is terminal for that operation; the
portal creates a new operation ID rather than inferring success. Refused is used
for malformed, untrusted, or too-many input and makes no mutation.

The relay’s only replay binding stores the operation hash, snapshot digest,
retryable/complete/confirmed state, and immutable original exp. The expiry is
never extended/replaced. Both request routes reject a binding when relay_now is
at or after that expiry regardless of its state. A scheduled relay task also
sweeps every state at or after its immutable expiry, deleting the binding without
a request.

## completion confirmation

After complete, the portal MUST durably record the outcome and exact
confirmation JWT before sending confirmation. A confirmation request carries
both the original purge envelope and the confirmation envelope. The relay
fully verifies the original under the purge rules, including that it is
unexpired now, then fully verifies the confirmation under the purge-confirm
rules, including that it is independently unexpired now.

Before looking up a binding, the relay requires the envelopes to agree on the
operation ID and canonical snapshot digest; confirmation state is always
"complete". No binding returns not_complete without mutation. When a binding
exists, the relay checks its immutable expiry before inspecting state. Its
snapshot digest and immutable expiry must then exactly match the original purge
envelope, or the relay returns altered_replay without mutation. A matching
retryable binding returns not_complete without mutation. A matching complete
binding atomically transitions to confirmed while preserving operation hash,
snapshot digest, and expiry, then returns confirmed. A matching confirmed
binding returns confirmed without mutation, resolving a lost confirmation
response. A duplicate original purge submit against an unexpired confirmed
binding also returns confirmed without re-deleting relay rows.

## privacy and logging

The relay logs only coarse event names, counts, and dispositions. It never logs
an instance ID, operation ID/hash, snapshot digest, receipt, fingerprint, label,
ticket, portal-account identifier, or D1 error text. It creates no
portal-owner association or completion ledger beyond the expiry-bounded replay
binding.
