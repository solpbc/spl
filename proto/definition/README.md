# SPL pair-link definition bundle

This directory is the defined source for SPL pair-link wire values, CA-pin
domains, direct-address admission values, and the journal identity derivation. It follows the integrity and
identity conventions of an existing sol pbc contract-bundle format while
keeping HTTP API projection fields out of a wire-protocol definition.

`definition.toml` and `vectors.json` are the authored sources. The TOML
comments preserve why a definition value or citation is represented a
particular way. The bundle contains canonical `definition.json` and
`vectors.json` payloads plus one JSON Schema 2020-12 document for each.
`bundle/manifest.json` contains the single format-level identity and SemVer,
payload digests, and generator-input digests.

The current bundle version is `4.0.1`. The stable identities are:

- generator: `spl.proto.definition.generate.v1`
- bundle schema: `spl.pair-link-definition-bundle.schema.v1`
- schema dialect: `https://json-schema.org/draft/2020-12/schema`

## Generate and check

Run `make definition-generate` after editing the authored source, then commit
all generated files. Run `make definition-ci` to check the committed bundle.
Both commands require system `python3` version 3.11 or newer and use only the
standard library. Root `make ci` therefore requires system `python3` in
addition to its component runtimes.

After a reviewed definition change intentionally changes resolved entry bytes,
re-bless the authored vector bindings and then regenerate the bundle:

```sh
python3 proto/definition/generate.py --bless-vectors
make definition-generate
```

`--bless-vectors` rewrites only `proto/definition/vectors.json` entry digests.
It has no Makefile target, CI never invokes it, and normal generation fails on
stale digests instead of silently repairing them.

The gate enforces:

- the declared record shapes and cross-record references, using the same shape
  declaration that emits the consumer schema;
- strict canonical CIDR parsing and canonicalization with Python `ipaddress`;
- integer byte values paired with matching lowercase `0x` labels;
- explicit gap references wherever source documents leave unknown-value
  behavior unspecified;
- citation documents that are digest-pinned generator inputs, and markers of
  at least 12 characters that occur exactly once by exact substring count;
- the exact conformance-vector id and declared/recorded sets, sorted unique
  vector order, and operation-specific record shapes;
- vector citations restricted to normative source documents, declared-vector
  payload literals present in both their own payload fields and cited document,
  and per-vector definition-entry digests or explicit unbound reasons;
- an authored `covers` list that is sorted and unique, resolves completely,
  includes every bound entry, and has at least one citing vector per claim;
- canonical JSON rendered with sorted keys, two-space indentation, and one
  trailing newline;
- SHA-256 digests over canonical rendered text for generated artifacts and
  over generator-input file contents as committed, sorted manifest entries,
  and the exact bundle file set `{manifest.json} ∪ files[]`;
- generated artifacts that are byte-identical to a fresh generation;
- initial version `1.0.0`, followed by a strict SemVer increase whenever any
  byte under `proto/definition/` differs from `HEAD`;
- the version sentence in this README, so a hand-maintained version cannot
  drift from the manifest the way it did between `1.1.1` and `1.1.3`.

The schema is published for consumers to validate with their own tooling. The
stdlib-only gate enforces the shared record shapes directly; it does not claim
to run a JSON Schema validator.

Citation length is necessary but not sufficient. The obvious markers
`` `0x01` = IPv4 ``, `first 16 bytes of SHA-256 over the CA cert DER`,
`loopback`, `128-bit single-use nonce`, `unsigned big-endian`, and
`` selector `0x00` `` each occur twice in the source set. In particular,
`` `0x01` = IPv4 `` is 13 characters and remains ambiguous. The authored
source uses measured unique table rows or surrounding clauses instead, and
markers may contain embedded newlines.

## Source and vocabulary policy

The digest-pinned input set is exactly `definition.toml`, `vectors.json`,
`generate.py`, `proto/identity.md`, `proto/pairing.md`, and
`proto/pair-window.md`. Only those three protocol documents ground this
definition and its conformance corpus; digesting unrelated protocol documents
would make their unrelated edits fail this gate.

Each vocabulary retains an internal JSON `source_pointer`, following the
contract-bundle convention, and also carries a real `{document, marker}`
citation. An API projection can use its own structure as a source pointer, but
an authored wire protocol must be grounded in normative prose.

The vocabularies are classified as follows:

| Vocabulary | Classification | Unknown-value behavior |
|---|---|---|
| pair-link version | `extensible` | `unspecified_in_source_documents` |
| direct `addr_type` | `closed` | `unspecified_in_source_documents` |
| `ca_fp_tag` | `extensible` | `unspecified_in_source_documents` |
| relay-origin selector | `closed` | `unspecified_in_source_documents` |
| `0x05` candidate count | `closed` | `reject` |
| direct-address allow-list | `closed` | `reject` |
| version-and-tag pin domain | `extensible` | `unspecified_in_source_documents` |

The version byte is the most consequential gap: the documents explain how to
discriminate forms and demonstrate an evolving byte space, but never say what
to do with an unrecognized version. The definition records that silence rather
than inventing refusal behavior. The relay-origin selector is `closed`: zero
is an in-band default sentinel and integers 1 through 255 are byte lengths, so
together they exhaust the byte space and the vocabulary cannot grow. It is a
length grammar with an in-band sentinel, not a set of enumerated alternatives.
The documents still do not state behavior when the declared length disagrees
with the blob.

`0x03` is retired and reserved against reuse by this definition. Its record
intentionally has no `fields` or `layout` key. Because the source documents do
not permanently reserve that byte, the assignment delta is recorded as a gap.
Likewise, direct forms use the explicit `absent_in_layout` tag sentinel and a
gap reference; a missing tag is never represented by a bare null.

## Conformance corpus

The corpus contains 11 `declared` vectors whose payload literals appear in the
protocol documents and 64 `recorded` vectors promoted from the public
`solpbc/spl-rust` conformance corpus. Because 64 of 75 vectors record one
implementation's behavior, this corpus is not broad conformance proof.

The six journal-identity vectors are the exception to that caveat: they are
authored from published constants rather than promoted from an implementation.
Two of them carry the same expected jid for the same key under two encodings,
which is a case no implementation can produce from its own output. The other
four cover all three refusal kinds.

Vectors cite only `proto/identity.md`, `proto/pairing.md`, and
`proto/pair-window.md`. `framing.md`, `session.md`, and `tokens.md` have zero
citing vectors. The
generator holds the assertion of which vector ids and kinds are
expected; `vectors.json` holds their data. Those are different responsibilities,
and this README intentionally copies neither id list.

A consumer vendors the complete five-file `bundle/` directory, verifies the
manifest and payload schemas, and executes the applicable vectors against its
own implementation. The gate proves that this corpus is internally consistent
and current with its cited documents. It proves no implementation conforms,
and it does not prove this promoted copy matches the generating package's
output. The generating package vendors this bundle and runs it against its own
code to establish that connection.

## Scope

This bundle does not define framing, session lifecycle, or token claims. It
defines the journal identity derivation, but not the journal mark built on top
of it. It carries no release tag, consumer adoption state, or rollout state. Silence
here grants no permission to change those areas.
