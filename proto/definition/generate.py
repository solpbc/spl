#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc

"""Generate and verify the committed SPL pair-link definition bundle."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import subprocess
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


GENERATOR_IDENTITY = "spl.proto.definition.generate.v1"
BUNDLE_SCHEMA_IDENTITY = "spl.pair-link-definition-bundle.schema.v1"
SCHEMA_DIALECT_URI = "https://json-schema.org/draft/2020-12/schema"
INITIAL_BUNDLE_SEMVER = "1.0.0"
DEFINITION_REL = Path("proto/definition/bundle/definition.json")
SCHEMA_REL = Path("proto/definition/bundle/definition.schema.json")
VECTORS_REL = Path("proto/definition/bundle/vectors.json")
VECTORS_SCHEMA_REL = Path("proto/definition/bundle/vectors.schema.json")
MANIFEST_REL = Path("proto/definition/bundle/manifest.json")
BUNDLE_REL = Path("proto/definition/bundle")
SOURCE_REL = Path("proto/definition/definition.toml")
VECTORS_SOURCE_REL = Path("proto/definition/vectors.json")
GENERATOR_REL = Path("proto/definition/generate.py")
PAYLOAD_RELS = (DEFINITION_REL, SCHEMA_REL, VECTORS_REL, VECTORS_SCHEMA_REL)

GENERATOR_INPUTS: tuple[tuple[str, Path, str], ...] = (
    ("definition.authored_source", SOURCE_REL, "authored_source"),
    ("definition.conformance_corpus", VECTORS_SOURCE_REL, "conformance_corpus"),
    ("definition.generator", GENERATOR_REL, "generator"),
    ("source.identity", Path("proto/identity.md"), "normative_source_document"),
    ("source.pair_window", Path("proto/pair-window.md"), "normative_source_document"),
    ("source.pairing", Path("proto/pairing.md"), "normative_source_document"),
)
README_REL = Path("proto/definition/README.md")

EXPECTED_VECTOR_IDS = (
    "direct.admission.link-local.above",
    "direct.admission.link-local.below",
    "direct.admission.link-local.example",
    "direct.admission.link-local.lower",
    "direct.admission.link-local.upper",
    "direct.admission.loopback.above",
    "direct.admission.loopback.below",
    "direct.admission.loopback.lower",
    "direct.admission.loopback.upper",
    "direct.admission.rfc1918-10.above",
    "direct.admission.rfc1918-10.below",
    "direct.admission.rfc1918-10.lower",
    "direct.admission.rfc1918-10.upper",
    "direct.admission.rfc1918-172.above",
    "direct.admission.rfc1918-172.below",
    "direct.admission.rfc1918-172.lower",
    "direct.admission.rfc1918-172.upper",
    "direct.admission.rfc1918-192.above",
    "direct.admission.rfc1918-192.below",
    "direct.admission.rfc1918-192.lower",
    "direct.admission.rfc1918-192.upper",
    "direct.admission.rfc6598.above",
    "direct.admission.rfc6598.below",
    "direct.admission.rfc6598.lower",
    "direct.admission.rfc6598.upper",
    "identity.jid.canonical",
    "identity.jid.compressed-point",
    "identity.jid.explicit-parameters",
    "identity.jid.malformed",
    "identity.jid.off-curve-point",
    "identity.jid.trailing-data",
    "identity.jid.unused-bits",
    "identity.jid.wrong-algorithm",
    "identity.jid.wrong-curve",
    "pair.v04.canonical.admission",
    "pair.v04.canonical.decode",
    "pair.v04.truncated.0",
    "pair.v04.truncated.1",
    "pair.v04.truncated.2",
    "pair.v04.truncated.24",
    "pair.v04.truncated.39",
    "pair.v04.truncated.6",
    "pair.v04.truncated.8",
    "pair.v04.unsupported-address-tag",
    "pair.v05.admission.all-allowed",
    "pair.v05.admission.mixed-refused",
    "pair.v05.count.0.refuse",
    "pair.v05.count.1",
    "pair.v05.count.2",
    "pair.v05.count.255.refuse",
    "pair.v05.count.3",
    "pair.v05.count.4",
    "pair.v05.count.5.refuse",
    "pair.v05.disallowed-member.first",
    "pair.v05.disallowed-member.last",
    "pair.v05.disallowed-member.middle",
    "pair.v05.duplicate.coalesced",
    "pair.v05.duplicate.count-five-refused",
    "pair.v05.duplicate.disallowed",
    "pair.v05.truncated.1",
    "pair.v05.truncated.12",
    "pair.v05.truncated.2",
    "pair.v05.truncated.3",
    "pair.v05.truncated.4",
    "pair.v05.truncated.44",
    "pair.v05.truncated.5",
    "pair.v05.truncated.8",
    "pair.v05.unsupported-address-tag",
    "pair.v06.custom-origin-invalid-utf8",
    "pair.v06.custom-origin-truncated",
    "pair.v06.custom.published",
    "pair.v06.default.published",
    "pair.v06.truncated.1",
    "pair.v06.truncated.10",
    "pair.v06.truncated.26",
    "pair.v06.truncated.9",
    "pair.v06.unknown-ca-tag",
    "relay.rk.published",
)
EXPECTED_DECLARED_VECTOR_IDS = (
    "identity.jid.canonical",
    "identity.jid.compressed-point",
    "identity.jid.explicit-parameters",
    "identity.jid.malformed",
    "identity.jid.off-curve-point",
    "identity.jid.trailing-data",
    "identity.jid.unused-bits",
    "identity.jid.wrong-algorithm",
    "identity.jid.wrong-curve",
    "pair.v04.canonical.admission",
    "pair.v04.canonical.decode",
    "pair.v06.custom.published",
    "pair.v06.default.published",
    "relay.rk.published",
)
EXPECTED_RECORDED_VECTOR_IDS = tuple(
    vector_id for vector_id in EXPECTED_VECTOR_IDS if vector_id not in EXPECTED_DECLARED_VECTOR_IDS
)
assert len(EXPECTED_VECTOR_IDS) == 78
assert EXPECTED_VECTOR_IDS == tuple(sorted(set(EXPECTED_VECTOR_IDS)))
assert len(EXPECTED_DECLARED_VECTOR_IDS) == 14
assert EXPECTED_DECLARED_VECTOR_IDS == tuple(sorted(set(EXPECTED_DECLARED_VECTOR_IDS)))
assert set(EXPECTED_DECLARED_VECTOR_IDS) < set(EXPECTED_VECTOR_IDS)
assert len(EXPECTED_RECORDED_VECTOR_IDS) == 64

SEMVER_RE = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
GAP_KINDS = {
    "assignment_delta",
    "internally_inconsistent",
    "silent",
    "stale_cross_reference",
}


def object_schema(properties: dict[str, Any], required: list[str] | None = None) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": properties,
        "required": required if required is not None else list(properties),
        "additionalProperties": False,
    }


STRING = {"type": "string", "minLength": 1}
NONNEGATIVE_INTEGER = {"type": "integer", "minimum": 0}
BYTE_INTEGER = {"type": "integer", "minimum": 0, "maximum": 255}
CITATION_REF = {"$ref": "#/$defs/citation"}
GAP_REF = {"anyOf": [STRING, {"type": "null"}]}
SCALAR_OFFSET = {"anyOf": [NONNEGATIVE_INTEGER, STRING]}

# This is the one record-shape declaration used by both direct validation and
# the emitted consumer schema.
RECORD_SCHEMAS: dict[str, dict[str, Any]] = {
    "citation": object_schema({"document": STRING, "marker": {"type": "string", "minLength": 1}}),
    "byte_value": object_schema({"value": BYTE_INTEGER, "label": STRING}),
    "byte_range": object_schema(
        {
            "minimum": BYTE_INTEGER,
            "minimum_label": STRING,
            "maximum": BYTE_INTEGER,
            "maximum_label": STRING,
        }
    ),
    "allow_entry": object_schema(
        {
            "id": STRING,
            "family": {"enum": ["ipv4", "ipv6", "unspecified_in_source_documents"]},
            "kind": {"enum": ["cidr", "source_term"]},
            "value": STRING,
            "citation": CITATION_REF,
            "gap_ref": GAP_REF,
        }
    ),
    "form_field": object_schema(
        {
            "id": STRING,
            "offset": SCALAR_OFFSET,
            "length": SCALAR_OFFSET,
            "encoding": STRING,
            "semantic_ref": {"anyOf": [STRING, {"type": "null"}]},
            "citation": CITATION_REF,
            "gap_refs": {"type": "array", "items": STRING},
        }
    ),
    "total_length_exact": object_schema(
        {"kind": {"const": "exact"}, "bytes": NONNEGATIVE_INTEGER, "citation": CITATION_REF}
    ),
    "total_length_expression": object_schema(
        {"kind": {"const": "expression"}, "expression": STRING, "citation": CITATION_REF}
    ),
    "total_length_incomplete": object_schema(
        {
            "kind": {"const": "incomplete_source_rule"},
            "base_bytes": NONNEGATIVE_INTEGER,
            "variable_field": STRING,
            "exact_rule": {"const": "unspecified_in_source_documents"},
            "citation": CITATION_REF,
            "gap_ref": STRING,
        }
    ),
    "active_form": object_schema(
        {
            "id": STRING,
            "version": BYTE_INTEGER,
            "label": STRING,
            "status": {"const": "active"},
            "fields": {"type": "array", "items": {"$ref": "#/$defs/form_field"}},
            "total_length": {
                "oneOf": [
                    {"$ref": "#/$defs/total_length_exact"},
                    {"$ref": "#/$defs/total_length_expression"},
                    {"$ref": "#/$defs/total_length_incomplete"},
                ]
            },
            "citation": CITATION_REF,
            "gap_refs": {"type": "array", "items": STRING},
        }
    ),
    "retired_form": object_schema(
        {
            "id": STRING,
            "version": BYTE_INTEGER,
            "label": STRING,
            "status": {"const": "retired"},
            "reuse": {"const": "reserved"},
            "citation": CITATION_REF,
            "gap_refs": {"type": "array", "items": STRING},
        }
    ),
    "ca_pin_tag": object_schema(
        {
            "id": STRING,
            "value": BYTE_INTEGER,
            "label": STRING,
            "status": {"const": "active"},
            "pin_domain_ref": STRING,
            "citation": CITATION_REF,
            "gap_ref": GAP_REF,
        }
    ),
    "pin_domain": object_schema(
        {
            "id": STRING,
            "versions": {"type": "array", "items": BYTE_INTEGER, "minItems": 1},
            "version_labels": {"type": "array", "items": STRING, "minItems": 1},
            "tag": {"anyOf": [BYTE_INTEGER, {"const": "absent_in_layout"}]},
            "tag_label": STRING,
            "hash": {"const": "sha256"},
            "input": {"enum": ["ca_certificate_der", "ca_subject_public_key_info_der"]},
            "prefix_bytes": {"const": 16},
            "citation": CITATION_REF,
            "gap_refs": {"type": "array", "items": STRING},
        }
    ),
    "gap": object_schema(
        {
            "id": STRING,
            "subject": STRING,
            "kind": {"enum": sorted(GAP_KINDS)},
            "citation": CITATION_REF,
            "description": STRING,
        }
    ),
    "source_claim": object_schema(
        {
            "id": STRING,
            "citation": CITATION_REF,
            "description": STRING,
        }
    ),
    # Journal identity: the jid derivation, its refusal vocabulary, and the
    # statement of what a device id is. One uniform shape across all of them,
    # because every record here answers the same question — what is normatively
    # fixed about this value — and a per-kind shape would only add ways to fail.
    "journal_identity": object_schema(
        {
            "id": STRING,
            "kind": {"enum": ["key_domain", "kdf", "stamp", "refusal", "device_fingerprint"]},
            "value": STRING,
            "citation": CITATION_REF,
            "gap_ref": GAP_REF,
        }
    ),
    "default_origin": object_schema({"value": STRING, "citation": CITATION_REF}),
    "selector_registry": object_schema(
        {
            "default_sentinel": {"$ref": "#/$defs/byte_value"},
            "default_origin": {"$ref": "#/$defs/default_origin"},
            "custom_origin_byte_length": {"$ref": "#/$defs/byte_range"},
        }
    ),
}

VOCABULARY_COMMON = {
    "id": STRING,
    "classification": {"enum": ["closed", "extensible", "extensible_integer"]},
    "unknown_value_behavior": STRING,
    "source_pointer": STRING,
    "citation": CITATION_REF,
}
VOCABULARY_VALUES = {
    "type": "array",
    "items": {"anyOf": [{"$ref": "#/$defs/byte_value"}, STRING]},
    "minItems": 1,
}
RECORD_SCHEMAS.update(
    {
        "vocabulary_values_documented": object_schema(
            {**VOCABULARY_COMMON, "values": VOCABULARY_VALUES}
        ),
        "vocabulary_values_gap": object_schema(
            {**VOCABULARY_COMMON, "values": VOCABULARY_VALUES, "gap_ref": STRING}
        ),
        "vocabulary_registry_documented": object_schema(
            {
                **VOCABULARY_COMMON,
                "known_registry": {"$ref": "#/$defs/selector_registry"},
            }
        ),
        "vocabulary_registry_gap": object_schema(
            {
                **VOCABULARY_COMMON,
                "known_registry": {"$ref": "#/$defs/selector_registry"},
                "gap_ref": STRING,
            }
        ),
    }
)

DEFINITION_SCHEMA: dict[str, Any] = {
    "$schema": SCHEMA_DIALECT_URI,
    "title": "SPL pair-link and direct-address definition",
    "type": "object",
    "properties": {
        "address_allow_list": {"type": "array", "items": {"$ref": "#/$defs/allow_entry"}},
        "ca_pin_tags": {"type": "array", "items": {"$ref": "#/$defs/ca_pin_tag"}},
        "forms": {
            "type": "array",
            "items": {
                "oneOf": [
                    {"$ref": "#/$defs/active_form"},
                    {"$ref": "#/$defs/retired_form"},
                ]
            },
        },
        "gaps": {"type": "array", "items": {"$ref": "#/$defs/gap"}},
        "journal_identity": {"type": "array", "items": {"$ref": "#/$defs/journal_identity"}},
        "pin_domains": {"type": "array", "items": {"$ref": "#/$defs/pin_domain"}},
        "source_claims": {"type": "array", "items": {"$ref": "#/$defs/source_claim"}},
        "vocabularies": {
            "type": "array",
            "items": {
                "oneOf": [
                    {"$ref": "#/$defs/vocabulary_values_documented"},
                    {"$ref": "#/$defs/vocabulary_values_gap"},
                    {"$ref": "#/$defs/vocabulary_registry_documented"},
                    {"$ref": "#/$defs/vocabulary_registry_gap"},
                ]
            },
        },
    },
    "required": [
        "address_allow_list",
        "ca_pin_tags",
        "forms",
        "gaps",
        "journal_identity",
        "pin_domains",
        "source_claims",
        "vocabularies",
    ],
    "additionalProperties": False,
    "$defs": RECORD_SCHEMAS,
}

FILE_ENTRY_SCHEMA = object_schema(
    {"path": STRING, "sha256": {"type": "string", "pattern": SHA256_RE.pattern}}
)
INPUT_ENTRY_SCHEMA = object_schema(
    {
        "id": STRING,
        "path": STRING,
        "role": STRING,
        "sha256": {"type": "string", "pattern": SHA256_RE.pattern},
    }
)
MANIFEST_SCHEMA = object_schema(
    {
        "bundle_schema_identity": {"const": BUNDLE_SCHEMA_IDENTITY},
        "bundle_semver": STRING,
        "files": {"type": "array", "items": FILE_ENTRY_SCHEMA},
        "generator_identity": {"const": GENERATOR_IDENTITY},
        "generator_inputs": {"type": "array", "items": INPUT_ENTRY_SCHEMA},
        "schema_dialect_uri": {"const": SCHEMA_DIALECT_URI},
    }
)

VECTOR_ERROR_SCHEMA = object_schema(
    {
        "kind": STRING,
        "address": STRING,
        "address_type": BYTE_INTEGER,
        "count": BYTE_INTEGER,
        "expected": NONNEGATIVE_INTEGER,
        "got": NONNEGATIVE_INTEGER,
        "tag": BYTE_INTEGER,
    },
    required=["kind"],
)
VECTOR_CANDIDATE_SCHEMA = object_schema({"host": STRING, "port": NONNEGATIVE_INTEGER})
VECTOR_EXPECTED_SCHEMA = object_schema(
    {
        "result": {"enum": ["direct", "error", "relay"]},
        "error": VECTOR_ERROR_SCHEMA,
        "candidates": {"type": "array", "items": VECTOR_CANDIDATE_SCHEMA},
        "nonce_hex": STRING,
        "ca_fp_hex": STRING,
        "secret_hex": STRING,
        "ca_fp_spki_hex": STRING,
        "relay_origin": STRING,
    },
    required=["result"],
)
VECTOR_COMMON_PROPERTIES = {
    "id": STRING,
    "kind": {"enum": ["declared", "recorded"]},
    "citation": CITATION_REF,
    "entry_digests": {
        "type": "object",
        "additionalProperties": {"type": "string", "pattern": SHA256_RE.pattern},
    },
    "unbound_reason": {"anyOf": [STRING, {"type": "null"}]},
    "document_literals": {"type": "array", "items": STRING},
}
VECTOR_COMMON_REQUIRED = [
    "id",
    "kind",
    "operation",
    "citation",
    "entry_digests",
    "unbound_reason",
    "document_literals",
]
VECTOR_PARSE_SCHEMA = object_schema(
    {
        **VECTOR_COMMON_PROPERTIES,
        "operation": {"const": "parse_pair_link"},
        "input": object_schema(
            {"encoding": {"enum": ["blob_hex", "link"]}, "value": {"type": "string"}}
        ),
        "expected": VECTOR_EXPECTED_SCHEMA,
    },
    required=[*VECTOR_COMMON_REQUIRED, "input", "expected"],
)
VECTOR_DECODE_SCHEMA = object_schema(
    {
        **VECTOR_COMMON_PROPERTIES,
        "operation": {"const": "decode_crockford"},
        "input": STRING,
        "expected_hex": STRING,
    },
    required=[*VECTOR_COMMON_REQUIRED, "input", "expected_hex"],
)
VECTOR_DERIVE_SCHEMA = object_schema(
    {
        **VECTOR_COMMON_PROPERTIES,
        "operation": {"const": "derive_relay_key"},
        "secret_hex": STRING,
        "expected_hex": STRING,
    },
    required=[*VECTOR_COMMON_REQUIRED, "secret_hex", "expected_hex"],
)
# The jid operation needs an expectation that can carry a refusal. The relay-key
# shape cannot: it is secret_hex plus expected_hex with no error branch, and the
# refusals are the half of this contract worth pinning.
# A refusal is one outcome. An implementation may carry a diagnostic reason and
# the contract does not compare it, so the vector records no kind.
VECTOR_JID_ERROR_SCHEMA = object_schema({}, required=[])
VECTOR_JID_EXPECTED_SCHEMA = object_schema(
    {
        "result": {"enum": ["jid", "error"]},
        "jid": STRING,
        "error": VECTOR_JID_ERROR_SCHEMA,
    },
    required=["result"],
)
VECTOR_DERIVE_JID_SCHEMA = object_schema(
    {
        **VECTOR_COMMON_PROPERTIES,
        "operation": {"const": "derive_jid"},
        "spki_der_hex": STRING,
        "expected": VECTOR_JID_EXPECTED_SCHEMA,
    },
    required=[*VECTOR_COMMON_REQUIRED, "spki_der_hex", "expected"],
)
VECTORS_SCHEMA: dict[str, Any] = {
    "$schema": SCHEMA_DIALECT_URI,
    "title": "SPL pair-link conformance vectors",
    "type": "object",
    "properties": {
        "covers": {"type": "array", "items": STRING},
        "vectors": {
            "type": "array",
            "items": {
                "oneOf": [
                    VECTOR_PARSE_SCHEMA,
                    VECTOR_DECODE_SCHEMA,
                    VECTOR_DERIVE_SCHEMA,
                    VECTOR_DERIVE_JID_SCHEMA,
                ]
            },
        },
    },
    "required": ["covers", "vectors"],
    "additionalProperties": False,
    "$defs": {"citation": RECORD_SCHEMAS["citation"]},
}


@dataclass
class Failures:
    messages: list[str] = field(default_factory=list)

    def add(self, message: str, recovery: str) -> None:
        self.messages.append(f"{message} Recovery: {recovery}.")

    def report(self) -> int:
        if not self.messages:
            return 0
        for message in sorted(set(self.messages)):
            print(message, file=sys.stderr)
        return 1


@dataclass
class CoverageReport:
    counts: dict[str, int] = field(default_factory=dict)
    unclaimed: list[str] = field(default_factory=list)


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def render_json(payload: object) -> str:
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def parse_semver(value: str) -> tuple[int, int, int]:
    match = SEMVER_RE.fullmatch(value)
    if not match:
        raise ValueError(f"invalid strict SemVer {value!r}")
    return tuple(int(part) for part in match.groups())


def compare_semver(left: str, right: str) -> int:
    left_parts = parse_semver(left)
    right_parts = parse_semver(right)
    return (left_parts > right_parts) - (left_parts < right_parts)


def read_text_exact(path: Path) -> str:
    return path.read_bytes().decode("utf-8")


def load_json(
    text: str,
    label: str,
    failures: Failures,
    recovery: str | None = None,
    namespace: str = "definition",
) -> Any | None:
    recovery = recovery or f"run make definition-generate to restore {label}"
    duplicates: list[str] = []

    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                duplicates.append(key)
            result[key] = value
        return result

    try:
        payload = json.loads(text, object_pairs_hook=no_duplicates)
    except json.JSONDecodeError as exc:
        failures.add(
            f"{namespace} JSON parse failed: {label}: {exc}",
            recovery,
        )
        return None
    if duplicates:
        failures.add(
            f"{namespace} JSON structure failed: {label} has duplicate key(s) {sorted(set(duplicates))}",
            recovery,
        )
    return payload


def resolve_schema_ref(ref: str) -> dict[str, Any]:
    prefix = "#/$defs/"
    if not ref.startswith(prefix):
        raise ValueError(f"unsupported schema reference {ref}")
    return RECORD_SCHEMAS[ref[len(prefix) :]]


def validate_schema_value(
    value: Any,
    schema: dict[str, Any],
    pointer: str,
    label: str,
    failures: Failures,
    namespace: str = "definition",
) -> None:
    if "$ref" in schema:
        validate_schema_value(
            value,
            resolve_schema_ref(schema["$ref"]),
            pointer,
            label,
            failures,
            namespace,
        )
        return
    if "oneOf" in schema:
        matches = sum(schema_matches(value, candidate) for candidate in schema["oneOf"])
        if matches != 1:
            failures.add(
                f"{namespace} structure failed: {label}{pointer} matches {matches} record variants, expected exactly one",
                f"fix {label}{pointer} to use one declared record shape",
            )
            return
        for candidate in schema["oneOf"]:
            if schema_matches(value, candidate):
                validate_schema_value(value, candidate, pointer, label, failures, namespace)
                return
    if "anyOf" in schema:
        for candidate in schema["anyOf"]:
            if schema_matches(value, candidate):
                validate_schema_value(value, candidate, pointer, label, failures, namespace)
                return
        failures.add(
            f"{namespace} structure failed: {label}{pointer} does not match any permitted type",
            f"fix {label}{pointer} to match its declared record shape",
        )
        return
    if "const" in schema and value != schema["const"]:
        failures.add(
            f"{namespace} structure failed: {label}{pointer} must equal {schema['const']!r}, got {value!r}",
            f"set {label}{pointer} to {schema['const']!r}",
        )
        return
    if "enum" in schema and value not in schema["enum"]:
        failures.add(
            f"{namespace} structure failed: {label}{pointer} has unsupported value {value!r}",
            f"set {label}{pointer} to one of {schema['enum']!r}",
        )
        return
    expected_type = schema.get("type")
    if expected_type == "object":
        if not isinstance(value, dict):
            type_failure(value, "object", pointer, label, failures, namespace)
            return
        properties = schema.get("properties", {})
        required = schema.get("required", [])
        missing = sorted(set(required) - set(value))
        extra = sorted(set(value) - set(properties)) if schema.get("additionalProperties") is False else []
        if missing:
            failures.add(
                f"{namespace} structure failed: {label}{pointer} is missing required key(s) {missing}",
                f"add {', '.join(missing)} to {label}{pointer}",
            )
        if extra:
            failures.add(
                f"{namespace} structure failed: {label}{pointer} has undeclared key(s) {extra}",
                f"remove {', '.join(extra)} from {label}{pointer}",
            )
        for key in sorted(set(value) & set(properties)):
            validate_schema_value(
                value[key], properties[key], f"{pointer}/{key}", label, failures, namespace
            )
        return
    if expected_type == "array":
        if not isinstance(value, list):
            type_failure(value, "array", pointer, label, failures, namespace)
            return
        if len(value) < schema.get("minItems", 0):
            failures.add(
                f"{namespace} structure failed: {label}{pointer} has too few items",
                f"add the required items to {label}{pointer}",
            )
        for index, item in enumerate(value):
            validate_schema_value(
                item, schema["items"], f"{pointer}/{index}", label, failures, namespace
            )
        return
    if expected_type == "string":
        if not isinstance(value, str):
            type_failure(value, "string", pointer, label, failures, namespace)
            return
        if len(value) < schema.get("minLength", 0):
            failures.add(
                f"{namespace} structure failed: {label}{pointer} is empty",
                f"set {label}{pointer} to a non-empty string",
            )
        pattern = schema.get("pattern")
        if pattern and re.fullmatch(pattern, value) is None:
            failures.add(
                f"{namespace} structure failed: {label}{pointer} does not match {pattern}",
                f"fix {label}{pointer} to match {pattern}",
            )
        return
    if expected_type == "integer":
        if not isinstance(value, int) or isinstance(value, bool):
            type_failure(value, "integer", pointer, label, failures, namespace)
            return
        if value < schema.get("minimum", value):
            failures.add(
                f"{namespace} structure failed: {label}{pointer} is below its minimum",
                f"raise {label}{pointer} to at least {schema['minimum']}",
            )
        if value > schema.get("maximum", value):
            failures.add(
                f"{namespace} structure failed: {label}{pointer} is above its maximum",
                f"lower {label}{pointer} to at most {schema['maximum']}",
            )
        return
    if expected_type == "null" and value is not None:
        type_failure(value, "null", pointer, label, failures, namespace)


def type_failure(
    value: Any,
    expected: str,
    pointer: str,
    label: str,
    failures: Failures,
    namespace: str = "definition",
) -> None:
    failures.add(
        f"{namespace} structure failed: {label}{pointer} must be {expected}, got {type(value).__name__}",
        f"fix {label}{pointer} to use the declared {expected} type",
    )


def schema_matches(value: Any, schema: dict[str, Any]) -> bool:
    if "$ref" in schema:
        return schema_matches(value, resolve_schema_ref(schema["$ref"]))
    if "oneOf" in schema:
        return sum(schema_matches(value, candidate) for candidate in schema["oneOf"]) == 1
    if "anyOf" in schema:
        return any(schema_matches(value, candidate) for candidate in schema["anyOf"])
    if "const" in schema and value != schema["const"]:
        return False
    if "enum" in schema and value not in schema["enum"]:
        return False
    expected_type = schema.get("type")
    if expected_type == "object":
        if not isinstance(value, dict):
            return False
        required = set(schema.get("required", []))
        properties = set(schema.get("properties", {}))
        return required <= set(value) and (
            schema.get("additionalProperties") is not False or set(value) <= properties
        )
    if expected_type == "array":
        return isinstance(value, list)
    if expected_type == "string":
        return isinstance(value, str)
    if expected_type == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected_type == "null":
        return value is None
    return True


def citation_payload(citations: dict[str, Any], citation_id: object, failures: Failures) -> dict[str, str]:
    if not isinstance(citation_id, str) or citation_id not in citations:
        failures.add(
            f"definition source reference failed: definition.toml citation {citation_id!r} is not declared",
            "declare the citation under definition.toml [citations] and reference its exact id",
        )
        return {"document": "missing", "marker": "missing citation marker"}
    citation = citations[citation_id]
    if not isinstance(citation, dict):
        failures.add(
            f"definition source structure failed: definition.toml citations.{citation_id} must be a table",
            f"make definition.toml citations.{citation_id} a document-and-marker table",
        )
        return {"document": "missing", "marker": "missing citation marker"}
    return {
        "document": citation.get("document", ""),
        "marker": citation.get("marker", ""),
    }


def build_definition(source: dict[str, Any], failures: Failures) -> dict[str, Any]:
    citations = source.get("citations", {})
    if not isinstance(citations, dict):
        failures.add(
            "definition source structure failed: definition.toml citations must be a table",
            "replace definition.toml citations with named document-and-marker tables",
        )
        citations = {}

    def cite(record: dict[str, Any]) -> dict[str, str]:
        return citation_payload(citations, record.get("citation"), failures)

    address_allow_list = [
        {
            "id": item.get("id"),
            "family": item.get("family"),
            "kind": item.get("kind"),
            "value": item.get("value"),
            "citation": cite(item),
            "gap_ref": item.get("gap_ref"),
        }
        for item in source.get("address_allow_list", [])
        if isinstance(item, dict)
    ]
    pin_domains = [
        {
            "id": item.get("id"),
            "versions": item.get("versions"),
            "version_labels": item.get("version_labels"),
            "tag": item.get("tag"),
            "tag_label": item.get("tag_label"),
            "hash": item.get("hash"),
            "input": item.get("input"),
            "prefix_bytes": item.get("prefix_bytes"),
            "citation": cite(item),
            "gap_refs": item.get("gap_refs", []),
        }
        for item in source.get("pin_domains", [])
        if isinstance(item, dict)
    ]
    ca_pin_tags = [
        {
            "id": item.get("id"),
            "value": item.get("value"),
            "label": item.get("label"),
            "status": item.get("status"),
            "pin_domain_ref": item.get("pin_domain_ref"),
            "citation": cite(item),
            "gap_ref": item.get("gap_ref"),
        }
        for item in source.get("ca_pin_tags", [])
        if isinstance(item, dict)
    ]
    forms: list[dict[str, Any]] = []
    for item in source.get("forms", []):
        if not isinstance(item, dict):
            continue
        if item.get("status") == "retired":
            forms.append(
                {
                    "id": item.get("id"),
                    "version": item.get("version"),
                    "label": item.get("label"),
                    "status": item.get("status"),
                    "reuse": item.get("reuse"),
                    "citation": cite(item),
                    "gap_refs": item.get("gap_refs", []),
                }
            )
            continue
        fields = []
        for form_field in item.get("fields", []):
            if not isinstance(form_field, dict):
                continue
            fields.append(
                {
                    "id": form_field.get("id"),
                    "offset": form_field.get("offset"),
                    "length": form_field.get("length"),
                    "encoding": form_field.get("encoding"),
                    "semantic_ref": form_field.get("semantic_ref"),
                    "citation": cite(form_field),
                    "gap_refs": form_field.get("gap_refs", []),
                }
            )
        total_source = item.get("total_length", {})
        total_length: dict[str, Any]
        if not isinstance(total_source, dict):
            total_length = {}
        elif total_source.get("kind") == "exact":
            total_length = {
                "kind": "exact",
                "bytes": total_source.get("bytes"),
                "citation": cite(total_source),
            }
        elif total_source.get("kind") == "expression":
            total_length = {
                "kind": "expression",
                "expression": total_source.get("expression"),
                "citation": cite(total_source),
            }
        else:
            total_length = {
                "kind": total_source.get("kind"),
                "base_bytes": total_source.get("base_bytes"),
                "variable_field": total_source.get("variable_field"),
                "exact_rule": total_source.get("exact_rule"),
                "citation": cite(total_source),
                "gap_ref": total_source.get("gap_ref"),
            }
        forms.append(
            {
                "id": item.get("id"),
                "version": item.get("version"),
                "label": item.get("label"),
                "status": item.get("status"),
                "fields": fields,
                "total_length": total_length,
                "citation": cite(item),
                "gap_refs": item.get("gap_refs", []),
            }
        )
    vocabularies: list[dict[str, Any]] = []
    for item in source.get("vocabularies", []):
        if not isinstance(item, dict):
            continue
        vocabulary = {
            "id": item.get("id"),
            "classification": item.get("classification"),
            "unknown_value_behavior": item.get("unknown_value_behavior"),
            "source_pointer": item.get("source_pointer"),
            "citation": cite(item),
        }
        if "values" in item:
            vocabulary["values"] = item["values"]
        if "known_registry" in item:
            registry = item["known_registry"]
            if isinstance(registry, dict) and "default_origin" in registry:
                registry = dict(registry)
                default_origin = registry.get("default_origin")
                if isinstance(default_origin, dict):
                    registry["default_origin"] = {
                        "value": default_origin.get("value"),
                        "citation": cite(default_origin),
                    }
            vocabulary["known_registry"] = registry
        if "gap_ref" in item:
            vocabulary["gap_ref"] = item["gap_ref"]
        vocabularies.append(vocabulary)
    source_claims = [
        {
            "id": item.get("id"),
            "citation": cite(item),
            "description": item.get("description"),
        }
        for item in source.get("source_claims", [])
        if isinstance(item, dict)
    ]
    gaps = [
        {
            "id": item.get("id"),
            "subject": item.get("subject"),
            "kind": item.get("kind"),
            "citation": cite(item),
            "description": item.get("description"),
        }
        for item in source.get("gaps", [])
        if isinstance(item, dict)
    ]
    journal_identity = [
        {
            "id": item.get("id"),
            "kind": item.get("kind"),
            "value": item.get("value"),
            "citation": cite(item),
            "gap_ref": item.get("gap_ref"),
        }
        for item in source.get("journal_identity", [])
        if isinstance(item, dict)
    ]
    return {
        "address_allow_list": address_allow_list,
        "ca_pin_tags": ca_pin_tags,
        "forms": forms,
        "gaps": gaps,
        "journal_identity": journal_identity,
        "pin_domains": pin_domains,
        "source_claims": source_claims,
        "vocabularies": vocabularies,
    }


def validate_source_top_level(source: dict[str, Any], failures: Failures) -> None:
    expected = {
        "address_allow_list",
        "bundle_semver",
        "ca_pin_tags",
        "citations",
        "forms",
        "gaps",
        "journal_identity",
        "pin_domains",
        "source_claims",
        "vocabularies",
    }
    missing = sorted(expected - set(source))
    extra = sorted(set(source) - expected)
    if missing:
        failures.add(
            f"definition source structure failed: definition.toml is missing top-level key(s) {missing}",
            f"add {', '.join(missing)} to definition.toml",
        )
    if extra:
        failures.add(
            f"definition source structure failed: definition.toml has undeclared top-level key(s) {extra}",
            f"remove {', '.join(extra)} from definition.toml",
        )


def validate_source_record(
    record: object,
    label: str,
    schema_name: str,
    optional: set[str],
    failures: Failures,
) -> bool:
    if not isinstance(record, dict):
        failures.add(
            f"definition source structure failed: definition.toml {label} must be a table",
            f"replace definition.toml {label} with a table",
        )
        return False
    allowed = set(RECORD_SCHEMAS[schema_name]["properties"])
    required = allowed - optional
    missing = sorted(required - set(record))
    extra = sorted(set(record) - allowed)
    if missing:
        failures.add(
            f"definition source structure failed: definition.toml {label} is missing key(s) {missing}",
            f"add {', '.join(missing)} to definition.toml {label}",
        )
    if extra:
        failures.add(
            f"definition source structure failed: definition.toml {label} has undeclared key(s) {extra}",
            f"remove {', '.join(extra)} from definition.toml {label}",
        )
    return True


def validate_source_records(source: dict[str, Any], failures: Failures) -> None:
    collection_shapes = {
        "address_allow_list": ("allow_entry", {"gap_ref"}),
        "ca_pin_tags": ("ca_pin_tag", {"gap_ref"}),
        "gaps": ("gap", set()),
        "journal_identity": ("journal_identity", {"gap_ref"}),
        "pin_domains": ("pin_domain", {"gap_refs"}),
        "source_claims": ("source_claim", set()),
    }
    for collection_name, (schema_name, optional) in collection_shapes.items():
        collection = source.get(collection_name)
        if not isinstance(collection, list):
            failures.add(
                f"definition source structure failed: definition.toml {collection_name} must be an array of tables",
                f"replace definition.toml {collection_name} with an array of tables",
            )
            continue
        for index, record in enumerate(collection):
            validate_source_record(
                record, f"{collection_name}[{index}]", schema_name, optional, failures
            )

    forms = source.get("forms")
    if not isinstance(forms, list):
        failures.add(
            "definition source structure failed: definition.toml forms must be an array of tables",
            "replace definition.toml forms with an array of tables",
        )
    else:
        for form_index, form in enumerate(forms):
            schema_name = (
                "retired_form"
                if isinstance(form, dict) and form.get("status") == "retired"
                else "active_form"
            )
            if not validate_source_record(
                form, f"forms[{form_index}]", schema_name, {"gap_refs"}, failures
            ):
                continue
            if schema_name == "retired_form":
                continue
            fields = form.get("fields")
            if isinstance(fields, list):
                for field_index, form_field in enumerate(fields):
                    validate_source_record(
                        form_field,
                        f"forms[{form_index}].fields[{field_index}]",
                        "form_field",
                        {"semantic_ref", "gap_refs"},
                        failures,
                    )
            else:
                failures.add(
                    f"definition source structure failed: definition.toml forms[{form_index}].fields must be an array of tables",
                    f"replace definition.toml forms[{form_index}].fields with an array of tables",
                )
            total_length = form.get("total_length")
            kind_to_schema = {
                "exact": "total_length_exact",
                "expression": "total_length_expression",
                "incomplete_source_rule": "total_length_incomplete",
            }
            total_schema = (
                kind_to_schema.get(total_length.get("kind"))
                if isinstance(total_length, dict)
                else None
            )
            if total_schema is None:
                failures.add(
                    f"definition source structure failed: definition.toml forms[{form_index}].total_length has no declared kind",
                    f"set definition.toml forms[{form_index}].total_length.kind to a declared total-length kind",
                )
            else:
                validate_source_record(
                    total_length,
                    f"forms[{form_index}].total_length",
                    total_schema,
                    set(),
                    failures,
                )

    vocabularies = source.get("vocabularies")
    if not isinstance(vocabularies, list):
        failures.add(
            "definition source structure failed: definition.toml vocabularies must be an array of tables",
            "replace definition.toml vocabularies with an array of tables",
        )
    else:
        for index, vocabulary in enumerate(vocabularies):
            registry = isinstance(vocabulary, dict) and "known_registry" in vocabulary
            gap = isinstance(vocabulary, dict) and "gap_ref" in vocabulary
            schema_name = f"vocabulary_{'registry' if registry else 'values'}_{'gap' if gap else 'documented'}"
            if not validate_source_record(
                vocabulary, f"vocabularies[{index}]", schema_name, set(), failures
            ):
                continue
            if not registry:
                continue
            registry_value = vocabulary.get("known_registry")
            if not validate_source_record(
                registry_value,
                f"vocabularies[{index}].known_registry",
                "selector_registry",
                set(),
                failures,
            ):
                continue
            nested_shapes = {
                "default_sentinel": "byte_value",
                "default_origin": "default_origin",
                "custom_origin_byte_length": "byte_range",
            }
            for key, nested_schema in nested_shapes.items():
                if key in registry_value:
                    validate_source_record(
                        registry_value[key],
                        f"vocabularies[{index}].known_registry.{key}",
                        nested_schema,
                        set(),
                        failures,
                    )


def byte_label(value: int) -> str:
    return f"0x{value:02x}"


def definition_entry_map(
    definition: dict[str, Any], failures: Failures | None = None
) -> dict[str, dict[str, Any]]:
    collections = [
        definition.get("address_allow_list", []),
        definition.get("ca_pin_tags", []),
        definition.get("forms", []),
        definition.get("gaps", []),
        definition.get("journal_identity", []),
        definition.get("pin_domains", []),
        definition.get("source_claims", []),
        definition.get("vocabularies", []),
    ]
    all_records = [record for collection in collections for record in collection if isinstance(record, dict)]
    for form in definition.get("forms", []):
        all_records.extend(form.get("fields", []))
    entries: dict[str, dict[str, Any]] = {}
    duplicates: set[str] = set()
    for record in all_records:
        record_id = record.get("id")
        if isinstance(record_id, str):
            if record_id in entries:
                duplicates.add(record_id)
            entries[record_id] = record
    if failures is not None and duplicates:
        failures.add(
            f"definition identity failed: definition.toml repeats id(s) {sorted(duplicates)}",
            "give every definition.toml record a unique id",
        )
    return entries


def validate_definition_invariants(definition: dict[str, Any], failures: Failures) -> None:
    entries = definition_entry_map(definition, failures)
    all_records = list(entries.values())

    gaps = {item.get("id") for item in definition.get("gaps", []) if isinstance(item.get("id"), str)}
    known_subjects = set(entries)
    for gap in definition.get("gaps", []):
        if gap.get("subject") not in known_subjects:
            failures.add(
                f"definition gap reference failed: {gap.get('id')} subject {gap.get('subject')!r} does not resolve",
                f"set definition.toml gap {gap.get('id')} subject to a declared record id",
            )
    gap_reference_records = [
        (str(record.get("id")), record)
        for record in all_records
    ]
    for form in definition.get("forms", []):
        total_length = form.get("total_length")
        if isinstance(total_length, dict):
            gap_reference_records.append(
                (f"{form.get('id')}.total_length", total_length)
            )
    for owner, record in gap_reference_records:
        refs: list[object] = []
        if "gap_ref" in record and record.get("gap_ref") is not None:
            refs.append(record.get("gap_ref"))
        refs.extend(record.get("gap_refs", []))
        for gap_ref in refs:
            if gap_ref not in gaps:
                failures.add(
                    f"definition gap reference failed: {owner} references missing gap {gap_ref!r}",
                    f"declare {gap_ref!r} in definition.toml gaps or fix {owner} gap_ref",
                )

    vocabularies = {
        item.get("id"): item for item in definition.get("vocabularies", []) if isinstance(item.get("id"), str)
    }
    pin_domains = {
        item.get("id"): item for item in definition.get("pin_domains", []) if isinstance(item.get("id"), str)
    }
    semantic_ids = set(vocabularies) | set(pin_domains)
    for form in definition.get("forms", []):
        if isinstance(form.get("version"), int) and form.get("label") != byte_label(form["version"]):
            failures.add(
                f"definition byte label failed: {form.get('id')} label {form.get('label')!r} does not match version {form.get('version')}",
                f"set definition.toml {form.get('id')} label to {byte_label(form['version'])}",
            )
        for form_field in form.get("fields", []):
            semantic_ref = form_field.get("semantic_ref")
            if semantic_ref is not None and semantic_ref not in semantic_ids:
                failures.add(
                    f"definition semantic reference failed: {form_field.get('id')} references {semantic_ref!r}",
                    f"set definition.toml {form_field.get('id')} semantic_ref to a declared vocabulary or pin domain",
                )

    for tag in definition.get("ca_pin_tags", []):
        value = tag.get("value")
        if isinstance(value, int) and tag.get("label") != byte_label(value):
            failures.add(
                f"definition byte label failed: {tag.get('id')} label {tag.get('label')!r} does not match value {value}",
                f"set definition.toml {tag.get('id')} label to {byte_label(value)}",
            )
        if tag.get("pin_domain_ref") not in pin_domains:
            failures.add(
                f"definition pin reference failed: {tag.get('id')} references {tag.get('pin_domain_ref')!r}",
                f"set definition.toml {tag.get('id')} pin_domain_ref to a declared pin domain",
            )
    declared_tag_values = {
        item.get("value")
        for item in definition.get("ca_pin_tags", [])
        if isinstance(item.get("value"), int)
    }
    for domain in definition.get("pin_domains", []):
        versions = domain.get("versions", [])
        labels = domain.get("version_labels", [])
        expected_labels = [byte_label(value) for value in versions if isinstance(value, int)]
        if labels != expected_labels:
            failures.add(
                f"definition byte label failed: {domain.get('id')} version_labels {labels!r} do not match versions {versions!r}",
                f"set definition.toml {domain.get('id')} version_labels to {expected_labels!r}",
            )
        tag = domain.get("tag")
        if isinstance(tag, int) and domain.get("tag_label") != byte_label(tag):
            failures.add(
                f"definition byte label failed: {domain.get('id')} tag_label does not match tag {tag}",
                f"set definition.toml {domain.get('id')} tag_label to {byte_label(tag)}",
            )
        if isinstance(tag, int) and tag not in declared_tag_values:
            failures.add(
                f"definition pin tag failed: {domain.get('id')} references undeclared tag {tag}",
                f"declare tag {tag} in definition.toml ca_pin_tags or fix {domain.get('id')} tag",
            )
        if tag == "absent_in_layout" and "gap.direct_forms.ca_fp_tag_missing" not in domain.get(
            "gap_refs", []
        ):
            failures.add(
                f"definition pin tag failed: {domain.get('id')} uses absent_in_layout without the missing-tag gap",
                f"add gap.direct_forms.ca_fp_tag_missing to definition.toml {domain.get('id')} gap_refs",
            )

    for entry in definition.get("address_allow_list", []):
        if entry.get("kind") != "cidr":
            continue
        value = entry.get("value")
        try:
            network = ipaddress.ip_network(value, strict=True)
        except (TypeError, ValueError) as exc:
            failures.add(
                f"definition CIDR failed: {entry.get('id')} value {value!r} is invalid: {exc}",
                f"set definition.toml {entry.get('id')} value to a canonical CIDR",
            )
            continue
        if str(network) != value:
            failures.add(
                f"definition CIDR failed: {entry.get('id')} value {value!r} is not canonical",
                f"set definition.toml {entry.get('id')} value to {network}",
            )
        expected_family = "ipv4" if network.version == 4 else "ipv6"
        if entry.get("family") != expected_family:
            failures.add(
                f"definition CIDR failed: {entry.get('id')} family {entry.get('family')!r} disagrees with {value}",
                f"set definition.toml {entry.get('id')} family to {expected_family}",
            )

    for vocabulary in definition.get("vocabularies", []):
        behavior = vocabulary.get("unknown_value_behavior")
        has_gap = "gap_ref" in vocabulary
        if behavior == "unspecified_in_source_documents" and not has_gap:
            failures.add(
                f"definition vocabulary gap failed: {vocabulary.get('id')} has unspecified behavior without gap_ref",
                f"add gap_ref to definition.toml vocabulary {vocabulary.get('id')}",
            )
        if behavior != "unspecified_in_source_documents" and has_gap:
            failures.add(
                f"definition vocabulary gap failed: {vocabulary.get('id')} has documented behavior but also gap_ref",
                f"remove gap_ref from definition.toml vocabulary {vocabulary.get('id')}",
            )
        resolve_json_pointer(definition, vocabulary.get("source_pointer"), vocabulary.get("id"), failures)
        values = vocabulary.get("values", [])
        for value in values:
            if isinstance(value, dict) and isinstance(value.get("value"), int):
                expected_label = byte_label(value["value"])
                if value.get("label") != expected_label:
                    failures.add(
                        f"definition byte label failed: {vocabulary.get('id')} value {value['value']} has label {value.get('label')!r}",
                        f"set definition.toml vocabulary {vocabulary.get('id')} label to {expected_label}",
                    )

    expected_vocabulary_values: dict[str, Any] = {
        "pair_link.version": [
            {"value": form["version"], "label": form["label"]}
            for form in definition.get("forms", [])
        ],
        "pair_link.ca_fp_tag": [
            {"value": tag["value"], "label": tag["label"]}
            for tag in definition.get("ca_pin_tags", [])
        ],
        "direct_address_policy.allow_list": [
            entry["value"] for entry in definition.get("address_allow_list", [])
        ],
        "pair_link.pin_domain": [domain["id"] for domain in definition.get("pin_domains", [])],
    }
    for vocabulary_id, expected_values in expected_vocabulary_values.items():
        actual = vocabularies.get(vocabulary_id, {}).get("values")
        if actual != expected_values:
            failures.add(
                f"definition vocabulary consistency failed: {vocabulary_id} values {actual!r} do not match defined records {expected_values!r}",
                f"update definition.toml vocabulary {vocabulary_id} values to match its source_pointer records",
            )
def resolve_json_pointer(
    document: dict[str, Any], pointer: object, vocabulary_id: object, failures: Failures
) -> None:
    if not isinstance(pointer, str) or not pointer.startswith("/"):
        failures.add(
            f"definition source_pointer failed: vocabulary {vocabulary_id} has invalid pointer {pointer!r}",
            f"set definition.toml vocabulary {vocabulary_id} source_pointer to an absolute JSON Pointer",
        )
        return
    node: Any = document
    try:
        for raw_part in pointer[1:].split("/"):
            part = raw_part.replace("~1", "/").replace("~0", "~")
            node = node[int(part)] if isinstance(node, list) else node[part]
    except (KeyError, IndexError, TypeError, ValueError):
        failures.add(
            f"definition source_pointer failed: vocabulary {vocabulary_id} pointer {pointer!r} does not resolve",
            f"fix definition.toml vocabulary {vocabulary_id} source_pointer",
        )


def validate_citation_reference(
    root: Path,
    citation: dict[str, Any],
    *,
    category: str,
    label: str,
    allowed_paths: set[str],
    allowed_description: str,
    allowed_recovery: str,
    missing_recovery: str,
    failures: Failures,
    read_label: str | None = None,
) -> str | None:
    document = citation.get("document")
    marker = citation.get("marker")
    if not isinstance(document, str) or document not in allowed_paths:
        failures.add(
            f"{category} path failed: {label}.document {document!r} is not {allowed_description}",
            allowed_recovery,
        )
    path = root / document if isinstance(document, str) else root / "missing"
    if not path.is_file():
        failures.add(
            f"{category} path failed: {label}.document {document!r} does not exist",
            missing_recovery,
        )
        return None
    if not isinstance(marker, str) or len(marker) < 12:
        observed = len(marker) if isinstance(marker, str) else 0
        failures.add(
            f"{category} marker failed: {label}.marker is too short: observed {observed}, minimum 12",
            f"set {label}.marker to a unique exact substring of at least 12 characters",
        )
        return None
    try:
        text = read_text_exact(path)
    except (OSError, UnicodeDecodeError) as exc:
        read_subject = f"{read_label} {document!r}" if read_label else str(document)
        failures.add(
            f"{category} read failed: {read_subject} is not UTF-8: {exc}",
            f"encode {document} as UTF-8",
        )
        return None
    count = text.count(marker)
    if count == 0:
        failures.add(
            f"{category} marker failed: {label}.marker is broken: observed 0 exact occurrences in {document}",
            f"set {label}.marker to a current unique clause in {document}",
        )
    elif count > 1:
        failures.add(
            f"{category} marker failed: {label}.marker is ambiguous: observed {count} exact occurrences in {document}",
            f"set {label}.marker to a longer unique clause in {document}",
        )
    return text


def validate_citations(root: Path, citations: object, failures: Failures) -> None:
    if not isinstance(citations, dict):
        return
    declared_paths = {path.as_posix() for _, path, _ in GENERATOR_INPUTS}
    normative_paths = sorted(
        path.as_posix() for _, path, role in GENERATOR_INPUTS if role == "normative_source_document"
    )
    for citation_id, citation in sorted(citations.items()):
        if not isinstance(citation, dict):
            failures.add(
                f"definition citation structure failed: definition.toml citations.{citation_id} must be a table",
                f"replace definition.toml citations.{citation_id} with a document-and-marker table",
            )
            continue
        keys = set(citation)
        if keys != {"document", "marker"}:
            failures.add(
                f"definition citation structure failed: definition.toml citations.{citation_id} keys are {sorted(keys)}",
                f"set definition.toml citations.{citation_id} to exactly document and marker",
            )
            continue
        label = f"definition.toml citations.{citation_id}"
        validate_citation_reference(
            root,
            citation,
            category="definition citation",
            label=label,
            allowed_paths=declared_paths,
            allowed_description="a declared generator input",
            allowed_recovery=f"set {label}.document to one of {normative_paths!r}",
            missing_recovery=f"set {label}.document to an existing declared generator input",
            failures=failures,
        )


def load_vector_source(root: Path, failures: Failures) -> dict[str, Any] | None:
    try:
        text = read_text_exact(root / VECTORS_SOURCE_REL)
    except (OSError, UnicodeDecodeError) as exc:
        failures.add(
            f"conformance corpus read failed: {VECTORS_SOURCE_REL.as_posix()}: {exc}",
            f"restore {VECTORS_SOURCE_REL.as_posix()} from the solpbc/spl-rust conformance corpus",
        )
        return None
    payload = load_json(
        text,
        VECTORS_SOURCE_REL.as_posix(),
        failures,
        f"fix {VECTORS_SOURCE_REL.as_posix()} as UTF-8 JSON without duplicate keys",
        namespace="conformance",
    )
    if payload is None:
        return None
    validate_schema_value(
        payload,
        VECTORS_SCHEMA,
        "",
        VECTORS_SOURCE_REL.as_posix(),
        failures,
        namespace="conformance",
    )
    return payload if isinstance(payload, dict) else None


def validate_vector_ids(vectors: list[Any], failures: Failures) -> None:
    ids = [vector.get("id") for vector in vectors if isinstance(vector, dict)]
    string_ids = [vector_id for vector_id in ids if isinstance(vector_id, str)]
    if string_ids != sorted(string_ids):
        failures.add(
            f"conformance vector ordering failed: {VECTORS_SOURCE_REL.as_posix()} vectors[] is not sorted by id",
            f"sort {VECTORS_SOURCE_REL.as_posix()} vectors[] by id",
        )
    duplicate_ids = sorted(
        vector_id for vector_id in set(string_ids) if string_ids.count(vector_id) > 1
    )
    if duplicate_ids:
        failures.add(
            f"conformance vector identity failed: {VECTORS_SOURCE_REL.as_posix()} vectors[].id repeats id(s) {duplicate_ids}",
            f"remove duplicate vectors[].id entries from {VECTORS_SOURCE_REL.as_posix()}",
        )
    actual_ids = set(string_ids)
    missing = sorted(set(EXPECTED_VECTOR_IDS) - actual_ids)
    unexpected = sorted(actual_ids - set(EXPECTED_VECTOR_IDS))
    if missing:
        failures.add(
            f"conformance vector id set failed: {VECTORS_SOURCE_REL.as_posix()} vectors[].id is missing id(s) {missing}",
            f"regenerate {VECTORS_SOURCE_REL.as_posix()} from the solpbc/spl-rust conformance corpus",
        )
    if unexpected:
        failures.add(
            f"conformance vector id set failed: {VECTORS_SOURCE_REL.as_posix()} vectors[].id has unexpected id(s) {unexpected}",
            f"regenerate {VECTORS_SOURCE_REL.as_posix()} from the solpbc/spl-rust conformance corpus",
        )
    declared_ids = {
        vector.get("id")
        for vector in vectors
        if isinstance(vector, dict)
        and isinstance(vector.get("id"), str)
        and vector.get("kind") == "declared"
    }
    declared_missing = sorted(set(EXPECTED_DECLARED_VECTOR_IDS) - declared_ids)
    declared_unexpected = sorted(declared_ids - set(EXPECTED_DECLARED_VECTOR_IDS))
    if declared_missing or declared_unexpected:
        failures.add(
            f"conformance vector kind set failed: {VECTORS_SOURCE_REL.as_posix()} vectors[].kind declared ids missing={declared_missing}, unexpected={declared_unexpected}",
            f"restore vectors[].kind values in {VECTORS_SOURCE_REL.as_posix()} from the solpbc/spl-rust conformance corpus",
        )
    recorded_ids = {
        vector.get("id")
        for vector in vectors
        if isinstance(vector, dict)
        and isinstance(vector.get("id"), str)
        and vector.get("kind") == "recorded"
    }
    expected_recorded_count = len(EXPECTED_RECORDED_VECTOR_IDS)
    if len(recorded_ids) != expected_recorded_count:
        failures.add(
            f"conformance vector kind count failed: {VECTORS_SOURCE_REL.as_posix()} vectors[].kind has {len(recorded_ids)} recorded ids, expected {expected_recorded_count}",
            f"restore vectors[].kind values in {VECTORS_SOURCE_REL.as_posix()} from the solpbc/spl-rust conformance corpus",
        )


def validate_vector_operation(vector: dict[str, Any], failures: Failures) -> None:
    """Check that a vector's declared operation agrees with its payload shape.

    The mapping is a table, and an unrecognised shape is a failure rather than a
    default. It used to fall through to `derive_relay_key`, so a payload shape
    nobody had declared was silently asserted to be the relay-key operation --
    and adding an operation whose payload carries `expected` would have been
    asserted to be `parse_pair_link` instead. Both are the same bug: an
    inference with a default answer cannot report that it does not know.
    """
    vector_id = vector.get("id")
    keys = set(vector)
    shapes: tuple[tuple[frozenset[str], str], ...] = (
        (frozenset({"spki_der_hex", "expected"}), "derive_jid"),
        (frozenset({"input", "expected"}), "parse_pair_link"),
        (frozenset({"input", "expected_hex"}), "decode_crockford"),
        (frozenset({"secret_hex", "expected_hex"}), "derive_relay_key"),
    )
    matched = [operation for payload, operation in shapes if payload <= keys]
    if len(matched) != 1:
        failures.add(
            f"conformance vector operation failed: {VECTORS_SOURCE_REL.as_posix()} vectors[{vector_id}] payload keys match {len(matched)} known operation shapes, expected exactly 1",
            f"give vectors[{vector_id}] the payload fields of exactly one declared operation in {VECTORS_SOURCE_REL.as_posix()}",
        )
        return
    expected_operation = matched[0]
    if vector.get("operation") != expected_operation:
        failures.add(
            f"conformance vector operation failed: {VECTORS_SOURCE_REL.as_posix()} vectors[{vector_id}].operation {vector.get('operation')!r} disagrees with its payload shape",
            f"set vectors[{vector_id}].operation to {expected_operation!r} in {VECTORS_SOURCE_REL.as_posix()}",
        )


def validate_vector_citation_and_literals(
    root: Path, vector: dict[str, Any], failures: Failures
) -> None:
    vector_id = vector.get("id")
    citation = vector.get("citation")
    document_text: str | None = None
    if isinstance(citation, dict):
        normative_paths = sorted(
            path.as_posix()
            for _, path, role in GENERATOR_INPUTS
            if role == "normative_source_document"
        )
        label = f"{VECTORS_SOURCE_REL.as_posix()} vectors[{vector_id}].citation"
        document_text = validate_citation_reference(
            root,
            citation,
            category="conformance citation",
            label=label,
            allowed_paths=set(normative_paths),
            allowed_description="a normative source document",
            allowed_recovery=f"set {label}.document to one of {normative_paths!r}",
            missing_recovery=f"set {label}.document to an existing normative source document",
            failures=failures,
            read_label=f"{label}.document",
        )

    literals = vector.get("document_literals")
    if not isinstance(literals, list):
        return
    kind = vector.get("kind")
    if kind == "declared" and not literals:
        failures.add(
            f"conformance document literal failed: {VECTORS_SOURCE_REL.as_posix()} vectors[{vector_id}].document_literals is empty for a declared vector",
            f"add the cited payload literals to vectors[{vector_id}].document_literals in {VECTORS_SOURCE_REL.as_posix()}",
        )
    if kind == "recorded" and literals:
        failures.add(
            f"conformance document literal failed: {VECTORS_SOURCE_REL.as_posix()} vectors[{vector_id}].document_literals is non-empty for a recorded vector",
            f"set vectors[{vector_id}].document_literals to [] in {VECTORS_SOURCE_REL.as_posix()}",
        )
    payload = {
        key: vector[key]
        for key in ("input", "expected", "expected_hex", "secret_hex", "spki_der_hex")
        if key in vector
    }
    payload_text = render_json(payload)
    for index, literal in enumerate(literals):
        if not isinstance(literal, str):
            continue
        field = f"vectors[{vector_id}].document_literals[{index}]"
        if len(literal) < 12:
            failures.add(
                f"conformance document literal failed: {VECTORS_SOURCE_REL.as_posix()} {field} is too short: observed {len(literal)}, minimum 12",
                f"replace {field} in {VECTORS_SOURCE_REL.as_posix()} with a payload literal of at least 12 characters",
            )
        if document_text is not None and literal not in document_text:
            failures.add(
                f"conformance document literal failed: {VECTORS_SOURCE_REL.as_posix()} {field} does not occur in its citation document",
                f"edit {field} in {VECTORS_SOURCE_REL.as_posix()} to match the cited document; separately review the public solpbc/spl-rust conformance corpus before changing any promoted payload",
            )
        if literal not in payload_text:
            failures.add(
                f"conformance document literal failed: {VECTORS_SOURCE_REL.as_posix()} {field} does not occur in the vector payload fields",
                f"edit {field} in {VECTORS_SOURCE_REL.as_posix()} if the literal is wrong, or restore vectors[{vector_id}] payload fields from the public solpbc/spl-rust conformance corpus",
            )


def validate_vectors(
    root: Path,
    corpus: dict[str, Any],
    definition: dict[str, Any],
    failures: Failures,
    *,
    bless: bool,
) -> CoverageReport:
    vectors_value = corpus.get("vectors", [])
    vectors = vectors_value if isinstance(vectors_value, list) else []
    validate_vector_ids(vectors, failures)
    entries = definition_entry_map(definition)

    covers_value = corpus.get("covers", [])
    covers = covers_value if isinstance(covers_value, list) else []
    string_covers = [entry_id for entry_id in covers if isinstance(entry_id, str)]
    if string_covers != sorted(string_covers):
        failures.add(
            f"conformance coverage ordering failed: {VECTORS_SOURCE_REL.as_posix()} covers is not sorted",
            f"sort {VECTORS_SOURCE_REL.as_posix()} covers by definition entry id",
        )
    duplicate_covers = sorted(
        entry_id for entry_id in set(string_covers) if string_covers.count(entry_id) > 1
    )
    if duplicate_covers:
        failures.add(
            f"conformance coverage identity failed: {VECTORS_SOURCE_REL.as_posix()} covers repeats id(s) {duplicate_covers}",
            f"remove duplicate ids from {VECTORS_SOURCE_REL.as_posix()} covers",
        )
    unresolved_covers = sorted(set(string_covers) - set(entries))
    if unresolved_covers:
        failures.add(
            f"conformance coverage reference failed: {VECTORS_SOURCE_REL.as_posix()} covers has unresolved id(s) {unresolved_covers}",
            f"replace unresolved covers ids with current definition entry ids in {VECTORS_SOURCE_REL.as_posix()}",
        )

    counts = {entry_id: 0 for entry_id in string_covers if entry_id in entries}
    bound_ids: set[str] = set()
    for vector in vectors:
        if not isinstance(vector, dict):
            continue
        vector_id = vector.get("id")
        validate_vector_operation(vector, failures)
        validate_vector_citation_and_literals(root, vector, failures)
        digests = vector.get("entry_digests")
        reason = vector.get("unbound_reason")
        if not isinstance(digests, dict):
            continue
        if not digests and not (isinstance(reason, str) and reason):
            failures.add(
                f"conformance binding failed: {VECTORS_SOURCE_REL.as_posix()} vectors[{vector_id}] has no entry_digests and no non-empty unbound_reason",
                f"bind vectors[{vector_id}] to exercised definition entries or state its unbound reason in {VECTORS_SOURCE_REL.as_posix()}",
            )
        if digests and reason is not None:
            failures.add(
                f"conformance binding failed: {VECTORS_SOURCE_REL.as_posix()} vectors[{vector_id}] has entry_digests and a non-null unbound_reason",
                f"set vectors[{vector_id}].unbound_reason to null in {VECTORS_SOURCE_REL.as_posix()}",
            )
        for entry_id, authored_digest in sorted(digests.items(), key=lambda item: str(item[0])):
            field = f"vectors[{vector_id}].entry_digests[{entry_id}]"
            if not isinstance(entry_id, str) or entry_id not in entries:
                failures.add(
                    f"conformance binding reference failed: {VECTORS_SOURCE_REL.as_posix()} {field} does not resolve to a definition entry",
                    f"replace {field} with a current definition entry id in {VECTORS_SOURCE_REL.as_posix()}",
                )
                continue
            bound_ids.add(entry_id)
            if entry_id in counts:
                counts[entry_id] += 1
            if not isinstance(authored_digest, str) or SHA256_RE.fullmatch(authored_digest) is None:
                failures.add(
                    f"conformance entry digest failed: {VECTORS_SOURCE_REL.as_posix()} {field} is not a lowercase SHA-256 digest",
                    f"run python3 proto/definition/generate.py --bless-vectors after reviewing the binding",
                )
                continue
            observed_digest = sha256_text(render_json(entries[entry_id]))
            if bless:
                digests[entry_id] = observed_digest
            elif authored_digest != observed_digest:
                failures.add(
                    f"conformance entry digest failed: {VECTORS_SOURCE_REL.as_posix()} {field} authored {authored_digest!r} does not match observed {observed_digest!r}",
                    "run python3 proto/definition/generate.py --bless-vectors after reviewing the definition change",
                )

    uncovered_bindings = sorted(bound_ids - set(string_covers))
    if uncovered_bindings:
        failures.add(
            f"conformance coverage claim failed: bound definition id(s) {uncovered_bindings} are absent from {VECTORS_SOURCE_REL.as_posix()} covers",
            f"add the bound ids to {VECTORS_SOURCE_REL.as_posix()} covers",
        )
    empty_claims = sorted(set(string_covers) - bound_ids)
    if empty_claims:
        failures.add(
            f"conformance coverage claim failed: {VECTORS_SOURCE_REL.as_posix()} covers id(s) {empty_claims} have no citing vector",
            f"bind a vector to each claimed id or remove the empty claims from {VECTORS_SOURCE_REL.as_posix()} covers",
        )
    return CoverageReport(
        counts=dict(sorted(counts.items())),
        unclaimed=sorted(set(entries) - set(string_covers)),
    )


def print_coverage_report(report: CoverageReport) -> None:
    print("Conformance coverage (definition entry id -> citing vector count):")
    for entry_id, count in report.counts.items():
        print(f"  {entry_id}: {count}")
    print("Definition entries not claimed by the conformance corpus:")
    for entry_id in report.unclaimed:
        print(f"  {entry_id}")


def validate_input_paths(root: Path, failures: Failures) -> list[dict[str, Any]]:
    bundle_root = (root / BUNDLE_REL).resolve()
    resolved_root = root.resolve()
    records: list[dict[str, Any]] = []
    for input_id, rel_path, role in GENERATOR_INPUTS:
        path = root / rel_path
        try:
            resolved = path.resolve(strict=True)
        except OSError:
            failures.add(
                f"definition generator input failed: {rel_path.as_posix()} does not exist",
                f"restore generator input {rel_path.as_posix()}",
            )
            continue
        if not resolved.is_relative_to(resolved_root):
            failures.add(
                f"definition generator input failed: {rel_path.as_posix()} resolves outside the repository",
                f"replace {rel_path.as_posix()} with a repository-local regular file",
            )
            continue
        if resolved.is_relative_to(bundle_root):
            failures.add(
                f"definition generator input failed: {input_id} points inside generated bundle at {rel_path.as_posix()}",
                f"move generator input {rel_path.as_posix()} outside {BUNDLE_REL.as_posix()}",
            )
            continue
        if path.is_symlink() or not path.is_file():
            failures.add(
                f"definition generator input failed: {rel_path.as_posix()} is not a non-symlink regular file",
                f"replace {rel_path.as_posix()} with a non-symlink regular file",
            )
            continue
        try:
            text = read_text_exact(path)
        except (OSError, UnicodeDecodeError) as exc:
            failures.add(
                f"definition generator input failed: {rel_path.as_posix()} cannot be read as UTF-8: {exc}",
                f"restore generator input {rel_path.as_posix()} as a readable UTF-8 file",
            )
            continue
        records.append(
            {
                "id": input_id,
                "path": rel_path.as_posix(),
                "role": role,
                "sha256": sha256_text(text),
            }
        )
    return sorted(records, key=lambda item: item["id"])


def build_bundle(
    root: Path, failures: Failures, *, bless_vectors: bool = False
) -> tuple[dict[Path, str], str | None, CoverageReport]:
    source_path = root / SOURCE_REL
    try:
        source_text = read_text_exact(source_path)
        source = tomllib.loads(source_text)
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        failures.add(
            f"definition source parse failed: {SOURCE_REL.as_posix()}: {exc}",
            f"fix {SOURCE_REL.as_posix()} as UTF-8 TOML",
        )
        return {}, None, CoverageReport()
    structure_failure_count = len(failures.messages)
    validate_source_top_level(source, failures)
    validate_source_records(source, failures)
    source_structure_failed = len(failures.messages) > structure_failure_count
    validate_citations(root, source.get("citations"), failures)
    semver = source.get("bundle_semver")
    if not isinstance(semver, str):
        failures.add(
            "definition SemVer failed: definition.toml bundle_semver is not a string",
            "set definition.toml bundle_semver to strict MAJOR.MINOR.PATCH",
        )
        semver = "invalid"
    else:
        try:
            parse_semver(semver)
        except ValueError as exc:
            failures.add(
                f"definition SemVer failed: definition.toml bundle_semver is invalid: {exc}",
                "set definition.toml bundle_semver to strict MAJOR.MINOR.PATCH",
            )
    generator_inputs = validate_input_paths(root, failures)
    if source_structure_failed:
        return {}, semver, CoverageReport()

    definition = build_definition(source, failures)
    shape_failure_count = len(failures.messages)
    validate_schema_value(definition, DEFINITION_SCHEMA, "", DEFINITION_REL.as_posix(), failures)
    if len(failures.messages) == shape_failure_count:
        validate_definition_invariants(definition, failures)
    corpus = load_vector_source(root, failures)
    coverage = CoverageReport()
    if corpus is not None:
        coverage = validate_vectors(
            root, corpus, definition, failures, bless=bless_vectors
        )
        corpus = {
            "covers": corpus.get("covers", []),
            "vectors": sorted(
                corpus.get("vectors", []),
                key=lambda vector: (
                    vector.get("id", "")
                    if isinstance(vector, dict) and isinstance(vector.get("id"), str)
                    else ""
                ),
            ),
        }
    else:
        corpus = {"covers": [], "vectors": []}
    definition_text = render_json(definition)
    schema_text = render_json(DEFINITION_SCHEMA)
    vectors_text = render_json(corpus)
    vectors_schema_text = render_json(VECTORS_SCHEMA)
    payload_texts = dict(
        zip(
            PAYLOAD_RELS,
            (definition_text, schema_text, vectors_text, vectors_schema_text),
            strict=True,
        )
    )
    manifest = {
        "bundle_schema_identity": BUNDLE_SCHEMA_IDENTITY,
        "bundle_semver": semver,
        "files": [
            {
                "path": rel_path.relative_to(BUNDLE_REL).as_posix(),
                "sha256": sha256_text(payload_texts[rel_path]),
            }
            for rel_path in sorted(payload_texts)
        ],
        "generator_identity": GENERATOR_IDENTITY,
        "generator_inputs": generator_inputs,
        "schema_dialect_uri": SCHEMA_DIALECT_URI,
    }
    return {MANIFEST_REL: render_json(manifest), **payload_texts}, semver, coverage


def write_bundle(root: Path, files: dict[Path, str]) -> None:
    (root / BUNDLE_REL).mkdir(parents=True, exist_ok=True)
    for rel_path, text in files.items():
        (root / rel_path).write_text(text, encoding="utf-8", newline="")


def validate_committed_bundle(
    root: Path, expected_files: dict[Path, str], semver: str | None, failures: Failures
) -> None:
    bundle_root = root / BUNDLE_REL
    expected_set = {MANIFEST_REL.relative_to(BUNDLE_REL).as_posix()}
    manifest_payload: Any | None = None
    manifest_text: str | None = None
    try:
        manifest_text = read_text_exact(root / MANIFEST_REL)
        manifest_payload = load_json(manifest_text, MANIFEST_REL.as_posix(), failures)
    except (OSError, UnicodeDecodeError) as exc:
        failures.add(
            f"definition manifest read failed: {MANIFEST_REL.as_posix()}: {exc}",
            "run make definition-generate to restore proto/definition/bundle/manifest.json",
        )
    if manifest_payload is not None:
        validate_schema_value(
            manifest_payload, MANIFEST_SCHEMA, "", MANIFEST_REL.as_posix(), failures
        )
        files_entries = manifest_payload.get("files", []) if isinstance(manifest_payload, dict) else []
        if isinstance(files_entries, list):
            paths = [item.get("path") for item in files_entries if isinstance(item, dict)]
            if paths != sorted(paths):
                failures.add(
                    "definition manifest ordering failed: proto/definition/bundle/manifest.json files[] is not sorted by path",
                    "run make definition-generate to sort manifest.json files[] by path",
                )
            for item in files_entries:
                if not isinstance(item, dict) or not isinstance(item.get("path"), str):
                    continue
                rel_name = item["path"]
                expected_set.add(rel_name)
                path = bundle_root / rel_name
                if Path(rel_name).is_absolute() or ".." in Path(rel_name).parts:
                    failures.add(
                        f"definition manifest path failed: files[] path {rel_name!r} escapes the bundle root",
                        f"remove files[] path {rel_name!r} from proto/definition/bundle/manifest.json",
                    )
                    continue
                try:
                    text = read_text_exact(path)
                except (OSError, UnicodeDecodeError) as exc:
                    failures.add(
                        f"definition bundle integrity failed: {path.relative_to(root).as_posix()} cannot be read: {exc}",
                        f"run make definition-generate to restore {path.relative_to(root).as_posix()}",
                    )
                    continue
                observed = sha256_text(text)
                if item.get("sha256") != observed:
                    failures.add(
                        f"definition bundle integrity failed: proto/definition/bundle/manifest.json files[{rel_name}].sha256 {item.get('sha256')!r} does not match observed {observed}",
                        f"run make definition-generate to restore manifest.json files[{rel_name}].sha256",
                    )
        input_entries = (
            manifest_payload.get("generator_inputs", []) if isinstance(manifest_payload, dict) else []
        )
        if isinstance(input_entries, list):
            ids = [item.get("id") for item in input_entries if isinstance(item, dict)]
            if ids != sorted(ids):
                failures.add(
                    "definition manifest ordering failed: proto/definition/bundle/manifest.json generator_inputs[] is not sorted by id",
                    "run make definition-generate to sort manifest.json generator_inputs[] by id",
                )
            expected_inputs = {
                input_id: (rel_path.as_posix(), role)
                for input_id, rel_path, role in GENERATOR_INPUTS
            }
            actual_ids = {item.get("id") for item in input_entries if isinstance(item, dict)}
            if actual_ids != set(expected_inputs):
                failures.add(
                    f"definition generator input set failed: manifest ids are {sorted(str(item) for item in actual_ids)}",
                    "run make definition-generate to restore the exact manifest generator_inputs[] set",
                )
            for item in input_entries:
                if not isinstance(item, dict) or item.get("id") not in expected_inputs:
                    continue
                input_id = item["id"]
                expected_path, expected_role = expected_inputs[input_id]
                if item.get("path") != expected_path or item.get("role") != expected_role:
                    failures.add(
                        f"definition generator input identity failed: manifest generator_inputs[{input_id}] path/role differs from the declared input",
                        f"run make definition-generate to restore manifest generator_inputs[{input_id}]",
                    )
                    continue
                path = root / expected_path
                if path.is_file() and not path.is_symlink():
                    try:
                        observed = sha256_text(read_text_exact(path))
                    except UnicodeDecodeError as exc:
                        failures.add(
                            f"definition generator input failed: {expected_path} is not UTF-8: {exc}",
                            f"encode generator input {expected_path} as UTF-8",
                        )
                        continue
                    if item.get("sha256") != observed:
                        failures.add(
                            f"definition generator input digest failed: proto/definition/bundle/manifest.json generator_inputs[{input_id}].sha256 {item.get('sha256')!r} does not match observed {observed} for {expected_path}",
                            f"run make definition-generate to update manifest generator_inputs[{input_id}].sha256 after reviewing {expected_path}",
                        )
        if semver is not None and isinstance(manifest_payload, dict):
            if manifest_payload.get("bundle_semver") != semver:
                failures.add(
                    f"definition SemVer consistency failed: manifest bundle_semver {manifest_payload.get('bundle_semver')!r} differs from definition.toml {semver!r}",
                    "run make definition-generate to copy definition.toml bundle_semver into manifest.json",
                )

    actual_entries: set[str] = set()
    if bundle_root.exists():
        for path in bundle_root.rglob("*"):
            relative = path.relative_to(bundle_root).as_posix()
            if path.is_file() and not path.is_symlink():
                actual_entries.add(relative)
            else:
                actual_entries.add(relative + ("/" if path.is_dir() else ""))
    missing = sorted(expected_set - actual_entries)
    extra = sorted(actual_entries - expected_set)
    if missing or extra:
        failures.add(
            f"definition bundle exact-set failed: missing={missing}, unexpected={extra}",
            "restore missing manifest files and remove unexpected entries under proto/definition/bundle",
        )

    for rel_path in PAYLOAD_RELS:
        path = root / rel_path
        try:
            text = read_text_exact(path)
        except (OSError, UnicodeDecodeError):
            continue
        payload = load_json(text, rel_path.as_posix(), failures)
        if payload is not None and render_json(payload) != text:
            failures.add(
                f"definition canonical JSON failed: {rel_path.as_posix()} is not sorted two-space JSON with one trailing newline",
                f"run make definition-generate to canonicalize {rel_path.as_posix()}",
            )
        if rel_path == DEFINITION_REL and payload is not None:
            validate_schema_value(payload, DEFINITION_SCHEMA, "", rel_path.as_posix(), failures)
        if rel_path == VECTORS_REL and payload is not None:
            validate_schema_value(payload, VECTORS_SCHEMA, "", rel_path.as_posix(), failures)

    for rel_path, expected in expected_files.items():
        path = root / rel_path
        try:
            actual = read_text_exact(path)
        except (OSError, UnicodeDecodeError):
            continue
        if actual != expected:
            failures.add(
                f"definition generated artifact is stale: {rel_path.as_posix()} differs from the authored definition",
                f"run make definition-generate to update {rel_path.as_posix()}",
            )


def git_bytes(root: Path, args: list[str]) -> bytes:
    env = {
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
    }
    env = {**os.environ, **env}
    return subprocess.run(
        ["git", *args], cwd=root, capture_output=True, check=True, env=env
    ).stdout


def current_definition_tree(root: Path, failures: Failures) -> dict[str, bytes]:
    base = root / Path("proto/definition")
    files: dict[str, bytes] = {}
    if not base.exists():
        return files
    for path in sorted(base.rglob("*")):
        if path.is_symlink() or (path.exists() and not path.is_file() and not path.is_dir()):
            failures.add(
                f"definition tree failed: {path.relative_to(root).as_posix()} is not a non-symlink regular file",
                f"replace {path.relative_to(root).as_posix()} with a non-symlink regular file",
            )
        if path.is_file() and not path.is_symlink():
            files[path.relative_to(root).as_posix()] = path.read_bytes()
    return files


def head_definition_tree(root: Path, failures: Failures) -> dict[str, bytes] | None:
    try:
        git_bytes(root, ["rev-parse", "--verify", "HEAD"])
        output = git_bytes(
            root, ["ls-tree", "-r", "--full-tree", "HEAD", "--", "proto/definition"]
        )
    except subprocess.CalledProcessError as exc:
        failures.add(
            f"definition compatibility failed: HEAD is unresolvable: {exc}",
            "run the gate inside a Git checkout with a resolvable HEAD",
        )
        return None
    files: dict[str, bytes] = {}
    for line in output.splitlines():
        try:
            metadata, path_bytes = line.split(b"\t", 1)
            mode, object_type, object_id = metadata.decode("ascii").split()
            path = path_bytes.decode("utf-8")
        except ValueError as exc:
            failures.add(
                f"definition compatibility failed: malformed git ls-tree entry {line!r}: {exc}",
                "repair the Git checkout before checking definition compatibility",
            )
            continue
        if object_type != "blob" or not mode.startswith("100"):
            failures.add(
                f"definition compatibility failed: HEAD path {path} is not a regular blob",
                f"replace HEAD path {path} with a regular file",
            )
            continue
        try:
            files[path] = git_bytes(root, ["show", object_id])
        except subprocess.CalledProcessError as exc:
            failures.add(
                f"definition compatibility failed: cannot read HEAD blob for {path}: {exc}",
                "restore the missing Git object before checking definition compatibility",
            )
    return files


def validate_semver_history(
    root: Path, current_semver: str | None, failures: Failures
) -> None:
    if current_semver is None:
        return
    try:
        parse_semver(current_semver)
    except ValueError:
        return
    head_files = head_definition_tree(root, failures)
    if head_files is None:
        return
    manifest_path = MANIFEST_REL.as_posix()
    if manifest_path not in head_files:
        if current_semver != INITIAL_BUNDLE_SEMVER:
            failures.add(
                f"definition compatibility failed: first committed bundle must use bundle_semver {INITIAL_BUNDLE_SEMVER}, got {current_semver}",
                f"set definition.toml bundle_semver to {INITIAL_BUNDLE_SEMVER} and run make definition-generate",
            )
        return
    previous_failures = Failures()
    try:
        previous_text = head_files[manifest_path].decode("utf-8")
    except UnicodeDecodeError as exc:
        failures.add(
            f"definition compatibility failed: HEAD manifest is not UTF-8: {exc}",
            "restore a valid UTF-8 proto/definition/bundle/manifest.json in HEAD",
        )
        return
    previous_manifest = load_json(previous_text, f"HEAD:{manifest_path}", previous_failures)
    if previous_failures.messages or not isinstance(previous_manifest, dict):
        for message in previous_failures.messages:
            failures.messages.append(message.replace("definition JSON", "definition compatibility"))
        return
    previous_semver = previous_manifest.get("bundle_semver")
    if not isinstance(previous_semver, str):
        failures.add(
            "definition compatibility failed: HEAD manifest has no string bundle_semver",
            "restore HEAD proto/definition/bundle/manifest.json bundle_semver",
        )
        return
    try:
        parse_semver(previous_semver)
    except ValueError as exc:
        failures.add(
            f"definition compatibility failed: HEAD bundle_semver is invalid: {exc}",
            "restore a strict MAJOR.MINOR.PATCH bundle_semver in HEAD manifest",
        )
        return
    current_files = current_definition_tree(root, failures)
    if current_files == head_files:
        return
    if compare_semver(current_semver, previous_semver) <= 0:
        changed = sorted(
            path
            for path in set(current_files) | set(head_files)
            if current_files.get(path) != head_files.get(path)
        )
        failures.add(
            f"definition compatibility failed: proto/definition content changed at {changed} without a strict bundle_semver increase from {previous_semver}",
            "increase definition.toml bundle_semver above HEAD and run make definition-generate",
        )


def validate_readme_semver(root: Path, semver: str, failures: Failures) -> None:
    """Check the README's hand-written version line against the real semver.

    The README states the current bundle version in prose. Nothing used to read
    it, so it drifted: it said 1.1.1 while the manifest said 1.1.3, two bumps
    behind, in the one file a consumer reads before vendoring anything. A version
    a human maintains by hand is a version that goes stale; this makes it fail
    the gate instead.
    """
    path = root / README_REL
    try:
        text = read_text_exact(path)
    except (OSError, UnicodeDecodeError) as exc:
        failures.add(
            f"definition readme failed: {README_REL.as_posix()} is unreadable: {exc}",
            f"restore {README_REL.as_posix()} as UTF-8 text",
        )
        return
    expected = f"The current bundle version is `{semver}`."
    if text.count(expected) != 1:
        failures.add(
            f"definition readme failed: {README_REL.as_posix()} does not state the current bundle version exactly once as {expected!r}",
            f"set the version sentence in {README_REL.as_posix()} to {expected!r}",
        )


def run_write(root: Path) -> int:
    failures = Failures()
    files, semver, _ = build_bundle(root, failures)
    validate_readme_semver(root, semver, failures)
    if failures.messages:
        return failures.report()
    write_bundle(root, files)
    return 0


def run_check(root: Path) -> int:
    failures = Failures()
    expected_files, semver, coverage = build_bundle(root, failures)
    validate_committed_bundle(root, expected_files, semver, failures)
    validate_semver_history(root, semver, failures)
    validate_readme_semver(root, semver, failures)
    print_coverage_report(coverage)
    return failures.report()


def run_bless_vectors(root: Path) -> int:
    failures = Failures()
    files, _, _ = build_bundle(root, failures, bless_vectors=True)
    if failures.messages:
        return failures.report()
    (root / VECTORS_SOURCE_REL).write_text(
        files[VECTORS_REL], encoding="utf-8", newline=""
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true", help="write canonical generated artifacts")
    mode.add_argument("--check", action="store_true", help="verify committed artifacts without writing")
    mode.add_argument(
        "--bless-vectors",
        action="store_true",
        help="rewrite authored conformance entry digests after a reviewed definition change",
    )
    args = parser.parse_args()
    root = repo_root()
    try:
        if args.write:
            return run_write(root)
        if args.check:
            return run_check(root)
        return run_bless_vectors(root)
    except Exception as exc:  # fail closed with the required remediation style
        print(
            f"definition gate failed unexpectedly: {type(exc).__name__}: {exc} "
            "Recovery: inspect proto/definition/definition.toml, proto/definition/vectors.json, and proto/definition/generate.py, then rerun the gate.",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
