"""Signed owner objects: the profile, canonical form, hash and schemas (P2a).

The vectors in tests/vectors/signed/ are shared with the TS SDK, and their
expected canonical forms and hashes come from an independent oracle
(generate.py), so both languages must agree with it, not with each other.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from uam.protocol.didkey import (
    InvalidDidKeyError,
    decode_did_key,
    encode_did_key,
)
from uam.protocol.signed import (
    SignedObjectError,
    canonical,
    object_hash,
    parse_body,
    validate,
)

VECTORS = Path(__file__).resolve().parents[1] / "vectors" / "signed"


def _load(name: str) -> list[dict]:
    return json.loads((VECTORS / name).read_text())


PROFILE = _load("profile.json")
OBJECTS = _load("objects.json")
DIDKEYS = _load("didkey.json")


def _id(case: dict) -> str:
    return case.get("name") or case["did"][:24]


@pytest.mark.parametrize("case", [c for c in PROFILE if c["ok"]], ids=_id)
def test_a_body_inside_the_profile_has_one_canonical_form(case):
    assert canonical(parse_body(case["text"])).decode() == case["canonical"]


@pytest.mark.parametrize("case", [c for c in PROFILE if not c["ok"]], ids=_id)
def test_a_body_outside_the_profile_is_refused(case):
    with pytest.raises(SignedObjectError):
        parse_body(case["text"])


@pytest.mark.parametrize("case", [c for c in OBJECTS if c["ok"]], ids=_id)
def test_a_valid_object_validates_and_hashes_as_the_oracle_does(case):
    body = parse_body(json.dumps(case["body"]))
    validate(body)
    assert canonical(body).decode() == case["canonical"]
    assert object_hash(body) == case["hash"]


@pytest.mark.parametrize("case", [c for c in OBJECTS if not c["ok"]], ids=_id)
def test_an_invalid_object_is_refused(case):
    with pytest.raises(SignedObjectError):
        validate(case["body"])
    with pytest.raises(SignedObjectError):
        object_hash(case["body"])


def test_the_hash_is_bound_to_the_type():
    """The same members under another type can't produce the same hash."""
    from uam.protocol.signed import _hash_canonical  # the step after validation

    body = {"type": "UamOwnerLink", "v": 1}
    other = {"type": "UamOwnerUnlink", "v": 1}
    assert _hash_canonical(body) != _hash_canonical(other)


def test_canonical_refuses_what_parse_would_refuse():
    for bad in ({"a": 1.5}, {"a": None}, {"a": "café"}, {1: "x"}, {"a": 2**53}):
        with pytest.raises(SignedObjectError):
            canonical(bad)


def test_bytes_are_accepted_and_must_be_utf8():
    assert parse_body(b'{"a":1}') == {"a": 1}
    with pytest.raises(SignedObjectError):
        parse_body(b'{"a":"\xff"}')


@pytest.mark.parametrize("case", [c for c in DIDKEYS if c["ok"]], ids=_id)
def test_a_did_key_decodes_and_round_trips(case):
    kind, key = decode_did_key(case["did"])
    assert (kind, key.hex()) == (case["kind"], case["key"])
    assert encode_did_key(kind, key) == case["did"]


@pytest.mark.parametrize("case", [c for c in DIDKEYS if not c["ok"]], ids=_id)
def test_a_bad_did_key_is_refused(case):
    with pytest.raises(InvalidDidKeyError):
        decode_did_key(case["did"])


@pytest.mark.parametrize("kind,key", [
    ("p256", b"\x04" + bytes(32)),  # uncompressed
    ("p256", b"\x02" + bytes(31)),  # short
    ("ed25519", bytes(31)),
    ("rsa", bytes(32)),
])
def test_only_well_formed_keys_are_encoded(kind, key):
    with pytest.raises(InvalidDidKeyError):
        encode_did_key(kind, key)
