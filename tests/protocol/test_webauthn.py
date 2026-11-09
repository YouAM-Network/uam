"""Passkeys: registration, assertions and the approval challenge (P2b).

The vectors (tests/vectors/webauthn/) come from a software authenticator in
generate.py and are shared with the TS SDK. Each rejection case changes
exactly one thing from a valid one.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from uam.protocol.didkey import decode_did_key
from uam.protocol.webauthn import (
    Credential,
    WebAuthnError,
    approval_challenge,
    verify_assertion,
    verify_registration,
)

VECTORS = json.loads(
    (Path(__file__).resolve().parents[1] / "vectors" / "webauthn" / "vectors.json").read_text()
)
RP_ID = VECTORS["rpId"]
ORIGIN = VECTORS["origin"]


def _b(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _register(case: dict) -> Credential:
    response = case["response"]
    return verify_registration(
        attestation_object=_b(response["attestationObject"]),
        client_data_json=_b(response["clientDataJSON"]),
        challenge=_b(case["challenge"]),
        origin=ORIGIN,
        rp_id=RP_ID,
    )


def _credential(data: dict) -> Credential:
    return Credential(
        id=b"cred",
        alg=data["alg"],
        public_key=bytes.fromhex(data["publicKey"]),
        backup_eligible=data["backupEligible"],
        sign_count=data["signCount"],
    )


def _assert(case: dict) -> int:
    response = case["response"]
    return verify_assertion(
        _credential(case["credential"]),
        authenticator_data=_b(response["authenticatorData"]),
        client_data_json=_b(response["clientDataJSON"]),
        signature=_b(response["signature"]),
        challenge=_b(VECTORS["getChallenge"]),
        origin=ORIGIN,
        rp_id=RP_ID,
    )


def _cases(kind: str, ok: bool) -> list[dict]:
    return [c for c in VECTORS[kind] if c["ok"] is ok]


@pytest.mark.parametrize("case", _cases("registrations", True), ids=lambda c: c["name"])
def test_a_registration_gives_the_credential(case):
    credential = _register(case)
    expected = case["credential"]
    assert credential.id == _b(expected["id"])
    assert credential.alg == expected["alg"]
    assert credential.public_key.hex() == expected["publicKey"]
    assert credential.backup_eligible is expected["backupEligible"]
    assert credential.sign_count == expected["signCount"]
    assert decode_did_key(credential.did) == ("p256", credential.public_key)


@pytest.mark.parametrize("case", _cases("registrations", False), ids=lambda c: c["name"])
def test_a_bad_registration_is_refused(case):
    with pytest.raises(WebAuthnError):
        _register(case)


@pytest.mark.parametrize("case", _cases("assertions", True), ids=lambda c: c["name"])
def test_a_good_assertion_gives_the_new_sign_count(case):
    assert _assert(case) == case["signCount"]


@pytest.mark.parametrize("case", _cases("assertions", False), ids=lambda c: c["name"])
def test_a_bad_assertion_is_refused(case):
    with pytest.raises(WebAuthnError):
        _assert(case)


def test_an_agent_without_the_stored_counter_can_skip_the_counter_check():
    case = next(c for c in VECTORS["assertions"] if c["name"] == "counter_went_back")
    response = case["response"]
    count = verify_assertion(
        _credential(case["credential"]),
        authenticator_data=_b(response["authenticatorData"]),
        client_data_json=_b(response["clientDataJSON"]),
        signature=_b(response["signature"]),
        challenge=_b(VECTORS["getChallenge"]),
        origin=ORIGIN,
        rp_id=RP_ID,
        check_counter=False,
    )
    assert count == 7


def test_the_approval_challenge_covers_every_object_and_the_screen():
    approval = VECTORS["approval"]
    items = [(entry["t"], entry["h"]) for entry in approval["set"]]
    challenge = approval_challenge(items, approval["screen"])
    assert challenge == _b(approval["challenge"])
    assert approval_challenge(items[:1], approval["screen"]) != challenge
    assert approval_challenge(items, approval["screen"] + " ") != challenge


def test_an_approval_needs_at_least_one_object():
    with pytest.raises(WebAuthnError):
        approval_challenge([], "nothing")
