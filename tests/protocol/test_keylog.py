"""The owner key log (P2c-2): a chain of UamOwnerKeys entries, each signed
with a passkey from the entry before it (entry 0 by a key it adds).

The owner id is the hash of entry 0, so no relay can make up an owner. A
verifier needs only the entries, the relay's RP ID and its owner origin.
"""

from __future__ import annotations

import json

import pytest

from tests._passkey import SoftPasskey, b64u, unb64u
from uam.protocol.keylog import (
    KeyLogError,
    entry_challenge,
    next_entry,
    screen_for,
    verify_key_log,
)
from uam.protocol.signed import canonical, object_hash

RP_ID = "test.local"
ORIGIN = "https://account.test.local"
RELAY = "test.local"


def _key(passkey: SoftPasskey, label: str) -> dict:
    from uam.protocol.webauthn import verify_registration

    options = {"rp": {"id": RP_ID}, "challenge": b64u(b"c" * 32)}
    made = passkey.create(options, ORIGIN)
    cred = verify_registration(
        attestation_object=unb64u(made["attestationObject"]),
        client_data_json=unb64u(made["clientDataJSON"]),
        challenge=b"c" * 32, origin=ORIGIN, rp_id=RP_ID,
    )
    return {"id": cred.did, "rpId": RP_ID, "backupEligible": cred.backup_eligible, "label": label}


def _signed(body: dict, previous: dict | None, signer: SoftPasskey, signer_did: str,
            *, screen: str | None = None, origin: str = ORIGIN) -> dict:
    h = object_hash(body)
    shown = screen_for(body, previous) if screen is None else screen
    got = signer.get(b64u(entry_challenge(h, shown)), rp_id=RP_ID, origin=origin)
    return {
        "seq": body["seq"],
        "body": canonical(body).decode(),
        "hash": h,
        "signer": signer_did,
        "authenticatorData": got["authenticatorData"],
        "clientDataJSON": got["clientDataJSON"],
        "signature": got["signature"],
        "screen": shown,
    }


@pytest.fixture()
def alice():
    """An owner with one passkey (phone) and a log of one entry."""
    phone = SoftPasskey()
    phone_key = _key(phone, "Alice iPhone")
    body0 = next_entry(None, relay=RELAY, add=[phone_key])
    return {"phone": phone, "phone_key": phone_key, "bodies": [body0],
            "entries": [_signed(body0, None, phone, phone_key["id"])]}


def _add_laptop(alice, signer="phone"):
    laptop = SoftPasskey(backup_eligible=False, counter=1)
    laptop_key = _key(laptop, "Alice laptop")
    prev = alice["bodies"][-1]
    body = next_entry(prev, add=[laptop_key])
    key = alice["phone_key"] if signer == "phone" else laptop_key
    who = alice["phone"] if signer == "phone" else laptop
    alice.update(laptop=laptop, laptop_key=laptop_key)
    alice["bodies"].append(body)
    alice["entries"].append(_signed(body, prev, who, key["id"]))
    return alice


def test_a_one_entry_log_verifies_and_names_the_owner(alice):
    log = verify_key_log(alice["entries"], rp_id=RP_ID, origin=ORIGIN)
    assert log.owner_id == alice["entries"][0]["hash"][:22]
    assert set(log.keys) == {alice["phone_key"]["id"]}
    assert log.seq == 0
    assert log.head == alice["entries"][0]["hash"]


def test_entry_zero_names_no_owner_id_and_no_prev(alice):
    body0 = alice["bodies"][0]
    assert body0 == {
        "type": "UamOwnerKeys", "v": 1, "owner": {"relay": RELAY}, "seq": 0,
        "keys": [alice["phone_key"]],
    }


def test_a_later_entry_chains_to_the_one_before(alice):
    _add_laptop(alice)
    body1 = alice["bodies"][1]
    assert body1["prev"] == alice["entries"][0]["hash"]
    assert body1["owner"] == {"relay": RELAY, "ownerId": alice["entries"][0]["hash"][:22]}
    assert body1["keys"] == [alice["phone_key"], alice["laptop_key"]]
    log = verify_key_log(alice["entries"], rp_id=RP_ID, origin=ORIGIN)
    assert set(log.keys) == {alice["phone_key"]["id"], alice["laptop_key"]["id"]}
    assert log.seq == 1


def test_the_screen_says_what_is_being_signed(alice):
    assert screen_for(alice["bodies"][0], None) == (
        'Create your UAM owner account on test.local with the passkey "Alice iPhone".'
    )
    _add_laptop(alice)
    assert screen_for(alice["bodies"][1], alice["bodies"][0]) == (
        'Add the passkey "Alice laptop" to your UAM owner account.'
    )


def test_a_new_key_cannot_sign_its_own_addition(alice):
    _add_laptop(alice, signer="laptop")
    with pytest.raises(KeyLogError, match="entry 1"):
        verify_key_log(alice["entries"], rp_id=RP_ID, origin=ORIGIN)


def test_entry_zero_must_be_signed_by_a_key_it_adds(alice):
    stranger = SoftPasskey()
    stranger_key = _key(stranger, "stranger")
    alice["entries"][0] = _signed(alice["bodies"][0], None, stranger, stranger_key["id"])
    with pytest.raises(KeyLogError, match="entry 0"):
        verify_key_log(alice["entries"], rp_id=RP_ID, origin=ORIGIN)


def test_a_removed_key_cannot_sign_again(alice):
    _add_laptop(alice)
    prev = alice["bodies"][1]
    body2 = next_entry(prev, remove=[(alice["phone_key"]["id"], "removed")])
    assert [k["id"] for k in body2["keys"]] == [alice["laptop_key"]["id"]]
    assert screen_for(body2, prev) == 'Remove the passkey "Alice iPhone" from your UAM owner account.'
    alice["entries"].append(_signed(body2, prev, alice["laptop"], alice["laptop_key"]["id"]))
    assert set(verify_key_log(alice["entries"], rp_id=RP_ID, origin=ORIGIN).keys) == {
        alice["laptop_key"]["id"]
    }
    body3 = next_entry(body2, add=[_key(SoftPasskey(), "spare")])
    alice["entries"].append(_signed(body3, body2, alice["phone"], alice["phone_key"]["id"]))
    with pytest.raises(KeyLogError, match="entry 3"):
        verify_key_log(alice["entries"], rp_id=RP_ID, origin=ORIGIN)


def _tamper(entries, i, **changes):
    body = json.loads(entries[i]["body"])
    body.update(changes)
    entries[i] = {**entries[i], "body": canonical(body).decode()}


@pytest.mark.parametrize(
    "breakage",
    [
        "empty",
        "hash",
        "not_canonical",
        "seq_gap",
        "prev",
        "owner_id",
        "relay",
        "screen",
        "signature",
        "origin",
        "rp_id",
        "signer_unknown",
        "not_a_key_log",
    ],
)
def test_a_broken_log_is_refused(alice, breakage):
    _add_laptop(alice)
    entries = alice["entries"]
    origin, rp_id = ORIGIN, RP_ID
    if breakage == "empty":
        entries = []
    elif breakage == "hash":
        entries[1] = {**entries[1], "hash": entries[0]["hash"]}
    elif breakage == "not_canonical":
        entries[1] = {**entries[1], "body": json.dumps(json.loads(entries[1]["body"]), indent=1)}
    elif breakage == "seq_gap":
        del entries[0]
    elif breakage == "prev":
        _tamper(entries, 1, prev="A" * 43)
    elif breakage == "owner_id":
        _tamper(entries, 1, owner={"relay": RELAY, "ownerId": "B" * 22})
    elif breakage == "relay":
        _tamper(entries, 1, owner={"relay": "other.example", "ownerId": entries[0]["hash"][:22]})
    elif breakage == "screen":
        entries[1] = {**entries[1], "screen": "Add nothing."}
    elif breakage == "signature":
        prev, body = alice["bodies"]
        entries[1] = _signed(body, prev, alice["phone"], alice["phone_key"]["id"],
                             screen="Add nothing.") | {"screen": entries[1]["screen"]}
    elif breakage == "origin":
        origin = "https://evil.example"
    elif breakage == "rp_id":
        rp_id = "other.example"
    elif breakage == "signer_unknown":
        entries[1] = {**entries[1], "signer": alice["laptop_key"]["id"]}
    elif breakage == "not_a_key_log":
        entries[0] = {**entries[0], "body": canonical({"type": "UamOwnerKeys"}).decode()}
    if breakage in ("prev", "owner_id", "relay"):
        # Re-hash and re-sign the tampered body so only the named rule is broken.
        body = json.loads(entries[1]["body"])
        entries[1] = _signed(body, alice["bodies"][0], alice["phone"], alice["phone_key"]["id"])
    with pytest.raises(KeyLogError):
        verify_key_log(entries, rp_id=rp_id, origin=origin)


def test_next_entry_refuses_to_remove_a_key_it_does_not_have(alice):
    other = _key(SoftPasskey(), "other")
    with pytest.raises(KeyLogError, match="not a current key"):
        next_entry(alice["bodies"][0], remove=[(other["id"], "removed")])


def test_next_entry_refuses_to_add_a_key_twice(alice):
    with pytest.raises(KeyLogError, match="already"):
        next_entry(alice["bodies"][0], add=[alice["phone_key"]])


def test_a_change_needs_something_to_change(alice):
    with pytest.raises(KeyLogError):
        next_entry(alice["bodies"][0])


def test_the_last_key_cannot_be_removed(alice):
    with pytest.raises(KeyLogError, match="last"):
        next_entry(alice["bodies"][0], remove=[(alice["phone_key"]["id"], "removed")])


def _crafted(alice, change):
    """Entry 1 built by hand (not by next_entry), changed by *change*, then
    hashed and signed properly by the phone, so only that rule is broken."""
    prev = alice["bodies"][0]
    h0 = object_hash(prev)
    laptop_key = _key(SoftPasskey(), "Alice laptop")
    body = {
        "type": "UamOwnerKeys", "v": 1, "owner": {"relay": RELAY, "ownerId": h0[:22]},
        "seq": 1, "prev": h0, "keys": [alice["phone_key"], laptop_key],
    }
    change(body, alice, laptop_key)
    return alice["entries"] + [_signed(body, prev, alice["phone"], alice["phone_key"]["id"])]


def _drop_phone(body, alice, laptop_key):
    body["keys"] = [laptop_key]


def _remove_and_keep(body, alice, laptop_key):
    body["removed"] = [{"id": alice["phone_key"]["id"], "reason": "removed"}]


def _remove_unknown(body, alice, laptop_key):
    body["keys"] = [alice["phone_key"]]
    body["removed"] = [{"id": laptop_key["id"], "reason": "removed"}]


def _no_change(body, alice, laptop_key):
    body["keys"] = [alice["phone_key"]]


def _skip_seq(body, alice, laptop_key):
    body["seq"] = 2


def _foreign_rp(body, alice, laptop_key):
    laptop_key["rpId"] = "other.example"


def _twice(body, alice, laptop_key):
    body["keys"] = [alice["phone_key"], laptop_key, laptop_key]


@pytest.mark.parametrize(
    ("change", "why"),
    [
        (_drop_phone, "drops a key without removing it"),
        (_remove_and_keep, "removes a key and keeps it"),
        (_remove_unknown, "removes a key that wasn't there"),
        (_no_change, "changes nothing"),
        (_skip_seq, "expected seq 1"),
        (_foreign_rp, "RP ID"),
        (_twice, "listed twice"),
    ],
)
def test_an_entry_breaking_one_rule_is_refused(alice, change, why):
    entries = _crafted(alice, change)
    with pytest.raises(KeyLogError, match=f"entry 1: .*{why}"):
        verify_key_log(entries, rp_id=RP_ID, origin=ORIGIN)


def test_the_crafted_entry_is_fine_unchanged(alice):
    """The control for the test above: unchanged, the crafted entry verifies."""
    entries = _crafted(alice, lambda body, alice, laptop_key: None)
    assert verify_key_log(entries, rp_id=RP_ID, origin=ORIGIN).seq == 1


def test_the_listed_seq_must_match_the_body(alice):
    alice["entries"][0] = {**alice["entries"][0], "seq": 1}
    with pytest.raises(KeyLogError, match="entry 0: expected seq 0"):
        verify_key_log(alice["entries"], rp_id=RP_ID, origin=ORIGIN)
