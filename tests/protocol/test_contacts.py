"""Introductions between owners (P2e): invite secrets, the four words two
owners compare, and the sentences each passkey signs.

An invite's secret is in the link's fragment (or held by the relay for a
call code); the invite carries only its hash. A pre-approved invite names
the invitee's email by a salted hash. Each sentence names the other person
by the email the relay checked, and how long the approval lasts.
"""

from __future__ import annotations

import base64
import hashlib

import pytest

from uam.protocol.contacts import (
    ContactError,
    email_hash,
    invite_id,
    invite_screen,
    invite_words,
    keep_screen,
    new_secret,
    policy_screen,
    redeem_screen,
    confirm_screen,
    secret_hash,
)
from uam.protocol.didkey import ED25519, P256, encode_did_key
from uam.protocol.links import word_list
from uam.protocol.signed import SignedObjectError, object_hash, validate

OWNER = {"relay": "youam.network", "ownerId": "A" * 22, "keysHash": "B" * 43}
AGENT_KEY = encode_did_key(ED25519, b"\x07" * 32)
PASSKEY = encode_did_key(P256, b"\x02" + b"\x11" * 32)


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _grant(**over):
    body = {
        "type": "UamContactGrant", "v": 1, "issuer": PASSKEY,
        "issuerOwner": {"relay": "youam.network", "ownerId": "A" * 22},
        "credentialSubject": {"kind": "owner", "owner": OWNER},
        "authorization_details": [
            {"type": "uam_contact", "actions": ["message"], "locations": ["shared"]},
        ],
        "via": "intro_code", "enforcer": "youam.network",
        "validFrom": "2026-11-10T12:00:00Z", "validUntil": "2027-02-08T12:00:00Z",
        "nonce": "n" * 22,
    }
    body.update(over)
    return body


def _policy(**over):
    body = {
        "type": "UamAgentPolicy", "v": 1, "owner": OWNER, "agent": "bob::youam.network",
        "agentKey": AGENT_KEY, "policy": "open", "sameOwner": True,
        "validFrom": "2026-11-10T12:00:00Z", "nonce": "n" * 22,
    }
    body.update(over)
    return body


# ---------------------------------------------------------------- secrets


def test_a_secret_is_128_random_bits():
    secrets = {new_secret() for _ in range(20)}
    assert len(secrets) == 20
    assert all(len(base64.urlsafe_b64decode(s + "==")) == 16 for s in secrets)


def test_the_invite_holds_only_the_secrets_hash():
    s = new_secret()
    want = _b64u(hashlib.sha256(b"UAM-INVITE-SECRET-v1\n" + s.encode()).digest())
    assert secret_hash(s) == want


def test_an_emails_hash_is_salted_by_the_nonce_and_ignores_case():
    want = _b64u(hashlib.sha256(b"UAM-INVITE-EMAIL-v1\n" + b"n1" + b"bob@x.io").digest())
    assert email_hash("n1", " Bob@X.io ") == want
    assert email_hash("n2", "bob@x.io") != want


def test_an_invites_link_id_is_16_characters_of_its_hash():
    assert invite_id("abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG") == "abcdefghijklmnop"


def test_the_words_come_from_the_invites_hash():
    h = "Z" * 43
    digest = hashlib.sha256(b"UAM-SAS-v1\n" + h.encode()).digest()
    head = int.from_bytes(digest, "big") >> (256 - 44)
    want = [word_list()[(head >> (11 * (3 - i))) & 2047] for i in range(4)]
    assert invite_words(h) == want
    assert invite_words("Y" * 43) != want


# ---------------------------------------------------------------- sentences


def test_the_inviter_signs_the_email_they_typed_and_the_end_date():
    text = invite_screen(_grant(credentialSubject={"kind": "invitee", "invite": "C" * 43}),
                         "bob@x.io")
    assert text == (
        "Invite bob@x.io to connect on YouAM. When they accept, their shared agents "
        "can message yours until 8 Feb 2027."
    )


def test_the_invitee_signs_the_inviters_email():
    assert redeem_screen(_grant(), "ada@x.io") == (
        "Connect with ada@x.io on YouAM. Their shared agents can message yours "
        "until 8 Feb 2027."
    )


def test_the_inviter_confirms_the_invitees_email():
    assert confirm_screen(_grant(), "bob@x.io") == redeem_screen(_grant(), "bob@x.io")


def test_a_sentence_needs_a_grant():
    with pytest.raises(ContactError):
        redeem_screen(_policy(), "ada@x.io")


def test_keeping_one_carried_over_contact():
    grant = _grant(credentialSubject={"kind": "agent", "id": AGENT_KEY, "address": "cat::x.io"},
                   via="carried_over")
    assert keep_screen([grant], "bob::youam.network") == (
        'Let "cat::x.io" keep messaging "bob::youam.network" until 8 Feb 2027.'
    )


def test_keeping_several_names_each_by_address():
    grants = [
        _grant(credentialSubject={"kind": "agent", "id": AGENT_KEY, "address": a},
               via="carried_over")
        for a in ("zed::x.io", "amy::x.io")
    ]
    assert keep_screen(grants, "bob::youam.network") == (
        'Let 2 agents keep messaging "bob::youam.network" until 8 Feb 2027: '
        '"amy::x.io", "zed::x.io".'
    )


@pytest.mark.parametrize("policy, same, text", [
    ("open", True, 'Let anyone message "bob::youam.network".'),
    ("contacts", True, 'Let your contacts and your own agents message "bob::youam.network".'),
    ("contacts", False, 'Let only your contacts message "bob::youam.network".'),
])
def test_the_policy_sentence_says_who_can_message_the_agent(policy, same, text):
    assert policy_screen(_policy(policy=policy, sameOwner=same)) == text


# ---------------------------------------------------------------- the policy object


def test_a_policy_object_validates():
    validate(_policy())
    assert object_hash(_policy()) != object_hash(_policy(policy="contacts"))


@pytest.mark.parametrize("over", [
    {"policy": "closed"},
    {"sameOwner": "yes"},
    {"agentKey": "did:key:zDnaeX"},
    {"agent": "not an address"},
])
def test_a_policy_object_is_checked(over):
    with pytest.raises(SignedObjectError):
        validate(_policy(**over))
