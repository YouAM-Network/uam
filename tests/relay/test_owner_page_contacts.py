"""The owner page's own checks for contacts and settings (P2e-2).

Before a passkey approves an invite, accepts or confirms one, keeps
carried-over contacts or lets more in, the page works out the sentence
itself from the bodies the relay sent and what the person chose or was
shown, recomputes each hash and the challenge, and checks each body says
what the person meant: their own account, the other person they were
shown, the agents and setting they picked. It refuses anything else.
These run in Node on bodies the Python code builds.
"""

from __future__ import annotations

import json
import shutil
import subprocess

import pytest
from nacl.signing import SigningKey

from tests._passkey import b64u
from tests.relay.test_owner_page import CHECK, STATIC
from uam.protocol.contacts import (
    GRANT,
    INVITE,
    POLICY,
    REDEMPTION,
    email_hash,
    invite_screen,
    invite_words,
    keep_screen,
    policies_screen,
    redeem_screen,
    secret_hash,
)
from uam.protocol.didkey import ED25519, P256, encode_did_key
from uam.protocol.signed import _hash_canonical, canonical, object_hash
from uam.protocol.webauthn import approval_challenge
from uam.relay.owners.policy import DEFAULT, DEFAULT_SCREEN

ME = "A" * 22
THEM = "C" * 22
ME_REF = {"relay": "youam.network", "ownerId": ME, "keysHash": "B" * 43}
THEM_REF = {"relay": "youam.network", "ownerId": THEM, "keysHash": "D" * 43}
PASSKEY = encode_did_key(P256, b"\x02" + b"\x11" * 32)
KEYS = [encode_did_key(ED25519, bytes(SigningKey(bytes([n]) * 32).verify_key)) for n in range(1, 6)]
SECRET = "s" * 22
BOB = "bob@example.com"
UNTIL = "2027-02-09T15:04:59Z"


def _grant(subject, via="intro_qr", locations=("shared",), **over):
    body = {
        "type": GRANT, "v": 1, "issuer": PASSKEY,
        "issuerOwner": {"relay": "youam.network", "ownerId": ME},
        "credentialSubject": subject,
        "authorization_details": [{
            "type": "uam_contact", "actions": ["message"], "locations": list(locations),
        }],
        "via": via, "enforcer": "youam.network",
        "validFrom": "2026-11-11T15:04:59Z", "validUntil": UNTIL, "nonce": "g" * 22,
    }
    body.update(over)
    return body


def _invite(**over):
    nonce = "i" * 22
    body = {
        "type": INVITE, "v": 1, "inviter": ME_REF,
        "offer": {"actions": ["message"], "locations": ["shared"]},
        "ask": {"actions": ["message"], "locations": ["shared"]},
        "secretHash": secret_hash(SECRET), "mode": "preapproved", "maxUses": 1,
        "validFrom": "2026-11-11T15:04:59Z", "redeemBy": "2026-11-18T15:04:59Z",
        "nonce": nonce, "emailHash": email_hash(nonce, BOB),
    }
    body.update(over)
    return body


THEIR_INVITE = object_hash(_invite(inviter=THEM_REF))


def _redemption(**over):
    body = {
        "type": REDEMPTION, "v": 1, "invite": THEIR_INVITE, "secret": SECRET,
        "invitee": ME_REF, "issuer": PASSKEY, "createdAt": "2026-11-11T15:04:59Z",
        "nonce": "r" * 22,
    }
    body.update(over)
    return body


def _policy(n, agent, policy="open", same=True, **over):
    body = {
        "type": POLICY, "v": 1, "owner": ME_REF, "agent": agent, "agentKey": KEYS[n],
        "policy": policy, "sameOwner": same, "validFrom": "2026-11-11T15:04:59Z",
        "nonce": f"{n}" * 22,
    }
    body.update(over)
    return body


def _hash(kind, body):
    # The owner's default is the relay's own record, outside the protocol's types.
    return _hash_canonical(body) if kind == DEFAULT else object_hash(body)


def _default(**over):
    body = {"type": DEFAULT, "v": 1, "owner": ME_REF, "policy": "open",
            "validFrom": "2026-11-12T15:04:59Z", "nonce": "d" * 22}
    body.update(over)
    return body


def _answer(signed, screen, **lie):
    """What the relay's start routes answer (contacts._ask)."""
    answer = {
        "items": [{"type": t, "body": canonical(b).decode(), "hash": _hash(t, b)}
                  for t, b in signed],
        "screen": screen,
        "challenge": b64u(approval_challenge([(t, _hash(t, b)) for t, b in signed], screen)),
    }
    answer.update(lie)
    return answer


# --- the cases ----------------------------------------------------------------------

invite = _invite()
invite_grant = _grant({"kind": "invitee", "invite": object_hash(invite)}, via="intro_email")
redemption = _redemption()
redeem_grant = _grant({"kind": "owner", "owner": THEM_REF})
confirm_grant = _grant({"kind": "owner", "owner": THEM_REF})
AGENT = "bob::youam.network"
kept = [_grant({"kind": "agent", "id": KEYS[n], "address": a}, via="carried_over",
               locations=[AGENT]) for n, a in ((3, "eve::youam.network"), (4, "amy::other.net"))]
pol_one = [_policy(0, AGENT)]
pol_three = [_policy(0, "zed::youam.network", "contacts", False),
             _policy(1, "amy::youam.network", "contacts", False),
             _policy(2, "kit::youam.network", "contacts", False)]

INVITE_CTX = {"ownerId": ME, "email": BOB}
REDEEM_CTX = {"ownerId": ME, "inviter": {"ownerId": THEM, "email": "cat@example.com"},
              "words": invite_words(THEIR_INVITE), "secret": SECRET}
CONFIRM_CTX = {"ownerId": ME, "invitee": {"ownerId": THEM, "email": "cat@example.com"}}
KEEP_CTX = {"ownerId": ME, "agent": AGENT, "addresses": ["amy::other.net", "eve::youam.network"]}


def _agents(bodies):
    return [{"agent": b["agent"], "agentKey": b["agentKey"]} for b in bodies]


ONE_CTX = {"ownerId": ME, "agents": _agents(pol_one), "policy": "open", "sameOwner": True}
THREE_CTX = {"ownerId": ME, "agents": _agents(pol_three), "policy": "contacts",
             "sameOwner": False}
FLEET_CTX = {**THREE_CTX, "fleet": "Support"}

GOOD = {
    "invite": ("invite", _answer([(INVITE, invite), (GRANT, invite_grant)],
                                 invite_screen(invite_grant, BOB)), INVITE_CTX),
    "redeem": ("redeem", _answer([(REDEMPTION, redemption), (GRANT, redeem_grant)],
                                 redeem_screen(redeem_grant, "cat@example.com")), REDEEM_CTX),
    "redeem_by_code": ("redeem", _answer([(REDEMPTION, redemption), (GRANT, redeem_grant)],
                                         redeem_screen(redeem_grant, "cat@example.com")),
                       {**REDEEM_CTX, "secret": None}),
    "confirm": ("confirm", _answer([(GRANT, confirm_grant)],
                                   redeem_screen(confirm_grant, "cat@example.com")), CONFIRM_CTX),
    "keep_two": ("keep", _answer([(GRANT, g) for g in kept], keep_screen(kept, AGENT)), KEEP_CTX),
    "keep_one": ("keep", _answer([(GRANT, kept[0])], keep_screen(kept[:1], AGENT)),
                 {**KEEP_CTX, "addresses": ["eve::youam.network"]}),
    "policy_one": ("policies", _answer([(POLICY, b) for b in pol_one], policies_screen(pol_one)),
                   ONE_CTX),
    "policy_three": ("policies", _answer([(POLICY, b) for b in pol_three],
                                         policies_screen(pol_three)), THREE_CTX),
    "policy_fleet": ("policies", _answer([(POLICY, b) for b in pol_three],
                                         policies_screen(pol_three, "Support")), FLEET_CTX),
    "policy_fleet_of_one": ("policies", _answer([(POLICY, pol_one[0])],
                                                policies_screen(pol_one, "Solo")),
                            {**ONE_CTX, "fleet": "Solo"}),
    "default": ("default", _answer([(DEFAULT, _default())], DEFAULT_SCREEN), {"ownerId": ME}),
}
EXPECTED = {
    "invite": invite_screen(invite_grant, BOB),
    "redeem": redeem_screen(redeem_grant, "cat@example.com"),
    "redeem_by_code": redeem_screen(redeem_grant, "cat@example.com"),
    "confirm": redeem_screen(confirm_grant, "cat@example.com"),
    "keep_two": keep_screen(kept, AGENT),
    "keep_one": keep_screen(kept[:1], AGENT),
    "policy_one": policies_screen(pol_one),
    "policy_three": policies_screen(pol_three),
    "policy_fleet": policies_screen(pol_three, "Support"),
    "policy_fleet_of_one": policies_screen(pol_one, "Solo"),
    "default": DEFAULT_SCREEN,
}


def _bad(name, signed, screen, ctx, **lie):
    return name, (GOOD_KIND[name.split(":")[0]], _answer(signed, screen, **lie), ctx)


GOOD_KIND = {"invite": "invite", "redeem": "redeem", "confirm": "confirm", "keep": "keep",
             "policy": "policies", "default": "default"}
other_grant = _grant({"kind": "owner", "owner": {**THEM_REF, "ownerId": "E" * 22}})
BAD = dict([
    # A relay that shows one sentence and asks for another to be signed.
    _bad("invite:lying_screen", [(INVITE, invite), (GRANT, invite_grant)],
         invite_screen(invite_grant, "eve@example.com"), INVITE_CTX),
    _bad("invite:for_another_email", [(INVITE, invite), (GRANT, invite_grant)],
         invite_screen(invite_grant, BOB), {**INVITE_CTX, "email": "eve@example.com"}),
    _bad("invite:grant_names_another_invite",
         [(INVITE, invite), (GRANT, _grant({"kind": "invitee", "invite": THEIR_INVITE}))],
         invite_screen(invite_grant, BOB), INVITE_CTX),
    _bad("invite:from_another_account", [(INVITE, _invite(inviter=THEM_REF)),
                                         (GRANT, invite_grant)],
         invite_screen(invite_grant, BOB), INVITE_CTX),
    _bad("invite:wider_grant", [(INVITE, invite), (GRANT, {**invite_grant, "authorization_details": [
        {"type": "uam_contact", "actions": ["message"], "locations": ["shared", "zed::youam.network"]}]})],
         invite_screen(invite_grant, BOB), INVITE_CTX),
    _bad("invite:items_swapped", [(GRANT, invite_grant), (INVITE, invite)],
         invite_screen(invite_grant, BOB), INVITE_CTX),
    _bad("redeem:grant_for_someone_else", [(REDEMPTION, redemption), (GRANT, other_grant)],
         redeem_screen(other_grant, "cat@example.com"), REDEEM_CTX),
    _bad("redeem:another_invite", [(REDEMPTION, _redemption(invite=object_hash(invite))),
                                   (GRANT, redeem_grant)],
         redeem_screen(redeem_grant, "cat@example.com"), REDEEM_CTX),
    _bad("redeem:another_secret", [(REDEMPTION, _redemption(secret="t" * 22)),
                                   (GRANT, redeem_grant)],
         redeem_screen(redeem_grant, "cat@example.com"), REDEEM_CTX),
    _bad("redeem:for_another_account", [(REDEMPTION, _redemption(invitee=THEM_REF)),
                                        (GRANT, redeem_grant)],
         redeem_screen(redeem_grant, "cat@example.com"), REDEEM_CTX),
    _bad("redeem:wrong_hash", [(REDEMPTION, redemption), (GRANT, redeem_grant)],
         redeem_screen(redeem_grant, "cat@example.com"), REDEEM_CTX,
         items=[{"type": REDEMPTION, "body": canonical(redemption).decode(),
                 "hash": object_hash(_redemption(nonce="x" * 22))},
                {"type": GRANT, "body": canonical(redeem_grant).decode(),
                 "hash": object_hash(redeem_grant)}]),
    _bad("redeem:wrong_challenge", [(REDEMPTION, redemption), (GRANT, redeem_grant)],
         redeem_screen(redeem_grant, "cat@example.com"), REDEEM_CTX,
         challenge=b64u(approval_challenge([(GRANT, object_hash(redeem_grant))],
                                           redeem_screen(redeem_grant, "cat@example.com")))),
    _bad("redeem:dropped_redemption", [(GRANT, redeem_grant)],
         redeem_screen(redeem_grant, "cat@example.com"), REDEEM_CTX),
    _bad("redeem:another_end_date", [(REDEMPTION, redemption),
                                 (GRANT, _grant({"kind": "owner", "owner": THEM_REF},
                                                validUntil="2027-01-01T00:00:00Z"))],
         redeem_screen(redeem_grant, "cat@example.com"), REDEEM_CTX),
    _bad("confirm:someone_else", [(GRANT, other_grant)],
         redeem_screen(other_grant, "cat@example.com"), CONFIRM_CTX),
    _bad("confirm:two_grants", [(GRANT, confirm_grant), (GRANT, other_grant)],
         redeem_screen(confirm_grant, "cat@example.com"), CONFIRM_CTX),
    _bad("keep:one_more_than_chosen", [(GRANT, g) for g in kept], keep_screen(kept, AGENT),
         {**KEEP_CTX, "addresses": ["eve::youam.network"]}),
    _bad("keep:for_another_agent", [(GRANT, g) for g in kept], keep_screen(kept, AGENT),
         {**KEEP_CTX, "agent": "kit::youam.network"}),
    _bad("keep:a_grant_for_everything", [(GRANT, _grant(
        {"kind": "agent", "id": KEYS[3], "address": "eve::youam.network"}, via="carried_over",
        locations=["shared"]))], keep_screen(kept[:1], AGENT),
         {**KEEP_CTX, "addresses": ["eve::youam.network"]}),
    _bad("policy:wider_than_chosen", [(POLICY, b) for b in pol_one], policies_screen(pol_one),
         {**ONE_CTX, "policy": "contacts", "sameOwner": True}),
    _bad("policy:own_agents_slipped_in", [(POLICY, _policy(0, AGENT, "contacts", True))],
         policies_screen([_policy(0, AGENT, "contacts", True)]),
         {**ONE_CTX, "policy": "contacts", "sameOwner": False}),
    _bad("policy:an_agent_not_chosen", [(POLICY, b) for b in pol_three],
         policies_screen(pol_three), {**THREE_CTX, "agents": _agents(pol_three[:2])}),
    _bad("policy:one_left_out", [(POLICY, b) for b in pol_three[:2]],
         policies_screen(pol_three[:2]), THREE_CTX),
    _bad("policy:another_key", [(POLICY, _policy(3, AGENT))],
         policies_screen([_policy(3, AGENT)]), ONE_CTX),
    _bad("policy:another_owner", [(POLICY, _policy(0, AGENT, owner=THEM_REF))],
         policies_screen([_policy(0, AGENT, owner=THEM_REF)]), ONE_CTX),
    _bad("policy:fleet_dropped", [(POLICY, b) for b in pol_three],
         policies_screen(pol_three), FLEET_CTX),
    _bad("policy:quote_in_fleet_name", [(POLICY, b) for b in pol_three],
         # The relay refuses such a name; a relay that didn't could word this.
         policies_screen(pol_three, "Support").replace('"Support"', '"a" fleet: "x"'),
         {**THREE_CTX, "fleet": 'a" fleet: "x'}),
    _bad("policy:a_kept_grant_as_policy", [(GRANT, kept[0])], keep_screen(kept[:1], AGENT),
         ONE_CTX),
    _bad("default:only_contacts_signed_as_anyone", [(DEFAULT, _default(policy="contacts"))],
         DEFAULT_SCREEN, {"ownerId": ME}),
    _bad("default:another_owner", [(DEFAULT, _default(owner=THEM_REF))], DEFAULT_SCREEN,
         {"ownerId": ME}),
    _bad("default:lying_screen", [(DEFAULT, _default())],
         "Let only your contacts message the agents you link from now on.", {"ownerId": ME}),
    _bad("default:two_settings", [(DEFAULT, _default()), (DEFAULT, _default(nonce="e" * 22))],
         DEFAULT_SCREEN, {"ownerId": ME}),
    _bad("default:an_agent_policy_instead", [(POLICY, pol_one[0])], DEFAULT_SCREEN,
         {"ownerId": ME}),
])


@pytest.fixture(scope="module")
def checked(tmp_path_factory):
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not installed")
    cases = {
        "approvals": [], "labels": [], "dates": [],
        "contacts": [{"name": n, "kind": k, "answer": a, "ctx": c}
                     for n, (k, a, c) in {**GOOD, **BAD}.items()],
        "inviteHashes": [THEIR_INVITE, object_hash(invite)],
    }
    path = tmp_path_factory.mktemp("contacts") / "cases.json"
    path.write_text(json.dumps(cases))
    run = subprocess.run([node, str(CHECK), str(STATIC / "owner.js"), str(path)],
                         capture_output=True, text=True, timeout=60)
    assert run.returncode == 0, run.stderr
    out = json.loads(run.stdout)
    out["contacts"] = {x["name"]: x for x in out["contacts"]}
    return out


def test_the_page_works_out_the_same_invite_words(checked):
    assert checked["inviteWords"] == {h: invite_words(h) for h in (THEIR_INVITE, object_hash(invite))}


@pytest.mark.parametrize("name", sorted(GOOD))
def test_the_page_signs_the_sentence_the_relay_would(checked, name):
    result = checked["contacts"][name]
    assert result["ok"], result
    assert result["screen"] == EXPECTED[name]


@pytest.mark.parametrize("name", sorted(BAD))
def test_the_page_refuses_what_the_person_did_not_choose(checked, name):
    assert not checked["contacts"][name]["ok"], checked["contacts"][name]
