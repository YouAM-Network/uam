"""Linking agents to owners (P2d, ships dark).

The owner makes a code on their page; the agent redeems it, gets the
``UamOwnerLink`` body the relay built, and signs it first. The owner sees
the agent and its four words and signs second, with a passkey. A ``setup``
code is for a brand-new agent and links at once; a ``link`` code is for an
existing agent and only starts 72 hours later. Unlinking needs the owner's
passkey (or the relay admin) and closes the agent's inbound policy.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from tests._passkey import SoftPasskey, b64u
from tests.relay._owner_fixtures import (  # noqa: F401  (fixtures are used by name)
    ADMIN_KEY,
    OWNER_ORIGIN,
    _exec,
    _on_owner_host,
    _rows,
    _sign_in,
    clock,
    codes,
    owner,
    owner_env,
    relay,
)
from tests.relay.test_owner_passkeys import RP_ID, _first_passkey, _register, _sign
from uam.protocol.crypto import generate_keypair, serialize_verify_key
from uam.protocol.didkey import ED25519, encode_did_key
from uam.protocol.links import (
    link_challenge,
    link_screen,
    sign_as_agent,
    unlink_challenge,
    unlink_screen,
    verify_agent_signature,
    words_for,
)
from uam.protocol.signed import object_hash, parse_body

CODE_RE = re.compile(r"^[ABCDEFGHJKMNPQRSTVWXYZ23456789]{4}-[ABCDEFGHJKMNPQRSTVWXYZ23456789]{4}$")


@pytest.fixture()
def ada(relay, owner, codes):
    """A signed-in owner with one passkey (so an owner id and a key log)."""
    _sign_in(relay, owner, codes)
    phone, signed = _first_passkey(owner)
    owner.phone = phone
    owner.owner_id = signed["owner_id"]
    owner.keys_hash = signed["hash"]
    return owner


def _agent(relay, name="bob"):
    sk, vk = generate_keypair()
    resp = relay.post("/api/v1/register", json={
        "agent_name": name, "public_key": serialize_verify_key(vk),
    })
    assert resp.status_code == 200, resp.text
    data = resp.json()
    return {
        "address": data["address"], "token": data["token"], "signing_key": sk,
        "key": encode_did_key(ED25519, bytes(vk)),
        "headers": {"Authorization": f"Bearer {data['token']}"},
    }


def _code(owner, kind="setup"):
    resp = owner.post("/api/owner/codes", json={"kind": kind})
    assert resp.status_code == 200, resp.text
    return resp.json()["code"]


def _redeem(relay, agent, code):
    return relay.post("/api/v1/owner/link/start", json={"code": code}, headers=agent["headers"])


def _agent_signs(relay, agent, started):
    body = parse_body(started["body"])
    return relay.post("/api/v1/owner/link/sign", json={
        "hash": started["hash"], "signature": sign_as_agent(body, agent["signing_key"]),
    }, headers=agent["headers"])


def _status(relay, agent):
    resp = relay.get("/api/v1/owner/link", headers=agent["headers"])
    assert resp.status_code == 200, resp.text
    return resp.json()


def _links(owner):
    resp = owner.get("/api/owner/links")
    assert resp.status_code == 200, resp.text
    return resp.json()["links"]


def _waiting(relay, owner, name="bob", kind="setup"):
    """An agent that redeemed a code and signed: the owner sees it waiting."""
    if kind == "setup":
        code = _code(owner, kind)
        agent = _agent(relay, name)
    else:
        agent = _agent(relay, name)
        code = _code(owner, kind)
    started = _redeem(relay, agent, code)
    assert started.status_code == 200, started.text
    started = started.json()
    assert _agent_signs(relay, agent, started).status_code == 200
    [link] = [x for x in _links(owner) if x["agent"] == agent["address"]]
    return agent, started, link


def _approve_start(owner, link_id):
    resp = owner.post(f"/api/owner/links/{link_id}/approve/start")
    assert resp.status_code == 200, resp.text
    return resp.json()


def _approve(owner, passkey, approval, *, origin=OWNER_ORIGIN):
    got = passkey.get(approval["challenge"], rp_id=RP_ID, origin=origin)
    return owner.post(f"/api/owner/links/{approval['link']}/approve", json=got)


def _linked(relay, owner, name="bob", kind="setup"):
    agent, started, link = _waiting(relay, owner, name, kind)
    resp = _approve(owner, owner.phone, _approve_start(owner, link["id"]))
    assert resp.status_code == 200, resp.text
    return agent, started, link


def _unlink(owner, link_id):
    approval = owner.post(f"/api/owner/links/{link_id}/unlink/start")
    assert approval.status_code == 200, approval.text
    approval = approval.json()
    got = owner.phone.get(approval["challenge"], rp_id=RP_ID, origin=OWNER_ORIGIN)
    return approval, owner.post(f"/api/owner/links/{link_id}/unlink", json=got)


def _time(text):
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


# ---------------------------------------------------------------- codes


def test_an_owner_makes_a_setup_code(ada):
    resp = ada.post("/api/owner/codes", json={"kind": "setup"})
    assert resp.status_code == 200, resp.text
    made = resp.json()
    assert CODE_RE.match(made["code"])
    assert made["kind"] == "setup"
    left = _time(made["expiresAt"]) - datetime.now(timezone.utc)
    assert timedelta(minutes=9) < left <= timedelta(minutes=10)


def test_codes_are_random(ada):
    assert len({_code(ada) for _ in range(5)}) == 5


def test_codes_are_kept_only_as_hashes(ada):
    code = _code(ada)
    [row] = _rows(ada, "SELECT code_hash FROM owner_codes")
    assert code.replace("-", "") not in row["code_hash"]


def test_a_code_needs_a_passkey_first(relay, owner, codes):
    _sign_in(relay, owner, codes)
    resp = owner.post("/api/owner/codes", json={"kind": "setup"})
    assert resp.status_code == 409
    assert resp.json()["error"] == "no_passkey"


@pytest.mark.parametrize("kind", ["admin", "", None])
def test_a_code_has_a_known_kind(ada, kind):
    assert ada.post("/api/owner/codes", json={"kind": kind}).status_code == 422


def test_codes_need_a_session_and_the_owner_origin(relay, owner, app):
    assert owner.post("/api/owner/codes", json={"kind": "setup"}).status_code == 401
    elsewhere = _on_owner_host(app, relay, origin="https://evil.example")
    assert elsewhere.post("/api/owner/codes", json={"kind": "setup"}).status_code == 403


# ---------------------------------------------------------------- the agent redeems


def test_a_new_agent_redeems_a_setup_code(ada, relay):
    code = _code(ada)
    bob = _agent(relay)
    resp = _redeem(relay, bob, code)
    assert resp.status_code == 200, resp.text
    started = resp.json()
    body = parse_body(started["body"])
    assert started["hash"] == object_hash(body)
    assert body["type"] == "UamOwnerLink"
    assert body["owner"] == {"relay": "test.local", "ownerId": ada.owner_id, "keysHash": ada.keys_hash}
    assert body["agent"] == bob["address"]
    assert body["agentKey"] == bob["key"]
    assert body["relay"] == "test.local"
    assert body["via"] == "setup"
    assert body["shared"] is True
    assert body["effectiveAt"] == body["validFrom"]
    assert abs(_time(body["validFrom"]) - datetime.now(timezone.utc)) < timedelta(minutes=1)
    assert started["account"] == "a•••@example.com"
    assert started["words"] == words_for(bob["key"])


def test_case_and_the_dash_do_not_matter(ada, relay):
    code = _code(ada)
    bob = _agent(relay)
    loose = " " + code.replace("-", "").lower() + " "
    assert _redeem(relay, bob, loose).status_code == 200


def test_a_code_works_once(ada, relay):
    code = _code(ada)
    assert _redeem(relay, _agent(relay, "bob"), code).status_code == 200
    resp = _redeem(relay, _agent(relay, "cat"), code)
    assert resp.status_code == 400
    assert resp.json()["error"] == "bad_code"


def test_a_code_lasts_ten_minutes(ada, relay, clock):
    code = _code(ada)
    bob = _agent(relay)
    clock(minutes=10, seconds=1)
    assert _redeem(relay, bob, code).json()["error"] == "bad_code"


def test_only_the_newest_code_counts(ada, relay):
    old = _code(ada)
    new = _code(ada)
    bob = _agent(relay)
    assert _redeem(relay, bob, old).json()["error"] == "bad_code"
    assert _redeem(relay, bob, new).status_code == 200


def test_a_newer_code_of_the_other_kind_leaves_a_code_alone(ada, relay):
    setup = _code(ada, "setup")
    _code(ada, "link")
    assert _redeem(relay, _agent(relay), setup).status_code == 200


def test_a_setup_code_is_only_for_an_agent_made_after_it(ada, relay):
    bob = _agent(relay)
    code = _code(ada, "setup")
    resp = _redeem(relay, bob, code)
    assert resp.status_code == 409
    assert resp.json()["error"] == "needs_link_code"
    # The code wasn't used up by the refusal.
    assert _redeem(relay, _agent(relay, "cat"), code).status_code == 200


def test_a_link_code_links_an_existing_agent_in_72_hours(ada, relay):
    bob = _agent(relay)
    started = _redeem(relay, bob, _code(ada, "link")).json()
    body = parse_body(started["body"])
    assert body["via"] == "link"
    assert _time(body["effectiveAt"]) - _time(body["validFrom"]) == timedelta(hours=72)


def test_five_wrong_codes_lock_the_agent_out_for_ten_minutes(ada, relay, clock):
    bob = _agent(relay)
    for _ in range(5):
        assert _redeem(relay, bob, "AAAA-AAAA").json()["error"] == "bad_code"
    code = _code(ada, "link")
    resp = _redeem(relay, bob, code)
    assert resp.status_code == 429
    clock(minutes=10, seconds=1)
    code = _code(ada, "link")
    assert _redeem(relay, bob, code).status_code == 200


def test_tries_count_per_agent(ada, relay):
    bob = _agent(relay, "bob")
    for _ in range(5):
        _redeem(relay, bob, "AAAA-AAAA")
    code = _code(ada)
    assert _redeem(relay, _agent(relay, "cat"), code).status_code == 200


@pytest.mark.parametrize("code", ["", "ABCD-EFG", "ABCD-EFGHJ", "ABCD-EFG0", "ABCD-EFGU"])
def test_malformed_codes_are_wrong_codes(ada, relay, code):
    assert _redeem(relay, _agent(relay), code).json()["error"] == "bad_code"


def test_redeeming_needs_an_agent_token(ada, relay):
    resp = relay.post("/api/v1/owner/link/start", json={"code": _code(ada)})
    assert resp.status_code in (401, 403)


def test_the_agent_routes_are_404_while_owners_are_off(app):
    with TestClient(app) as relay:
        bob = _agent(relay)
        assert _redeem(relay, bob, "ABCD-EFGH").status_code == 404
        assert relay.get("/api/v1/owner/link", headers=bob["headers"]).status_code == 404


# ---------------------------------------------------------------- the agent signs


def test_the_agent_signs_and_the_owner_sees_it_waiting(ada, relay):
    code = _code(ada)
    bob = _agent(relay)
    started = _redeem(relay, bob, code).json()
    assert _links(ada) == []  # nothing until the agent has signed
    resp = _agent_signs(relay, bob, started)
    assert resp.status_code == 200, resp.text
    [link] = _links(ada)
    assert link["agent"] == bob["address"]
    assert link["agentKey"] == bob["key"]
    assert link["words"] == words_for(bob["key"])
    assert link["via"] == "setup"
    assert link["state"] == "waiting"
    assert link["effective"] is False
    assert link["private"] is False
    assert _status(relay, bob)["state"] == "waiting_for_owner"


def test_the_stored_agent_signature_verifies(ada, relay):
    bob, started, _ = _waiting(relay, ada)
    [row] = _rows(ada, "SELECT body, agent_signature FROM owner_links")
    verify_agent_signature(parse_body(row["body"]), row["agent_signature"])
    assert row["body"] == started["body"]


def test_a_bad_agent_signature_is_refused(ada, relay):
    code = _code(ada)
    bob = _agent(relay)
    started = _redeem(relay, bob, code).json()
    other, _ = generate_keypair()
    resp = relay.post("/api/v1/owner/link/sign", json={
        "hash": started["hash"], "signature": sign_as_agent(parse_body(started["body"]), other),
    }, headers=bob["headers"])
    assert resp.status_code == 400
    assert resp.json()["error"] == "bad_signature"
    assert _links(ada) == []
    assert _status(relay, bob)["state"] == "waiting_for_agent"


def test_an_agent_cannot_sign_another_agents_link(ada, relay):
    code = _code(ada)
    bob = _agent(relay, "bob")
    started = _redeem(relay, bob, code).json()
    cat = _agent(relay, "cat")
    resp = relay.post("/api/v1/owner/link/sign", json={
        "hash": started["hash"],
        "signature": sign_as_agent(parse_body(started["body"]), bob["signing_key"]),
    }, headers=cat["headers"])
    assert resp.status_code == 404


def test_an_agent_without_a_link_says_none(relay, owner_env):
    bob = _agent(relay)
    assert _status(relay, bob) == {"state": "none"}


# ---------------------------------------------------------------- the owner approves


def test_the_approval_shows_the_agent_and_its_words(ada, relay):
    bob, started, link = _waiting(relay, ada)
    approval = _approve_start(ada, link["id"])
    body = parse_body(approval["body"])
    assert approval["body"] == started["body"]
    assert approval["hash"] == started["hash"]
    assert approval["screen"] == link_screen(body)
    assert " ".join(words_for(bob["key"])) in approval["screen"]
    assert approval["challenge"] == b64u(link_challenge(body))
    assert approval["allowCredentials"] == [ada.phone.id]
    assert approval["rpId"] == RP_ID
    assert approval["link"] == link["id"]


def test_approving_with_a_passkey_links_the_agent(ada, relay):
    bob, _, link = _waiting(relay, ada)
    resp = _approve(ada, ada.phone, _approve_start(ada, link["id"]))
    assert resp.status_code == 200, resp.text
    [listed] = _links(ada)
    assert listed["state"] == "active" and listed["effective"] is True
    status = _status(relay, bob)
    assert status["state"] == "linked"
    assert status["account"] == "a•••@example.com"


def test_the_stored_owner_signature_is_by_a_key_in_the_linked_entry(ada, relay):
    _linked(relay, ada)
    [row] = _rows(ada, "SELECT owner_signer, screen FROM owner_links")
    log = ada.get(f"/api/owner/keys/{ada.owner_id}").json()["entries"]
    head = parse_body(log[-1]["body"])
    assert row["owner_signer"] in {k["id"] for k in head["keys"]}
    assert row["screen"].startswith('Link the agent "')


def test_an_approval_works_once(ada, relay):
    _, _, link = _waiting(relay, ada)
    approval = _approve_start(ada, link["id"])
    assert _approve(ada, ada.phone, approval).status_code == 200
    resp = _approve(ada, ada.phone, approval)
    assert resp.status_code == 400


def test_an_approval_lasts_five_minutes(ada, relay, clock):
    _, _, link = _waiting(relay, ada)
    approval = _approve_start(ada, link["id"])
    clock(minutes=5, seconds=1)
    assert _approve(ada, ada.phone, approval).json()["error"] == "bad_challenge"


def test_an_approval_from_another_origin_is_refused(ada, relay):
    _, _, link = _waiting(relay, ada)
    approval = _approve_start(ada, link["id"])
    resp = _approve(ada, ada.phone, approval, origin="https://evil.example")
    assert resp.status_code == 400
    assert _links(ada)[0]["state"] == "waiting"


def test_a_passkey_added_after_the_link_started_cannot_approve_it(ada, relay):
    _, _, link = _waiting(relay, ada)
    laptop = SoftPasskey(backup_eligible=False)
    added = _register(ada, laptop, "Ada laptop")
    assert _sign(ada, ada.phone, added).status_code == 200
    approval = _approve_start(ada, link["id"])
    assert approval["allowCredentials"] == [ada.phone.id]
    resp = _approve(ada, laptop, approval)
    assert resp.status_code == 400
    assert resp.json()["error"] == "bad_signer"
    assert _approve(ada, ada.phone, _approve_start(ada, link["id"])).status_code == 200


def test_another_owner_cannot_see_or_approve_the_link(ada, relay, app, codes):
    _, _, link = _waiting(relay, ada)
    bo = _on_owner_host(app, relay)
    _sign_in(relay, bo, codes, email="bo@example.com")
    _first_passkey(bo)
    assert _links(bo) == []
    assert bo.post(f"/api/owner/links/{link['id']}/approve/start").status_code == 404


def test_a_link_code_link_starts_after_72_hours(ada, relay, clock, codes):
    bob, started, link = _linked(relay, ada, kind="link")
    [listed] = _links(ada)
    assert listed["state"] == "active" and listed["effective"] is False
    status = _status(relay, bob)
    assert status["state"] == "starts"
    assert status["effectiveAt"] == parse_body(started["body"])["effectiveAt"]
    clock(hours=72, seconds=1)
    assert _status(relay, bob)["state"] == "linked"
    _sign_in_again(ada, codes)  # 72 hours outlast the owner's session
    assert _links(ada)[0]["effective"] is True


def _sign_in_again(owner, codes, email="ada@example.com"):
    assert owner.post("/api/owner/sign-in/start", json={"email": email}).status_code == 202
    resp = owner.post("/api/owner/sign-in/finish", json={"email": email, "code": codes[-1][2]})
    assert resp.status_code == 200, resp.text


def test_asking_to_approve_again_gives_a_working_challenge(ada, relay):
    _, _, link = _waiting(relay, ada)
    first = _approve_start(ada, link["id"])
    again = _approve_start(ada, link["id"])
    assert again["challenge"] == first["challenge"]
    assert _approve(ada, ada.phone, again).status_code == 200


def test_the_owner_is_told_when_a_link_code_is_used(ada, relay, app):
    told = []
    app.state.owner_link_notice = lambda owner_pk, link: told.append((owner_pk, link["agent"]))
    bob, _, _ = _waiting(relay, ada, kind="link")
    [row] = _rows(ada, "SELECT id FROM owners")
    assert told == [(row["id"], bob["address"])]


def test_audit_records_the_approval(ada, relay):
    _linked(relay, ada)
    actions = [r["action"] for r in _rows(ada, "SELECT action FROM owner_audit ORDER BY id")]
    assert "link_approved" in actions


# ---------------------------------------------------------------- one live link


def test_a_linked_agent_cannot_redeem_another_code(ada, relay):
    bob, _, _ = _linked(relay, ada)
    resp = _redeem(relay, bob, _code(ada, "link"))
    assert resp.status_code == 409
    assert resp.json()["error"] == "already_linked"


def test_an_agent_waiting_for_its_owner_cannot_start_another(ada, relay):
    bob, _, _ = _waiting(relay, ada)
    resp = _redeem(relay, bob, _code(ada, "link"))
    assert resp.json()["error"] == "already_linked"


def test_redeeming_again_replaces_a_link_the_agent_never_signed(ada, relay):
    bob = _agent(relay)
    _redeem(relay, bob, _code(ada, "link"))
    started = _redeem(relay, bob, _code(ada, "link")).json()
    assert _agent_signs(relay, bob, started).status_code == 200
    assert len(_links(ada)) == 1


# ---------------------------------------------------------------- cancel


def test_the_owner_cancels_a_waiting_link(ada, relay):
    bob, _, link = _waiting(relay, ada)
    resp = ada.post(f"/api/owner/links/{link['id']}/cancel")
    assert resp.status_code == 200, resp.text
    assert _links(ada)[0]["state"] == "cancelled"
    assert _status(relay, bob)["state"] == "cancelled"
    assert _approve_start_status(ada, link["id"]) == 409
    # The agent can be linked again with a new code.
    assert _redeem(relay, bob, _code(ada, "link")).status_code == 200


def _approve_start_status(owner, link_id):
    return owner.post(f"/api/owner/links/{link_id}/approve/start").status_code


def test_a_link_can_be_cancelled_until_it_starts(ada, relay, clock):
    _, _, link = _linked(relay, ada, kind="link")
    assert ada.post(f"/api/owner/links/{link['id']}/cancel").status_code == 200


def test_a_link_in_effect_is_unlinked_not_cancelled(ada, relay):
    _, _, link = _linked(relay, ada)
    resp = ada.post(f"/api/owner/links/{link['id']}/cancel")
    assert resp.status_code == 409


def test_cancel_needs_the_owner_origin(ada, relay, app):
    _, _, link = _waiting(relay, ada)
    elsewhere = _on_owner_host(app, relay, origin="https://evil.example")
    assert elsewhere.post(f"/api/owner/links/{link['id']}/cancel").status_code == 403


# ---------------------------------------------------------------- unlink


def test_the_owner_unlinks_with_a_passkey(ada, relay):
    bob, _, link = _linked(relay, ada)
    approval, resp = _unlink(ada, link["id"])
    assert resp.status_code == 200, resp.text
    body = parse_body(approval["body"])
    assert body["type"] == "UamOwnerUnlink"
    assert body["agent"] == bob["address"] and body["agentKey"] == bob["key"]
    assert body["reason"] == "owner"
    assert body["owner"]["ownerId"] == ada.owner_id
    assert approval["screen"] == unlink_screen(body)
    assert approval["challenge"] == b64u(unlink_challenge(body))
    assert _links(ada)[0]["state"] == "unlinked"
    assert _status(relay, bob)["state"] == "unlinked"
    [row] = _rows(ada, "SELECT reason, hash, signer FROM owner_unlinks")
    assert row["reason"] == "owner" and row["hash"] == approval["hash"]
    assert row["signer"] == parse_body(
        ada.get(f"/api/owner/keys/{ada.owner_id}").json()["entries"][-1]["body"]
    )["keys"][0]["id"]


def test_unlinking_closes_the_agents_inbound_policy(ada, relay):
    bob, _, link = _linked(relay, ada)
    _unlink(ada, link["id"])
    [row] = _rows(ada, "SELECT policy, set_by FROM inbound_policies WHERE agent_address = :a",
                  a=bob["address"])
    assert row == {"policy": "closed", "set_by": "owner"}


def test_an_unlink_needs_a_valid_passkey_signature(ada, relay):
    _, _, link = _linked(relay, ada)
    approval = ada.post(f"/api/owner/links/{link['id']}/unlink/start").json()
    stranger = SoftPasskey()
    got = stranger.get(approval["challenge"], rp_id=RP_ID, origin=OWNER_ORIGIN)
    resp = ada.post(f"/api/owner/links/{link['id']}/unlink", json=got)
    assert resp.status_code == 400
    assert _links(ada)[0]["state"] == "active"


def test_only_an_active_link_can_be_unlinked(ada, relay):
    _, _, link = _waiting(relay, ada)
    assert ada.post(f"/api/owner/links/{link['id']}/unlink/start").status_code == 409


def test_an_unlinked_agent_can_be_linked_again(ada, relay):
    bob, _, link = _linked(relay, ada)
    _unlink(ada, link["id"])
    assert _redeem(relay, bob, _code(ada, "link")).status_code == 200


def test_an_agent_has_no_route_to_unlink_itself(ada, relay):
    bob, _, _ = _linked(relay, ada)
    assert relay.delete("/api/v1/owner/link", headers=bob["headers"]).status_code == 405
    assert relay.post("/api/v1/owner/link/unlink", headers=bob["headers"]).status_code == 404


def test_the_admin_can_unlink(ada, relay):
    bob, _, link = _linked(relay, ada)
    resp = relay.post(
        f"/api/v1/admin/links/{link['id']}/unlink", headers={"X-Admin-Key": ADMIN_KEY}
    )
    assert resp.status_code == 200, resp.text
    [row] = _rows(ada, "SELECT reason, signer, body FROM owner_unlinks")
    assert row["reason"] == "admin" and row["signer"] == "relay"
    assert parse_body(row["body"])["reason"] == "admin"
    assert _status(relay, bob)["state"] == "unlinked"
    [policy] = _rows(ada, "SELECT policy FROM inbound_policies WHERE agent_address = :a",
                     a=bob["address"])
    assert policy["policy"] == "closed"


def test_the_admin_unlink_needs_the_admin_key(ada, relay):
    _, _, link = _linked(relay, ada)
    assert relay.post(f"/api/v1/admin/links/{link['id']}/unlink").status_code in (401, 403)


# ---------------------------------------------------------------- private


def test_an_owner_can_make_a_link_private(ada, relay):
    _, _, link = _linked(relay, ada)
    resp = ada.post(f"/api/owner/links/{link['id']}/private", json={"private": True})
    assert resp.status_code == 200, resp.text
    assert _links(ada)[0]["private"] is True


def test_making_it_shared_again_is_not_here_yet(ada, relay):
    _, _, link = _linked(relay, ada)
    ada.post(f"/api/owner/links/{link['id']}/private", json={"private": True})
    resp = ada.post(f"/api/owner/links/{link['id']}/private", json={"private": False})
    assert resp.status_code == 409
    assert _links(ada)[0]["private"] is True


# ---------------------------------------------------------------- edges


def test_a_frozen_owners_code_does_not_work(ada, relay):
    code = _code(ada)
    _exec(ada, "UPDATE owners SET status = 'frozen'")
    assert _redeem(relay, _agent(relay), code).json()["error"] == "bad_code"


def test_a_setup_code_does_not_notify(ada, relay, app):
    told = []
    app.state.owner_link_notice = lambda owner_pk, link: told.append(link)
    _waiting(relay, ada, kind="setup")
    assert told == []


def test_an_unsigned_link_is_not_the_owners_to_act_on(ada, relay):
    code = _code(ada)
    started = _redeem(relay, _agent(relay), code).json()
    assert ada.post(f"/api/owner/links/{started['link']}/approve/start").status_code == 404
    assert ada.post(f"/api/owner/links/{started['link']}/cancel").status_code == 404


def test_an_approval_for_one_link_cannot_approve_another(ada, relay):
    _, _, first = _waiting(relay, ada, "bob")
    _, _, second = _waiting(relay, ada, "cat")
    approval = _approve_start(ada, first["id"])
    got = ada.phone.get(approval["challenge"], rp_id=RP_ID, origin=OWNER_ORIGIN)
    resp = ada.post(f"/api/owner/links/{second['id']}/approve", json=got)
    assert resp.status_code == 409
    assert {x["id"]: x["state"] for x in _links(ada)} == {
        first["id"]: "waiting", second["id"]: "waiting",
    }


def test_an_unlink_for_one_agent_cannot_unlink_another(ada, relay):
    _, _, first = _linked(relay, ada, "bob")
    _, _, second = _linked(relay, ada, "cat")
    approval = ada.post(f"/api/owner/links/{first['id']}/unlink/start").json()
    got = ada.phone.get(approval["challenge"], rp_id=RP_ID, origin=OWNER_ORIGIN)
    resp = ada.post(f"/api/owner/links/{second['id']}/unlink", json=got)
    assert resp.status_code == 409
    assert {x["state"] for x in _links(ada)} == {"active"}


def test_a_used_code_is_just_a_wrong_code_to_anyone(ada, relay):
    old = _agent(relay, "old")
    code = _code(ada)
    assert _redeem(relay, _agent(relay, "bob"), code).status_code == 200
    # Not "needs a link code": that would say the code was once real.
    assert _redeem(relay, old, code).json()["error"] == "bad_code"


def test_the_agent_names_the_hash_it_signs(ada, relay):
    code = _code(ada)
    bob = _agent(relay)
    started = _redeem(relay, bob, code).json()
    resp = relay.post("/api/v1/owner/link/sign", json={
        "hash": "x" * 43,
        "signature": sign_as_agent(parse_body(started["body"]), bob["signing_key"]),
    }, headers=bob["headers"])
    assert resp.status_code == 404
    assert _status(relay, bob)["state"] == "waiting_for_agent"


def test_an_ended_link_cannot_be_made_private(ada, relay):
    _, _, link = _waiting(relay, ada)
    ada.post(f"/api/owner/links/{link['id']}/cancel")
    resp = ada.post(f"/api/owner/links/{link['id']}/private", json={"private": True})
    assert resp.status_code == 409
    assert _links(ada)[0]["private"] is False
