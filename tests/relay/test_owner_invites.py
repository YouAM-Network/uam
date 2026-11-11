"""Owners connect (P2e-1): invites, redemptions and each side's grant.

- Ada makes an invite: a code she reads out on a call (10 minutes), a link
  (7 days), or Bob's email (pre-approved: her passkey signs the invite and
  her grant at once, and the email goes out after 10 minutes, so she can
  undo it). At most 10 open invites and 20 a day.
- Bob, signed in with a passkey, finds the invite by its code or by its
  link's id and secret, sees Ada's checked email, how long her account has
  existed and four words, and accepts with one passkey approval: his
  redemption and his grant naming Ada.
- An invite works once. A second try gets 409 and Ada hears about it.
- For a code or a link, Ada then confirms Bob with her passkey, seeing his
  checked email. A pre-approved invite needs nothing more from her.
- Removing someone revokes your grant at once; cancelling an invite ends
  it. Both go on the relay's revocation list.
"""

from __future__ import annotations

import base64
from datetime import timedelta

import pytest

from tests.relay._owner_fixtures import (  # noqa: F401  (fixtures are used by name)
    EMAIL,
    OWNER_ORIGIN,
    _on_owner_host,
    _rows,
    _sign_in,
    clock,
    codes,
    owner,
    owner_env,
    relay,
)
from tests.relay.test_owner_links import ada  # noqa: F401
from tests.relay.test_owner_passkeys import RP_ID, _first_passkey, _register
from uam.protocol.contacts import (
    confirm_screen,
    email_hash,
    invite_id,
    invite_screen,
    invite_words,
    redeem_screen,
    secret_hash,
)
from uam.protocol.signed import object_hash, parse_body
from uam.protocol.webauthn import approval_challenge

BOB = "bob@example.com"
CAT = "cat@example.com"


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _person(relay, app, codes, email, label):
    client = _on_owner_host(app, relay)
    _sign_in(relay, client, codes, email)
    phone, signed = _first_passkey(client, label)
    client.phone = phone
    client.owner_id = signed["owner_id"]
    client.keys_hash = signed["hash"]
    client.email = email
    return client


@pytest.fixture()
def bob(relay, app, codes, ada):
    return _person(relay, app, codes, BOB, "Bob phone")


@pytest.fixture()
def cat(relay, app, codes, ada):
    return _person(relay, app, codes, CAT, "Cat phone")


@pytest.fixture()
def notices(app):
    got = []
    app.state.owner_contact_sink = lambda owner_pk, event, details: got.append(
        (owner_pk, event, details)
    )
    return got


@pytest.fixture()
def emails(app):
    got = []
    app.state.owner_invite_email_sink = lambda to, link, inviter: got.append((to, link, inviter))
    return got


def _invite(client, how="code"):
    resp = client.post("/api/owner/invites", json={"how": how})
    assert resp.status_code == 200, resp.text
    return resp.json()


def _key(made):
    """What the invitee types or opens: a code, or a link's id and secret."""
    if "code" in made:
        return {"code": made["code"]}
    path, secret = made["link"].split("#")
    return {"link": path.rsplit("/", 1)[1], "secret": secret}


def _approve(client, asked, route, passkey=None, *, origin=OWNER_ORIGIN):
    got = (passkey or client.phone).get(asked["challenge"], rp_id=RP_ID, origin=origin)
    return client.post(route, json=got)


def _redeem(client, made):
    asked = client.post("/api/owner/invites/redeem/start", json=_key(made))
    assert asked.status_code == 200, asked.text
    return _approve(client, asked.json(), "/api/owner/invites/redeem")


def _confirm(client, invite_id_):
    asked = client.post(f"/api/owner/invites/{invite_id_}/confirm/start")
    assert asked.status_code == 200, asked.text
    return _approve(client, asked.json(), f"/api/owner/invites/{invite_id_}/confirm")


def _invites(client):
    resp = client.get("/api/owner/invites")
    assert resp.status_code == 200, resp.text
    return resp.json()["invites"]


def _contacts(client):
    resp = client.get("/api/owner/contacts")
    assert resp.status_code == 200, resp.text
    return resp.json()["contacts"]


def _email_invite(client, email=BOB):
    asked = client.post("/api/owner/invites/email/start", json={"email": email})
    assert asked.status_code == 200, asked.text
    resp = _approve(client, asked.json(), "/api/owner/invites/email")
    assert resp.status_code == 200, resp.text
    return resp.json()


def _connected(ada, bob, how="code"):
    made = _invite(ada, how)
    assert _redeem(bob, made).status_code == 200
    assert _confirm(ada, made["id"]).status_code == 200
    return made


# ---------------------------------------------------------------- making invites


def test_a_code_invite_lasts_ten_minutes(ada):
    made = _invite(ada, "code")
    assert made["how"] == "code" and made["mode"] == "confirm" and made["state"] == "open"
    assert len(made["code"]) == 9 and made["code"][4] == "-"
    [row] = _rows(ada, "SELECT body, created_at, redeem_by, secret FROM owner_invites")
    body = parse_body(row["body"])
    assert body["type"] == "UamInvite" and body["mode"] == "confirm"
    assert body["inviter"] == {"relay": "test.local", "ownerId": ada.owner_id,
                               "keysHash": ada.keys_hash}
    assert body["offer"] == body["ask"] == {"actions": ["message"], "locations": ["shared"]}
    assert body["secretHash"] == secret_hash(row["secret"])
    span = (_time(body["redeemBy"]) - _time(body["validFrom"]))
    assert span == timedelta(minutes=10)
    assert made["words"] == invite_words(object_hash(body))


def test_a_link_invite_lasts_seven_days_and_the_relay_keeps_no_secret(ada):
    made = _invite(ada, "link")
    path, secret = made["link"].split("#")
    [row] = _rows(ada, "SELECT body, hash, secret, link_id FROM owner_invites")
    assert row["secret"] is None
    assert path == f"{OWNER_ORIGIN}/i/{row['link_id']}"
    assert row["link_id"] == invite_id(row["hash"])
    body = parse_body(row["body"])
    assert body["secretHash"] == secret_hash(secret)
    assert _time(body["redeemBy"]) - _time(body["validFrom"]) == timedelta(days=7)


def test_codes_are_kept_only_as_hashes(ada):
    made = _invite(ada, "code")
    [row] = _rows(ada, "SELECT code_hash FROM owner_invites")
    assert made["code"].replace("-", "") not in row["code_hash"]


def test_an_invite_needs_a_passkey_first(relay, owner, codes):
    _sign_in(relay, owner, codes)
    resp = owner.post("/api/owner/invites", json={"how": "code"})
    assert resp.status_code == 409 and resp.json()["error"] == "no_passkey"


@pytest.mark.parametrize("how", ["email", "qr", ""])
def test_a_plain_invite_is_a_code_or_a_link(ada, how):
    assert ada.post("/api/owner/invites", json={"how": how}).status_code == 422


def test_invites_need_a_session_and_the_owner_origin(relay, owner, app):
    assert owner.post("/api/owner/invites", json={"how": "code"}).status_code == 401
    assert owner.get("/api/owner/invites").status_code == 401
    elsewhere = _on_owner_host(app, relay, origin="https://evil.example")
    assert elsewhere.post("/api/owner/invites", json={"how": "code"}).status_code == 403


def test_ten_open_invites_at_most(ada):
    for _ in range(10):
        _invite(ada, "link")
    resp = ada.post("/api/owner/invites", json={"how": "link"})
    assert resp.status_code == 429 and resp.json()["error"] == "too_many"


def test_a_cancelled_invite_frees_a_place(ada):
    made = [_invite(ada, "link") for _ in range(10)]
    assert ada.post(f"/api/owner/invites/{made[0]['id']}/cancel").status_code == 200
    _invite(ada, "link")


def test_twenty_invites_a_day_at_most(ada):
    for _ in range(20):
        made = _invite(ada, "link")
        assert ada.post(f"/api/owner/invites/{made['id']}/cancel").status_code == 200
    resp = ada.post("/api/owner/invites", json={"how": "link"})
    assert resp.status_code == 429 and resp.json()["error"] == "too_many"


def test_an_owner_lists_their_invites(ada):
    code = _invite(ada, "code")
    link = _invite(ada, "link")
    listed = {x["id"]: x for x in _invites(ada)}
    assert set(listed) == {code["id"], link["id"]}
    assert "code" not in listed[code["id"]] and "link" not in listed[link["id"]]
    assert listed[code["id"]]["words"] == code["words"]


def test_an_expired_invite_shows_as_expired(ada, clock):
    made = _invite(ada, "code")
    clock(minutes=10, seconds=1)
    [listed] = _invites(ada)
    assert listed["id"] == made["id"] and listed["state"] == "expired"


def test_cancelling_an_invite_needs_no_passkey(ada):
    made = _invite(ada, "code")
    resp = ada.post(f"/api/owner/invites/{made['id']}/cancel")
    assert resp.status_code == 200 and resp.json()["state"] == "cancelled"


def test_an_owner_cancels_only_their_own_invites(ada, bob):
    made = _invite(ada, "code")
    assert bob.post(f"/api/owner/invites/{made['id']}/cancel").status_code == 404


# ---------------------------------------------------------------- finding one


def test_the_invitee_sees_the_inviters_checked_email_and_the_words(ada, bob):
    made = _invite(ada, "code")
    resp = bob.post("/api/owner/invites/find", json=_key(made))
    assert resp.status_code == 200, resp.text
    found = resp.json()
    assert found["inviter"]["email"] == EMAIL.lower()
    assert found["inviter"]["since"]
    assert found["words"] == made["words"]
    assert found["mode"] == "confirm"


def test_a_link_is_found_by_its_id_and_secret(ada, bob):
    made = _invite(ada, "link")
    assert bob.post("/api/owner/invites/find", json=_key(made)).status_code == 200


def test_a_code_ignores_case_and_the_dash(ada, bob):
    made = _invite(ada, "code")
    loose = " " + made["code"].replace("-", "").lower() + " "
    assert bob.post("/api/owner/invites/find", json={"code": loose}).status_code == 200


@pytest.mark.parametrize("wrong", ["code", "secret"])
def test_a_wrong_code_or_secret_finds_nothing(ada, bob, wrong):
    made = _invite(ada, "code" if wrong == "code" else "link")
    key = {"code": "AAAA-AAAA"} if wrong == "code" else {**_key(made), "secret": "x" * 22}
    resp = bob.post("/api/owner/invites/find", json=key)
    assert resp.status_code == 404 and resp.json()["error"] == "no_invite"


def test_five_wrong_tries_lock_the_account_out_for_ten_minutes(ada, bob, clock):
    made = _invite(ada, "link")
    for _ in range(5):
        assert bob.post("/api/owner/invites/find", json={"code": "AAAA-AAAA"}).status_code == 404
    resp = bob.post("/api/owner/invites/find", json=_key(made))
    assert resp.status_code == 429 and resp.json()["error"] == "too_many_tries"
    clock(minutes=10, seconds=1)
    assert bob.post("/api/owner/invites/find", json=_key(made)).status_code == 200


def test_an_expired_invite_is_gone(ada, bob, clock):
    made = _invite(ada, "code")
    clock(minutes=10, seconds=1)
    resp = bob.post("/api/owner/invites/find", json=_key(made))
    assert resp.status_code == 410 and resp.json()["error"] == "invite_ended"


def test_a_cancelled_invite_is_gone(ada, bob):
    made = _invite(ada, "code")
    ada.post(f"/api/owner/invites/{made['id']}/cancel")
    assert bob.post("/api/owner/invites/find", json=_key(made)).status_code == 410


def test_you_cannot_accept_your_own_invite(ada):
    made = _invite(ada, "code")
    resp = ada.post("/api/owner/invites/find", json=_key(made))
    assert resp.status_code == 409 and resp.json()["error"] == "own_invite"


def test_finding_needs_a_passkey(relay, app, codes, ada):
    made = _invite(ada, "code")
    newcomer = _on_owner_host(app, relay)
    _sign_in(relay, newcomer, codes, "new@example.com")
    resp = newcomer.post("/api/owner/invites/find", json=_key(made))
    assert resp.status_code == 409 and resp.json()["error"] == "no_passkey"


@pytest.mark.parametrize("key", [{}, {"code": "x", "link": "y"}, {"link": "abc"}])
def test_finding_takes_a_code_or_a_link_and_secret(bob, key):
    assert bob.post("/api/owner/invites/find", json=key).status_code == 422


# ---------------------------------------------------------------- redeeming


def test_one_passkey_signs_the_redemption_and_the_grant(ada, bob):
    made = _invite(ada, "code")
    asked = bob.post("/api/owner/invites/redeem/start", json=_key(made)).json()
    [redemption, grant] = [parse_body(x["body"]) for x in asked["items"]]
    [invite] = _rows(ada, "SELECT hash, secret FROM owner_invites")
    assert redemption["type"] == "UamRedemption"
    assert redemption["invite"] == invite["hash"]
    assert redemption["secret"] == invite["secret"]
    assert redemption["invitee"] == {"relay": "test.local", "ownerId": bob.owner_id,
                                     "keysHash": bob.keys_hash}
    assert grant["type"] == "UamContactGrant" and grant["via"] == "intro_code"
    assert grant["issuerOwner"] == {"relay": "test.local", "ownerId": bob.owner_id}
    assert grant["credentialSubject"] == {"kind": "owner", "owner": {
        "relay": "test.local", "ownerId": ada.owner_id, "keysHash": ada.keys_hash}}
    assert grant["authorization_details"] == [
        {"type": "uam_contact", "actions": ["message"], "locations": ["shared"]}]
    assert _time(grant["validUntil"]) - _time(grant["validFrom"]) == timedelta(days=90)
    assert grant["issuer"] == redemption["issuer"] == _did(bob, bob.phone)
    assert asked["screen"] == redeem_screen(grant, EMAIL.lower())
    assert asked["challenge"] == b64u(approval_challenge(
        [("UamRedemption", object_hash(redemption)), ("UamContactGrant", object_hash(grant))],
        asked["screen"],
    ))
    resp = _approve(bob, asked, "/api/owner/invites/redeem")
    assert resp.status_code == 200, resp.text
    [row] = _rows(ada, "SELECT hash, signer, screen FROM invite_redemptions")
    assert row["hash"] == object_hash(redemption) and row["screen"] == asked["screen"]


def test_a_link_invite_is_via_a_link(ada, bob):
    made = _invite(ada, "link")
    asked = bob.post("/api/owner/invites/redeem/start", json=_key(made)).json()
    assert parse_body(asked["items"][1]["body"])["via"] == "intro_qr"


def test_redeeming_tells_the_inviter(ada, bob, notices):
    made = _invite(ada, "code")
    _redeem(bob, made)
    [(owner_pk, event, details)] = notices
    assert event == "invite_redeemed" and details["invite"] == made["id"]
    assert details["email"] == BOB


def test_after_redeeming_the_inviter_sees_who_and_confirms(ada, bob):
    made = _invite(ada, "code")
    _redeem(bob, made)
    [listed] = _invites(ada)
    assert listed["state"] == "redeemed"
    assert listed["invitee"]["email"] == BOB and listed["invitee"]["since"]


def test_an_invite_works_once(ada, bob, cat, notices):
    made = _invite(ada, "code")
    assert _redeem(bob, made).status_code == 200
    resp = cat.post("/api/owner/invites/redeem/start", json=_key(made))
    assert resp.status_code == 409 and resp.json()["error"] == "used"
    assert notices[-1][1] == "invite_reused"
    [audit] = _rows(ada, "SELECT action FROM owner_audit WHERE action = 'invite_reused'")
    assert audit


def test_a_race_to_redeem_has_one_winner(ada, bob, cat, notices):
    made = _invite(ada, "link")
    first = bob.post("/api/owner/invites/redeem/start", json=_key(made)).json()
    second = cat.post("/api/owner/invites/redeem/start", json=_key(made)).json()
    assert _approve(bob, first, "/api/owner/invites/redeem").status_code == 200
    resp = _approve(cat, second, "/api/owner/invites/redeem")
    assert resp.status_code == 409 and resp.json()["error"] == "used"
    assert _rows(ada, "SELECT count(*) AS n FROM invite_redemptions")[0]["n"] == 1
    assert _rows(ada, "SELECT count(*) AS n FROM owner_grants")[0]["n"] == 1
    assert notices[-1][1] == "invite_reused"


def test_an_invite_cancelled_after_the_ask_is_not_redeemed(ada, bob):
    made = _invite(ada, "code")
    asked = bob.post("/api/owner/invites/redeem/start", json=_key(made)).json()
    ada.post(f"/api/owner/invites/{made['id']}/cancel")
    resp = _approve(bob, asked, "/api/owner/invites/redeem")
    assert resp.status_code == 410
    assert _rows(ada, "SELECT count(*) AS n FROM owner_grants")[0]["n"] == 0


def test_an_invite_that_expires_after_the_ask_is_not_redeemed(ada, bob, clock):
    made = _invite(ada, "code")
    clock(minutes=9)  # asked a minute before the code's 10 minutes end
    asked = bob.post("/api/owner/invites/redeem/start", json=_key(made)).json()
    clock(minutes=1, seconds=1)  # approved after, while the challenge (5 minutes) lives
    resp = _approve(bob, asked, "/api/owner/invites/redeem")
    assert resp.status_code == 410 and resp.json()["error"] == "invite_ended"
    assert _rows(ada, "SELECT count(*) AS n FROM invite_redemptions")[0]["n"] == 0


def test_the_redeem_approval_works_once(ada, bob):
    made = _invite(ada, "code")
    asked = bob.post("/api/owner/invites/redeem/start", json=_key(made)).json()
    assert _approve(bob, asked, "/api/owner/invites/redeem").status_code == 200
    assert _approve(bob, asked, "/api/owner/invites/redeem").status_code == 400


def test_a_redeem_approval_from_another_origin_is_refused(ada, bob):
    made = _invite(ada, "code")
    asked = bob.post("/api/owner/invites/redeem/start", json=_key(made)).json()
    resp = _approve(bob, asked, "/api/owner/invites/redeem", origin="https://evil.example")
    assert resp.status_code == 400


def test_a_redeem_approval_cannot_approve_a_link(ada, bob):
    made = _invite(ada, "code")
    asked = bob.post("/api/owner/invites/redeem/start", json=_key(made)).json()
    assert _approve(bob, asked, "/api/owner/link-sets/approve").status_code == 400


def test_the_approval_names_the_passkey_this_browser_uses(ada, bob):
    laptop = _second_passkey(bob, "Bob laptop")
    made = _invite(ada, "code")
    asked = bob.post("/api/owner/invites/redeem/start",
                     json={**_key(made), "credentialId": laptop.id}).json()
    assert asked["allowCredentials"] == [laptop.id]
    assert parse_body(asked["items"][1]["body"])["issuer"] == _did(bob, laptop)
    assert _approve(bob, asked, "/api/owner/invites/redeem", laptop).status_code == 200


def test_without_one_the_newest_passkey_is_asked(ada, bob):
    laptop = _second_passkey(bob, "Bob laptop")
    made = _invite(ada, "code")
    asked = bob.post("/api/owner/invites/redeem/start", json=_key(made)).json()
    assert asked["allowCredentials"] == [laptop.id]
    resp = _approve(bob, asked, "/api/owner/invites/redeem", bob.phone)
    assert resp.status_code == 400


# ---------------------------------------------------------------- confirming


def test_the_inviter_confirms_with_the_invitees_checked_email(ada, bob):
    made = _invite(ada, "code")
    _redeem(bob, made)
    asked = ada.post(f"/api/owner/invites/{made['id']}/confirm/start").json()
    [grant] = [parse_body(x["body"]) for x in asked["items"]]
    assert grant["credentialSubject"] == {"kind": "owner", "owner": {
        "relay": "test.local", "ownerId": bob.owner_id, "keysHash": bob.keys_hash}}
    assert grant["issuerOwner"]["ownerId"] == ada.owner_id
    assert asked["screen"] == confirm_screen(grant, BOB)
    resp = _approve(ada, asked, f"/api/owner/invites/{made['id']}/confirm")
    assert resp.status_code == 200, resp.text
    assert resp.json()["state"] == "connected"


def test_confirming_tells_the_invitee(ada, bob, notices):
    _connected(ada, bob)
    assert notices[-1][1] == "contact_confirmed"


def test_only_a_redeemed_invite_can_be_confirmed(ada):
    made = _invite(ada, "code")
    resp = ada.post(f"/api/owner/invites/{made['id']}/confirm/start")
    assert resp.status_code == 409 and resp.json()["error"] == "not_waiting"


def test_only_the_inviter_confirms(ada, bob):
    made = _invite(ada, "code")
    _redeem(bob, made)
    assert bob.post(f"/api/owner/invites/{made['id']}/confirm/start").status_code == 404


def test_declining_a_redeemed_invite_withdraws_the_invitees_grant(ada, bob):
    made = _invite(ada, "code")
    _redeem(bob, made)
    resp = ada.post(f"/api/owner/invites/{made['id']}/cancel")
    assert resp.status_code == 200 and resp.json()["state"] == "cancelled"
    [grant] = _rows(ada, "SELECT revoked_at FROM owner_grants")
    assert grant["revoked_at"] is not None
    assert _contacts(bob) == []


def test_a_connected_invite_cannot_be_cancelled(ada, bob):
    made = _connected(ada, bob)
    resp = ada.post(f"/api/owner/invites/{made['id']}/cancel")
    assert resp.status_code == 409 and resp.json()["error"] == "not_cancellable"


# ---------------------------------------------------------------- pre-approved by email


def test_an_email_invite_signs_the_invite_and_the_grant_at_once(ada):
    asked = ada.post("/api/owner/invites/email/start", json={"email": " Bob@Example.com "}).json()
    [invite, grant] = [parse_body(x["body"]) for x in asked["items"]]
    assert invite["mode"] == "preapproved"
    assert invite["emailHash"] == email_hash(invite["nonce"], BOB)
    assert grant["credentialSubject"] == {"kind": "invitee", "invite": object_hash(invite)}
    assert grant["via"] == "intro_email"
    assert asked["screen"] == invite_screen(grant, BOB)
    resp = _approve(ada, asked, "/api/owner/invites/email")
    assert resp.status_code == 200, resp.text
    made = resp.json()
    assert made["how"] == "email" and made["email"] == BOB and "link" not in made


def test_the_email_goes_out_after_ten_minutes(ada, relay, app, emails, clock):
    made = _email_invite(ada)
    _send_due(relay, app)
    assert emails == []
    clock(minutes=10, seconds=1)
    _send_due(relay, app)
    [(to, link, inviter)] = emails
    assert to == BOB and inviter == EMAIL.lower()
    [row] = _rows(ada, "SELECT link_id, sent_at FROM owner_invites")
    assert link.startswith(f"{OWNER_ORIGIN}/i/{row['link_id']}#") and row["sent_at"]
    _send_due(relay, app)
    assert len(emails) == 1
    assert made["sendAt"]


def test_undoing_within_ten_minutes_sends_nothing(ada, relay, app, emails, clock):
    made = _email_invite(ada)
    ada.post(f"/api/owner/invites/{made['id']}/cancel")
    clock(minutes=11)
    _send_due(relay, app)
    assert emails == []


def test_the_invitee_redeems_and_is_connected_at_once(ada, bob, relay, app, emails, clock):
    _email_invite(ada)
    clock(minutes=11)
    _send_due(relay, app)
    [(_, link, _)] = emails
    path, secret = link.split("#")
    made = {"link": link}
    resp = _redeem(bob, made)
    assert resp.status_code == 200, resp.text
    [listed] = _invites(ada)
    assert listed["state"] == "connected"
    [contact] = _contacts(ada)
    assert contact["email"] == BOB and contact["youAllow"] and contact["theyAllow"]


def test_an_email_invite_is_only_for_that_email(ada, cat, relay, app, emails, clock):
    _email_invite(ada, BOB)
    clock(minutes=11)
    _send_due(relay, app)
    [(_, link, _)] = emails
    resp = cat.post("/api/owner/invites/find", json=_key({"link": link}))
    assert resp.status_code == 403 and resp.json()["error"] == "not_for_you"


def test_an_email_invite_cannot_go_to_your_own_email(ada):
    resp = ada.post("/api/owner/invites/email/start", json={"email": EMAIL})
    assert resp.status_code == 409 and resp.json()["error"] == "own_invite"


@pytest.mark.parametrize("email", ["", "not-an-email", "a@b"])
def test_an_email_invite_needs_an_email(ada, email):
    assert ada.post("/api/owner/invites/email/start", json={"email": email}).status_code == 422


def test_email_invites_count_toward_the_caps(ada):
    for _ in range(10):
        _invite(ada, "link")
    resp = ada.post("/api/owner/invites/email/start", json={"email": BOB})
    assert resp.status_code == 429


# ---------------------------------------------------------------- contacts


def test_once_both_approve_each_sees_the_other(ada, bob):
    _connected(ada, bob)
    [mine] = _contacts(ada)
    [theirs] = _contacts(bob)
    assert mine["ownerId"] == bob.owner_id and mine["email"] == BOB
    assert theirs["ownerId"] == ada.owner_id and theirs["email"] == EMAIL.lower()
    for c in (mine, theirs):
        assert c["youAllow"] and c["theyAllow"] and c["via"] == "intro_code"
        assert c["until"] and c["since"]


def test_before_confirming_only_the_invitee_allows(ada, bob):
    made = _invite(ada, "code")
    _redeem(bob, made)
    [mine] = _contacts(ada)
    assert mine["theyAllow"] and not mine["youAllow"]


def test_a_contact_lists_their_shared_agents(ada, bob, relay):
    from tests.relay.test_owner_links import _linked

    _connected(ada, bob)
    agent, _, _ = _linked(relay, bob, "bobbot")
    [mine] = _contacts(ada)
    assert [a["address"] for a in mine["agents"]] == [agent["address"]]
    assert mine["agents"][0]["words"]


def test_removing_someone_revokes_your_grant(ada, bob):
    _connected(ada, bob)
    resp = ada.post(f"/api/owner/contacts/{bob.owner_id}/remove")
    assert resp.status_code == 200, resp.text
    [mine] = _contacts(ada)
    assert not mine["youAllow"] and mine["theyAllow"]
    [theirs] = _contacts(bob)
    assert theirs["youAllow"] and not theirs["theyAllow"]


def test_removing_needs_no_passkey_and_only_narrows(ada, bob):
    _connected(ada, bob)
    ada.post(f"/api/owner/contacts/{bob.owner_id}/remove")
    rows = _rows(ada, "SELECT owner_pk, revoked_at FROM owner_grants ORDER BY id")
    assert [r["revoked_at"] is not None for r in rows] == [False, True]


def test_removing_someone_you_have_not_connected_with(ada, bob):
    resp = ada.post(f"/api/owner/contacts/{bob.owner_id}/remove")
    assert resp.status_code == 404 and resp.json()["error"] == "no_contact"


# ---------------------------------------------------------------- revocations


def test_revocations_are_listed_in_order(ada, bob, relay):
    _connected(ada, bob)
    other = _invite(ada, "code")
    ada.post(f"/api/owner/contacts/{bob.owner_id}/remove")
    ada.post(f"/api/owner/invites/{other['id']}/cancel")
    resp = relay.get("/api/v1/owner/revocations")
    assert resp.status_code == 200, resp.text
    got = resp.json()
    assert [e["t"] for e in got["entries"]] == ["UamContactGrant", "UamInvite"]
    assert set(got["entries"][0]) == {"t", "h", "at"}
    [grant] = _rows(ada, "SELECT hash FROM owner_grants WHERE revoked_at IS NOT NULL")
    assert got["entries"][0]["h"] == grant["hash"]
    later = relay.get(f"/api/v1/owner/revocations?since={got['through'] - 1}").json()
    assert [e["t"] for e in later["entries"]] == ["UamInvite"]
    assert relay.get(f"/api/v1/owner/revocations?since={got['through']}").json()["entries"] == []


def test_the_revocation_list_is_signed_when_the_relay_has_a_key(ada, relay, app):
    from nacl.signing import SigningKey

    from uam.protocol.contacts import revocations_message
    from uam.protocol.crypto import verify_signature

    key = SigningKey.generate()
    app.state.relay_signing_key = key
    made = _invite(ada, "code")
    ada.post(f"/api/owner/invites/{made['id']}/cancel")
    got = relay.get("/api/v1/owner/revocations").json()
    verify_signature(revocations_message(got), got["signature"], key.verify_key)


# ---------------------------------------------------------------- helpers


def _time(text):
    from datetime import datetime, timezone

    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _second_passkey(client, label):
    from tests._passkey import SoftPasskey
    from tests.relay.test_owner_passkeys import _sign

    laptop = SoftPasskey()
    approval = _register(client, laptop, label)
    resp = _sign(client, client.phone, approval)
    assert resp.status_code == 200, resp.text
    client.keys_hash = resp.json()["hash"]
    return laptop


def _did(client, passkey):
    [row] = _rows(client, "SELECT did FROM owner_passkeys WHERE credential_id = :c", c=passkey.id)
    return row["did"]


def _send_due(relay, app):
    import uam.db.session as sess
    from uam.relay.owners import contacts

    async def run():
        async with sess._session_factory() as s:
            await contacts.send_due(s, app)

    relay.portal.call(run)
