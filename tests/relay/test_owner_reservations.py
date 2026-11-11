"""Reservations become setup codes (P2s-2, DEC-005, spec P2 §4.2).

Once owners are on, a name is reserved with an email. The email gets a
confirmation link (token in the URL fragment, as for an agent's request).
Opening it makes the account if there is none, with a session that can
only set up that name. The account makes a setup code for the name, and
only an agent registering that name with that code gets it. Names
reserved without an email (made before owners were on) still block the
name until they expire. The relay admin can give an account a name from
the reserved list.
"""

from __future__ import annotations

import datetime as dt

import pytest

from tests.relay._owner_fixtures import (  # noqa: F401  (fixtures are used by name)
    ADMIN_KEY,
    EMAIL,
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
from tests.relay.test_owner_links import _agent_signs, _redeem
from tests.relay.test_owner_passkeys import _first_passkey
from uam.protocol import generate_keypair, serialize_verify_key
from uam.protocol.didkey import ED25519, encode_did_key

NEW = "nina@example.org"
SENT = "If that address can take it, a confirmation is on its way."
_PAST = dt.datetime(2000, 1, 1, tzinfo=dt.timezone.utc)
_NOW = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)
_FUTURE = dt.datetime(2999, 1, 1, tzinfo=dt.timezone.utc)


@pytest.fixture()
def sent(app):
    """The reservation emails the relay sent: (email, message)."""
    out = []
    app.state.owner_reservation_sink = lambda email, message: out.append((email, message))
    return out


@pytest.fixture()
def ada(relay, owner, codes):
    """An owner with a passkey, signed in on *owner* (email EMAIL)."""
    _sign_in(relay, owner, codes)
    phone, signed = _first_passkey(owner)
    owner.phone = phone
    owner.owner_id = signed["owner_id"]
    return owner


def _reserve(relay, name="bob", email=NEW):
    body = {"name": name} if email is None else {"name": name, "email": email}
    return relay.post("/api/v1/reserve", json=body)


def _reserved(relay, name="bob", email=NEW):
    resp = _reserve(relay, name, email)
    assert resp.status_code == 201, resp.text
    return resp.json()


def _token(message):
    url = message["url"]
    assert url.startswith(f"{OWNER_ORIGIN}/#reserve=")
    return url.split("#reserve=", 1)[1]


def _open(client, token):
    return client.post("/api/owner/reservations/open", json={"token": token})


def _opened(client, token):
    resp = _open(client, token)
    assert resp.status_code == 200, resp.text
    return resp.json()["reservation"]


def _held(client):
    resp = client.get("/api/owner/reservations")
    assert resp.status_code == 200, resp.text
    return resp.json()["reservations"]


def _named_code(client, reservation_id):
    resp = client.post(f"/api/owner/reservations/{reservation_id}/code")
    assert resp.status_code == 200, resp.text
    return resp.json()


def _register(relay, name="bob", setup_code=None):
    sk, vk = generate_keypair()
    body = {"agent_name": name, "public_key": serialize_verify_key(vk)}
    if setup_code is not None:
        body["setup_code"] = setup_code
    resp = relay.post("/api/v1/register", json=body)
    agent = None
    if resp.status_code == 200:
        data = resp.json()
        agent = {
            "address": data["address"], "token": data["token"], "signing_key": sk,
            "key": encode_did_key(ED25519, bytes(vk)),
            "headers": {"Authorization": f"Bearer {data['token']}"},
        }
    return resp, agent


def _visitor(app, relay):
    return _on_owner_host(app, relay)


def _grant(relay, owner_id, name, days=None):
    body = {"name": name} if days is None else {"name": name, "days": days}
    return relay.post(f"/api/v1/admin/owners/{owner_id}/names", json=body,
                      headers={"X-Admin-Key": ADMIN_KEY})


# ---------------------------------------------------------------- reserving


def test_reserving_needs_an_email_once_owners_are_on(relay, sent):
    resp = _reserve(relay, email=None)
    assert resp.status_code == 422
    assert "email" in resp.json()["detail"]
    assert sent == []


def test_a_reservation_with_an_email_sends_a_confirmation(relay, sent):
    reply = _reserved(relay)
    assert reply == {
        "address": "bob::test.local", "expires_at": reply["expires_at"], "detail": SENT,
        "claim_token": None, "vcf_url": None,
    }
    [(email, message)] = sent
    assert email == NEW
    assert message["name"] == "bob"
    assert message["address"] == "bob::test.local"
    assert message["hasAccount"] is False
    token = _token(message)
    assert message["neverUrl"] == f"{OWNER_ORIGIN}/#never={token}"


def test_the_token_is_stored_only_as_a_hash(relay, sent):
    _reserved(relay)
    token = _token(sent[0][1])
    [row] = _rows(relay, "SELECT token_hash, email_enc, claim_token FROM reservations")
    assert token not in str(row)
    assert NEW not in str(row)


def test_an_existing_account_hears_it_has_an_account(relay, ada, sent):
    _reserved(relay, email=EMAIL)
    assert sent[0][1]["hasAccount"] is True


def test_the_email_must_be_an_address(relay, sent):
    assert _reserve(relay, email="not-an-email").status_code == 422


def test_a_reserved_name_is_not_available(relay, sent):
    _reserved(relay)
    assert relay.get("/api/v1/reserve/check/bob").json()["available"] is False
    assert _reserve(relay, email="other@example.org").status_code == 409


def test_one_email_an_hour_to_an_address(relay, sent, clock):
    _reserved(relay, "bob")
    _reserved(relay, "carl")
    assert len(sent) == 1
    clock(hours=1, minutes=1)
    _reserved(relay, "dina")
    assert len(sent) == 2


def test_never_email_me_stops_reservation_emails(relay, app, sent, clock):
    _reserved(relay)
    visitor = _visitor(app, relay)
    resp = visitor.post("/api/owner/requests/never", json={"token": _token(sent[0][1])})
    assert resp.status_code == 200, resp.text
    clock(hours=2)
    _reserved(relay, "carl")
    assert len(sent) == 1


def test_without_owners_reserving_is_unchanged(client):
    resp = client.post("/api/v1/reserve", json={"name": "bob"})
    assert resp.status_code == 201
    assert resp.json()["claim_token"]
    assert resp.json()["vcf_url"]


# ---------------------------------------------------------------- the link


def test_opening_the_link_makes_the_account_with_a_session_for_the_name(relay, app, sent):
    _reserved(relay)
    visitor = _visitor(app, relay)
    shown = _opened(visitor, _token(sent[0][1]))
    assert shown["name"] == "bob"
    assert shown["address"] == "bob::test.local"
    me = visitor.get("/api/owner/me").json()
    assert me["email"] == NEW
    assert me["reservation"] == shown["id"]
    assert me["owner_id"] is None
    # The session can't see the rest of the account, or make other codes.
    assert visitor.get("/api/owner/links").status_code == 401
    assert visitor.post("/api/owner/codes", json={"kind": "setup"}).status_code == 401
    assert [r["name"] for r in _held(visitor)] == ["bob"]


def test_an_unknown_token_opens_nothing(relay, app, sent):
    assert _open(_visitor(app, relay), "x" * 43).status_code == 404


def test_a_reservation_session_adds_the_first_passkey_then_makes_a_code(relay, app, sent):
    _reserved(relay)
    visitor = _visitor(app, relay)
    shown = _opened(visitor, _token(sent[0][1]))
    assert visitor.post(f"/api/owner/reservations/{shown['id']}/code").status_code == 409
    _first_passkey(visitor)
    made = _named_code(visitor, shown["id"])
    assert made["name"] == "bob"
    assert made["kind"] == "setup"


def test_a_reservation_session_makes_codes_only_for_its_name(relay, ada, app, sent):
    _reserved(relay, "bob", EMAIL)
    _reserved(relay, "carl", EMAIL)
    bob, carl = sorted(_held(ada), key=lambda r: r["name"])
    visitor = _visitor(app, relay)
    _opened(visitor, _token(sent[0][1]))
    assert visitor.post(f"/api/owner/reservations/{carl['id']}/code").status_code == 403
    assert _named_code(visitor, bob["id"])["name"] == "bob"


def test_an_account_sees_names_reserved_for_its_email(relay, ada, sent, clock):
    _reserved(relay, "bob", EMAIL)
    clock(hours=2)
    _reserved(relay, "carl", "someone@example.org")
    assert [r["name"] for r in _held(ada)] == ["bob"]


def test_another_account_cannot_make_a_code_for_the_name(relay, ada, app, codes, sent):
    _reserved(relay, "bob", NEW)
    [row] = _rows(relay, "SELECT id FROM reservations")
    assert ada.post(f"/api/owner/reservations/{row['id']}/code").status_code == 404


def test_an_expired_reservation_is_gone(relay, ada, sent):
    _reserved(relay, "bob", EMAIL)
    [held] = _held(ada)
    _exec(relay, "UPDATE reservations SET expires_at = :at", at=_PAST)
    assert _held(ada) == []
    assert ada.post(f"/api/owner/reservations/{held['id']}/code").status_code == 404


# ---------------------------------------------------------------- registering


def test_a_held_name_needs_its_setup_code(relay, ada, sent):
    _reserved(relay, "bob", EMAIL)
    [held] = _held(ada)
    resp, _ = _register(relay, "bob")
    assert resp.status_code == 403
    assert "reserved" in resp.json()["detail"]
    plain = ada.post("/api/owner/codes", json={"kind": "setup"}).json()["code"]
    assert _register(relay, "bob", plain)[0].status_code == 403
    code = _named_code(ada, held["id"])["code"]
    resp, bob = _register(relay, "bob", code)
    assert resp.status_code == 200, resp.text
    [row] = _rows(relay, "SELECT status FROM reservations")
    assert row["status"] == "claimed"
    started = _redeem(relay, bob, code)
    assert started.status_code == 200, started.text
    assert _agent_signs(relay, bob, started.json()).status_code == 200


def test_a_named_code_links_only_its_name(relay, ada, sent):
    _reserved(relay, "bob", EMAIL)
    [held] = _held(ada)
    code = _named_code(ada, held["id"])["code"]
    resp, carl = _register(relay, "carl", code)  # carl isn't held: the code is ignored
    assert resp.status_code == 200
    refused = _redeem(relay, carl, code)
    assert refused.status_code == 400
    assert refused.json()["error"] == "bad_code"


def test_a_wrong_code_for_a_held_name_is_refused(relay, ada, sent):
    _reserved(relay, "bob", EMAIL)
    assert _register(relay, "bob", "ABCD-EFGH")[0].status_code == 403


def test_a_name_reserved_without_an_email_blocks_registering(relay, sent, clock):
    _exec(relay, "INSERT INTO reservations (address, claim_token, status, expires_at, created_at,"
          " emailed) VALUES ('bob::test.local', 'tok', 'reserved', :at, :now, false)",
          at=_FUTURE, now=_NOW)
    assert _register(relay, "bob")[0].status_code == 403


def test_an_expired_hold_does_not_block(relay, sent, clock):
    _reserved(relay, "bob", NEW)
    _exec(relay, "UPDATE reservations SET expires_at = :at", at=_PAST)
    assert _register(relay, "bob")[0].status_code == 200


def test_a_held_reservation_cannot_be_claimed_with_its_token(relay, sent):
    _reserved(relay, "bob", NEW)
    [row] = _rows(relay, "SELECT claim_token FROM reservations")
    _, vk = generate_keypair()
    resp = relay.post("/api/v1/reserve/claim", json={
        "claim_token": row["claim_token"], "public_key": serialize_verify_key(vk),
    })
    assert resp.status_code == 404
    assert relay.get(f"/api/v1/reserve/{row['claim_token']}/vcf").status_code == 404


# ---------------------------------------------------------------- the admin


def test_the_admin_gives_an_account_a_reserved_name(relay, ada, sent):
    assert _register(relay, "support")[0].status_code == 403  # on the reserved list
    resp = _grant(relay, ada.owner_id, "support")
    assert resp.status_code == 201, resp.text
    assert resp.json()["address"] == "support::test.local"
    [held] = _held(ada)
    assert held["name"] == "support"
    assert _register(relay, "support")[0].status_code == 403
    code = _named_code(ada, held["id"])["code"]
    resp, _ = _register(relay, "support", code)
    assert resp.status_code == 200, resp.text


def test_the_admin_cannot_give_a_taken_name(relay, ada, sent):
    assert _register(relay, "bob")[0].status_code == 200
    assert _grant(relay, ada.owner_id, "bob").status_code == 409


def test_the_admin_names_an_owner_that_exists(relay, sent):
    assert _grant(relay, "A" * 22, "support").status_code == 404


def test_a_given_name_lasts_the_days_asked(relay, ada, sent):
    from datetime import datetime, timedelta, timezone

    given = _grant(relay, ada.owner_id, "support", days=3).json()
    expires = datetime.strptime(given["expiresAt"], "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc)
    left = expires - datetime.now(timezone.utc)
    assert timedelta(days=3) - timedelta(minutes=1) < left <= timedelta(days=3)
    assert [r["expiresAt"] for r in _held(ada)] == [given["expiresAt"]]


def test_the_admin_gives_between_one_and_365_days(relay, ada, sent):
    assert _grant(relay, ada.owner_id, "support", days=0).status_code == 422
    assert _grant(relay, ada.owner_id, "support", days=366).status_code == 422


# ---------------------------------------------------------------- sessions


def test_a_reservation_session_cannot_approve_links(relay, ada, app, sent):
    _reserved(relay, "bob", EMAIL)
    visitor = _visitor(app, relay)
    _opened(visitor, _token(sent[0][1]))
    for path in ("/api/owner/link-sets/approve/start", "/api/owner/link-sets/approve"):
        assert visitor.post(path, json={"ids": [1]}).status_code in (401, 422)
    assert visitor.post("/api/owner/link-sets/approve/start", json={"ids": [1]}).status_code == 401
    assert visitor.get("/api/owner/requests").status_code == 401


def test_a_request_session_cannot_see_reservations(relay, app, sent):
    from tests.relay.test_owner_links import _agent
    from tests.relay.test_owner_requests import _token as request_token

    asked = []
    app.state.owner_request_sink = lambda email, message: asked.append(message)
    bob = _agent(relay)
    assert relay.post("/api/v1/owner/link/request", json={"email": NEW},
                      headers=bob["headers"]).status_code == 202
    visitor = _visitor(app, relay)
    assert visitor.post("/api/owner/requests/open",
                        json={"token": request_token(asked[0])}).status_code == 200
    assert visitor.get("/api/owner/reservations").status_code == 401


def test_opening_while_signed_in_keeps_the_session(relay, ada, sent):
    _reserved(relay, "bob", EMAIL)
    _opened(ada, _token(sent[0][1]))
    assert ada.get("/api/owner/me").json()["reservation"] is None
    assert ada.get("/api/owner/links").status_code == 200


def test_an_expired_reservation_link_has_ended(relay, app, sent):
    _reserved(relay)
    _exec(relay, "UPDATE reservations SET expires_at = :at", at=_PAST)
    resp = _open(_visitor(app, relay), _token(sent[0][1]))
    assert resp.status_code == 410


def test_unfinished_accounts_from_a_reservation_go_after_a_day(relay, app, sent, clock):
    _reserved(relay)
    _opened(_visitor(app, relay), _token(sent[0][1]))
    assert len(_rows(relay, "SELECT id FROM owners")) == 1
    clock(hours=25)
    _reserved(relay, "carl", "other@example.org")
    _opened(_visitor(app, relay), _token(sent[1][1]))
    assert len(_rows(relay, "SELECT id FROM owners")) == 1
    [bob] = _rows(relay, "SELECT owner_pk FROM reservations WHERE address = 'bob::test.local'")
    assert bob["owner_pk"] is None


def test_without_owners_a_reservation_still_holds_its_name(client):
    assert client.post("/api/v1/reserve", json={"name": "bob"}).status_code == 201
    _, vk = generate_keypair()
    resp = client.post("/api/v1/register", json={
        "agent_name": "bob", "public_key": serialize_verify_key(vk),
    })
    assert resp.status_code == 403
    assert "reserved" in resp.json()["detail"]
