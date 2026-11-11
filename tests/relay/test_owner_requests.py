"""Agents ask for an owner by email (P2s-3, DEC-009, spec P2 §4.3).

An agent sends ``POST /api/v1/owner/link/request {email}``. The email gets
a link whose token sits in the URL fragment. Opening it on the owner page
makes the account if there is none, with a session that can only finish
this request. The owner accepts, the agent signs the link the relay
built (its SDK does it without asking: asking was its consent), and the
owner approves with a passkey. Limits keep emails few. Over a limit the
request is still recorded, but no email goes out and the agent's answer
doesn't change.
"""

from __future__ import annotations

import pytest

from tests._passkey import SoftPasskey
from tests.relay._owner_fixtures import (  # noqa: F401  (fixtures are used by name)
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
from tests.relay.test_owner_links import _agent, _linked, _status, _unlink
from tests.relay.test_owner_passkeys import RP_ID, _first_passkey, _register, _sign
from uam.protocol.links import links_screen, sign_as_agent, words_for
from uam.protocol.signed import parse_body

NEW = "nina@example.org"
REPLY = "If that address can take requests, a confirmation is on its way."


@pytest.fixture()
def sent(app):
    """The request emails the relay sent: (email, message)."""
    out = []
    app.state.owner_request_sink = lambda email, message: out.append((email, message))
    return out


@pytest.fixture()
def ada(relay, owner, codes):
    """An owner with a passkey, signed in on *owner*."""
    _sign_in(relay, owner, codes)
    phone, signed = _first_passkey(owner)
    owner.phone = phone
    owner.owner_id = signed["owner_id"]
    return owner


def _ask(relay, agent, email=NEW):
    return relay.post("/api/v1/owner/link/request", json={"email": email},
                      headers=agent["headers"])


def _asked(relay, agent, email=NEW):
    resp = _ask(relay, agent, email)
    assert resp.status_code == 202, resp.text
    return resp.json()


def _token(message):
    url = message["url"]
    assert url.startswith(f"{OWNER_ORIGIN}/#request=")
    return url.split("#request=", 1)[1]


def _visitor(app, relay):
    """A fresh browser on the owner origin (no cookie yet)."""
    return _on_owner_host(app, relay)


def _open(client, token):
    return client.post("/api/owner/requests/open", json={"token": token})


def _opened(client, token):
    resp = _open(client, token)
    assert resp.status_code == 200, resp.text
    return resp.json()["request"]


def _accept(client, request_id):
    resp = client.post(f"/api/owner/requests/{request_id}/accept")
    assert resp.status_code == 200, resp.text
    return resp.json()


def _requests(client):
    resp = client.get("/api/owner/requests")
    assert resp.status_code == 200, resp.text
    return resp.json()["requests"]


def _sign_offer(relay, agent):
    """What the SDK does: read the offer for its own request and sign it."""
    offer = _status(relay, agent)["offer"]
    body = parse_body(offer["body"])
    return relay.post("/api/v1/owner/link/sign", json={
        "hash": offer["hash"], "signature": sign_as_agent(body, agent["signing_key"]),
    }, headers=agent["headers"])


def _approve(client, passkey, link_id):
    start = client.post("/api/owner/link-sets/approve/start", json={"ids": [link_id]})
    assert start.status_code == 200, start.text
    got = passkey.get(start.json()["challenge"], rp_id=RP_ID, origin=OWNER_ORIGIN)
    return start.json(), client.post("/api/owner/link-sets/approve", json=got)


# ---------------------------------------------------------------- the agent asks


def test_an_agent_asks_and_an_email_goes_out(relay, sent):
    bob = _agent(relay)
    reply = _asked(relay, bob)
    assert reply == {
        "detail": REPLY, "words": words_for(bob["key"]), "via": "setup",
        "expiresAt": reply["expiresAt"],
    }
    [(email, message)] = sent
    assert email == NEW
    assert message["agent"] == bob["address"]
    assert message["words"] == words_for(bob["key"])
    assert message["hasAccount"] is False
    assert message["expiresAt"] == reply["expiresAt"]
    token = _token(message)
    assert message["neverUrl"] == f"{OWNER_ORIGIN}/#never={token}"


def test_the_email_link_carries_the_token_only_in_its_fragment(relay, sent):
    _asked(relay, _agent(relay))
    token = _token(sent[0][1])
    [row] = _rows(relay, "SELECT * FROM owner_requests")
    assert token not in " ".join(str(v) for v in row.values())
    assert NEW not in " ".join(str(v) for v in row.values())
    assert "?" not in sent[0][1]["url"]


def test_the_answer_is_the_same_with_and_without_an_account(relay, ada, sent):
    bob = _agent(relay)
    with_account = _asked(relay, bob, EMAIL)
    without = _asked(relay, bob, NEW)
    with_account.pop("expiresAt"), without.pop("expiresAt")
    assert with_account == without
    assert [m["hasAccount"] for _, m in sent] == [True, False]


def test_an_existing_account_hears_join_not_owner(relay, ada, sent):
    _asked(relay, _agent(relay), EMAIL)
    assert sent[0][1]["hasAccount"] is True


def test_an_account_without_a_passkey_hears_owner(relay, owner, codes, sent):
    _sign_in(relay, owner, codes)
    _asked(relay, _agent(relay), EMAIL)
    assert sent[0][1]["hasAccount"] is False


@pytest.mark.parametrize("email", ["", "not-an-email", "a@b", "x" * 400 + "@example.com"])
def test_the_email_must_be_an_address(relay, sent, email):
    assert _ask(relay, _agent(relay), email).status_code == 422
    assert sent == []


def test_asking_needs_the_agents_token(relay):
    resp = relay.post("/api/v1/owner/link/request", json={"email": NEW})
    assert resp.status_code == 401


def test_a_new_agent_asks_to_be_set_up(relay, sent):
    assert _asked(relay, _agent(relay))["via"] == "setup"


def test_an_agent_older_than_an_hour_asks_to_be_linked(relay, sent, clock):
    bob = _agent(relay)
    clock(hours=1, minutes=1)
    assert _asked(relay, bob)["via"] == "link"


def test_an_agent_that_had_an_owner_asks_to_be_linked(relay, ada, sent):
    bob, _, link = _linked(relay, ada)
    _, resp = _unlink(ada, link["id"])
    assert resp.status_code == 200, resp.text
    assert _asked(relay, bob)["via"] == "link"


def test_an_agent_with_an_owner_cannot_ask_for_another(relay, ada, sent):
    bob, _, _ = _linked(relay, ada)
    resp = _ask(relay, bob)
    assert resp.status_code == 409
    assert resp.json()["error"] == "has_owner"
    assert sent == []


def test_a_new_request_replaces_the_old_one(relay, app, sent):
    bob = _agent(relay)
    _asked(relay, bob, NEW)
    _asked(relay, bob, "other@example.org")
    first, second = _token(sent[0][1]), _token(sent[1][1])
    visitor = _visitor(app, relay)
    resp = _open(visitor, first)
    assert resp.status_code == 410
    assert resp.json()["error"] == "ended"
    assert _opened(_visitor(app, relay), second)["agent"] == bob["address"]


# ---------------------------------------------------------------- limits


def test_an_agent_asks_three_times_a_day(relay, sent, clock):
    bob = _agent(relay)
    for i in range(3):
        _asked(relay, bob, f"p{i}@example.org")
    resp = _ask(relay, bob, "p3@example.org")
    assert resp.status_code == 429
    assert resp.json()["error"] == "too_many"
    clock(hours=24, minutes=1)
    _asked(relay, bob, "p4@example.org")


def test_one_address_asks_ten_times_an_hour(relay, sent, monkeypatch):
    from uam.relay.routes import owner_links

    monkeypatch.setattr(owner_links, "REQUESTS_PER_IP_HOUR", 2)
    agents = [_agent(relay, f"bot{i}") for i in range(3)]
    for i, agent in enumerate(agents[:2]):
        _asked(relay, agent, f"p{i}@example.org")
    resp = _ask(relay, agents[2], "p2@example.org")
    assert resp.status_code == 429
    assert resp.json()["error"] == "too_many"


def _emails(relay):
    return _rows(relay, "SELECT emailed FROM owner_requests ORDER BY id")


def test_one_email_an_hour_to_an_address(relay, sent, clock):
    _asked(relay, _agent(relay, "a1"))
    reply = _asked(relay, _agent(relay, "a2"))
    assert reply["detail"] == REPLY
    assert len(sent) == 1
    assert [r["emailed"] for r in _emails(relay)] == [True, False]
    clock(hours=1, minutes=1)
    _asked(relay, _agent(relay, "a3"))
    assert len(sent) == 2


def test_three_emails_a_day_to_an_address(relay, sent, clock):
    for i in range(4):
        _asked(relay, _agent(relay, f"a{i}"))
        clock(hours=1, minutes=1)
    assert len(sent) == 3
    assert len(_emails(relay)) == 4


def test_the_relay_sends_at_most_its_daily_cap(relay, app, sent):
    app.state.settings.owner_request_emails_per_day = 2
    for i in range(3):
        _asked(relay, _agent(relay, f"a{i}"), f"p{i}@example.org")
    assert len(sent) == 2
    assert len(_emails(relay)) == 3


def test_never_email_me_about_agents(relay, app, sent, clock):
    _asked(relay, _agent(relay, "a1"))
    token = _token(sent[0][1])
    visitor = _visitor(app, relay)
    resp = visitor.post("/api/owner/requests/never", json={"token": token})
    assert resp.status_code == 200, resp.text
    [row] = _rows(relay, "SELECT state FROM owner_requests")
    assert row["state"] == "declined"
    clock(hours=2)  # past the hourly limit, so only the opt-out stops it
    reply = _asked(relay, _agent(relay, "a2"))
    assert reply["detail"] == REPLY
    assert len(sent) == 1
    assert len(_emails(relay)) == 2


def test_never_email_me_needs_the_owner_origin(relay, app, sent):
    _asked(relay, _agent(relay))
    elsewhere = _on_owner_host(app, relay, origin="https://evil.example")
    resp = elsewhere.post("/api/owner/requests/never", json={"token": _token(sent[0][1])})
    assert resp.status_code == 403


def test_an_account_sees_requests_that_were_not_emailed(relay, ada, sent):
    _asked(relay, _agent(relay, "a1"), EMAIL)
    _asked(relay, _agent(relay, "a2"), EMAIL)  # over the hourly limit: not emailed
    assert len(sent) == 1
    assert sorted(r["agent"].split("::")[0] for r in _requests(ada)) == ["a1", "a2"]


# ---------------------------------------------------------------- opening the link


def test_opening_the_link_makes_the_account_once(relay, app, sent):
    _asked(relay, _agent(relay))
    token = _token(sent[0][1])
    shown = _opened(_visitor(app, relay), token)
    _opened(_visitor(app, relay), token)
    [owner_row] = _rows(relay, "SELECT id, created_via, owner_id FROM owners")
    assert owner_row["created_via"] == "request"
    assert owner_row["owner_id"] is None
    [email] = _rows(relay, "SELECT verified_at FROM owner_emails")
    assert email["verified_at"] is not None
    assert shown["words"] == sent[0][1]["words"]
    assert shown["state"] == "open"


def test_an_unknown_token_opens_nothing(relay, app, sent):
    resp = _open(_visitor(app, relay), "A" * 43)
    assert resp.status_code == 404
    assert _rows(relay, "SELECT id FROM owners") == []


def test_loading_the_page_does_nothing(relay, owner, sent):
    _asked(relay, _agent(relay))
    token = _token(sent[0][1])
    assert owner.get("/").status_code == 200
    assert owner.get(f"/?request={token}").status_code == 200
    assert _rows(relay, "SELECT id FROM owners") == []


def test_a_request_session_sees_only_its_request(relay, app, sent):
    _asked(relay, _agent(relay))
    visitor = _visitor(app, relay)
    request = _opened(visitor, _token(sent[0][1]))
    me = visitor.get("/api/owner/me").json()
    assert me["email"] == NEW and me["request"] == request["id"]
    assert [r["id"] for r in _requests(visitor)] == [request["id"]]
    for method, path, body in [
        ("get", "/api/owner/links", None), ("get", "/api/owner/passkeys", None),
        ("post", "/api/owner/codes", {"kind": "setup"}),
        ("post", "/api/owner/links/1/cancel", None),
    ]:
        resp = getattr(visitor, method)(path, **({"json": body} if body else {}))
        assert resp.status_code == 401, (path, resp.text)


def test_a_request_expires_after_seven_days(relay, app, sent, clock):
    _asked(relay, _agent(relay))
    clock(days=7, minutes=1)
    resp = _open(_visitor(app, relay), _token(sent[0][1]))
    assert resp.status_code == 410


def test_unfinished_accounts_from_a_request_go_after_a_day(relay, app, sent, clock):
    _asked(relay, _agent(relay, "a1"))
    _opened(_visitor(app, relay), _token(sent[0][1]))
    clock(hours=24, minutes=1)
    _asked(relay, _agent(relay, "a2"), "z@example.org")  # sign-ups sweep on the way
    visitor = _visitor(app, relay)
    visitor.post("/api/owner/sign-up", json={"email": "y@example.org"})
    assert [r["created_via"] for r in _rows(relay, "SELECT created_via FROM owners")] == ["signup"]


# ---------------------------------------------------------------- a new person, start to end


def test_a_new_person_owns_the_agent_that_asked(relay, app, sent):
    bob = _agent(relay)
    _asked(relay, bob)
    nina = _visitor(app, relay)
    request = _opened(nina, _token(sent[0][1]))

    phone = SoftPasskey()
    approval = _register(nina, phone, "Nina phone")
    assert _sign(nina, phone, approval).status_code == 200

    accepted = _accept(nina, request["id"])
    assert accepted["state"] == "waiting_for_agent"
    assert _status(relay, bob)["state"] == "waiting_for_agent"

    assert _sign_offer(relay, bob).status_code == 200
    [shown] = _requests(nina)
    assert shown["state"] == "waiting_for_you"

    start, resp = _approve(nina, phone, accepted["link"])
    assert resp.status_code == 200, resp.text
    assert start["screen"] == links_screen([parse_body(b) for b in start["bodies"]])
    assert _requests(nina)[0]["state"] == "approved"
    assert _status(relay, bob)["state"] == "linked"


def test_a_request_session_adds_only_the_first_passkey(relay, ada, app, sent):
    _asked(relay, _agent(relay), EMAIL)
    visitor = _visitor(app, relay)
    _opened(visitor, _token(sent[0][1]))
    resp = visitor.post("/api/owner/passkeys/register/start")
    assert resp.status_code == 401


def test_an_existing_owner_approves_with_their_passkey(relay, ada, app, sent):
    bob = _agent(relay)
    _asked(relay, bob, EMAIL)
    visitor = _visitor(app, relay)
    request = _opened(visitor, _token(sent[0][1]))
    accepted = _accept(visitor, request["id"])
    assert _sign_offer(relay, bob).status_code == 200
    _, resp = _approve(visitor, ada.phone, accepted["link"])
    assert resp.status_code == 200, resp.text
    assert _status(relay, bob)["state"] == "linked"
    assert [x["agent"] for x in ada.get("/api/owner/links").json()["links"]] == [bob["address"]]


def test_a_request_session_approves_only_its_own_link(relay, ada, app, sent):
    from tests.relay.test_owner_links import _waiting

    _, _, other = _waiting(relay, ada, "carl")
    bob = _agent(relay)
    _asked(relay, bob, EMAIL)
    visitor = _visitor(app, relay)
    request = _opened(visitor, _token(sent[0][1]))
    accepted = _accept(visitor, request["id"])
    assert _sign_offer(relay, bob).status_code == 200
    resp = visitor.post("/api/owner/link-sets/approve/start",
                        json={"ids": [accepted["link"], other["id"]]})
    assert resp.status_code == 403
    resp = visitor.post("/api/owner/link-sets/approve/start", json={"ids": [other["id"]]})
    assert resp.status_code == 403


def test_the_owner_page_shows_the_request_and_approves_it(relay, ada, sent):
    bob = _agent(relay)
    _asked(relay, bob, EMAIL)
    [request] = _requests(ada)
    accepted = _accept(ada, request["id"])
    assert _sign_offer(relay, bob).status_code == 200
    _, resp = _approve(ada, ada.phone, accepted["link"])
    assert resp.status_code == 200, resp.text
    assert _requests(ada) == []  # an approved request leaves the list


def test_accepting_needs_a_passkey_first(relay, app, sent):
    _asked(relay, _agent(relay))
    visitor = _visitor(app, relay)
    request = _opened(visitor, _token(sent[0][1]))
    resp = visitor.post(f"/api/owner/requests/{request['id']}/accept")
    assert resp.status_code == 409
    assert resp.json()["error"] == "no_passkey"


def test_a_link_request_starts_three_days_after(relay, ada, sent, clock):
    bob = _agent(relay)
    clock(hours=2)
    _asked(relay, bob, EMAIL)
    [request] = _requests(ada)
    accepted = _accept(ada, request["id"])
    body = parse_body(_status(relay, bob)["offer"]["body"])
    assert body["via"] == "link"
    assert accepted["via"] == "link"


# ---------------------------------------------------------------- declining


def test_declining_ends_the_request(relay, app, sent):
    bob = _agent(relay)
    _asked(relay, bob)
    visitor = _visitor(app, relay)
    request = _opened(visitor, _token(sent[0][1]))
    resp = visitor.post(f"/api/owner/requests/{request['id']}/decline", json={"block": False})
    assert resp.status_code == 200, resp.text
    assert resp.json()["state"] == "declined"
    assert _status(relay, bob)["request"]["state"] == "declined"
    _asked(relay, bob, "other@example.org")  # it may ask someone else


def test_decline_and_stop_this_agent_asking(relay, ada, sent, clock):
    bob = _agent(relay)
    _asked(relay, bob, EMAIL)
    [request] = _requests(ada)
    ada.post(f"/api/owner/requests/{request['id']}/decline", json={"block": True})
    clock(hours=2)
    _asked(relay, bob, EMAIL)  # same answer
    assert len(sent) == 1
    assert _requests(ada) == []  # and the page doesn't show it
    assert _status(relay, bob)["request"]["state"] == "declined"
    _asked(relay, _agent(relay, "carl"), EMAIL)  # another agent still reaches them
    assert len(sent) == 2


def test_declining_after_accepting_cancels_the_link(relay, ada, sent):
    bob = _agent(relay)
    _asked(relay, bob, EMAIL)
    [request] = _requests(ada)
    _accept(ada, request["id"])
    assert _sign_offer(relay, bob).status_code == 200
    resp = ada.post(f"/api/owner/requests/{request['id']}/decline", json={"block": False})
    assert resp.status_code == 200, resp.text
    assert _status(relay, bob)["state"] == "cancelled"


# ---------------------------------------------------------------- the agent's offer


def test_the_offer_appears_only_after_the_owner_accepts(relay, ada, sent):
    bob = _agent(relay)
    _asked(relay, bob, EMAIL)
    status = _status(relay, bob)
    assert status["request"]["state"] == "open"
    assert "offer" not in status
    [request] = _requests(ada)
    _accept(ada, request["id"])
    offer = _status(relay, bob)["offer"]
    body = parse_body(offer["body"])
    assert body["agent"] == bob["address"] and body["agentKey"] == bob["key"]
    assert body["owner"]["ownerId"] == ada.owner_id


def test_an_old_offer_is_built_again_with_fresh_times(relay, ada, sent, clock):
    bob = _agent(relay)
    _asked(relay, bob, EMAIL)
    [request] = _requests(ada)
    _accept(ada, request["id"])
    first = _status(relay, bob)["offer"]
    clock(hours=5)
    again = _status(relay, bob)["offer"]
    assert again["hash"] != first["hash"]
    assert parse_body(again["body"])["validFrom"] > parse_body(first["body"])["validFrom"]
    assert _sign_offer(relay, bob).status_code == 200


def test_a_code_link_is_not_offered(relay, ada, sent):
    from tests.relay.test_owner_links import _code, _redeem

    code = _code(ada)
    bob = _agent(relay)
    assert _redeem(relay, bob, code).status_code == 200
    assert "offer" not in _status(relay, bob)


def test_the_agent_can_cancel_an_accepted_request(relay, ada, sent):
    bob = _agent(relay)
    _asked(relay, bob, EMAIL)
    [request] = _requests(ada)
    _accept(ada, request["id"])
    assert relay.post("/api/v1/owner/link/cancel", headers=bob["headers"]).status_code == 200
    assert _requests(ada) == []


def test_a_request_session_reads_its_request_and_no_other(relay, ada, app, sent):
    _asked(relay, _agent(relay, "a1"), EMAIL)
    [mine] = _requests(ada)
    visitor = _visitor(app, relay)
    _asked(relay, _agent(relay, "a2"), "z@example.org")
    other = _opened(visitor, _token(sent[-1][1]))
    assert visitor.get(f"/api/owner/requests/{other['id']}").json()["agent"] == "a2::test.local"
    assert visitor.get(f"/api/owner/requests/{mine['id']}").status_code == 403
    assert ada.get(f"/api/owner/requests/{other['id']}").status_code == 404
    assert ada.get(f"/api/owner/requests/{mine['id']}").json()["state"] == "open"
