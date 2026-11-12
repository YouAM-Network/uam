"""An owner who lost every passkey starts again (DEC-010).

The relay admin freezes the account by its email: nobody can sign in and
its sessions end, but its agents and contacts carry on. The email is told
and can keep the account for 72 hours. After that the account closes: its
agents are unlinked (the relay signs each unlink), its contacts end, its
open invites are cancelled, names held for it are released, and the email
is free to make a new account.
"""

from __future__ import annotations

import pytest

from tests.relay._owner_fixtures import (  # noqa: F401  (fixtures are used by name)
    ADMIN_KEY,
    EMAIL,
    OWNER_ORIGIN,
    _admin,
    _on_owner_host,
    _rows,
    clock,
    codes,
    owner,
    owner_env,
    relay,
)
from tests.relay.test_owner_invites import (  # noqa: F401
    BOB,
    _approve,
    _connected,
    _email_invite,
    _contacts,
    _invite,
    _key,
    bob,
    emails,
)
from tests.relay.test_owner_links import _linked, _links, _status, ada  # noqa: F401


@pytest.fixture()
def told(app):
    """Emails about the account: (kind, email, data)."""
    got = []
    app.state.owner_account_sink = lambda kind, email, data: got.append((kind, email, data))
    return got


def _freeze(relay, email=EMAIL, headers=None):
    return relay.post("/api/v1/admin/owners/freeze", json={"email": email},
                      headers=_admin() if headers is None else headers)


def _keep_token(told):
    [(kind, _, data)] = [t for t in told if t[0] == "account_frozen"]
    return data["keepUrl"].split("#keep=", 1)[1]


def _keep(client, token):
    return client.post("/api/owner/freeze/keep", json={"token": token})


def _close_due(relay, app):
    import uam.db.session as sess
    from uam.relay.owners import freeze

    async def run():
        async with sess._session_factory() as s:
            return await freeze.finish_due(s, app)

    return relay.portal.call(run)


def _status_of(relay):
    return [r["status"] for r in _rows(relay, "SELECT status FROM owners ORDER BY id")]


# ---------------------------------------------------------------- freezing


def test_the_admin_freezes_an_account_by_its_email(ada, relay, told):
    resp = _freeze(relay, "  ADA@example.com ")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "frozen" and body["ownerId"] == ada.owner_id
    assert body["closesAt"].endswith("Z")
    assert _status_of(relay) == ["frozen"]


def test_freezing_ends_the_accounts_sessions(ada, relay, told):
    assert ada.get("/api/owner/me").status_code == 200
    _freeze(relay)
    assert ada.get("/api/owner/me").status_code == 401
    [row] = _rows(relay, "SELECT revoked_at FROM owner_sessions")
    assert row["revoked_at"] is not None


def test_a_frozen_account_cannot_sign_in(ada, relay, owner, codes, told):
    _freeze(relay)
    sent = len(codes)
    assert owner.post("/api/owner/sign-in/start", json={"email": EMAIL}).status_code == 202
    assert len(codes) == sent


def test_freezing_needs_the_admin_key(ada, relay, told):
    assert _freeze(relay, headers={}).status_code in (401, 403)
    assert _freeze(relay, headers={"X-Admin-Key": ADMIN_KEY + "x"}).status_code in (401, 403)
    assert _status_of(relay) == ["active"]


def test_an_email_without_an_account_is_404(relay, told):
    assert _freeze(relay, "nobody@example.com").status_code == 404
    assert told == []


def test_a_frozen_account_cannot_be_frozen_again(ada, relay, told):
    assert _freeze(relay).status_code == 200
    assert _freeze(relay).status_code == 409
    assert len(told) == 1


def test_the_freeze_route_is_404_while_owners_are_off(app):
    from fastapi.testclient import TestClient

    with TestClient(app) as c:
        assert c.post("/api/v1/admin/owners/freeze", json={"email": EMAIL},
                      headers=_admin()).status_code == 404


# ---------------------------------------------------------------- the email, and keeping the account


def test_the_email_is_told_when_it_closes_and_how_to_keep_it(ada, relay, told):
    closes = _freeze(relay).json()["closesAt"]
    [(kind, email, data)] = told
    assert kind == "account_frozen" and email == "ada@example.com"
    assert data["closesAt"] == closes
    assert data["keepUrl"].startswith(f"{OWNER_ORIGIN}/#keep=")


def test_the_keep_link_is_stored_only_as_a_hash(ada, relay, told):
    _freeze(relay)
    token = _keep_token(told)
    [row] = _rows(relay, "SELECT token_hash FROM owner_freezes")
    assert token not in row["token_hash"]


def test_the_keep_link_gives_the_account_back(ada, relay, app, owner, codes, told):
    agent, _, _ = _linked(relay, ada)
    _freeze(relay)
    resp = _keep(owner, _keep_token(told))
    assert resp.status_code == 200, resp.text
    assert _status_of(relay) == ["active"]
    assert owner.post("/api/owner/sign-in/start", json={"email": EMAIL}).status_code == 202
    resp = owner.post("/api/owner/sign-in/finish", json={"email": EMAIL, "code": codes[-1][2]})
    assert resp.status_code == 200
    assert _status(relay, agent)["state"] == "linked"


def test_the_keep_link_works_once(ada, relay, owner, told):
    _freeze(relay)
    token = _keep_token(told)
    assert _keep(owner, token).status_code == 200
    assert _keep(owner, token).status_code == 404


def test_the_keep_link_ends_after_72_hours(ada, relay, owner, told, clock):
    _freeze(relay)
    clock(hours=72, seconds=1)
    assert _keep(owner, _keep_token(told)).status_code == 404
    assert _status_of(relay) == ["frozen"]


def test_a_wrong_keep_token_is_404(ada, relay, owner, told):
    _freeze(relay)
    assert _keep(owner, "x" * 43).status_code == 404
    assert _status_of(relay) == ["frozen"]


def test_the_keep_route_is_only_on_the_owner_origin(ada, relay, told):
    _freeze(relay)
    assert relay.post("/api/owner/freeze/keep", json={"token": _keep_token(told)}).status_code == 404


# ---------------------------------------------------------------- while frozen


def test_a_frozen_accounts_agents_and_contacts_carry_on(ada, bob, relay, told):
    agent, _, _ = _linked(relay, ada)
    _connected(ada, bob)
    _freeze(relay)
    assert _status(relay, agent)["state"] == "linked"
    assert [c["email"] for c in _contacts(bob)] == ["ada@example.com"]


def test_nobody_can_accept_a_frozen_accounts_invite(ada, bob, relay, told):
    made = _invite(ada)
    _freeze(relay)
    resp = bob.post("/api/owner/invites/find", json=_key(made))
    assert resp.status_code == 410, resp.text


def test_an_invite_started_before_the_freeze_cannot_finish_after_it(ada, bob, relay, told):
    made = _invite(ada)
    asked = bob.post("/api/owner/invites/redeem/start", json=_key(made))
    assert asked.status_code == 200, asked.text
    _freeze(relay)
    resp = _approve(bob, asked.json(), "/api/owner/invites/redeem")
    assert resp.status_code == 410, resp.text
    assert _rows(relay, "SELECT count(*) AS n FROM invite_redemptions") == [{"n": 0}]


def test_a_frozen_accounts_emailed_invite_is_not_sent(ada, relay, app, told, emails, clock):
    from uam.relay.owners import contacts

    _email_invite(ada)
    _freeze(relay)
    clock(minutes=11)
    import uam.db.session as sess

    async def run():
        async with sess._session_factory() as s:
            return await contacts.send_due(s, app)

    assert relay.portal.call(run) == 0
    assert emails == []


def test_nothing_closes_before_72_hours(ada, relay, app, told, clock):
    _freeze(relay)
    clock(hours=71)
    assert _close_due(relay, app) == 0
    assert _status_of(relay) == ["frozen"]


# ---------------------------------------------------------------- closing


def test_after_72_hours_the_account_closes(ada, relay, app, told, clock):
    _freeze(relay)
    clock(hours=72, seconds=1)
    assert _close_due(relay, app) == 1
    assert _status_of(relay) == ["closed"]
    assert _close_due(relay, app) == 0


def test_closing_unlinks_its_agents_with_the_relays_signature(ada, relay, app, told, clock):
    agent, _, link = _linked(relay, ada)
    _freeze(relay)
    clock(hours=73)
    _close_due(relay, app)
    assert _status(relay, agent)["state"] == "unlinked"
    [row] = _rows(relay, "SELECT reason, signer FROM owner_unlinks")
    assert row == {"reason": "admin", "signer": "relay"}


def test_closing_cancels_links_not_yet_approved(ada, relay, app, told, clock):
    from tests.relay.test_owner_links import _waiting

    agent, _, link = _waiting(relay, ada, "carl")
    _freeze(relay)
    clock(hours=73)
    _close_due(relay, app)
    [row] = _rows(relay, "SELECT state, live_for FROM owner_links WHERE id = :id", id=link["id"])
    assert row == {"state": "cancelled", "live_for": None}


def test_closing_ends_its_contacts_both_ways(ada, bob, relay, app, told, clock):
    _connected(ada, bob)
    _freeze(relay)
    clock(hours=73)
    _close_due(relay, app)
    # (Bob's session has idled out by now, so look at the grants themselves.)
    assert len(_rows(relay, "SELECT id FROM owner_grants")) == 2
    live = _rows(relay, "SELECT id FROM owner_grants WHERE revoked_at IS NULL")
    assert live == []
    assert _rows(relay, "SELECT count(*) AS n FROM owner_revocations")[0]["n"] >= 2


def test_closing_cancels_its_open_invites(ada, relay, app, told, clock):
    made = _invite(ada)
    _freeze(relay)
    clock(hours=73)
    _close_due(relay, app)
    [row] = _rows(relay, "SELECT state FROM owner_invites WHERE id = :id", id=made["id"])
    assert row["state"] == "cancelled"


def test_closing_releases_names_held_for_it(ada, relay, app, told, clock):
    resp = relay.post(f"/api/v1/admin/owners/{ada.owner_id}/names", json={"name": "ada-bot"},
                      headers=_admin())
    assert resp.status_code == 201, resp.text
    _freeze(relay)
    clock(hours=73)
    _close_due(relay, app)
    [row] = _rows(relay, "SELECT status, expires_at FROM reservations WHERE address LIKE 'ada-bot::%'")
    assert row["status"] == "reserved"  # the expiry sweep releases it
    from uam.relay.owners import service

    assert row["expires_at"] is not None
    expires = row["expires_at"]
    if isinstance(expires, str):
        from datetime import datetime

        expires = datetime.fromisoformat(expires)
    assert service._aware(expires) <= service.utcnow()


def test_after_closing_the_email_makes_a_new_account(ada, relay, app, owner, codes, told, clock):
    _freeze(relay)
    clock(hours=73)
    _close_due(relay, app)
    fresh = _on_owner_host(app, relay)
    assert fresh.post("/api/owner/sign-up", json={"email": EMAIL}).status_code == 202
    resp = fresh.post("/api/owner/sign-in/finish", json={"email": EMAIL, "code": codes[-1][2]})
    assert resp.status_code == 200, resp.text
    me = fresh.get("/api/owner/me").json()
    assert me["status"] == "active" and me["owner_id"] is None
    assert _status_of(relay) == ["closed", "active"]


def test_the_email_is_told_when_the_account_closes(ada, relay, app, told, clock):
    _freeze(relay)
    clock(hours=73)
    _close_due(relay, app)
    kind, email, data = told[-1]
    assert kind == "account_closed" and email == "ada@example.com"
    assert data["url"] == f"{OWNER_ORIGIN}/"


def test_the_closed_account_keeps_no_email(ada, relay, app, told, clock):
    _freeze(relay)
    clock(hours=73)
    _close_due(relay, app)
    assert _rows(relay, "SELECT id FROM owner_emails") == []
    actions = [r["action"] for r in _rows(relay, "SELECT action FROM owner_audit ORDER BY id")]
    assert "frozen" in actions and actions[-1] == "closed"


def test_an_account_closes_once_even_if_two_sweeps_race(ada, relay, app, told, clock):
    import uam.db.session as sess
    from uam.relay.owners import freeze

    _freeze(relay)
    clock(hours=73)
    [row] = _rows(relay, "SELECT id FROM owner_freezes")

    async def close():
        async with sess._session_factory() as s:
            return await freeze._close(s, app, row["id"])

    assert relay.portal.call(close) == "ada@example.com"
    assert relay.portal.call(close) is None
    assert [t[0] for t in told].count("account_closed") == 0  # _close itself never tells
    actions = [r["action"] for r in _rows(relay, "SELECT action FROM owner_audit")]
    assert actions.count("closed") == 1


def test_one_account_failing_to_close_doesnt_stop_the_rest(ada, relay, app, told, clock,
                                                           monkeypatch):
    from uam.relay.owners import freeze

    assert _freeze(relay).status_code == 200
    assert relay.post("/api/v1/admin/owners", json={"email": BOB}, headers=_admin()).status_code == 201
    assert _freeze(relay, BOB).status_code == 200
    first = _rows(relay, "SELECT owner_pk FROM owner_freezes ORDER BY id")[0]["owner_pk"]
    real = freeze._end_contacts

    async def broken(session, owner_pk, now):
        if owner_pk == first:
            raise RuntimeError("boom")
        return await real(session, owner_pk, now)

    monkeypatch.setattr(freeze, "_end_contacts", broken)
    clock(hours=73)
    assert _close_due(relay, app) == 1
    assert _status_of(relay)[1] == "closed"


def test_a_kept_account_never_closes(ada, relay, app, owner, told, clock):
    _freeze(relay)
    _keep(owner, _keep_token(told))
    clock(hours=73)
    assert _close_due(relay, app) == 0
    assert _status_of(relay) == ["active"]


# ---------------------------------------------------------------- the emails' text


def test_the_frozen_email_says_what_happens_and_when():
    from uam.relay.owners.mail import render

    subject, text = render("account_frozen", {
        "keepUrl": "https://account.youam.network/#keep=abc", "closesAt": "2026-11-15T10:00:00Z",
    }, "https://account.youam.network")
    assert subject == "Your YouAM account is frozen"
    assert "15 Nov 2026" in text and "https://account.youam.network/#keep=abc" in text
    assert "unlinked" in text and "contacts" in text


def test_the_closed_email_says_how_to_start_again():
    from uam.relay.owners.mail import render

    subject, text = render("account_closed", {"url": "https://account.youam.network/"},
                           "https://account.youam.network")
    assert subject == "Your old YouAM account is closed"
    assert "https://account.youam.network/" in text and "setup code" in text
