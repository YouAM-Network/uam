"""Self-serve sign-up (P2s, DEC-005).

Anyone can make an owner account with their email: a code goes to the
email, and the account is theirs once they add a first passkey. The answer
never says whether the email already had an account (an existing one just
gets a sign-in code), and an account nobody finished is deleted after 24
hours, so the email can sign up again.
"""

from __future__ import annotations

import pytest

from tests.relay._owner_fixtures import (  # noqa: F401  (fixtures are used by name)
    EMAIL,
    _create,
    _exec,
    _on_owner_host,
    _rows,
    clock,
    codes,
    owner,
    owner_env,
    relay,
)
from tests.relay.test_owner_passkeys import _first_passkey


def _sign_up(owner, email=EMAIL):
    return owner.post("/api/owner/sign-up", json={"email": email})


def _finish(owner, codes, email=EMAIL):
    return owner.post("/api/owner/sign-in/finish", json={"email": email, "code": codes[-1][2]})


def _owners(relay):
    return _rows(relay, "SELECT id, created_via, owner_id FROM owners ORDER BY id")


def test_anyone_can_make_an_account_with_their_email(relay, owner, codes):
    resp = _sign_up(owner)
    assert resp.status_code == 202, resp.text
    assert len(codes) == 1 and codes[0][1] == "ada@example.com"
    assert _finish(owner, codes).status_code == 200
    assert owner.get("/api/owner/me").json()["owner_id"] is None  # no passkey yet
    [row] = _owners(relay)
    assert row["created_via"] == "signup" and row["owner_id"] is None
    _first_passkey(owner)
    [row] = _owners(relay)
    assert row["owner_id"] is not None


def test_signing_up_with_a_known_email_sends_a_sign_in_code(relay, owner, codes):
    assert _create(relay).status_code == 201
    first = _sign_up(owner)
    assert first.status_code == 202
    assert len(codes) == 1
    assert _finish(owner, codes).status_code == 200
    assert len(_owners(relay)) == 1


def test_the_answer_does_not_say_whether_the_email_is_known(relay, owner, codes):
    new = _sign_up(owner, "new@example.com")
    assert _create(relay, "old@example.com").status_code == 201
    old = _sign_up(owner, "old@example.com")
    assert new.status_code == old.status_code == 202
    assert new.json() == old.json()


def test_an_email_gets_at_most_three_codes_an_hour(relay, owner, codes):
    for _ in range(4):
        assert _sign_up(owner).status_code == 202
    assert len(codes) == 3


def test_one_address_can_start_ten_sign_ups_an_hour(relay, owner, codes, clock):
    for n in range(10):
        assert _sign_up(owner, f"p{n}@example.com").status_code == 202
    resp = _sign_up(owner, "p10@example.com")
    assert resp.status_code == 429
    assert resp.json()["error"] == "too_many"
    assert len(_owners(relay)) == 10


@pytest.mark.parametrize("email", ["not-an-email", "", "a@b", "x" * 400 + "@example.com"])
def test_a_bad_email_is_refused(owner, email):
    assert _sign_up(owner, email).status_code == 422


def test_an_unfinished_sign_up_is_gone_after_a_day(relay, owner, codes, clock):
    _sign_up(owner)
    assert len(_owners(relay)) == 1
    clock(hours=24, seconds=1)
    _sign_up(owner, "someone@example.com")  # any sign-up sweeps
    assert [r["created_via"] for r in _owners(relay)] == ["signup"]
    assert len(_rows(relay, "SELECT id FROM owner_emails")) == 1
    # The first email can sign up again, as a new account.
    _sign_up(owner)
    assert codes[-1][1] == "ada@example.com"
    assert _finish(owner, codes).status_code == 200


def test_a_finished_account_is_kept(relay, owner, codes, clock):
    _sign_up(owner)
    _finish(owner, codes)
    _first_passkey(owner)
    clock(hours=48)
    _sign_up(owner, "someone@example.com")
    assert len(_owners(relay)) == 2


def test_an_admin_made_account_without_a_passkey_is_kept(relay, owner, codes, clock):
    assert _create(relay).status_code == 201
    clock(hours=48)
    _sign_up(owner, "someone@example.com")
    assert [r["created_via"] for r in _owners(relay)] == ["admin", "signup"]


def test_a_sign_up_less_than_a_day_old_is_kept(relay, owner, codes, clock):
    _sign_up(owner)
    clock(hours=23)
    _sign_up(owner, "someone@example.com")
    assert len(_owners(relay)) == 2


def test_sign_up_is_only_on_the_owner_origin(relay, app):
    elsewhere = _on_owner_host(app, relay, origin="https://evil.example")
    assert _sign_up(elsewhere).status_code == 403


def test_sign_up_is_404_while_owners_are_off(app):
    from fastapi.testclient import TestClient

    with TestClient(app) as plain:
        assert plain.post("/api/owner/sign-up", json={"email": EMAIL}).status_code == 404


def test_the_audit_records_how_the_account_was_made(relay, owner, codes):
    _sign_up(owner)
    [row] = _rows(relay, "SELECT action, details FROM owner_audit WHERE action = 'created'")
    assert '"signup"' in row["details"]


def test_a_frozen_account_cannot_sign_up_again(relay, owner, codes):
    assert _create(relay).status_code == 201
    _exec(relay, "UPDATE owners SET status = 'frozen'")
    assert _sign_up(owner).status_code == 202
    assert codes == []
    assert len(_owners(relay)) == 1
