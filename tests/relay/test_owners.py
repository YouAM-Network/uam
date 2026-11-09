"""Owner accounts, sign-in and sessions (P2c-1, ships dark).

Owners are the people who approve contacts for their agents. In P2c-1 the
relay admin creates them; they sign in with an emailed code and get a
session cookie on the owner origin, a separate host from the relay API.
"""

from __future__ import annotations

import base64
import json
import logging

import pytest
from fastapi.testclient import TestClient

from tests.relay._owner_fixtures import (  # noqa: F401  (fixtures are used by name)
    ADMIN_KEY,
    COOKIE,
    EMAIL,
    KEY,
    OWNER_ENV,
    OWNER_ORIGIN,
    PEPPER,
    _admin,
    _create,
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


# ---------------------------------------------------------------- settings


def test_owners_are_off_by_default(app):
    with TestClient(app) as c:
        assert c.post("/api/v1/admin/owners", json={"email": EMAIL}).status_code == 404
        owner_host = _on_owner_host(app, c, origin=None)
        assert owner_host.get("/api/owner/me").status_code == 404
        assert "owner_origin" not in c.get("/.well-known/uam-relay.json").json()


@pytest.mark.parametrize("missing", ["UAM_EMAIL_PEPPER", "UAM_EMAIL_KEY", "UAM_OWNER_ORIGIN", "UAM_RP_ID"])
def test_enabled_without_a_setting_refuses_to_start(owner_env, monkeypatch, missing):
    from uam.relay.config import Settings

    monkeypatch.delenv(missing)
    with pytest.raises(RuntimeError, match=missing):
        Settings()


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("UAM_EMAIL_PEPPER", "short"),
        ("UAM_EMAIL_KEY", base64.urlsafe_b64encode(b"x" * 16).decode()),
        ("UAM_EMAIL_KEY", "not base64 !!"),
        ("UAM_OWNER_ORIGIN", "http://account.test.local"),
        ("UAM_OWNER_ORIGIN", "https://account.test.local/path"),
        ("UAM_OWNER_ORIGIN", "https://user@account.test.local"),
        ("UAM_RP_ID", "other.example"),
        ("UAM_RP_ID", "count.test.local"),
    ],
)
def test_bad_owner_settings_refuse_to_start(owner_env, monkeypatch, name, value):
    from uam.relay.config import Settings

    monkeypatch.setenv(name, value)
    with pytest.raises(RuntimeError, match=name):
        Settings()


def test_the_owner_origin_cannot_be_the_relay_host(owner_env, monkeypatch):
    """Otherwise the owner app would shadow the whole relay API."""
    from uam.relay.config import Settings

    monkeypatch.setenv("UAM_RELAY_HTTP_URL", "https://Account.test.local")
    with pytest.raises(RuntimeError, match="UAM_OWNER_ORIGIN"):
        Settings()


def test_a_localhost_owner_origin_may_use_http(owner_env, monkeypatch):
    from uam.relay.config import Settings

    monkeypatch.setenv("UAM_OWNER_ORIGIN", "http://localhost:3011")
    monkeypatch.setenv("UAM_RP_ID", "localhost")
    assert Settings().owner_origin == "http://localhost:3011"


def test_codes_to_the_log_refuse_a_production_rp_id(owner_env, monkeypatch):
    from uam.relay.config import Settings

    monkeypatch.setenv("UAM_OWNER_ORIGIN", "https://account.youam.network")
    monkeypatch.setenv("UAM_RP_ID", "youam.network")
    monkeypatch.setenv("UAM_OWNER_CODES_TO_LOG", "true")
    with pytest.raises(RuntimeError, match="UAM_OWNER_CODES_TO_LOG"):
        Settings()


def test_well_known_names_the_owner_origin_when_enabled(relay):
    doc = relay.get("/.well-known/uam-relay.json").json()
    assert doc["owner_origin"] == OWNER_ORIGIN
    assert doc["rp_id"] == "test.local"


# ---------------------------------------------------------------- admin


def test_admin_creates_an_owner(relay):
    resp = _create(relay)
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["status"] == "active"
    assert body["owner_id"] is None
    [row] = _rows(relay, "SELECT email_hmac, email_enc, verified_at FROM owner_emails")
    assert "ada" not in row["email_hmac"].lower() and "ada" not in row["email_enc"].lower()
    assert row["verified_at"] is None
    [audit] = _rows(relay, "SELECT action, details FROM owner_audit")
    assert audit["action"] == "created"
    assert json.loads(audit["details"]) == {"via": "admin"}


def test_an_email_has_one_owner_whatever_its_case(relay):
    assert _create(relay).status_code == 201
    resp = _create(relay, "  ada@EXAMPLE.com ")
    assert resp.status_code == 409


def test_creating_an_owner_needs_the_admin_key(relay):
    assert relay.post("/api/v1/admin/owners", json={"email": EMAIL}).status_code == 401
    wrong = {"X-Admin-Key": "wrong"}
    assert relay.post("/api/v1/admin/owners", json={"email": EMAIL}, headers=wrong).status_code == 401


@pytest.mark.parametrize("email", ["", "no-at-sign", "a@b@c.com", "a b@c.com", "a@", "@c.com", "a@c", "x" * 250 + "@c.com"])
def test_an_owner_needs_a_real_looking_email(relay, email):
    assert _create(relay, email).status_code == 422


def test_the_stored_email_decrypts_to_the_normalised_address(relay, app):
    from uam.relay.owners.crypto import EmailVault

    _create(relay)
    [row] = _rows(relay, "SELECT email_hmac, email_enc FROM owner_emails")
    vault = EmailVault(PEPPER, KEY)
    assert vault.decrypt(row["email_enc"]) == "ada@example.com"
    assert vault.lookup("ADA@example.com ") == row["email_hmac"]


def test_a_code_hash_is_bound_to_its_email():
    from uam.relay.owners.crypto import EmailVault

    vault = EmailVault(PEPPER, KEY)
    a, b = vault.lookup("a@example.com"), vault.lookup("b@example.com")
    assert vault.code_hash(a, "123456") != vault.code_hash(b, "123456")
    assert vault.code_hash(a, "123456") != EmailVault(PEPPER + "x", KEY).code_hash(a, "123456")


# ---------------------------------------------------------------- hosts


def test_owner_routes_are_not_on_the_relay_host(relay):
    assert relay.get("/api/owner/me").status_code == 404
    assert relay.post("/api/owner/sign-in/start", json={"email": EMAIL}).status_code == 404


def test_relay_routes_are_not_on_the_owner_host(owner):
    assert owner.get("/health").status_code == 404
    assert owner.post("/api/v1/register", json={}).status_code == 404
    assert owner.post("/api/v1/admin/owners", json={"email": EMAIL}, headers=_admin()).status_code == 404


def test_owner_responses_carry_strict_headers(owner):
    resp = owner.get("/api/owner/me")
    csp = resp.headers["content-security-policy"]
    assert "default-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp
    assert "script-src 'self'" in csp and "unsafe-inline" not in csp
    assert resp.headers["x-content-type-options"] == "nosniff"
    assert resp.headers["referrer-policy"] == "no-referrer"
    assert resp.headers["cache-control"] == "no-store"
    assert "access-control-allow-origin" not in resp.headers


@pytest.mark.parametrize("origin", [None, "https://evil.example", "https://test.local", "null"])
def test_owner_writes_need_the_owner_origin(owner, codes, origin):
    c = _on_owner_host(owner.app, owner, origin=origin)
    resp = c.post("/api/owner/sign-in/start", json={"email": EMAIL})
    assert resp.status_code == 403
    assert codes == []


# ---------------------------------------------------------------- sign-in


def test_sign_in_start_answers_the_same_for_an_unknown_email(owner, codes):
    resp = owner.post("/api/owner/sign-in/start", json={"email": "nobody@example.com"})
    assert resp.status_code == 202
    assert codes == []
    assert _rows(owner, "SELECT id FROM owner_login_codes") == []


def test_sign_in_start_answers_before_doing_the_work(relay, owner, monkeypatch, owner_log):
    """The answer can't depend on whether the email has an account, not even
    by taking longer: the lookup and the writes happen after it's sent."""
    from uam.relay.owners import service

    async def broken(*args, **kwargs):
        raise RuntimeError("database fell over")

    _create(relay)
    monkeypatch.setattr(service, "start_sign_in", broken)
    assert owner.post("/api/owner/sign-in/start", json={"email": EMAIL}).status_code == 202
    assert any("sign-in start failed" in line for line in owner_log)
    assert not any("ada" in line.lower() for line in owner_log)


def test_sign_in_start_sends_a_six_digit_code_stored_hashed(relay, owner, codes):
    _create(relay)
    resp = owner.post("/api/owner/sign-in/start", json={"email": EMAIL})
    assert resp.status_code == 202
    [(owner_pk, email, code)] = codes
    assert email == "ada@example.com"
    assert len(code) == 6 and code.isdigit()
    [row] = _rows(owner, "SELECT code_hash FROM owner_login_codes")
    assert code not in row["code_hash"]


def test_at_most_three_codes_an_hour(relay, owner, codes, clock):
    _create(relay)
    for _ in range(4):
        assert owner.post("/api/owner/sign-in/start", json={"email": EMAIL}).status_code == 202
    assert len(codes) == 3
    clock(minutes=61)
    owner.post("/api/owner/sign-in/start", json={"email": EMAIL})
    assert len(codes) == 4


def test_parallel_starts_still_make_at_most_three_codes(relay, owner, codes):
    """Each code brings fresh tries, so a burst must not mint extra codes."""
    import asyncio

    import uam.db.session as sess
    from uam.relay.owners import service
    from uam.relay.owners.crypto import EmailVault

    _create(relay)
    vault = EmailVault(PEPPER, KEY)

    async def one():
        async with sess._session_factory() as s:
            await service.start_sign_in(s, vault, "ada@example.com", lambda *a: codes.append(a))

    async def burst():
        await asyncio.gather(*(one() for _ in range(6)))

    relay.portal.call(burst)
    assert len(codes) == 3
    assert len(_rows(owner, "SELECT id FROM owner_login_codes")) == 3


def test_sign_in_sets_a_host_only_strict_session_cookie(relay, owner, codes):
    resp = _sign_in(relay, owner, codes)
    cookie = resp.headers["set-cookie"]
    assert cookie.startswith(f"{COOKIE}=")
    lowered = cookie.lower()
    for attr in ("httponly", "secure", "samesite=strict", "path=/"):
        assert attr in lowered
    assert "domain=" not in lowered
    me = owner.get("/api/owner/me")
    assert me.status_code == 200
    assert me.json() == {"email": "ada@example.com", "status": "active", "owner_id": None}


def test_signing_in_verifies_the_email(relay, owner, codes):
    _sign_in(relay, owner, codes)
    [row] = _rows(owner, "SELECT verified_at FROM owner_emails")
    assert row["verified_at"] is not None


def test_the_session_token_is_stored_hashed(relay, owner, codes):
    _sign_in(relay, owner, codes)
    token = owner.cookies[COOKIE]
    [row] = _rows(owner, "SELECT token_hash FROM owner_sessions")
    assert token not in row["token_hash"]


def _finish(owner, code, email=EMAIL):
    return owner.post("/api/owner/sign-in/finish", json={"email": email, "code": code})


def _wrong(code):
    return f"{(int(code) + 1) % 1_000_000:06d}"


def test_a_wrong_code_is_refused(relay, owner, codes):
    _create(relay)
    owner.post("/api/owner/sign-in/start", json={"email": EMAIL})
    resp = _finish(owner, _wrong(codes[0][2]))
    assert resp.status_code == 400
    assert resp.json()["error"] == "bad_code"
    assert COOKIE not in owner.cookies


def test_five_wrong_tries_burn_the_code(relay, owner, codes):
    _create(relay)
    owner.post("/api/owner/sign-in/start", json={"email": EMAIL})
    code = codes[0][2]
    for _ in range(5):
        assert _finish(owner, _wrong(code)).status_code == 400
    assert _finish(owner, code).status_code == 400


def test_a_code_works_once(relay, owner, codes):
    _create(relay)
    owner.post("/api/owner/sign-in/start", json={"email": EMAIL})
    code = codes[0][2]
    assert _finish(owner, code).status_code == 200
    assert _finish(owner, code).status_code == 400


def test_a_code_works_once_even_when_two_finishes_race(relay, owner, codes, monkeypatch):
    """The second finish read the code before the first one used it."""
    from uam.relay.owners import service

    real = service.crud.newest_code

    async def stale(session, email_hmac):
        row = await real(session, email_hmac)
        if row is not None:
            session.expunge(row)
            row.used_at = None
        return row

    _create(relay)
    owner.post("/api/owner/sign-in/start", json={"email": EMAIL})
    code = codes[0][2]
    assert _finish(owner, code).status_code == 200
    monkeypatch.setattr(service.crud, "newest_code", stale)
    assert _finish(owner, code).status_code == 400
    assert len(_rows(owner, "SELECT id FROM owner_sessions")) == 1


def test_a_code_expires_after_ten_minutes(relay, owner, codes, clock):
    _create(relay)
    owner.post("/api/owner/sign-in/start", json={"email": EMAIL})
    clock(minutes=10, seconds=1)
    assert _finish(owner, codes[0][2]).status_code == 400


def test_only_the_newest_code_counts(relay, owner, codes):
    _create(relay)
    owner.post("/api/owner/sign-in/start", json={"email": EMAIL})
    owner.post("/api/owner/sign-in/start", json={"email": EMAIL})
    first, second = codes[0][2], codes[1][2]
    if first != second:
        assert _finish(owner, first).status_code == 400
    assert _finish(owner, second).status_code == 200


def test_a_code_is_for_its_own_email(relay, owner, codes):
    _create(relay)
    _create(relay, "bob@example.com")
    owner.post("/api/owner/sign-in/start", json={"email": EMAIL})
    assert _finish(owner, codes[0][2], email="bob@example.com").status_code == 400


def test_a_frozen_owner_cannot_sign_in(relay, owner, codes):
    _create(relay)
    owner.post("/api/owner/sign-in/start", json={"email": EMAIL})
    _exec(owner, "UPDATE owners SET status = 'frozen'")
    assert _finish(owner, codes[0][2]).status_code == 400


def test_a_frozen_owner_gets_no_code(relay, owner, codes):
    _create(relay)
    _exec(owner, "UPDATE owners SET status = 'frozen'")
    assert owner.post("/api/owner/sign-in/start", json={"email": EMAIL}).status_code == 202
    assert codes == []


class _Lines(logging.Handler):
    def __init__(self):
        super().__init__(logging.DEBUG)
        self.lines: list[str] = []

    def emit(self, record):
        self.lines.append(record.getMessage())


@pytest.fixture()
def owner_log():
    logger = logging.getLogger("uam.relay.owners")
    handler, level = _Lines(), logger.level
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    yield handler.lines
    logger.removeHandler(handler)
    logger.setLevel(level)


def test_codes_go_to_the_log_only_when_asked(owner_env, monkeypatch, app, owner_log):
    monkeypatch.setenv("UAM_OWNER_CODES_TO_LOG", "true")
    from uam.relay.app import create_app

    logged_app = create_app()
    with TestClient(logged_app) as relay:
        assert _create(relay).status_code == 201
        o = _on_owner_host(logged_app, relay)
        assert o.post("/api/owner/sign-in/start", json={"email": EMAIL}).status_code == 202
    [line] = [m for m in owner_log if "sign-in code" in m]
    assert "ada" not in line.lower()
    assert line[-6:].isdigit()


def test_codes_are_not_logged_by_default(relay, owner, owner_log):
    _create(relay)
    del relay.app.state.owner_code_sink
    assert owner.post("/api/owner/sign-in/start", json={"email": EMAIL}).status_code == 202
    assert _rows(owner, "SELECT id FROM owner_login_codes") != []
    assert owner_log  # the default path does log, just not the code
    for line in owner_log:
        assert "sign-in code" not in line
        assert not any(w.isdigit() and len(w) == 6 for w in line.replace(":", " ").split())


# ---------------------------------------------------------------- sessions


def test_me_needs_a_session(owner):
    resp = owner.get("/api/owner/me")
    assert resp.status_code == 401


def test_a_forged_cookie_is_refused(owner):
    owner.cookies.set(COOKIE, "forged-token", domain="account.test.local")
    assert owner.get("/api/owner/me").status_code == 401


def test_sign_out_ends_the_session(relay, owner, codes):
    _sign_in(relay, owner, codes)
    token = owner.cookies[COOKIE]
    resp = owner.post("/api/owner/sign-out")
    assert resp.status_code == 204
    assert f"{COOKIE}=" in resp.headers["set-cookie"]
    assert owner.get("/api/owner/me").status_code == 401
    replay = _on_owner_host(owner.app, owner, origin=None)
    replay.cookies.set(COOKIE, token, domain="account.test.local")
    assert replay.get("/api/owner/me").status_code == 401


def test_a_session_ends_after_twelve_idle_hours(relay, owner, codes, clock):
    _sign_in(relay, owner, codes)
    clock(hours=11, minutes=59)
    assert owner.get("/api/owner/me").status_code == 200
    clock(hours=12, minutes=1)
    assert owner.get("/api/owner/me").status_code == 401


def test_a_session_ends_after_seven_days_however_active(relay, owner, codes, clock):
    _sign_in(relay, owner, codes)
    for _ in range(15):
        clock(hours=11)
        assert owner.get("/api/owner/me").status_code == 200
    clock(hours=4)  # 7 days and 1 hour after sign-in
    assert owner.get("/api/owner/me").status_code == 401


def test_freezing_an_owner_ends_their_sessions(relay, owner, codes):
    _sign_in(relay, owner, codes)
    _exec(owner, "UPDATE owners SET status = 'frozen'")
    assert owner.get("/api/owner/me").status_code == 401


def test_sign_out_needs_the_owner_origin(relay, owner, codes):
    _sign_in(relay, owner, codes)
    token = owner.cookies[COOKIE]
    cross = _on_owner_host(owner.app, owner, origin="https://evil.example")
    cross.cookies.set(COOKIE, token, domain="account.test.local")
    assert cross.post("/api/owner/sign-out").status_code == 403
    assert owner.get("/api/owner/me").status_code == 200


# ---------------------------------------------------------------- audit


def test_the_audit_never_holds_an_email(relay, owner, codes):
    _sign_in(relay, owner, codes)
    owner.post("/api/owner/sign-out")
    rows = _rows(owner, "SELECT action, details FROM owner_audit ORDER BY id")
    assert [r["action"] for r in rows] == ["created", "code_sent", "signed_in", "signed_out"]
    for r in rows:
        assert "@" not in r["details"] and "ada" not in r["details"].lower()
