"""Shared fixtures for the owner tests (accounts, passkeys, key log)."""

from __future__ import annotations

import base64
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

ADMIN_KEY = "admin-key-for-owner-tests-0123456789"
OWNER_ORIGIN = "https://account.test.local"
EMAIL = "Ada@Example.com"
PEPPER = "owner-email-pepper-for-tests-0123456789"
KEY = base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip("=")
COOKIE = "__Host-uam_owner"

OWNER_ENV = {
    "UAM_ADMIN_API_KEY": ADMIN_KEY,
    "UAM_OWNERS_ENABLED": "true",
    "UAM_OWNER_ORIGIN": OWNER_ORIGIN,
    "UAM_RP_ID": "test.local",
    "UAM_EMAIL_PEPPER": PEPPER,
    "UAM_EMAIL_KEY": KEY,
}


@pytest.fixture()
def owner_env(monkeypatch):
    for name, value in OWNER_ENV.items():
        monkeypatch.setenv(name, value)


@pytest.fixture()
def codes():
    return []


@pytest.fixture()
def relay(owner_env, app, codes):
    app.state.owner_code_sink = lambda owner_pk, email, code: codes.append((owner_pk, email, code))
    with TestClient(app) as c:
        yield c


def _on_owner_host(app, started, origin=OWNER_ORIGIN):
    """A client on the owner host that runs on *started*'s event loop.

    A TestClient outside ``with`` otherwise makes a new loop per request,
    and Postgres (asyncpg) connections only work on the loop that opened
    them. *origin* None sends no Origin header."""
    c = TestClient(app, base_url=OWNER_ORIGIN, headers={"Origin": origin} if origin else {})
    c.portal = started.portal
    return c


@pytest.fixture()
def owner(relay, app):
    """A client on the owner origin (same app, the owner host)."""
    return _on_owner_host(app, relay)


@pytest.fixture()
def clock(monkeypatch):
    """Moves the owner service's clock forward."""
    from uam.relay.owners import service

    real = service.utcnow
    state = {"offset": timedelta(0)}
    monkeypatch.setattr(service, "utcnow", lambda: real() + state["offset"])

    def advance(**kwargs):
        state["offset"] += timedelta(**kwargs)

    return advance


def _admin():
    return {"X-Admin-Key": ADMIN_KEY}


def _create(relay, email=EMAIL):
    return relay.post("/api/v1/admin/owners", json={"email": email}, headers=_admin())


def _rows(client, sql, **params):
    import uam.db.session as sess

    async def run():
        async with sess._session_factory() as s:
            return [dict(r._mapping) for r in await s.execute(text(sql), params)]

    return client.portal.call(run)


def _exec(client, sql, **params):
    import uam.db.session as sess

    async def run():
        async with sess._session_factory() as s:
            await s.execute(text(sql), params)
            await s.commit()

    client.portal.call(run)


def _sign_in(relay, owner, codes, email=EMAIL):
    assert _create(relay, email).status_code == 201
    assert owner.post("/api/owner/sign-in/start", json={"email": email}).status_code == 202
    resp = owner.post("/api/owner/sign-in/finish", json={"email": email, "code": codes[-1][2]})
    assert resp.status_code == 200, resp.text
    return resp
