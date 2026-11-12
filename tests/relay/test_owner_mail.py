"""Owner email (P2g-1): the outbox, the Resend transport, and the text.

Emails go through ``owner_mail`` (recipient and contents encrypted), sent by
the relay's mail task. These tests swap Resend for a fake transport; no test
sends real email.
"""

from __future__ import annotations

import asyncio
import json
import re
import time
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from fastapi.testclient import TestClient

from tests.relay._owner_fixtures import (  # noqa: F401  (fixtures)
    EMAIL,
    OWNER_ORIGIN,
    _admin,
    _create,
    _exec,
    _on_owner_host,
    _rows,
    owner_env,
)
from uam.relay.owners.mail import GiveUp, ResendTransport, Retry, render


class FakeTransport:
    """Records what would have been sent; *fail* is a list of exceptions to raise first."""

    def __init__(self) -> None:
        self.sent: list[dict] = []
        self.fail: list[Exception] = []
        self.keys: list[str] = []

    async def send(self, *, to, subject, text, key):
        self.keys.append(key)
        if self.fail:
            raise self.fail.pop(0)
        self.sent.append({"to": to, "subject": subject, "text": text, "key": key})
        return f"resend-{len(self.sent)}"


@pytest.fixture()
def transport():
    return FakeTransport()


@pytest.fixture()
def relay(owner_env, app, transport):  # noqa: F811  (replaces the shared relay fixture)
    app.state.owner_mail_transport = transport
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def owner(relay, app):
    return _on_owner_host(app, relay)


def _wait(predicate, seconds=5.0):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if predicate():
            return True
        time.sleep(0.05)
    return False


def _first(relay, column):
    """The first outbox row's *column*, or None while nothing is stored yet."""
    rows = _rows(relay, f"SELECT {column} FROM owner_mail ORDER BY id")
    return rows[0][column] if rows else None


def _mailer(app):
    return app.state.owner_mailer


def _once(relay, app):
    return relay.portal.call(_mailer(app).once)


def _call(relay, sink, *args):
    """Call a sink on the relay's event loop, as the relay does."""
    relay.portal.call(lambda: sink(*args))


# ------------------------------------------------------------------ end to end


def test_a_sign_in_code_arrives_by_email_and_signs_in(relay, owner, transport):
    assert _create(relay).status_code == 201
    assert owner.post("/api/owner/sign-in/start", json={"email": EMAIL}).status_code == 202
    assert _wait(lambda: transport.sent), "no email sent"
    [mail] = transport.sent
    assert mail["to"] == EMAIL.lower()
    assert mail["subject"] == "Your YouAM sign-in code"
    code = re.search(r"Your code is (\d{6})\.", mail["text"]).group(1)
    resp = owner.post("/api/owner/sign-in/finish", json={"email": EMAIL, "code": code})
    assert resp.status_code == 200, resp.text


def test_the_outbox_keeps_neither_the_address_nor_the_code_in_the_clear(relay, owner, transport):
    _create(relay)
    owner.post("/api/owner/sign-in/start", json={"email": EMAIL})
    assert _wait(lambda: transport.sent)
    code = re.search(r"(\d{6})", transport.sent[0]["text"]).group(1)
    assert _wait(lambda: _first(relay, "sent_at") is not None)
    [row] = _rows(relay, "SELECT * FROM owner_mail")
    assert row["kind"] == "sign_in_code"
    assert row["owner_pk"] is not None
    assert row["provider_id"] == "resend-1"
    stored = json.dumps({k: str(v) for k, v in row.items()})
    assert "example.com" not in stored.lower()
    assert code not in stored


def test_without_a_key_or_transport_there_is_no_mailer(owner_env, app):  # noqa: F811
    with TestClient(app):
        assert app.state.owner_mailer is None


# ------------------------------------------------------------------ retries


def test_a_retry_tries_again_with_the_same_key(relay, app, transport):
    transport.fail = [Retry("http 503")]
    _call(relay, _mailer(app).code, None, "ada@example.com", "123456")
    assert _wait(lambda: len(transport.keys) == 1)
    assert _wait(lambda: _first(relay, "last_error"))
    [row] = _rows(relay, "SELECT attempts, sent_at, failed_at, last_error FROM owner_mail")
    assert row["attempts"] == 1 and row["sent_at"] is None and row["failed_at"] is None
    assert row["last_error"] == "http 503"
    _exec(relay, "UPDATE owner_mail SET next_try_at = :t",
          t=datetime.now(timezone.utc) - timedelta(seconds=1))
    _once(relay, app)
    assert _wait(lambda: transport.sent)
    assert transport.keys[0] == transport.keys[-1] == transport.sent[0]["key"]
    [row] = _rows(relay, "SELECT attempts, sent_at, last_error FROM owner_mail")
    assert row["sent_at"] is not None and row["last_error"] is None


def test_a_refused_email_is_given_up(relay, app, transport):
    transport.fail = [GiveUp("http 422 validation_error")]
    _call(relay, _mailer(app).code, None, "ada@example.com", "123456")
    assert _wait(lambda: _first(relay, "failed_at"))
    [row] = _rows(relay, "SELECT sent_at, last_error FROM owner_mail")
    assert row["sent_at"] is None and row["last_error"] == "http 422 validation_error"
    _exec(relay, "UPDATE owner_mail SET next_try_at = :t",
          t=datetime.now(timezone.utc) - timedelta(seconds=1))
    _once(relay, app)
    assert len(transport.keys) == 1


def test_a_code_too_old_to_use_is_not_sent(relay, app, transport):
    transport.fail = [Retry("network ConnectError")]
    _call(relay, _mailer(app).code, None, "ada@example.com", "123456")
    assert _wait(lambda: len(transport.keys) == 1)
    old = datetime.now(timezone.utc) - timedelta(minutes=11)
    _exec(relay, "UPDATE owner_mail SET created_at = :c, next_try_at = :c", c=old)
    _once(relay, app)
    assert _wait(lambda: _first(relay, "failed_at"))
    assert transport.sent == [] and len(transport.keys) == 1


def test_mail_is_deleted_a_week_after_it_was_sent(relay, app, transport):
    for _ in range(2):
        _call(relay, _mailer(app).code, None, "ada@example.com", "123456")
    assert _wait(lambda: len(transport.sent) == 2)
    assert _wait(lambda: (rows := _rows(relay, "SELECT sent_at FROM owner_mail"))
                 and all(r["sent_at"] for r in rows))
    ids = [r["id"] for r in _rows(relay, "SELECT id FROM owner_mail ORDER BY id")]
    _exec(relay, "UPDATE owner_mail SET sent_at = :t WHERE id = :i",
          t=datetime.now(timezone.utc) - timedelta(days=8), i=ids[0])
    _exec(relay, "UPDATE owner_mail SET sent_at = :t WHERE id = :i",
          t=datetime.now(timezone.utc) - timedelta(days=6), i=ids[1])
    assert relay.portal.call(_purge, app) == 1
    assert [r["id"] for r in _rows(relay, "SELECT id FROM owner_mail")] == [ids[1]]


async def _purge(app):
    import uam.db.session as sess

    async with sess._session_factory() as s:
        return await app.state.owner_mailer.purge(s)


# ------------------------------------------------------------------ notices


def _owner_pk(relay):
    return _rows(relay, "SELECT id FROM owners ORDER BY id")[-1]["id"]


def test_contact_news_goes_to_the_owners_email(relay, app, transport):
    _create(relay)
    _call(relay, _mailer(app).notice, _owner_pk(relay), "invite_redeemed",
                        {"invite": 4, "email": "bob@example.com", "connected": False})
    assert _wait(lambda: transport.sent)
    [mail] = transport.sent
    assert mail["to"] == EMAIL.lower()
    assert mail["subject"] == "bob@example.com accepted your invitation: confirm them"
    assert f"{OWNER_ORIGIN}/" in mail["text"]


def test_an_unknown_event_sends_nothing(relay, app, transport):
    _create(relay)
    _call(relay, _mailer(app).notice, _owner_pk(relay), "something_else", {})
    _once(relay, app)
    assert transport.sent == [] and _rows(relay, "SELECT id FROM owner_mail") == []


def test_an_agent_asking_to_be_linked_is_emailed_to_the_owner(relay, app, transport):
    _create(relay)
    _call(relay, _mailer(app).link, _owner_pk(relay), {
        "state": "pending", "agent": "bob::test.local", "effectiveAt": "2026-11-14T10:00:00Z",
    })
    assert _wait(lambda: transport.sent)
    text = transport.sent[0]["text"]
    assert '"bob::test.local" asked to be linked' in text
    assert "linked on 14 Nov 2026 unless you cancel it" in text


# ------------------------------------------------------------------ the text


@pytest.mark.parametrize("kind, data, subject, contains", [
    ("sign_in_code", {"code": "042517"}, "Your YouAM sign-in code", "Your code is 042517."),
    ("owner_request",
     {"agent": "bob::youam.network", "words": ["a", "b", "c", "d"], "via": "email",
      "expiresAt": "2026-11-18T09:00:00Z", "hasAccount": False,
      "url": "https://account.x/#request=T", "neverUrl": "https://account.x/#never=T"},
     "An agent asked you to be its owner on YouAM", "Approve or decline by 18 Nov 2026"),
    ("name_reserved",
     {"name": "ada", "address": "ada::youam.network", "expiresAt": "2026-11-12T09:00:00Z",
      "hasAccount": True, "url": "https://account.x/#reserve=T",
      "neverUrl": "https://account.x/#never=T"},
     "Confirm your YouAM name ada::youam.network", "confirm by 12 Nov 2026"),
    ("invite", {"link": "https://account.x/i/abc#s", "inviter": "ada@x.io"},
     "ada@x.io invited you to connect on YouAM", "https://account.x/i/abc#s"),
    ("invite_redeemed", {"email": "bob@x.io", "connected": True},
     "bob@x.io accepted your invitation", "You're connected"),
    ("invite_reused", {}, "Someone tried to use your YouAM invitation again", "works once"),
    ("contact_confirmed", {"email": "ada@x.io"}, "You're connected with ada@x.io on YouAM",
     "ada@x.io confirmed you"),
    ("link_cancelled", {"agent": "bob::x.io"},
     "An agent cancelled its link to your YouAM account", '"bob::x.io" cancelled'),
])
def test_each_email_says_who_and_what(kind, data, subject, contains):
    got_subject, text = render(kind, data, "https://account.x")
    assert got_subject == subject
    assert contains in text
    assert text.endswith("--\nYouAM · account.x")


def test_an_unknown_kind_has_no_text():
    with pytest.raises(KeyError):
        render("nope", {}, "https://account.x")


# ------------------------------------------------------------------ Resend


def _resend(handler):
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return ResendTransport("re_test_key", "YouAM <account@notify.youam.network>", client)


def test_resend_gets_the_email_with_the_key_and_idempotency_key():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["auth"] = request.headers["authorization"]
        seen["key"] = request.headers["idempotency-key"]
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json={"id": "abc-123"})

    got = asyncio.run(_resend(handler).send(to="ada@x.io", subject="S", text="T", key="uam-1"))
    assert got == "abc-123"
    assert seen["url"] == "https://api.resend.com/emails"
    assert seen["auth"] == "Bearer re_test_key"
    assert seen["key"] == "uam-1"
    assert seen["body"] == {"from": "YouAM <account@notify.youam.network>", "to": ["ada@x.io"],
                            "subject": "S", "text": "T"}


@pytest.mark.parametrize("status, outcome", [
    (429, Retry), (500, Retry), (503, Retry), (401, Retry), (403, Retry), (409, Retry),
    (400, GiveUp), (422, GiveUp),
])
def test_resend_failures_retry_or_give_up(status, outcome):
    def handler(request):
        return httpx.Response(status, json={"name": "some_error", "message": "for ada@x.io"})

    with pytest.raises(outcome) as info:
        asyncio.run(_resend(handler).send(to="ada@x.io", subject="S", text="T", key="k"))
    assert str(info.value) == f"http {status} some_error"
    assert "ada@x.io" not in str(info.value)


def test_a_network_error_is_retried():
    def handler(request):
        raise httpx.ConnectError("down")

    with pytest.raises(Retry, match="network ConnectError"):
        asyncio.run(_resend(handler).send(to="ada@x.io", subject="S", text="T", key="k"))


# ------------------------------------------------------------------ settings


def test_a_production_rp_id_needs_a_resend_key(owner_env, monkeypatch):  # noqa: F811
    from uam.relay.config import Settings

    monkeypatch.setenv("UAM_OWNER_ORIGIN", "https://account.youam.network")
    monkeypatch.setenv("UAM_RP_ID", "youam.network")
    monkeypatch.delenv("UAM_RESEND_API_KEY", raising=False)
    with pytest.raises(RuntimeError, match="UAM_RESEND_API_KEY"):
        Settings()
    monkeypatch.setenv("UAM_RESEND_API_KEY", "re_x")
    assert Settings().resend_api_key == "re_x"


@pytest.mark.parametrize("sender", ['A "B" <a@x.io>', "<a@x.io>", "a@x", "A <a@x.io>\r\nBcc: z@y.io"])
def test_a_bad_sender_is_refused(owner_env, monkeypatch, sender):  # noqa: F811
    from uam.relay.config import Settings

    monkeypatch.setenv("UAM_RESEND_API_KEY", "re_x")
    monkeypatch.setenv("UAM_EMAIL_FROM", sender)
    with pytest.raises(RuntimeError, match="UAM_EMAIL_FROM"):
        Settings()


# ---------------------------------------------------------------- a frozen account (DEC-010)


def _no_memory_queue(app):
    """Fail if an email goes on the in-memory queue: a restart would lose it."""
    def refuse(item):
        raise AssertionError(f"{item.kind} was queued in memory, not stored with its change")

    app.state.owner_mailer._put = refuse


def test_the_frozen_email_is_stored_with_the_freeze(relay, app):
    assert _create(relay).status_code == 201
    _no_memory_queue(app)
    resp = relay.post("/api/v1/admin/owners/freeze", json={"email": EMAIL}, headers=_admin())
    assert resp.status_code == 200, resp.text
    assert [r["kind"] for r in _rows(relay, "SELECT kind FROM owner_mail")] == ["account_frozen"]


def test_the_closed_email_is_stored_with_the_close(relay, app, monkeypatch):
    import uam.db.session as sess
    from uam.relay.owners import freeze, service

    assert _create(relay).status_code == 201
    _no_memory_queue(app)
    relay.post("/api/v1/admin/owners/freeze", json={"email": EMAIL}, headers=_admin())
    later = service.utcnow() + timedelta(hours=73)
    monkeypatch.setattr(service, "utcnow", lambda: later)

    async def run():
        async with sess._session_factory() as s:
            return await freeze.finish_due(s, app)

    assert relay.portal.call(run) == 1
    kinds = [r["kind"] for r in _rows(relay, "SELECT kind FROM owner_mail ORDER BY id")]
    assert kinds == ["account_frozen", "account_closed"]
