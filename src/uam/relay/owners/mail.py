"""Owner email (P2g-1): an outbox in the database, sent through Resend.

The owner code calls a *sink* when something should be emailed: a sign-in
code, an agent asking for an owner or to be linked, a reserved name, an
invitation, or news about a contact. Sinks are plain functions called right after a commit, so
they must not write to the database themselves (on SQLite the caller may
still hold a read). The :class:`Mailer`'s sinks only put the email on an
in-memory queue; its task writes each one to ``owner_mail`` within moments,
then sends what is due.

Recipients and contents are encrypted with the email key. Retries back off
up to a kind's age limit (a sign-in code is useless after 10 minutes), and
each send carries an idempotency key so a retry never mails twice. Rows are
deleted 7 days after they were sent or given up.

The text is plain: it says who, what and until when, names people by the
email YouAM checked, and never repeats anything an agent wrote.
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Protocol

import httpx
from sqlalchemy import delete, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from uam.db.models import OwnerMail
from uam.relay.owners.crypto import EmailVault

log = logging.getLogger(__name__)

RESEND_URL = "https://api.resend.com/emails"
#: How long each kind is worth trying; past it the email is given up.
MAX_AGE = {"sign_in_code": timedelta(minutes=10)}
DEFAULT_MAX_AGE = timedelta(hours=20)  # inside Resend's 24-hour idempotency window
#: Waits between tries (the last repeats).
BACKOFF = (timedelta(seconds=20), timedelta(minutes=1), timedelta(minutes=5),
           timedelta(minutes=20), timedelta(hours=1))
KEEP = timedelta(days=7)
#: How often the task looks for due mail when nothing wakes it.
TICK = 15.0
PURGE_EVERY = timedelta(hours=1)
BATCH = 50

_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun",
           "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


# --------------------------------------------------------------------------- the text


def _day(stamp: str | None) -> str:
    """"12 Nov 2026" from an ISO time, or "" if there isn't one."""
    if not stamp:
        return ""
    try:
        at = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
    except ValueError:
        return ""
    return f"{at.day} {_MONTHS[at.month - 1]} {at.year}"


def _footer(origin: str) -> str:
    host = origin.split("://", 1)[-1]
    return f"\n\n--\nYouAM · {host}"


def render(kind: str, data: dict[str, Any], origin: str) -> tuple[str, str]:
    """(subject, plain text) for one email. KeyError for an unknown kind."""
    page = origin + "/"
    if kind == "sign_in_code":
        return ("Your YouAM sign-in code", (
            f"Your code is {data['code']}. It works for 10 minutes.\n\n"
            "If you didn't ask to sign in to YouAM, you can ignore this email."
        ) + _footer(origin))
    if kind == "owner_request":
        until = _day(data.get("expiresAt"))
        return ("An agent asked you to be its owner on YouAM", (
            f"The agent \"{data['agent']}\" asked you to be its owner on YouAM.\n\n"
            f"It shows these four words: {' '.join(data['words'])}\n"
            "Check they match what it shows where it runs before you approve.\n\n"
            f"Approve or decline{f' by {until}' if until else ''}:\n{data['url']}\n\n"
            "If you don't know this agent, ignore this email. To stop agents asking "
            f"at this address:\n{data['neverUrl']}"
        ) + _footer(origin))
    if kind == "name_reserved":
        until = _day(data.get("expiresAt"))
        return (f"Confirm your YouAM name {data['address']}", (
            f"Someone reserved \"{data['address']}\" on YouAM with this email.\n\n"
            f"To keep it, confirm{f' by {until}' if until else ''}:\n{data['url']}\n\n"
            "If it wasn't you, ignore this email and the name is released. To stop "
            f"emails like this:\n{data['neverUrl']}"
        ) + _footer(origin))
    if kind == "invite":
        return (f"{data['inviter']} invited you to connect on YouAM", (
            f"{data['inviter']} invited you to connect on YouAM, so your AI agents "
            "can message each other.\n\n"
            f"Open the invitation (it works once):\n{data['link']}\n\n"
            "You'll both see four words. Check they match before you connect.\n\n"
            "If you don't know them, ignore this email."
        ) + _footer(origin))
    if kind == "invite_redeemed":
        who = data["email"]
        if data.get("connected"):
            return (f"{who} accepted your invitation", (
                f"{who} accepted your invitation on YouAM. You're connected: your "
                "shared agents can message each other.\n\n"
                f"Your contacts:\n{page}"
            ) + _footer(origin))
        return (f"{who} accepted your invitation: confirm them", (
            f"{who} accepted your invitation on YouAM.\n\n"
            "Ask them which four words they see, and confirm only if they match "
            f"yours:\n{page}"
        ) + _footer(origin))
    if kind == "invite_reused":
        return ("Someone tried to use your YouAM invitation again", (
            "An invitation you made was already used, and someone just tried to use "
            "it again. Nothing changed: an invitation works once.\n\n"
            "If you sent it to only one person, it may have been passed on. You can "
            f"check and remove contacts here:\n{page}"
        ) + _footer(origin))
    if kind == "contact_confirmed":
        who = data["email"]
        return (f"You're connected with {who} on YouAM", (
            f"{who} confirmed you. Your shared agents can now message each other.\n\n"
            f"Your contacts:\n{page}"
        ) + _footer(origin))
    if kind == "link_requested":
        until = _day(data.get("effectiveAt"))
        return ("An agent asked to be linked to your YouAM account", (
            f"The agent \"{data['agent']}\" asked to be linked to your YouAM account.\n\n"
            f"It will be linked{f' on {until}' if until else ''} unless you cancel it. "
            f"If you didn't ask for this, cancel it here:\n{page}"
        ) + _footer(origin))
    if kind == "link_cancelled":
        return ("An agent cancelled its link to your YouAM account", (
            f"The agent \"{data['agent']}\" cancelled its request to be linked to your "
            "YouAM account. Nothing else changed.\n\n"
            f"Your agents:\n{page}"
        ) + _footer(origin))
    raise KeyError(kind)


#: Contact events the owner code reports, and the email each one sends.
NOTICES = {"invite_redeemed", "invite_reused", "contact_confirmed"}


# --------------------------------------------------------------------------- sending


class Retry(Exception):
    """Sending failed in a way that may pass (network, 429, 5xx, a key problem)."""


class GiveUp(Exception):
    """Sending failed for good (Resend refused this email)."""


class Transport(Protocol):
    async def send(self, *, to: str, subject: str, text: str, key: str) -> str: ...


class ResendTransport:
    """Resend's send-email API. *key* is the idempotency key."""

    def __init__(self, api_key: str, sender: str, client: httpx.AsyncClient | None = None):
        self._api_key = api_key
        self._sender = sender
        self._client = client

    async def send(self, *, to: str, subject: str, text: str, key: str) -> str:
        body = {"from": self._sender, "to": [to], "subject": subject, "text": text}
        headers = {"Authorization": f"Bearer {self._api_key}", "Idempotency-Key": key}
        try:
            if self._client is not None:
                r = await self._client.post(RESEND_URL, json=body, headers=headers)
            else:
                async with httpx.AsyncClient(timeout=15.0) as client:
                    r = await client.post(RESEND_URL, json=body, headers=headers)
        except httpx.HTTPError as exc:
            raise Retry(f"network {type(exc).__name__}") from None
        if 200 <= r.status_code < 300:
            try:
                return str(r.json().get("id", ""))
            except ValueError:
                return ""
        try:
            name = str(r.json().get("name", ""))[:60]
        except ValueError:
            name = ""
        reason = f"http {r.status_code} {name}".strip()
        # 401/403: our key or domain is wrong; fixable, so keep trying until the age limit.
        if r.status_code in (401, 403, 408, 409, 429) or r.status_code >= 500:
            raise Retry(reason)
        raise GiveUp(reason)


# --------------------------------------------------------------------------- the outbox


@dataclass
class _Queued:
    kind: str
    to: str | None
    owner_pk: int | None
    data: dict[str, Any]


class Mailer:
    """Owns the outbox: sinks that queue, and the task that stores and sends."""

    def __init__(self, vault: EmailVault, transport: Transport, origin: str,
                 factory: Callable[[], AsyncSession] | None = None) -> None:
        self._vault = vault
        self._transport = transport
        self._origin = origin
        self._factory = factory
        self._pending: list[_Queued] = []
        self._wake = asyncio.Event()
        self._last_purge: datetime | None = None

    # -- sinks (plain functions; called after a commit) --

    def _put(self, item: _Queued) -> None:
        self._pending.append(item)
        self._wake.set()

    def add(self, session: AsyncSession, kind: str, to: str, owner_pk: int | None,
            data: dict[str, Any]) -> None:
        """Add an email to *session*, to be committed with the caller's change.
        For background work only: a request's sink must not write (see above)."""
        render(kind, data, self._origin)  # KeyError now, not at send time
        session.add(OwnerMail(
            kind=kind, owner_pk=owner_pk, to_enc=self._vault.encrypt(to),
            data_enc=self._vault.seal(json.dumps(data)), next_try_at=utcnow(),
        ))

    def poke(self) -> None:
        """Wake the task to send what was just committed."""
        self._wake.set()

    def code(self, owner_pk: int, email: str, code: str) -> None:
        self._put(_Queued("sign_in_code", email, owner_pk, {"code": code}))

    def request(self, email: str, message: dict[str, Any]) -> None:
        self._put(_Queued("owner_request", email, None, dict(message)))

    def reservation(self, email: str, message: dict[str, Any]) -> None:
        self._put(_Queued("name_reserved", email, None, dict(message)))

    def invite(self, to: str, link: str, inviter: str) -> None:
        self._put(_Queued("invite", to, None, {"link": link, "inviter": inviter}))

    def link(self, owner_pk: int, link: dict[str, Any]) -> None:
        kind = "link_cancelled" if link.get("state") == "cancelled" else "link_requested"
        data = {"agent": link["agent"], "effectiveAt": link.get("effectiveAt")}
        self._put(_Queued(kind, None, owner_pk, data))

    def notice(self, owner_pk: int, event: str, details: dict[str, Any]) -> None:
        if event not in NOTICES:
            log.warning("no email for owner event %s", event)
            return
        data = {k: v for k, v in details.items() if k in ("email", "connected")}
        self._put(_Queued(event, None, owner_pk, data))

    # -- the task --

    async def _session(self) -> AsyncSession:
        if self._factory is not None:
            return self._factory()
        from uam.db.engine import get_engine
        from uam.db.session import async_session_factory

        return async_session_factory(get_engine())()

    async def store(self, session: AsyncSession) -> int:
        """Write queued emails to the outbox. Returns how many."""
        items, self._pending = self._pending, []
        stored = 0
        for item in items:
            to = item.to
            if to is None:
                from uam.relay.owners.contacts import _email_of

                try:
                    to = await _email_of(session, self._vault, item.owner_pk)
                except Exception:
                    log.exception("no email for owner %s (%s)", item.owner_pk, item.kind)
                    continue
            self.add(session, item.kind, to, item.owner_pk, item.data)
            stored += 1
        if stored:
            await session.commit()
        return stored

    async def send_due(self, session: AsyncSession) -> int:
        """Send what is due. Returns how many were sent."""
        now = utcnow()
        rows = (await session.execute(
            select(OwnerMail)
            .where(OwnerMail.sent_at.is_(None), OwnerMail.failed_at.is_(None),
                   OwnerMail.next_try_at <= now)
            .order_by(OwnerMail.id).limit(BATCH)
        )).scalars().all()
        sent = 0
        for row in rows:
            sent += await self._send_one(session, row, now)
        return sent

    async def _send_one(self, session: AsyncSession, row: OwnerMail, now: datetime) -> int:
        tries = row.attempts
        wait = BACKOFF[min(tries, len(BACKOFF) - 1)]
        # Claim it: only one sender moves next_try_at on from what it read.
        claimed = await session.execute(
            update(OwnerMail)
            .where(OwnerMail.id == row.id, OwnerMail.attempts == tries,
                   OwnerMail.sent_at.is_(None), OwnerMail.failed_at.is_(None))
            .values(attempts=tries + 1, next_try_at=now + wait)
        )
        await session.commit()
        if claimed.rowcount != 1:
            return 0
        too_old = now - _aware(row.created_at) > MAX_AGE.get(row.kind, DEFAULT_MAX_AGE)
        try:
            to = self._vault.decrypt(row.to_enc)
            subject, text = render(row.kind, json.loads(self._vault.unseal(row.data_enc)),
                                   self._origin)
        except Exception:
            log.exception("owner mail %s can't be read; giving up", row.id)
            await self._finish(session, row.id, failed=now, error="unreadable")
            return 0
        if too_old:
            await self._finish(session, row.id, failed=now, error=row.last_error or "too old")
            log.warning("owner mail %s (%s) given up after %d tries: %s",
                        row.id, row.kind, tries, row.last_error)
            return 0
        try:
            provider_id = await self._transport.send(
                to=to, subject=subject, text=text, key=f"uam-owner-mail-{row.id}")
        except GiveUp as exc:
            log.error("owner mail %s (%s) refused: %s", row.id, row.kind, exc)
            await self._finish(session, row.id, failed=utcnow(), error=str(exc)[:120])
            return 0
        except Retry as exc:
            log.warning("owner mail %s (%s) will be retried: %s", row.id, row.kind, exc)
            await self._finish(session, row.id, error=str(exc)[:120])
            return 0
        await self._finish(session, row.id, sent=utcnow(), provider_id=provider_id[:100])
        return 1

    async def _finish(self, session: AsyncSession, mail_id: int, *, sent: datetime | None = None,
                      failed: datetime | None = None, error: str | None = None,
                      provider_id: str | None = None) -> None:
        values: dict[str, Any] = {}
        if sent is not None:
            values.update(sent_at=sent, provider_id=provider_id, last_error=None)
        if failed is not None:
            values["failed_at"] = failed
        if error is not None:
            values["last_error"] = error
        await session.execute(update(OwnerMail).where(OwnerMail.id == mail_id).values(**values))
        await session.commit()

    async def purge(self, session: AsyncSession) -> int:
        """Delete mail sent or given up more than 7 days ago."""
        before = utcnow() - KEEP
        result = await session.execute(
            delete(OwnerMail).where(or_(OwnerMail.sent_at < before, OwnerMail.failed_at < before))
        )
        await session.commit()
        return result.rowcount or 0

    async def once(self) -> int:
        """Store what's queued, send what's due, and purge hourly. Returns sent."""
        async with await self._session() as session:
            await self.store(session)
            sent = await self.send_due(session)
            now = utcnow()
            if self._last_purge is None or now - self._last_purge >= PURGE_EVERY:
                await self.purge(session)
                self._last_purge = now
            return sent

    async def run(self) -> None:
        """The relay's mail task: wakes when something is queued, else every TICK."""
        try:
            while True:
                try:
                    await asyncio.wait_for(self._wake.wait(), timeout=TICK)
                except asyncio.TimeoutError:
                    pass
                self._wake.clear()
                try:
                    await self.once()
                except asyncio.CancelledError:
                    raise
                except Exception:
                    log.exception("owner mail task failed; will try again")
        finally:
            if self._pending:
                # Queued in the last moments before shutdown, never stored.
                log.warning("owner mail: %d email(s) not stored at shutdown", len(self._pending))
