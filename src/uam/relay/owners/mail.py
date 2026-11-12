"""Owner email (P2g-1): an outbox in the database, sent through Resend.

The owner code calls a *sink* when something should be emailed: a sign-in
code, an agent asking for an owner or to be linked, a reserved name, an
invitation, news about a contact, or a frozen or closed account. Sinks
are plain functions called right after a commit, so they must not write
to the database themselves (on SQLite the caller may still hold a read). The :class:`Mailer`'s sinks only put the email on an
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
import html
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


def _host(origin: str) -> str:
    return origin.split("://", 1)[-1]


def _footer(origin: str) -> str:
    return f"\n\n--\nYouAM · {_host(origin)}"


# Each email is a subject, a heading and a list of blocks. The plain text
# and the HTML are both made from the blocks, so they say the same thing.


@dataclass(frozen=True)
class P:
    """A paragraph."""
    text: str


@dataclass(frozen=True)
class Code:
    """A sign-in code, shown large."""
    code: str
    note: str


@dataclass(frozen=True)
class Words:
    """The four words to compare."""
    lead: str
    words: tuple[str, ...]


@dataclass(frozen=True)
class Button:
    """The one thing to do. *lead*, if any, says why or by when, in both versions;
    without one the plain text uses the label."""
    label: str
    url: str
    lead: str | None = None


@dataclass(frozen=True)
class Note:
    """Small print, with a link if there is one."""
    text: str
    url: str | None = None


Block = P | Code | Words | Button | Note


@dataclass(frozen=True)
class Email:
    subject: str
    heading: str
    blocks: tuple[Block, ...]


def compose(kind: str, data: dict[str, Any], origin: str) -> Email:
    """The email for *kind*. KeyError for an unknown kind."""
    page = origin + "/"
    if kind == "sign_in_code":
        return Email("Your YouAM sign-in code", "Your sign-in code", (
            Code(data["code"], "It works for 10 minutes."),
            Note("If you didn't ask to sign in to YouAM, you can ignore this email."),
        ))
    if kind == "owner_request":
        until = _day(data.get("expiresAt"))
        return Email("An agent asked you to be its owner on YouAM",
                     "An agent asked you to be its owner", (
            P(f"The agent \"{data['agent']}\" asked you to be its owner on YouAM."),
            Words("It shows these four words", tuple(data["words"])),
            P("Check they match what it shows where it runs before you approve."),
            Button("Review the request", data["url"],
                   f"Approve or decline{f' by {until}' if until else ''}"),
            Note("If you don't know this agent, ignore this email. To stop agents asking "
                 "at this address", data["neverUrl"]),
        ))
    if kind == "name_reserved":
        until = _day(data.get("expiresAt"))
        return Email(f"Confirm your YouAM name {data['address']}", "Confirm your name", (
            P(f"Someone reserved \"{data['address']}\" on YouAM with this email."),
            Button("Keep this name", data["url"],
                   f"To keep it, confirm{f' by {until}' if until else ''}"),
            Note("If it wasn't you, ignore this email and the name is released. To stop "
                 "emails like this", data["neverUrl"]),
        ))
    if kind == "invite":
        inviter = data["inviter"]
        return Email(f"{inviter} invited you to connect on YouAM", "You're invited to connect", (
            P(f"{inviter} invited you to connect on YouAM, so your AI agents can message "
              "each other."),
            P("You'll both see four words. Check they match before you connect. "
              "The invitation works once."),
            Button("Open the invitation", data["link"]),
            Note("If you don't know them, ignore this email."),
        ))
    if kind == "invite_redeemed":
        who = data["email"]
        if data.get("connected"):
            return Email(f"{who} accepted your invitation", "Invitation accepted", (
                P(f"{who} accepted your invitation on YouAM. You're connected: your "
                  "shared agents can message each other."),
                Button("See your contacts", page),
            ))
        return Email(f"{who} accepted your invitation: confirm them", "Confirm your new contact", (
            P(f"{who} accepted your invitation on YouAM."),
            Button("Confirm them", page, "Ask them which four words they see, and confirm "
                   "only if they match yours"),
        ))
    if kind == "invite_reused":
        return Email("Someone tried to use your YouAM invitation again",
                     "Your invitation was used again", (
            P("An invitation you made was already used, and someone just tried to use "
              "it again. Nothing changed: an invitation works once."),
            Button("Check your contacts", page, "If you sent it to only one person, it may "
                   "have been passed on. You can check and remove contacts here"),
        ))
    if kind == "contact_confirmed":
        who = data["email"]
        return Email(f"You're connected with {who} on YouAM", "You're connected", (
            P(f"{who} confirmed you. Your shared agents can now message each other."),
            Button("See your contacts", page),
        ))
    if kind == "link_requested":
        until = _day(data.get("effectiveAt"))
        return Email("An agent asked to be linked to your YouAM account",
                     "An agent asked to be linked", (
            P(f"The agent \"{data['agent']}\" asked to be linked to your YouAM account."),
            P(f"It will be linked{f' on {until}' if until else ''} unless you cancel it."),
            Button("Review it", page, "If you didn't ask for this, cancel it here"),
        ))
    if kind == "link_cancelled":
        return Email("An agent cancelled its link to your YouAM account",
                     "An agent cancelled its link", (
            P(f"The agent \"{data['agent']}\" cancelled its request to be linked to your "
              "YouAM account. Nothing else changed."),
            Button("See your agents", page),
        ))
    if kind == "account_frozen":
        until = _day(data.get("closesAt"))
        return Email("Your YouAM account is frozen", "Your account is frozen", (
            P("Your YouAM account was frozen because you lost your passkeys and asked "
              "to start again. Nobody can sign in to it now."),
            P(f"{f'On {until}' if until else 'In 72 hours'} it closes: your agents are "
              "unlinked and your contacts end. Then you can make a new account with this "
              "email and link your agents again with setup codes."),
            Button("Keep my account", data["keepUrl"],
                   "If you didn't ask for this, keep your account"),
        ))
    if kind == "account_closed":
        return Email("Your old YouAM account is closed", "Your old account is closed", (
            P("Your old YouAM account is closed. You can make a new one with this email."),
            Button("Make a new account", data["url"]),
            P("Then add a passkey on each device you use, link your agents with a "
              "setup code from your account page, and invite your contacts again."),
        ))
    raise KeyError(kind)


def _text_block(block: Block) -> str:
    if isinstance(block, Code):
        return f"Your code is {block.code}. {block.note}"
    if isinstance(block, Words):
        return f"{block.lead}: {' '.join(block.words)}"
    if isinstance(block, Button):
        return f"{block.lead or block.label}:\n{block.url}"
    if isinstance(block, Note):
        return f"{block.text}:\n{block.url}" if block.url else block.text
    return block.text


def render(kind: str, data: dict[str, Any], origin: str) -> tuple[str, str]:
    """(subject, plain text) for one email. KeyError for an unknown kind."""
    email = compose(kind, data, origin)
    return email.subject, "\n\n".join(_text_block(b) for b in email.blocks) + _footer(origin)


# --------------------------------------------------------------------------- the HTML

# Inline styles and tables only: that is what mail apps render the same way.
# Everything that came from a person (an agent's name, an email) is escaped.
_INK, _SOFT, _FAINT, _RULE, _WASH = "#18181b", "#52525b", "#a1a1aa", "#e4e4e7", "#f4f4f5"
_FONT = ("-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif")
_MONO = "ui-monospace,SFMono-Regular,Menlo,Consolas,monospace"


def _e(value: str) -> str:
    return html.escape(value, quote=True)


def _mark() -> str:
    """The YouAM mark (four squares) and name, drawn without an image."""
    sq = f'<td width="7" height="7" style="width:7px;height:7px;background:{_INK};font-size:0;line-height:0">&nbsp;</td>'
    gap = '<td width="3" style="width:3px;font-size:0;line-height:0">&nbsp;</td>'
    row = f"<tr>{sq}{gap}{sq}</tr>"
    space = '<tr><td colspan="3" height="3" style="height:3px;font-size:0;line-height:0">&nbsp;</td></tr>'
    squares = (f'<table role="presentation" cellpadding="0" cellspacing="0" border="0">'
               f"{row}{space}{row}</table>")
    return (
        '<table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr>'
        f'<td style="vertical-align:middle;padding-right:8px">{squares}</td>'
        f'<td style="vertical-align:middle;font:700 20px/1 {_FONT};color:{_INK};'
        'letter-spacing:-0.5px">YouAM</td></tr></table>'
    )


def _html_block(block: Block) -> str:
    p = f"margin:0 0 16px;font:400 15px/1.6 {_FONT};color:{_SOFT}"
    if isinstance(block, Code):
        return (
            f'<p style="margin:0 0 8px;font:600 34px/1.2 {_MONO};color:{_INK};'
            f'letter-spacing:8px;background:{_WASH};border-radius:12px;padding:18px 0;'
            f'text-align:center">{_e(block.code)}</p>'
            f'<p style="{p};text-align:center">{_e(block.note)}</p>'
        )
    if isinstance(block, Words):
        words = "".join(
            f'<td style="padding:4px"><span style="display:inline-block;padding:8px 12px;'
            f'border-radius:8px;background:{_WASH};font:500 15px/1 {_MONO};color:{_INK}">'
            f"{_e(w)}</span></td>"
            for w in block.words
        )
        return (
            f'<p style="margin:0 0 8px;font:500 13px/1.4 {_FONT};color:{_FAINT};'
            f'text-transform:uppercase;letter-spacing:0.6px">{_e(block.lead)}</p>'
            '<table role="presentation" cellpadding="0" cellspacing="0" border="0" '
            f'style="margin:0 0 16px -4px"><tr>{words}</tr></table>'
        )
    if isinstance(block, Button):
        lead = f'<p style="{p}">{_e(block.lead)}.</p>' if block.lead else ""
        return lead + (
            '<table role="presentation" cellpadding="0" cellspacing="0" border="0" '
            'style="margin:8px 0 24px"><tr>'
            f'<td style="border-radius:10px;background:{_INK}">'
            f'<a href="{_e(block.url)}" style="display:inline-block;padding:14px 26px;'
            f'font:600 15px/1 {_FONT};color:#ffffff;text-decoration:none;border-radius:10px">'
            f"{_e(block.label)}</a></td></tr></table>"
        )
    if isinstance(block, Note):
        link = (f'<br><a href="{_e(block.url)}" style="color:{_SOFT};text-decoration:underline;'
                f'word-break:break-all">{_e(block.url)}</a>' if block.url else "")
        return (f'<p style="margin:0 0 12px;font:400 13px/1.5 {_FONT};color:{_FAINT}">'
                f"{_e(block.text)}{':' if block.url else ''}{link}</p>")
    return f'<p style="{p}">{_e(block.text)}</p>'


def render_html(kind: str, data: dict[str, Any], origin: str) -> str:
    """The HTML for one email. KeyError for an unknown kind."""
    email = compose(kind, data, origin)
    first = next((b.text for b in email.blocks if isinstance(b, P)), email.heading)
    button = next((b for b in email.blocks if isinstance(b, Button)), None)
    # Where the button goes, spelled out for mail apps that hide buttons.
    fallback = (
        f'<p style="margin:0;font:400 12px/1.5 {_FONT};color:{_FAINT}">'
        f'Button not working? Open this link:<br><a href="{_e(button.url)}" '
        f'style="color:{_SOFT};word-break:break-all">{_e(button.url)}</a></p>'
        if button else ""
    )
    body = "".join(_html_block(b) for b in email.blocks)
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<meta name="color-scheme" content="light"><meta name="supported-color-schemes" content="light">'
        f"<title>{_e(email.subject)}</title></head>"
        f'<body style="margin:0;padding:0;background:{_WASH}">'
        # The preview line mail apps show next to the subject.
        f'<div style="display:none;max-height:0;overflow:hidden;opacity:0">{_e(first)}</div>'
        f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" '
        f'style="background:{_WASH}"><tr><td align="center" style="padding:32px 16px">'
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" '
        'style="max-width:520px">'
        f'<tr><td style="padding:0 4px 20px">{_mark()}</td></tr>'
        f'<tr><td style="background:#ffffff;border:1px solid {_RULE};border-radius:16px;'
        'overflow:hidden">'
        # A thin band in the site's colours.
        '<div style="height:4px;background:#8b5cf6;'
        'background-image:linear-gradient(90deg,#8b5cf6,#e879f9,#34d399)"></div>'
        '<div style="padding:32px 32px 28px">'
        f'<h1 style="margin:0 0 16px;font:700 22px/1.3 {_FONT};color:{_INK};'
        f'letter-spacing:-0.3px">{_e(email.heading)}</h1>'
        f"{body}{fallback}</div></td></tr>"
        f'<tr><td style="padding:20px 4px 0;font:400 12px/1.5 {_FONT};color:{_FAINT}">'
        f"YouAM · {_e(_host(origin))}<br>Agents that message only with their owners' say-so."
        "</td></tr></table></td></tr></table></body></html>"
    )


#: Contact events the owner code reports, and the email each one sends.
NOTICES = {"invite_redeemed", "invite_reused", "contact_confirmed"}


# --------------------------------------------------------------------------- sending


class Retry(Exception):
    """Sending failed in a way that may pass (network, 429, 5xx, a key problem)."""


class GiveUp(Exception):
    """Sending failed for good (Resend refused this email)."""


class Transport(Protocol):
    async def send(self, *, to: str, subject: str, text: str, key: str,
                   html: str | None = None) -> str: ...


class ResendTransport:
    """Resend's send-email API. *key* is the idempotency key."""

    def __init__(self, api_key: str, sender: str, client: httpx.AsyncClient | None = None):
        self._api_key = api_key
        self._sender = sender
        self._client = client

    async def send(self, *, to: str, subject: str, text: str, key: str,
                   html: str | None = None) -> str:
        body = {"from": self._sender, "to": [to], "subject": subject, "text": text}
        if html is not None:
            body["html"] = html
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
        For background work, or a change the caller is already writing (a
        frozen account); a sink must not write (see above)."""
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
            data = json.loads(self._vault.unseal(row.data_enc))
            subject, text = render(row.kind, data, self._origin)
            page = render_html(row.kind, data, self._origin)
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
                to=to, subject=subject, text=text, html=page, key=f"uam-owner-mail-{row.id}")
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
