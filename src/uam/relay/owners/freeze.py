"""An owner who lost every passkey starts again (DEC-010).

A passkey can't be added without one: each change to an owner's passkeys
is signed by a passkey they already have, and agents check that chain. So
for now an owner who loses them all gets a new account (recovery that keeps
the old one comes later, with renewal):

1. The relay admin, having confirmed the person another way, freezes the
   account by its email. Nobody can sign in to it and its sessions end.
   Its agents and contacts carry on, but nobody can accept its invites.
2. The email is told, with a link that keeps the account until it closes,
   72 hours later. Only the link's hash is kept.
3. Then the account closes. Its agents are unlinked (the relay signs each
   unlink) and links not yet approved are cancelled. The contacts it gave
   and was given end. Its open invites are cancelled, and names held for it
   are released. Its email is forgotten, so the person can make a new
   account with it, and is told so.

Closing is done in steps that can each run again, so one that stops part
way finishes on the next sweep. The account is marked closed first, which
ends the keep link.
"""

from __future__ import annotations

import hashlib
import logging
from collections.abc import Callable
from datetime import timedelta
from typing import Any

from sqlalchemy import delete, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from uam.db.crud import owner_contacts as contact_crud
from uam.db.crud import owner_links as link_crud
from uam.db.crud import owners as owner_crud
from uam.db.models import (
    Owner,
    OwnerEmail,
    OwnerFreeze,
    OwnerGrant,
    OwnerInvite,
    OwnerLink,
    OwnerSession,
    Reservation,
)
from uam.protocol.contacts import INVITE
from uam.relay.owners import links, service
from uam.relay.owners.crypto import new_token
from uam.relay.owners.passkeys import PasskeyError

log = logging.getLogger(__name__)

FREEZE_FOR = timedelta(hours=72)
#: Accounts closed per sweep.
BATCH = 20

#: Where an email about the account goes: (kind, email, data). ``kind`` is
#: ``account_frozen`` (data: keepUrl, closesAt) or ``account_closed`` (url).
AccountNotice = Callable[[str, str, dict[str, Any]], None]


def log_notice(kind: str, email: str, data: dict[str, Any]) -> None:
    """UAM_OWNER_CODES_TO_LOG: the link, never the email."""
    log.warning("owner account email %s: %s", kind, data.get("keepUrl") or data.get("url"))


def drop_notice(kind: str, email: str, data: dict[str, Any]) -> None:
    log.debug("no %s email (owner mail is off)", kind)


def _tellers(app):
    """(mailer, sink): with a mailer, an email is stored in the outbox in the
    same commit as its change, so a restart can't lose the keep link. A test's
    sink, or a log line, is called after the commit instead."""
    sink = getattr(app.state, "owner_account_sink", None)
    if sink is not None:
        return None, sink
    mailer = getattr(app.state, "owner_mailer", None)
    if mailer is not None:
        return mailer, None
    return None, (log_notice if app.state.settings.owner_codes_to_log else drop_notice)


def _keep_hash(token: str) -> str:
    """The keep link carries 256 random bits, so a plain SHA-256 is enough."""
    return hashlib.sha256(b"UAM-OWNER-KEEP-v1\n" + token.encode()).hexdigest()


# --------------------------------------------------------------------------- freezing


async def freeze(session: AsyncSession, app, email: str) -> dict[str, Any]:
    """Freeze the account with *email* (normalised) and tell that email."""
    settings, mailer, sink = app.state.settings, *_tellers(app)
    found = await owner_crud.find_by_email(session, app.state.owner_vault.lookup(email))
    if found is None:
        raise PasskeyError(404, "no_owner", "No account has that email.")
    owner = found[0]
    owner_pk, owner_id = owner.id, owner.owner_id
    moved = await session.execute(
        update(Owner).where(Owner.id == owner_pk, Owner.status == "active").values(status="frozen")
    )
    if moved.rowcount != 1:
        await session.rollback()
        raise PasskeyError(409, "not_active", "That account isn't active.")
    now = service.utcnow()
    token = new_token()
    closes_at = now + FREEZE_FOR
    session.add(OwnerFreeze(owner_pk=owner_pk, token_hash=_keep_hash(token), frozen_at=now,
                            closes_at=closes_at))
    await session.execute(
        update(OwnerSession)
        .where(OwnerSession.owner_pk == owner_pk, OwnerSession.revoked_at.is_(None))
        .values(revoked_at=now)
    )
    await owner_crud.audit(session, owner_pk, "frozen", {"by": "admin"})
    closes = links._stamp(closes_at)
    data = {"keepUrl": f"{settings.owner_origin}/#keep={token}", "closesAt": closes}
    if mailer is not None:
        mailer.add(session, "account_frozen", email, owner_pk, data)
    await session.commit()
    if mailer is not None:
        mailer.poke()
    else:
        sink("account_frozen", email, data)
    return {"ownerId": owner_id, "status": "frozen", "closesAt": closes}


def _no_link() -> PasskeyError:
    return PasskeyError(404, "no_freeze", "This link has ended or was already used.")


async def keep(session: AsyncSession, token: str) -> dict[str, Any]:
    """The keep link from the email: the account is active again."""
    row = await session.scalar(
        select(OwnerFreeze).where(
            OwnerFreeze.token_hash == _keep_hash(token),
            OwnerFreeze.kept_at.is_(None), OwnerFreeze.closed_at.is_(None),
        )
    )
    now = service.utcnow()
    if row is None or service._aware(row.closes_at) <= now:
        raise _no_link()
    # Racing the close: whichever moves the account out of "frozen" first wins.
    moved = await session.execute(
        update(Owner).where(Owner.id == row.owner_pk, Owner.status == "frozen")
        .values(status="active")
    )
    if moved.rowcount != 1:
        await session.rollback()
        raise _no_link()
    row.kept_at = now
    await owner_crud.audit(session, row.owner_pk, "freeze_kept")
    await session.commit()
    return {"detail": "It works as before, with your passkeys, agents and contacts. "
                      "Sign in as usual."}


# --------------------------------------------------------------------------- closing


async def finish_due(session: AsyncSession, app) -> int:
    """Close the accounts whose 72 hours have passed. Returns how many."""
    now = service.utcnow()
    due = list((await session.execute(
        select(OwnerFreeze.id).where(
            OwnerFreeze.kept_at.is_(None), OwnerFreeze.closed_at.is_(None),
            OwnerFreeze.closes_at <= now,
        ).order_by(OwnerFreeze.id).limit(BATCH)
    )).scalars())
    mailer, sink = _tellers(app)
    closed = 0
    for freeze_id in due:
        try:
            email = await _close(session, app, freeze_id)
        except Exception:
            # Its steps can run again: the next sweep finishes it.
            await session.rollback()
            log.exception("closing a frozen account (freeze %s) failed", freeze_id)
            continue
        if email is None:
            continue
        closed += 1
        if mailer is not None:
            mailer.poke()
        else:
            sink("account_closed", email, _closed_data(app))
    return closed


def _closed_data(app) -> dict[str, Any]:
    return {"url": f"{app.state.settings.owner_origin}/"}


async def _close(session: AsyncSession, app, freeze_id: int) -> str | None:
    """Close one account; returns the email it had, or None if it was kept or
    another sweep closed it first. With a mailer, the closed email is stored
    in the last commit; otherwise the caller tells the email."""
    state = app.state
    mailer, _ = _tellers(app)
    row = await session.get(OwnerFreeze, freeze_id)
    owner_pk = row.owner_pk
    moved = await session.execute(
        update(Owner).where(Owner.id == owner_pk, Owner.status.in_(("frozen", "closed")))
        .values(status="closed")
    )
    if moved.rowcount != 1:  # kept a moment ago
        await session.rollback()
        return None
    email_row = await owner_crud.primary_email(session, owner_pk)
    email = state.owner_vault.decrypt(email_row.email_enc) if email_row else None
    await session.commit()

    await _end_links(session, state, owner_pk)
    now = service.utcnow()
    await _end_contacts(session, owner_pk, now)
    await session.execute(
        update(Reservation)
        .where(Reservation.owner_pk == owner_pk, Reservation.status == "reserved")
        .values(expires_at=now)
    )
    await session.execute(delete(OwnerEmail).where(OwnerEmail.owner_pk == owner_pk))
    # Only one sweep finishes it: the one that marks it closed.
    claimed = await session.execute(
        update(OwnerFreeze).where(OwnerFreeze.id == freeze_id, OwnerFreeze.closed_at.is_(None))
        .values(closed_at=now)
    )
    if claimed.rowcount != 1:
        await session.rollback()
        return None
    await owner_crud.audit(session, owner_pk, "closed")
    if mailer is not None and email is not None:
        mailer.add(session, "account_closed", email, owner_pk, _closed_data(app))
    await session.commit()
    return email


async def _end_links(session: AsyncSession, state, owner_pk: int) -> None:
    """Unlink linked agents (the relay signs it); cancel links not yet approved."""
    found = list((await session.execute(
        select(OwnerLink.id, OwnerLink.state).where(
            OwnerLink.owner_pk == owner_pk,
            OwnerLink.state.in_(("started", "agent_signed", "active")),
        ).order_by(OwnerLink.id)
    )).all())
    for link_id, link_state in found:
        if link_state == "active":
            try:
                await links.admin_unlink(
                    session, state.settings, getattr(state, "relay_signing_key", None), link_id
                )
            except PasskeyError:
                await session.rollback()  # it ended a moment ago
            continue
        now = service.utcnow()
        # Either waiting state: the agent may sign while this runs.
        if await link_crud.move_link(session, link_id, ("started", "agent_signed"),
                                     state="cancelled", live_for=None, ended_at=now):
            await owner_crud.audit(session, owner_pk, "link_cancelled",
                                   {"link": link_id, "by": "closed"})
        await session.commit()


async def _end_contacts(session: AsyncSession, owner_pk: int, now) -> None:
    """Revoke the grants it gave and was given; cancel its open invites."""
    grants = list((await session.execute(
        select(OwnerGrant).where(
            or_(OwnerGrant.owner_pk == owner_pk, OwnerGrant.subject_owner_pk == owner_pk),
            OwnerGrant.revoked_at.is_(None),
        ).order_by(OwnerGrant.id)
    )).scalars())
    for grant in grants:
        await contact_crud.revoke(session, grant, now)
    invites = list((await session.execute(
        select(OwnerInvite).where(
            OwnerInvite.owner_pk == owner_pk, OwnerInvite.state.in_(contact_crud.OPEN)
        )
    )).scalars())
    for invite in invites:
        if await contact_crud.move_invite(session, invite.id, contact_crud.OPEN,
                                          state="cancelled", ended_at=now):
            await contact_crud.add_revocation(session, INVITE, invite.hash, now)
