"""Names held for an account (P2s-2, DEC-005, spec P2 §4.2).

Once owners are on, a name is reserved with an email. The email gets a
confirmation link whose token sits in the URL fragment, as for an agent's
request. Opening it makes the account if there is none, with a session
that can only set up that name. Any account with that email (signed in
the usual way, too) sees the name and can make a setup code for it. Only
an agent registering the name with that code gets the name, and the code
links only that agent.

Reservation emails share the request emails' limits: per address 1 an
hour and 3 a day, the relay-wide daily cap, and "never email me".
Over a limit the name is still held, and the account sees it once signed
in.

The relay admin can give an account a name, including one on the
reserved list (``give``).
"""

from __future__ import annotations

import hashlib
import logging
import secrets
from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from uam.db.crud import owner_links as link_crud
from uam.db.crud import owner_requests as request_crud
from uam.db.crud import owners as owner_crud
from uam.db.crud import reservations as crud
from uam.db.models import Owner, OwnerEmail, Reservation
from uam.relay.owners import links, requests, service
from uam.relay.owners.crypto import EmailVault, new_token, normalise_link_code
from uam.relay.owners.crypto import token_hash as session_token_hash
from uam.relay.owners.passkeys import PasskeyError

log = logging.getLogger("uam.relay.owners")

REPLY = "If that address can take it, a confirmation is on its way."
#: How long a name the admin gives lasts, unless the admin says.
GIVE_DAYS = 30
MAX_GIVE_DAYS = 365

#: Where a reservation email goes: (email, message). P2g sends a real
#: email; the message has ``name``, ``address``, ``expiresAt``,
#: ``hasAccount``, ``url`` and ``neverUrl``.
ReservationSink = Callable[[str, dict[str, Any]], None]


def log_sink(email: str, message: dict[str, Any]) -> None:
    """UAM_OWNER_CODES_TO_LOG: the link, never the email."""
    log.warning("name %s reserved: %s", message["address"], message["url"])


def drop_sink(email: str, message: dict[str, Any]) -> None:
    log.debug("name %s reserved: no email sent, owner email arrives in P2g", message["address"])


def _token_hash(token: str) -> str:
    return hashlib.sha256(f"UAM-OWNER-RESERVE-v1\n{token}".encode()).hexdigest()


class Refused(Exception):
    """Registering a reserved name without the right setup code."""

    def __init__(self, detail: str) -> None:
        super().__init__(detail)
        self.detail = detail


ANONYMOUS = "This name is reserved. Pick another name."
HELD = (
    "This name is reserved for a YouAM account. Set it up with `uam init --setup` and a "
    "setup code for it from that account's page."
)


def name_of(row: Reservation) -> str:
    return row.address.split("::", 1)[0]


def held(row: Reservation | None, now: datetime) -> bool:
    """Whether *row* is a live reservation held for an email."""
    return (
        row is not None and row.email_hmac is not None and row.status == "reserved"
        and row.deleted_at is None and service._aware(row.expires_at) > now
    )


def view(row: Reservation) -> dict[str, Any]:
    return {
        "id": row.id, "name": name_of(row), "address": row.address,
        "expiresAt": links._stamp(row.expires_at),
    }


# --- reserving ------------------------------------------------------------------


async def reserve(
    session: AsyncSession, settings, vault: EmailVault, address: str, email: str,
    client_ip: str, sink: ReservationSink,
) -> dict[str, Any]:
    """Hold *address* for *email*, and email it a link if the limits allow.

    Raises ``crud.AddressAlreadyReserved`` if another reservation won."""
    now = service.utcnow()
    email_hmac = vault.lookup(email)
    token = new_token()
    expires_at = now + timedelta(hours=settings.reservation_ttl_hours)
    row = Reservation(
        address=address, claim_token=secrets.token_urlsafe(32), status="reserved",
        ip_address=client_ip, created_at=now, expires_at=expires_at,
        email_hmac=email_hmac, email_enc=vault.encrypt(email), token_hash=_token_hash(token),
        emailed=await requests.may_email(session, settings, email_hmac, None, now),
    )
    session.add(row)
    try:
        await session.flush()
    except IntegrityError:
        await session.rollback()
        raise crud.AddressAlreadyReserved(address) from None
    found = await owner_crud.find_by_email(session, email_hmac)
    if found is not None:
        await owner_crud.audit(session, found[0].id, "name_reserved",
                               {"reservation": row.id, "emailed": row.emailed})
    await session.commit()
    if row.emailed:
        origin = settings.owner_origin
        sink(email, {
            "name": name_of(row), "address": address, "expiresAt": links._stamp(expires_at),
            "hasAccount": found is not None and found[0].owner_id is not None,
            "url": f"{origin}/#reserve={token}", "neverUrl": f"{origin}/#never={token}",
        })
    return {"address": address, "expires_at": expires_at.isoformat(), "detail": REPLY}


async def by_token(session: AsyncSession, token: str) -> Reservation | None:
    return await crud.by_token_hash(session, _token_hash(token))


async def never(session: AsyncSession, token: str) -> bool:
    """"Never email me": a reservation email's token proves the email too.
    False if the token isn't a reservation's. The name stays held until it
    expires."""
    row = await by_token(session, token)
    if row is None:
        return False
    await request_crud.add_opt_out(session, row.email_hmac, None, service.utcnow())
    await session.commit()
    return True


# --- the owner's side -----------------------------------------------------------


def _gone() -> PasskeyError:
    return PasskeyError(410, "ended", "This name is no longer reserved.")


async def open_reservation(
    session: AsyncSession, vault: EmailVault, token: str
) -> tuple[Owner, Reservation]:
    """The reservation a token names, and its email's account, made now if
    there is none (the token confirms the email)."""
    row = await by_token(session, token)
    if row is None:
        raise PasskeyError(404, "no_reservation", "This link doesn't work.")
    now = service.utcnow()
    if not held(row, now):
        raise _gone()
    await owner_crud.drop_unfinished_signups(session, now - service.SIGNUP_TTL)
    found = await owner_crud.find_by_email(session, row.email_hmac)
    if found is None:
        try:
            await owner_crud.create_owner(
                session, email_hmac=row.email_hmac, email_enc=row.email_enc,
                created_via="reservation",
            )
        except owner_crud.EmailTaken:
            pass  # made a moment ago by a sign-up or another open
        await session.refresh(row)
        found = await owner_crud.find_by_email(session, row.email_hmac)
    owner, owner_email = found
    if owner.status != "active":
        await session.rollback()
        raise _gone()
    if owner_email.verified_at is None:
        owner_email.verified_at = now
    row.owner_pk = owner.id
    await owner_crud.audit(session, owner.id, "reservation_opened", {"reservation": row.id})
    await session.commit()
    return owner, row


async def scoped_session(session: AsyncSession, owner: Owner, row: Reservation) -> str:
    """A session that can only set up *row*'s name: its token for the cookie."""
    now = service.utcnow()
    token = new_token()
    await owner_crud.add_session(
        session, owner_pk=owner.id, token_hash=session_token_hash(token), now=now,
        expires_at=now + service.SESSION_MAX, reservation_id=row.id,
    )
    await session.commit()
    return token


async def _emails(session: AsyncSession, owner: Owner) -> list[str]:
    return list((await session.execute(
        select(OwnerEmail.email_hmac).where(OwnerEmail.owner_pk == owner.id)
    )).scalars())


async def list_held(
    session: AsyncSession, owner: Owner, scope: int | None
) -> list[dict[str, Any]]:
    """The names held for this account's emails (a scoped session: its own)."""
    rows = await crud.held_for(session, await _emails(session, owner), service.utcnow())
    return [view(r) for r in rows if scope is None or r.id == scope]


async def _mine(
    session: AsyncSession, owner: Owner, reservation_id: int, scope: int | None
) -> Reservation:
    if scope is not None and scope != reservation_id:
        raise PasskeyError(403, "not_yours", "This session can only set up its own name.")
    row = await session.get(Reservation, reservation_id)
    if not held(row, service.utcnow()) or row.email_hmac not in await _emails(session, owner):
        raise PasskeyError(404, "no_reservation", "No such name.")
    return row


async def make_code(
    session: AsyncSession, vault: EmailVault, owner: Owner, reservation_id: int,
    scope: int | None,
) -> dict[str, Any]:
    """A setup code for a held name: only an agent registering it can use it."""
    row = await _mine(session, owner, reservation_id, scope)
    made = await links.make_code(session, vault, owner, "setup", reservation_id=row.id)
    return {**made, "name": name_of(row), "address": row.address}


# --- registering ----------------------------------------------------------------


async def check_register(
    session: AsyncSession, vault: EmailVault | None, row: Reservation, typed: str | None
) -> None:
    """Let an agent register *row*'s name only with a setup code made for it.

    Raises ``Refused``. The code isn't used here: the agent redeems it
    next, as for any setup code."""
    if row.email_hmac is None or vault is None:
        raise Refused(ANONYMOUS)
    code = normalise_link_code(typed) if typed else None
    found = await link_crud.code_by_hash(session, vault.link_code_hash(code)) if code else None
    now = service.utcnow()
    if (
        found is None or found.reservation_id != row.id or found.kind != "setup"
        or found.used_at is not None or service._aware(found.expires_at) <= now
        or found.id != await link_crud.newest_code_id(session, found.owner_pk, "setup")
    ):
        raise Refused(HELD)
    owner = await session.get(Owner, found.owner_pk)
    if (
        owner is None or owner.status != "active" or owner.owner_id is None
        or row.email_hmac not in await _emails(session, owner)
    ):
        raise Refused(HELD)


# --- the admin ------------------------------------------------------------------


async def give(
    session: AsyncSession, owner: Owner, address: str, days: int
) -> Reservation:
    """Hold *address* for *owner*: a name on the reserved list, say.

    Raises ``crud.AddressAlreadyReserved`` if the name is taken."""
    if not await crud.check_address_available(session, address):
        raise crud.AddressAlreadyReserved(address)
    email = await owner_crud.primary_email(session, owner.id)
    now = service.utcnow()
    row = Reservation(
        address=address, claim_token=secrets.token_urlsafe(32), status="reserved",
        created_at=now, expires_at=now + timedelta(days=days),
        email_hmac=email.email_hmac, email_enc=email.email_enc, owner_pk=owner.id,
    )
    session.add(row)
    try:
        await session.flush()
    except IntegrityError:
        await session.rollback()
        raise crud.AddressAlreadyReserved(address) from None
    await owner_crud.audit(session, owner.id, "name_given", {"reservation": row.id})
    await session.commit()
    return row
