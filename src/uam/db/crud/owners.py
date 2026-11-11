"""CRUD for owner accounts, sign-in codes, sessions and their audit (P2c-1).

Callers pass hashes and ciphertext, never a plain email, code or token
(see ``uam.relay.owners.crypto``). Functions that change rows flush; the
caller commits, so one sign-in step is one transaction.
"""

from __future__ import annotations

import json
from datetime import datetime

from sqlalchemy import delete, func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from uam.db.models import (
    Owner,
    OwnerAudit,
    OwnerEmail,
    OwnerKeyLogEntry,
    OwnerLoginCode,
    OwnerPasskey,
    OwnerRequest,
    OwnerSession,
    WebAuthnChallenge,
)


class EmailTaken(Exception):
    """Another owner already has this email."""


async def create_owner(
    session: AsyncSession, *, email_hmac: str, email_enc: str, created_via: str
) -> Owner:
    """Add an owner and their email; raises EmailTaken (after rolling back)."""
    owner = Owner(created_via=created_via)
    session.add(owner)
    await session.flush()
    session.add(OwnerEmail(owner_pk=owner.id, email_hmac=email_hmac, email_enc=email_enc))
    try:
        await session.flush()
    except IntegrityError as exc:
        await session.rollback()
        raise EmailTaken from exc
    await audit(session, owner.id, "created", {"via": created_via})
    return owner


async def drop_unfinished_signups(session: AsyncSession, before: datetime) -> int:
    """Delete self-made accounts (a sign-up, or an agent's request email)
    that never added a passkey, made before *before*. Returns how many.

    The child rows go first, explicitly, rather than trusting ON DELETE
    CASCADE: that holds on Postgres and on our SQLite engine (it turns
    foreign keys on), but not on a SQLite connection made elsewhere."""
    ids = list((await session.execute(
        select(Owner.id).where(
            Owner.created_via.in_(("signup", "request")), Owner.owner_id.is_(None),
            Owner.created_at < before,
        )
    )).scalars())
    if not ids:
        return 0
    for table in (OwnerEmail, OwnerSession, OwnerAudit, WebAuthnChallenge, OwnerPasskey):
        await session.execute(delete(table).where(table.owner_pk.in_(ids)))
    # A request that made the account stays: its email link can make it again.
    await session.execute(
        update(OwnerRequest).where(OwnerRequest.owner_pk.in_(ids)).values(owner_pk=None)
    )
    await session.execute(delete(Owner).where(Owner.id.in_(ids)))
    return len(ids)


async def lock_email(session: AsyncSession, email_hmac: str) -> bool:
    """Take a write lock on one email's row until the transaction ends; False
    if no owner has it. Run it first in the transaction: a no-op UPDATE
    row-locks on Postgres and takes SQLite's write lock, so a check made
    after it (like the hourly code count) can't be raced."""
    result = await session.execute(
        update(OwnerEmail)
        .where(OwnerEmail.email_hmac == email_hmac)
        .values(email_hmac=OwnerEmail.email_hmac)
    )
    return result.rowcount == 1


async def find_by_email(
    session: AsyncSession, email_hmac: str
) -> tuple[Owner, OwnerEmail] | None:
    row = (
        await session.execute(
            select(Owner, OwnerEmail)
            .join(OwnerEmail, OwnerEmail.owner_pk == Owner.id)
            .where(OwnerEmail.email_hmac == email_hmac)
        )
    ).first()
    return (row[0], row[1]) if row else None


async def primary_email(session: AsyncSession, owner_pk: int) -> OwnerEmail | None:
    return await session.scalar(
        select(OwnerEmail).where(OwnerEmail.owner_pk == owner_pk).order_by(OwnerEmail.id).limit(1)
    )


async def codes_since(session: AsyncSession, email_hmac: str, since: datetime) -> int:
    return await session.scalar(
        select(func.count())
        .select_from(OwnerLoginCode)
        .where(OwnerLoginCode.email_hmac == email_hmac, OwnerLoginCode.created_at >= since)
    ) or 0


async def add_code(
    session: AsyncSession, *, email_hmac: str, code_hash: str, now: datetime, expires_at: datetime
) -> None:
    session.add(OwnerLoginCode(
        email_hmac=email_hmac, code_hash=code_hash, created_at=now, expires_at=expires_at
    ))
    await session.flush()


async def newest_code(session: AsyncSession, email_hmac: str) -> OwnerLoginCode | None:
    return await session.scalar(
        select(OwnerLoginCode)
        .where(OwnerLoginCode.email_hmac == email_hmac)
        .order_by(OwnerLoginCode.created_at.desc(), OwnerLoginCode.id.desc())
        .limit(1)
    )


async def claim_try(session: AsyncSession, code_id: int, max_tries: int) -> bool:
    """Count one try against a code, atomically; False if none are left, so
    parallel guesses can't share a try."""
    result = await session.execute(
        update(OwnerLoginCode)
        .where(OwnerLoginCode.id == code_id, OwnerLoginCode.tries < max_tries)
        .values(tries=OwnerLoginCode.tries + 1)
    )
    return result.rowcount == 1


async def mark_used(session: AsyncSession, code_id: int, now: datetime) -> bool:
    """Use a code up, atomically; False if something else already did."""
    result = await session.execute(
        update(OwnerLoginCode)
        .where(OwnerLoginCode.id == code_id, OwnerLoginCode.used_at.is_(None))
        .values(used_at=now)
    )
    return result.rowcount == 1


async def add_session(
    session: AsyncSession, *, owner_pk: int, token_hash: str, now: datetime, expires_at: datetime,
    request_id: int | None = None,
) -> None:
    session.add(OwnerSession(
        owner_pk=owner_pk, token_hash=token_hash, created_at=now, last_seen=now,
        expires_at=expires_at, request_id=request_id,
    ))
    await session.flush()


async def find_session(
    session: AsyncSession, token_hash: str
) -> tuple[OwnerSession, Owner] | None:
    row = (
        await session.execute(
            select(OwnerSession, Owner)
            .join(Owner, Owner.id == OwnerSession.owner_pk)
            .where(OwnerSession.token_hash == token_hash, OwnerSession.revoked_at.is_(None))
        )
    ).first()
    return (row[0], row[1]) if row else None


async def audit(session: AsyncSession, owner_pk: int, action: str, details: dict | None = None) -> None:
    """Record what happened to an account. Never pass an email or an IP."""
    session.add(OwnerAudit(
        owner_pk=owner_pk, action=action, details=json.dumps(details or {}, sort_keys=True)
    ))
    await session.flush()


# --- passkeys, key log, WebAuthn challenges (P2c-2) --------------------------


async def add_challenge(
    session: AsyncSession,
    *,
    owner_pk: int,
    purpose: str,
    challenge: str,
    now: datetime,
    expires_at: datetime,
    passkey_pk: int | None = None,
    body: str | None = None,
    screen: str | None = None,
) -> WebAuthnChallenge:
    row = WebAuthnChallenge(
        owner_pk=owner_pk, purpose=purpose, challenge=challenge, created_at=now,
        expires_at=expires_at, passkey_pk=passkey_pk, body=body, screen=screen,
    )
    session.add(row)
    await session.flush()
    return row


async def find_challenge(
    session: AsyncSession, owner_pk: int, purpose: str | None, challenge: str
) -> WebAuthnChallenge | None:
    """The owner's challenge row with these bytes (for *purpose*, unless None)."""
    query = select(WebAuthnChallenge).where(
        WebAuthnChallenge.owner_pk == owner_pk, WebAuthnChallenge.challenge == challenge,
    )
    if purpose is not None:
        query = query.where(WebAuthnChallenge.purpose == purpose)
    return await session.scalar(query)


async def use_challenge(session: AsyncSession, challenge_id: int, now: datetime) -> bool:
    """Use a challenge up, atomically; False if something already did."""
    result = await session.execute(
        update(WebAuthnChallenge)
        .where(WebAuthnChallenge.id == challenge_id, WebAuthnChallenge.used_at.is_(None))
        .values(used_at=now)
    )
    return result.rowcount == 1


async def passkeys(
    session: AsyncSession, owner_pk: int, states: tuple[str, ...] = ("active",)
) -> list[OwnerPasskey]:
    return list((await session.execute(
        select(OwnerPasskey)
        .where(OwnerPasskey.owner_pk == owner_pk, OwnerPasskey.state.in_(states))
        .order_by(OwnerPasskey.id)
    )).scalars())


async def passkey_by_credential(
    session: AsyncSession, owner_pk: int, credential_id: str
) -> OwnerPasskey | None:
    return await session.scalar(
        select(OwnerPasskey).where(
            OwnerPasskey.owner_pk == owner_pk, OwnerPasskey.credential_id == credential_id
        )
    )


async def drop_stale_held(session: AsyncSession, owner_pk: int, before: datetime) -> None:
    """Held passkeys whose entry was never signed in time."""
    await session.execute(
        delete(OwnerPasskey).where(
            OwnerPasskey.owner_pk == owner_pk,
            OwnerPasskey.state == "held",
            OwnerPasskey.created_at < before,
        )
    )


async def key_log_head(session: AsyncSession, owner_pk: int) -> OwnerKeyLogEntry | None:
    return await session.scalar(
        select(OwnerKeyLogEntry)
        .where(OwnerKeyLogEntry.owner_pk == owner_pk)
        .order_by(OwnerKeyLogEntry.seq.desc())
        .limit(1)
    )


async def key_log(
    session: AsyncSession, owner_pk: int, since: int = 0
) -> list[OwnerKeyLogEntry]:
    return list((await session.execute(
        select(OwnerKeyLogEntry)
        .where(OwnerKeyLogEntry.owner_pk == owner_pk, OwnerKeyLogEntry.seq >= since)
        .order_by(OwnerKeyLogEntry.seq)
    )).scalars())


async def owner_by_owner_id(session: AsyncSession, owner_id: str) -> Owner | None:
    return await session.scalar(select(Owner).where(Owner.owner_id == owner_id))
