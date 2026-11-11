"""Owner sign-in and sessions (P2c-1, spec P2 §3.1).

Sign-in: an emailed 6-digit code, valid 10 minutes, 5 tries, at most 3 per
email an hour; only the newest code counts. Starting a sign-in answers the
same whether or not the email has an account. A session lasts 12 idle
hours and at most 7 days.
"""

from __future__ import annotations

import hmac
import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from uam.db.crud import owners as crud
from uam.db.models import Owner
from uam.relay.owners.crypto import EmailVault, new_code, new_token, token_hash

log = logging.getLogger("uam.relay.owners")

CODE_TTL = timedelta(minutes=10)
CODE_TRIES = 5
CODES_PER_HOUR = 3
SESSION_IDLE = timedelta(hours=12)
SESSION_MAX = timedelta(days=7)
#: last_seen is written at most this often, so reads don't all write.
TOUCH_EVERY = timedelta(minutes=1)

#: Where a new code goes: (owner_pk, email, code). P2g replaces it with email.
CodeSink = Callable[[int, str, str], None]


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _aware(value: datetime) -> datetime:
    """SQLite hands back naive datetimes; they were written as UTC."""
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def log_sink(owner_pk: int, email: str, code: str) -> None:
    """UAM_OWNER_CODES_TO_LOG: the code, never the email."""
    log.warning("owner sign-in code for owner %d: %s", owner_pk, code)


def drop_sink(owner_pk: int, email: str, code: str) -> None:
    log.debug("owner %d: no code mailed, owner email arrives in P2g", owner_pk)


async def start_sign_in(
    session: AsyncSession, vault: EmailVault, email: str, sink: CodeSink
) -> None:
    """Make and send a code if *email* (normalised) belongs to an active owner.

    Call it in a fresh session: it locks the email first so parallel starts
    can't each pass the hourly limit."""
    email_hmac = vault.lookup(email)
    if not await crud.lock_email(session, email_hmac):
        await session.rollback()
        return
    found = await crud.find_by_email(session, email_hmac)
    if found is None or found[0].status != "active":
        await session.rollback()
        return
    owner, _ = found
    now = utcnow()
    if await crud.codes_since(session, email_hmac, now - timedelta(hours=1)) >= CODES_PER_HOUR:
        await session.rollback()
        return
    code = new_code()
    await crud.add_code(
        session, email_hmac=email_hmac, code_hash=vault.code_hash(email_hmac, code),
        now=now, expires_at=now + CODE_TTL,
    )
    await crud.audit(session, owner.id, "code_sent")
    await session.commit()
    sink(owner.id, email, code)


#: An account someone started but never added a passkey to is deleted after this.
SIGNUP_TTL = timedelta(hours=24)


async def sign_up(
    session: AsyncSession, vault: EmailVault, email: str, sink: CodeSink
) -> None:
    """Make an account for *email* if it has none, then send a sign-in code.

    The account is the person's once they add a first passkey; until then
    it gives nothing, and after a day without one it is deleted. Call it in
    a fresh session, after the caller has answered: whether the email was
    known never shows."""
    await crud.drop_unfinished_signups(session, utcnow() - SIGNUP_TTL)
    await session.commit()
    email_hmac = vault.lookup(email)
    if await crud.find_by_email(session, email_hmac) is None:
        try:
            await crud.create_owner(
                session, email_hmac=email_hmac, email_enc=vault.encrypt(email),
                created_via="signup",
            )
            await session.commit()
        except crud.EmailTaken:
            pass  # someone signed up with it a moment ago: send them a code too
    await start_sign_in(session, vault, email, sink)


async def finish_sign_in(
    session: AsyncSession, vault: EmailVault, email: str, code: str
) -> str | None:
    """Check the code; on success open a session and return its token."""
    email_hmac = vault.lookup(email)
    row = await crud.newest_code(session, email_hmac)
    now = utcnow()
    if row is None or row.used_at is not None or _aware(row.expires_at) <= now:
        return None
    code_id, stored = row.id, row.code_hash
    if not await crud.claim_try(session, code_id, CODE_TRIES):
        await session.commit()
        return None
    await session.commit()
    if not hmac.compare_digest(stored, vault.code_hash(email_hmac, code)):
        return None
    if not await crud.mark_used(session, code_id, now):
        await session.commit()
        return None
    found = await crud.find_by_email(session, email_hmac)
    if found is None or found[0].status != "active":
        await session.commit()
        return None
    owner, owner_email = found
    if owner_email.verified_at is None:
        owner_email.verified_at = now
    token = new_token()
    await crud.add_session(
        session, owner_pk=owner.id, token_hash=token_hash(token), now=now,
        expires_at=now + SESSION_MAX,
    )
    await crud.audit(session, owner.id, "signed_in")
    await session.commit()
    return token


@dataclass
class SignedIn:
    owner: Owner
    session_id: int
    #: Set for a session opened from an agent's request email: it may only
    #: finish that request (P2s-3).
    request_id: int | None = None


async def current_owner(session: AsyncSession, token: str | None) -> SignedIn | None:
    """The owner a session token belongs to, if the session is still live."""
    if not token:
        return None
    found = await crud.find_session(session, token_hash(token))
    if found is None:
        return None
    owner_session, owner = found
    now = utcnow()
    if (
        owner.status != "active"
        or _aware(owner_session.expires_at) <= now
        or _aware(owner_session.last_seen) + SESSION_IDLE <= now
    ):
        return None
    if now - _aware(owner_session.last_seen) >= TOUCH_EVERY:
        owner_session.last_seen = now
        await session.commit()
    return SignedIn(owner=owner, session_id=owner_session.id,
                    request_id=owner_session.request_id)


async def sign_out(session: AsyncSession, signed_in: SignedIn) -> None:
    from uam.db.models import OwnerSession

    row = await session.get(OwnerSession, signed_in.session_id)
    if row is not None and row.revoked_at is None:
        row.revoked_at = utcnow()
        await crud.audit(session, signed_in.owner.id, "signed_out")
        await session.commit()
