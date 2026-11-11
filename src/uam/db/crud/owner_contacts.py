"""CRUD for owners connecting (P2e): invites, tries, grants, revocations.

Functions flush where they must and leave committing to the caller.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import delete, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from uam.db.models import (
    InviteRedemption,
    OwnerGrant,
    OwnerInvite,
    OwnerInviteTry,
    OwnerLink,
    OwnerRevocation,
)

#: Invite states that hold a place: not yet redeemed, or waiting for the inviter.
OPEN = ("open", "redeemed")


async def open_invites(session: AsyncSession, owner_pk: int, now: datetime) -> int:
    """Invites that count toward the 10: open and unexpired, or redeemed."""
    return await session.scalar(
        select(func.count()).select_from(OwnerInvite).where(
            OwnerInvite.owner_pk == owner_pk,
            or_(
                (OwnerInvite.state == "open") & (OwnerInvite.redeem_by > now),
                OwnerInvite.state == "redeemed",
            ),
        )
    ) or 0


async def invites_since(session: AsyncSession, owner_pk: int, since: datetime) -> int:
    return await session.scalar(
        select(func.count()).select_from(OwnerInvite).where(
            OwnerInvite.owner_pk == owner_pk, OwnerInvite.created_at >= since
        )
    ) or 0


async def invites_for_owner(session: AsyncSession, owner_pk: int) -> list[OwnerInvite]:
    return list((await session.execute(
        select(OwnerInvite).where(OwnerInvite.owner_pk == owner_pk).order_by(OwnerInvite.id.desc())
    )).scalars())


async def invite_for_owner(session: AsyncSession, owner_pk: int, invite_pk: int) -> OwnerInvite | None:
    return await session.scalar(
        select(OwnerInvite).where(OwnerInvite.id == invite_pk, OwnerInvite.owner_pk == owner_pk)
    )


async def invite_by_code_hash(session: AsyncSession, code_hash: str) -> OwnerInvite | None:
    return await session.scalar(select(OwnerInvite).where(OwnerInvite.code_hash == code_hash))


async def invite_by_link_id(session: AsyncSession, link_id: str) -> OwnerInvite | None:
    return await session.scalar(select(OwnerInvite).where(OwnerInvite.link_id == link_id))


async def move_invite(
    session: AsyncSession, invite_pk: int, from_states: tuple[str, ...], **values
) -> bool:
    """Change an invite's row if it is still in one of *from_states*, atomically."""
    result = await session.execute(
        update(OwnerInvite)
        .where(OwnerInvite.id == invite_pk, OwnerInvite.state.in_(from_states))
        .values(**values)
    )
    return result.rowcount == 1


async def emails_due(session: AsyncSession, now: datetime) -> list[OwnerInvite]:
    """Pre-approved invites whose undo time has passed and whose email hasn't gone."""
    return list((await session.execute(
        select(OwnerInvite).where(
            OwnerInvite.how == "email", OwnerInvite.state == "open",
            OwnerInvite.sent_at.is_(None), OwnerInvite.send_at <= now,
            OwnerInvite.redeem_by > now,
        ).order_by(OwnerInvite.id)
    )).scalars())


async def mark_sent(session: AsyncSession, invite_pk: int, now: datetime) -> bool:
    result = await session.execute(
        update(OwnerInvite)
        .where(OwnerInvite.id == invite_pk, OwnerInvite.sent_at.is_(None),
               OwnerInvite.state == "open")
        .values(sent_at=now)
    )
    return result.rowcount == 1


async def redemption_of(session: AsyncSession, invite_hash: str) -> InviteRedemption | None:
    return await session.get(InviteRedemption, invite_hash)


# --- wrong codes ----------------------------------------------------------------


async def add_try(session: AsyncSession, owner_pk: int, now: datetime) -> None:
    session.add(OwnerInviteTry(owner_pk=owner_pk, at=now))
    await session.flush()


async def tries_since(session: AsyncSession, owner_pk: int, since: datetime) -> int:
    return await session.scalar(
        select(func.count()).select_from(OwnerInviteTry).where(
            OwnerInviteTry.owner_pk == owner_pk, OwnerInviteTry.at >= since
        )
    ) or 0


async def drop_tries_before(session: AsyncSession, owner_pk: int, before: datetime) -> None:
    await session.execute(
        delete(OwnerInviteTry).where(OwnerInviteTry.owner_pk == owner_pk, OwnerInviteTry.at < before)
    )


# --- grants ---------------------------------------------------------------------


def _live(now: datetime):
    return (OwnerGrant.revoked_at.is_(None)) & (OwnerGrant.valid_until > now)


async def live_grants_from(session: AsyncSession, owner_pk: int, now: datetime) -> list[OwnerGrant]:
    """Grants *owner_pk* issued that name another owner and are in force."""
    return list((await session.execute(
        select(OwnerGrant).where(
            OwnerGrant.owner_pk == owner_pk, OwnerGrant.subject_owner_pk.is_not(None), _live(now)
        ).order_by(OwnerGrant.id)
    )).scalars())


async def live_grants_naming(session: AsyncSession, owner_pk: int, now: datetime) -> list[OwnerGrant]:
    """Grants by other owners that name *owner_pk* and are in force."""
    return list((await session.execute(
        select(OwnerGrant).where(OwnerGrant.subject_owner_pk == owner_pk, _live(now))
        .order_by(OwnerGrant.id)
    )).scalars())


async def grants_for_invite(session: AsyncSession, invite_pk: int) -> list[OwnerGrant]:
    return list((await session.execute(
        select(OwnerGrant).where(OwnerGrant.invite_pk == invite_pk, OwnerGrant.revoked_at.is_(None))
    )).scalars())


async def owner_grant(
    session: AsyncSession, issuer_pk: int, subject_pk: int, now: datetime
) -> OwnerGrant | None:
    """A grant in force by *issuer_pk* naming the owner *subject_pk*."""
    return await session.scalar(
        select(OwnerGrant).where(
            OwnerGrant.owner_pk == issuer_pk, OwnerGrant.subject_owner_pk == subject_pk,
            _live(now),
        ).limit(1)
    )


async def agent_grants(
    session: AsyncSession, issuer_pk: int, address: str, now: datetime
) -> list[OwnerGrant]:
    """Grants in force by *issuer_pk* naming the agent at *address*."""
    return list((await session.execute(
        select(OwnerGrant).where(
            OwnerGrant.owner_pk == issuer_pk, OwnerGrant.subject_kind == "agent",
            OwnerGrant.subject_address == address, _live(now),
        )
    )).scalars())


async def revoke(session: AsyncSession, grant: OwnerGrant, now: datetime) -> None:
    grant.revoked_at = now
    await add_revocation(session, "UamContactGrant", grant.hash, now)


async def add_revocation(session: AsyncSession, kind: str, digest: str, now: datetime) -> None:
    session.add(OwnerRevocation(t=kind, h=digest, at=now))
    await session.flush()


async def revocations_after(session: AsyncSession, seq: int, limit: int) -> list[OwnerRevocation]:
    return list((await session.execute(
        select(OwnerRevocation).where(OwnerRevocation.seq > seq)
        .order_by(OwnerRevocation.seq).limit(limit)
    )).scalars())


# --- links, as the gate and contacts see them -------------------------------------


async def effective_link(session: AsyncSession, address: str, now: datetime) -> OwnerLink | None:
    """The agent's link if it is active and has started."""
    return await session.scalar(
        select(OwnerLink).where(
            OwnerLink.live_for == address, OwnerLink.state == "active",
            OwnerLink.effective_at <= now,
        )
    )


async def shared_links(session: AsyncSession, owner_pk: int, now: datetime) -> list[OwnerLink]:
    """An owner's agents others' approvals cover: active, started, not private."""
    return list((await session.execute(
        select(OwnerLink).where(
            OwnerLink.owner_pk == owner_pk, OwnerLink.state == "active",
            OwnerLink.effective_at <= now, OwnerLink.private.is_(False),
        ).order_by(OwnerLink.agent_address)
    )).scalars())
