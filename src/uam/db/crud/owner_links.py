"""CRUD for linking agents to owners: codes, tries, links, unlinks (P2d).

Codes are passed in as hashes. Functions that change rows flush; the
caller commits, so each step is one transaction.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import case, delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from uam.db.models import (
    InboundPolicy,
    OwnerCode,
    OwnerCodeTry,
    OwnerKeyLogEntry,
    OwnerLink,
)

LIVE = ("started", "agent_signed", "active")


async def add_code(
    session: AsyncSession, *, owner_pk: int, kind: str, code_hash: str,
    now: datetime, expires_at: datetime, max_uses: int = 1,
) -> OwnerCode:
    row = OwnerCode(
        owner_pk=owner_pk, kind=kind, code_hash=code_hash, created_at=now, expires_at=expires_at,
        max_uses=max_uses,
    )
    session.add(row)
    await session.flush()
    return row


async def code_by_hash(session: AsyncSession, code_hash: str) -> OwnerCode | None:
    return await session.scalar(select(OwnerCode).where(OwnerCode.code_hash == code_hash))


async def newest_code_id(session: AsyncSession, owner_pk: int, kind: str) -> int | None:
    return await session.scalar(
        select(func.max(OwnerCode.id)).where(
            OwnerCode.owner_pk == owner_pk, OwnerCode.kind == kind
        )
    )


async def use_code(session: AsyncSession, code_id: int, now: datetime, agent: str) -> bool:
    """Take one use of a code, atomically; False if none are left.

    ``used_at`` is set when the last use is taken, so a used-up code reads
    the same whether it was for one agent or a fleet."""
    last = OwnerCode.uses + 1 >= OwnerCode.max_uses
    result = await session.execute(
        update(OwnerCode)
        .where(OwnerCode.id == code_id, OwnerCode.used_at.is_(None))
        .values(
            uses=OwnerCode.uses + 1, used_by=agent,
            used_at=case((last, now), else_=OwnerCode.used_at),
        )
    )
    return result.rowcount == 1


async def add_try(session: AsyncSession, agent: str, now: datetime) -> None:
    session.add(OwnerCodeTry(agent_address=agent, at=now))
    await session.flush()


async def tries_since(session: AsyncSession, agent: str, since: datetime) -> int:
    return await session.scalar(
        select(func.count()).select_from(OwnerCodeTry).where(
            OwnerCodeTry.agent_address == agent, OwnerCodeTry.at >= since
        )
    ) or 0


async def drop_tries_before(session: AsyncSession, agent: str, before: datetime) -> None:
    await session.execute(
        delete(OwnerCodeTry).where(
            OwnerCodeTry.agent_address == agent, OwnerCodeTry.at < before
        )
    )


async def live_link(session: AsyncSession, agent: str) -> OwnerLink | None:
    return await session.scalar(select(OwnerLink).where(OwnerLink.live_for == agent))


async def newest_link(session: AsyncSession, agent: str) -> OwnerLink | None:
    return await session.scalar(
        select(OwnerLink)
        .where(OwnerLink.agent_address == agent)
        .order_by(OwnerLink.id.desc())
        .limit(1)
    )


async def link_for_owner(session: AsyncSession, owner_pk: int, link_id: int) -> OwnerLink | None:
    return await session.scalar(
        select(OwnerLink).where(OwnerLink.id == link_id, OwnerLink.owner_pk == owner_pk)
    )


async def links_for_owner(session: AsyncSession, owner_pk: int) -> list[OwnerLink]:
    """The owner's links the agent has signed (a started one isn't theirs to see yet)."""
    return list((await session.execute(
        select(OwnerLink)
        .where(OwnerLink.owner_pk == owner_pk, OwnerLink.agent_signature.is_not(None))
        .order_by(OwnerLink.id)
    )).scalars())


async def move_link(
    session: AsyncSession, link_id: int, from_states: tuple[str, ...], **values
) -> bool:
    """Change a link's row if it is still in one of *from_states*, atomically."""
    result = await session.execute(
        update(OwnerLink)
        .where(OwnerLink.id == link_id, OwnerLink.state.in_(from_states))
        .values(**values)
    )
    return result.rowcount == 1


async def key_log_entry(session: AsyncSession, owner_pk: int, entry_hash: str) -> OwnerKeyLogEntry | None:
    return await session.scalar(
        select(OwnerKeyLogEntry).where(
            OwnerKeyLogEntry.owner_pk == owner_pk, OwnerKeyLogEntry.hash == entry_hash
        )
    )


async def close_policy(session: AsyncSession, agent: str, set_by: str, now: datetime) -> None:
    """Set the agent's inbound policy to ``closed``, bumping its revision."""
    row = await session.get(InboundPolicy, agent)
    if row is None:
        row = InboundPolicy(agent_address=agent, policy="closed", revision=0, set_by=set_by)
        session.add(row)
    row.policy = "closed"
    row.set_by = set_by
    row.revision += 1
    row.updated_at = now
    await session.flush()
