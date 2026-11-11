"""CRUD for agents asking for an owner by email (P2s-3).

Emails and tokens come in as HMACs, ciphertext and hashes. Functions that
change rows flush; the caller commits.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from uam.db.models import OwnerLink, OwnerRequest, OwnerRequestOptOut, Reservation


async def live_request(session: AsyncSession, agent: str) -> OwnerRequest | None:
    return await session.scalar(select(OwnerRequest).where(OwnerRequest.live_for == agent))


async def newest_request(session: AsyncSession, agent: str) -> OwnerRequest | None:
    return await session.scalar(
        select(OwnerRequest)
        .where(OwnerRequest.agent_address == agent)
        .order_by(OwnerRequest.id.desc())
        .limit(1)
    )


async def by_token(session: AsyncSession, token_hash: str) -> OwnerRequest | None:
    return await session.scalar(select(OwnerRequest).where(OwnerRequest.token_hash == token_hash))


async def by_link(session: AsyncSession, link_id: int) -> OwnerRequest | None:
    return await session.scalar(select(OwnerRequest).where(OwnerRequest.link_id == link_id))


async def live_for_email(session: AsyncSession, email_hmac: str) -> list[OwnerRequest]:
    """Requests to *email_hmac* that are still open or accepted."""
    return list((await session.execute(
        select(OwnerRequest)
        .where(OwnerRequest.email_hmac == email_hmac, OwnerRequest.live_for.is_not(None))
        .order_by(OwnerRequest.id)
    )).scalars())


async def asked_since(session: AsyncSession, agent: str, since: datetime) -> int:
    return await session.scalar(
        select(func.count()).select_from(OwnerRequest)
        .where(OwnerRequest.agent_address == agent, OwnerRequest.created_at >= since)
    ) or 0


async def emailed_since(session: AsyncSession, since: datetime, email_hmac: str | None = None) -> int:
    """Request and reservation emails sent since *since*: to one address, or
    relay-wide. Both kinds share the limits."""
    total = 0
    for table in (OwnerRequest, Reservation):
        query = (
            select(func.count()).select_from(table)
            .where(table.emailed.is_(True), table.created_at >= since)
        )
        if email_hmac is not None:
            query = query.where(table.email_hmac == email_hmac)
        total += await session.scalar(query) or 0
    return total


async def opted_out(session: AsyncSession, email_hmac: str, agent: str) -> bool:
    """Whether *email_hmac* asked not to hear about agents, or about *agent*."""
    found = await session.scalar(
        select(OwnerRequestOptOut.id).where(
            OwnerRequestOptOut.email_hmac == email_hmac,
            or_(OwnerRequestOptOut.agent_address.is_(None),
                OwnerRequestOptOut.agent_address == agent),
        ).limit(1)
    )
    return found is not None


async def blocked_agent(session: AsyncSession, email_hmac: str, agent: str) -> bool:
    """Whether *email_hmac* stopped *agent* in particular from asking."""
    found = await session.scalar(
        select(OwnerRequestOptOut.id).where(
            OwnerRequestOptOut.email_hmac == email_hmac,
            OwnerRequestOptOut.agent_address == agent,
        ).limit(1)
    )
    return found is not None


async def add_opt_out(
    session: AsyncSession, email_hmac: str, agent: str | None, now: datetime
) -> None:
    query = select(OwnerRequestOptOut.id).where(OwnerRequestOptOut.email_hmac == email_hmac)
    query = query.where(
        OwnerRequestOptOut.agent_address.is_(None) if agent is None
        else OwnerRequestOptOut.agent_address == agent
    )
    if await session.scalar(query.limit(1)) is None:
        session.add(OwnerRequestOptOut(email_hmac=email_hmac, agent_address=agent, created_at=now))
        await session.flush()


async def ever_owned(session: AsyncSession, agent: str) -> bool:
    """Whether an owner ever approved a link for *agent*."""
    found = await session.scalar(
        select(OwnerLink.id)
        .where(OwnerLink.agent_address == agent, OwnerLink.approved_at.is_not(None))
        .limit(1)
    )
    return found is not None
