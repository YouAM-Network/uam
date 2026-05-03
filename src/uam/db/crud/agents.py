"""CRUD operations for Agent entities.

Every function takes ``session: AsyncSession`` as its first parameter.
Read queries filter ``deleted_at IS NULL`` by default.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from uam.db.models import Agent


async def create_agent(
    session: AsyncSession,
    address: str,
    public_key: str,
    token_hash: str,
    *,
    commit: bool = True,
    **kwargs: object,
) -> Agent:
    """Create a new Agent record.

    Phase 47 T7.5: caller MUST pass the precomputed ``token_hash``. The
    plaintext token is no longer stored anywhere on the relay; callers
    (register, reserve) keep it only long enough to return it in the HTTP
    response. ``token_hash`` is the authoritative auth column (HMAC-SHA-256
    of the original token + server pepper); see ``uam.relay.auth`` and
    ``uam.relay.token_hashing.hash_token``.

    When *commit* is ``False`` the row is flushed but the caller is
    responsible for committing the session.
    """
    agent = Agent(
        address=address,
        public_key=public_key,
        token_hash=token_hash,
        **kwargs,
    )
    session.add(agent)
    if commit:
        await session.commit()
        await session.refresh(agent)
    else:
        await session.flush()
    return agent


async def get_agent_by_address(
    session: AsyncSession, address: str
) -> Agent | None:
    """Look up an agent by address (soft-delete filtered)."""
    stmt = select(Agent).where(
        Agent.address == address, Agent.deleted_at.is_(None)  # type: ignore[union-attr]
    )
    result = await session.execute(stmt)
    return result.scalar_one_or_none()


async def get_agent_by_address_with_deleted(
    session: AsyncSession, address: str
) -> Agent | None:
    """Look up an agent by address, including soft-deleted records."""
    stmt = select(Agent).where(Agent.address == address)
    result = await session.execute(stmt)
    return result.scalar_one_or_none()


async def update_agent(
    session: AsyncSession, address: str, *, commit: bool = True, **kwargs: object
) -> Agent | None:
    """Update fields on an agent identified by *address*.

    Returns the updated agent or ``None`` if not found.

    When *commit* is ``False`` the change is flushed but the caller is
    responsible for committing the session.
    """
    agent = await get_agent_by_address(session, address)
    if agent is None:
        return None
    for key, value in kwargs.items():
        setattr(agent, key, value)
    # T7.4: updated_at populated server-side via onupdate=func.now() on the
    # Agent.updated_at column (models.py); no Python-side write needed.
    session.add(agent)
    if commit:
        await session.commit()
        await session.refresh(agent)
    else:
        await session.flush()
    return agent


async def deactivate_agent(
    session: AsyncSession, address: str
) -> Agent | None:
    """Soft-delete an agent by setting status and deleted_at."""
    agent = await get_agent_by_address(session, address)
    if agent is None:
        return None
    agent.status = "deactivated"
    # T7.4: deleted_at is an explicit-action column (no server_default);
    # use tz-aware now() so the value matches the column's DateTime(timezone=True).
    agent.deleted_at = datetime.now(timezone.utc)
    session.add(agent)
    await session.commit()
    await session.refresh(agent)
    return agent


async def reactivate_agent(
    session: AsyncSession, address: str
) -> Agent | None:
    """Reactivate a soft-deleted agent."""
    agent = await get_agent_by_address_with_deleted(session, address)
    if agent is None:
        return None
    agent.status = "active"
    agent.deleted_at = None
    # T7.4: updated_at populated server-side via onupdate=func.now().
    session.add(agent)
    await session.commit()
    await session.refresh(agent)
    return agent


async def suspend_agent(
    session: AsyncSession, address: str
) -> Agent | None:
    """Suspend an agent (keeps it visible but non-operational)."""
    agent = await get_agent_by_address(session, address)
    if agent is None:
        return None
    agent.status = "suspended"
    # T7.4: updated_at populated server-side via onupdate=func.now().
    session.add(agent)
    await session.commit()
    await session.refresh(agent)
    return agent


async def list_agents(
    session: AsyncSession, limit: int = 100, offset: int = 0
) -> list[Agent]:
    """List active agents (soft-delete filtered)."""
    stmt = (
        select(Agent)
        .where(Agent.deleted_at.is_(None))  # type: ignore[union-attr]
        .offset(offset)
        .limit(limit)
    )
    result = await session.execute(stmt)
    return list(result.scalars().all())


async def list_agents_with_deleted(
    session: AsyncSession, limit: int = 100, offset: int = 0
) -> list[Agent]:
    """List all agents including soft-deleted records."""
    stmt = select(Agent).offset(offset).limit(limit)
    result = await session.execute(stmt)
    return list(result.scalars().all())
