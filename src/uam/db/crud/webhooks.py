"""CRUD operations for WebhookDelivery entities.

Every function takes ``session: AsyncSession`` as its first parameter.
Read queries filter ``deleted_at IS NULL`` by default.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from uam.db.models import Agent, WebhookDelivery


async def create_delivery(
    session: AsyncSession,
    agent_address: str,
    message_id: str,
    envelope: str,
    *,
    commit: bool = True,
) -> WebhookDelivery:
    """Create a new pending webhook delivery.

    When *commit* is ``False`` the row is flushed but the caller is
    responsible for committing the session.
    """
    delivery = WebhookDelivery(
        agent_address=agent_address,
        message_id=message_id,
        envelope=envelope,
        status="pending",
    )
    session.add(delivery)
    if commit:
        await session.commit()
        await session.refresh(delivery)
    else:
        await session.flush()
    return delivery


async def get_pending_deliveries(
    session: AsyncSession,
    agent_address: str | None = None,
    limit: int = 50,
) -> list[WebhookDelivery]:
    """Get pending deliveries, optionally filtered by *agent_address*."""
    stmt = select(WebhookDelivery).where(
        WebhookDelivery.status == "pending",
        WebhookDelivery.deleted_at.is_(None),  # type: ignore[union-attr]
    )
    if agent_address is not None:
        stmt = stmt.where(WebhookDelivery.agent_address == agent_address)
    stmt = stmt.limit(limit)
    result = await session.execute(stmt)
    return list(result.scalars().all())


async def record_attempt(
    session: AsyncSession,
    delivery_id: int,
    status_code: int | None = None,
    error: str | None = None,
    *,
    commit: bool = True,
) -> WebhookDelivery | None:
    """Record a delivery attempt (increment counter, set status to in_progress).

    When *commit* is ``False`` the change is flushed but the caller is
    responsible for committing the session.
    """
    stmt = select(WebhookDelivery).where(WebhookDelivery.id == delivery_id)
    result = await session.execute(stmt)
    delivery = result.scalar_one_or_none()
    if delivery is None:
        return None
    delivery.attempt_count += 1
    delivery.last_status_code = status_code
    delivery.last_error = error
    delivery.status = "in_progress"
    session.add(delivery)
    if commit:
        await session.commit()
        await session.refresh(delivery)
    else:
        await session.flush()
    return delivery


async def complete_delivery(
    session: AsyncSession,
    delivery_id: int,
    status: str,
    error: str | None = None,
    *,
    commit: bool = True,
) -> WebhookDelivery | None:
    """Mark a delivery as completed (succeeded or failed).

    When *commit* is ``False`` the change is flushed but the caller is
    responsible for committing the session.
    """
    stmt = select(WebhookDelivery).where(WebhookDelivery.id == delivery_id)
    result = await session.execute(stmt)
    delivery = result.scalar_one_or_none()
    if delivery is None:
        return None
    delivery.status = status
    delivery.completed_at = datetime.utcnow()
    delivery.last_error = error
    session.add(delivery)
    if commit:
        await session.commit()
        await session.refresh(delivery)
    else:
        await session.flush()
    return delivery


async def get_deliveries_for_agent(
    session: AsyncSession, agent_address: str, limit: int = 50
) -> list[WebhookDelivery]:
    """List deliveries for a specific agent (newest first)."""
    stmt = (
        select(WebhookDelivery)
        .where(
            WebhookDelivery.agent_address == agent_address,
            WebhookDelivery.deleted_at.is_(None),  # type: ignore[union-attr]
        )
        .order_by(WebhookDelivery.id.desc())  # type: ignore[union-attr]
        .limit(limit)
    )
    result = await session.execute(stmt)
    return list(result.scalars().all())


async def update_circuit_breaker(
    session: AsyncSession,
    agent_address: str,
    is_open: bool,
    reset_at: datetime | None = None,
) -> Agent | None:
    """Store circuit breaker state in the agent's ``contact_card`` JSON.

    This is a pragmatic approach -- the Agent model's ``contact_card``
    JSON field stores circuit breaker state until a dedicated column is
    added in a future migration.
    """
    stmt = select(Agent).where(
        Agent.address == agent_address,
        Agent.deleted_at.is_(None),  # type: ignore[union-attr]
    )
    result = await session.execute(stmt)
    agent = result.scalar_one_or_none()
    if agent is None:
        return None

    card = dict(agent.contact_card) if agent.contact_card else {}
    card["circuit_breaker"] = {
        "is_open": is_open,
        "reset_at": reset_at.isoformat() if reset_at else None,
    }
    agent.contact_card = card
    agent.updated_at = datetime.utcnow()
    session.add(agent)
    await session.commit()
    await session.refresh(agent)
    return agent
