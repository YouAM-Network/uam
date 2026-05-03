"""CRUD operations for WebhookDelivery entities.

Every function takes ``session: AsyncSession`` as its first parameter.
Read queries filter ``deleted_at IS NULL`` by default.

Phase 44 Plan 44-06 (T4.7):
    ``record_attempt`` and ``complete_delivery`` are now single atomic
    ``UPDATE`` statements:

      - ``record_attempt`` increments ``attempt_count`` in SQL
        (``attempt_count = attempt_count + 1``) so 20 concurrent calls
        land 20 increments. No ``WHERE status=?`` filter — the function
        is intentionally idempotent across pending/in_progress states
        because the route layer in ``relay/webhook.py`` calls it during
        every retry attempt regardless of current status.
      - ``complete_delivery`` filters
        ``WHERE status IN ('pending', 'in_progress')`` so a row that
        was already finalised cannot be re-completed by a stale
        concurrent caller.

    ``update_circuit_breaker`` (which stomps the agent's
    ``contact_card`` JSON for circuit-breaker state) is OUT OF SCOPE
    for this plan — it requires a dedicated ``webhook_circuit_breakers``
    table and is deferred to Phase 47/48 per RESEARCH § Out of Scope.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import func, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from uam.db.models import Agent, WebhookDelivery

# Note: ``datetime`` is imported only for type annotations on the
# ``reset_at: datetime | None`` parameter of ``update_circuit_breaker``.
# All wall-clock writes go through ``sa.func.now()`` (server-side) or are
# elided in favour of ``onupdate=func.now()`` per T7.4.


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

    T4.7: atomic ``UPDATE WebhookDelivery SET attempt_count =
    attempt_count + 1, last_status_code=?, last_error=?,
    status='in_progress' WHERE id=?``. The increment evaluates
    atomically inside the row lock so 20 concurrent calls land 20
    increments — the prior SELECT-then-mutate pattern lost updates.

    No ``WHERE status=?`` pre-state filter is applied: the route layer
    in ``relay/webhook.py`` calls this function during every retry
    attempt regardless of whether the row is still ``pending`` or
    already ``in_progress`` from a previous attempt. Idempotent
    transitions (``in_progress`` -> ``in_progress``) are intentional.

    When *commit* is ``False`` the change is flushed but the caller is
    responsible for committing the session.
    """
    stmt = (
        update(WebhookDelivery)
        .where(WebhookDelivery.id == delivery_id)
        .values(
            attempt_count=WebhookDelivery.attempt_count + 1,
            last_status_code=status_code,
            last_error=error,
            status="in_progress",
        )
        .returning(WebhookDelivery)
    )
    result = await session.execute(stmt)
    delivery = result.scalar_one_or_none()

    if commit:
        await session.commit()
    else:
        await session.flush()

    if delivery is None:
        return None
    await session.refresh(delivery)
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

    T4.7: atomic ``UPDATE WebhookDelivery SET status=?, completed_at=now,
    last_error=? WHERE id=? AND status IN ('pending', 'in_progress')``.
    The pre-state filter prevents a stale concurrent caller from
    re-completing a row that was already finalised — the loser's WHERE
    clause matches no rows and the call returns ``None``.

    When *commit* is ``False`` the change is flushed but the caller is
    responsible for committing the session.
    """
    stmt = (
        update(WebhookDelivery)
        .where(
            WebhookDelivery.id == delivery_id,
            WebhookDelivery.status.in_(["pending", "in_progress"]),  # type: ignore[union-attr]
        )
        .values(
            status=status,
            completed_at=func.now(),
            last_error=error,
        )
        .returning(WebhookDelivery)
    )
    result = await session.execute(stmt)
    delivery = result.scalar_one_or_none()

    if commit:
        await session.commit()
    else:
        await session.flush()

    if delivery is None:
        return None
    await session.refresh(delivery)
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
    # T7.4: updated_at populated server-side via onupdate=func.now() on the
    # Agent.updated_at column (models.py); no Python-side write needed.
    session.add(agent)
    await session.commit()
    await session.refresh(agent)
    return agent
