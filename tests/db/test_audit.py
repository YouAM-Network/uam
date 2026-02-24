"""Tests for AuditLog CRUD operations."""

from __future__ import annotations

from uam.db.crud.audit import (
    count_audit_log,
    log_action,
    query_audit_log,
)


async def test_log_action(session):
    entry = await log_action(
        session,
        action="create",
        entity_type="agent",
        entity_id="alice::youam.network",
        actor_address="admin::youam.network",
        details={"reason": "registration"},
        ip_address="127.0.0.1",
    )
    assert entry.action == "create"
    assert entry.entity_type == "agent"
    assert entry.entity_id == "alice::youam.network"
    assert entry.actor_address == "admin::youam.network"
    assert entry.details == {"reason": "registration"}
    assert entry.ip_address == "127.0.0.1"
    assert entry.timestamp is not None


async def test_query_by_entity_type(session):
    await log_action(session, action="create", entity_type="agent", entity_id="a1")
    await log_action(session, action="update", entity_type="agent", entity_id="a1")
    await log_action(session, action="create", entity_type="message", entity_id="m1")

    results = await query_audit_log(session, entity_type="agent")
    assert len(results) == 2
    assert all(r.entity_type == "agent" for r in results)


async def test_query_by_actor(session):
    await log_action(
        session, action="create", entity_type="agent", entity_id="a1",
        actor_address="admin::youam.network",
    )
    await log_action(
        session, action="create", entity_type="agent", entity_id="a2",
        actor_address="admin::youam.network",
    )
    await log_action(
        session, action="create", entity_type="agent", entity_id="a3",
        actor_address="other::youam.network",
    )

    results = await query_audit_log(session, actor_address="admin::youam.network")
    assert len(results) == 2
    assert all(r.actor_address == "admin::youam.network" for r in results)


async def test_count_audit_log(session):
    await log_action(session, action="create", entity_type="agent", entity_id="a1")
    await log_action(session, action="create", entity_type="agent", entity_id="a2")
    await log_action(session, action="create", entity_type="message", entity_id="m1")

    total = await count_audit_log(session)
    assert total == 3

    agent_count = await count_audit_log(session, entity_type="agent")
    assert agent_count == 2
