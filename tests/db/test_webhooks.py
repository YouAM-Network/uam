"""Tests for WebhookDelivery CRUD operations."""

from __future__ import annotations

from uam.db.crud.webhooks import (
    complete_delivery,
    create_delivery,
    record_attempt,
)


async def test_create_delivery(session):
    d = await create_delivery(
        session,
        agent_address="alice::youam.network",
        message_id="msg-001",
        envelope='{"encrypted": "data"}',
    )
    assert d.status == "pending"
    assert d.agent_address == "alice::youam.network"
    assert d.message_id == "msg-001"
    assert d.attempt_count == 0
    assert d.completed_at is None


async def test_record_attempt(session):
    d = await create_delivery(
        session,
        agent_address="alice::youam.network",
        message_id="msg-001",
        envelope='{"encrypted": "data"}',
    )
    updated = await record_attempt(session, d.id, status_code=502, error="Bad Gateway")
    assert updated is not None
    assert updated.attempt_count == 1
    assert updated.last_status_code == 502
    assert updated.last_error == "Bad Gateway"
    assert updated.status == "in_progress"


async def test_complete_delivery_succeeded(session):
    d = await create_delivery(
        session,
        agent_address="alice::youam.network",
        message_id="msg-001",
        envelope='{"encrypted": "data"}',
    )
    completed = await complete_delivery(session, d.id, status="succeeded")
    assert completed is not None
    assert completed.status == "succeeded"
    assert completed.completed_at is not None
    assert completed.last_error is None


async def test_complete_delivery_failed(session):
    d = await create_delivery(
        session,
        agent_address="alice::youam.network",
        message_id="msg-001",
        envelope='{"encrypted": "data"}',
    )
    completed = await complete_delivery(
        session, d.id, status="failed", error="Max retries exceeded"
    )
    assert completed is not None
    assert completed.status == "failed"
    assert completed.completed_at is not None
    assert completed.last_error == "Max retries exceeded"
