"""Tests for DomainVerification CRUD operations."""

from __future__ import annotations

from datetime import datetime, timedelta

from sqlmodel import select

from uam.db.crud.domain_verification import (
    downgrade_verification,
    get_verification,
    list_expired,
    upsert_verification,
)
from uam.db.models import DomainVerification


async def test_upsert_new(session):
    v = await upsert_verification(
        session,
        agent_address="alice::youam.network",
        domain="youam.network",
        public_key="pk_alice",
        method="dns",
        ttl_hours=24,
    )
    assert v.agent_address == "alice::youam.network"
    assert v.domain == "youam.network"
    assert v.public_key == "pk_alice"
    assert v.status == "verified"
    assert v.method == "dns"
    assert v.ttl_hours == 24


async def test_upsert_update(session):
    v1 = await upsert_verification(
        session,
        agent_address="alice::youam.network",
        domain="youam.network",
        public_key="pk_old",
    )
    v2 = await upsert_verification(
        session,
        agent_address="alice::youam.network",
        domain="youam.network",
        public_key="pk_new",
    )
    # Same record updated
    assert v2.id == v1.id
    assert v2.public_key == "pk_new"
    assert v2.status == "verified"


async def test_get_verification(session):
    await upsert_verification(
        session,
        agent_address="alice::youam.network",
        domain="youam.network",
        public_key="pk_alice",
    )
    found = await get_verification(session, "alice::youam.network")
    assert found is not None
    assert found.domain == "youam.network"

    # Non-existent
    missing = await get_verification(session, "nobody::youam.network")
    assert missing is None


async def test_downgrade(session):
    v = await upsert_verification(
        session,
        agent_address="alice::youam.network",
        domain="youam.network",
        public_key="pk_alice",
    )
    downgraded = await downgrade_verification(session, v.id)
    assert downgraded is not None
    assert downgraded.status == "expired"

    # Should no longer appear in verified query
    found = await get_verification(session, "alice::youam.network")
    assert found is None


async def test_list_expired(session):
    # Create a verification and manually backdate its last_checked
    v = await upsert_verification(
        session,
        agent_address="alice::youam.network",
        domain="youam.network",
        public_key="pk_alice",
        ttl_hours=1,
    )
    # Backdate last_checked to 2 hours ago (TTL is 1 hour)
    stmt = select(DomainVerification).where(DomainVerification.id == v.id)
    result = await session.execute(stmt)
    record = result.scalar_one()
    record.last_checked = datetime.utcnow() - timedelta(hours=2)
    session.add(record)
    await session.commit()

    # Create a fresh (non-expired) verification
    await upsert_verification(
        session,
        agent_address="bob::youam.network",
        domain="other.network",
        public_key="pk_bob",
        ttl_hours=24,
    )

    expired = await list_expired(session)
    assert len(expired) == 1
    assert expired[0].agent_address == "alice::youam.network"
