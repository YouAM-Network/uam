"""Unit tests for the ephemeral SessionManager."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import pytest

from uam.relay.demo_sessions import SessionManager


class TestSessionManagerCreate:
    """Tests for SessionManager.create()."""

    async def test_create_session(self):
        mgr = SessionManager(ttl_minutes=10)
        session = await mgr.create("youam.network")

        assert session.session_id
        assert session.token
        assert session.signing_key_b64
        assert session.verify_key_b64
        assert session.address.startswith("demo-")
        assert session.address.endswith("::youam.network")
        assert session.created_at < session.expires_at

        # expires_at should be ~10 minutes after created_at
        delta = session.expires_at - session.created_at
        assert timedelta(minutes=9, seconds=59) <= delta <= timedelta(minutes=10, seconds=1)


class TestSessionManagerGet:
    """Tests for SessionManager.get()."""

    async def test_get_valid_session(self):
        mgr = SessionManager(ttl_minutes=10)
        session = await mgr.create("youam.network")
        retrieved = await mgr.get(session.session_id)
        assert retrieved is session

    async def test_get_expired_session(self):
        mgr = SessionManager(ttl_minutes=0)
        session = await mgr.create("youam.network")
        # ttl_minutes=0 means expires_at == created_at, so it's already expired
        retrieved = await mgr.get(session.session_id)
        assert retrieved is None

    async def test_get_nonexistent_session(self):
        mgr = SessionManager(ttl_minutes=10)
        retrieved = await mgr.get("nonexistent-session-id")
        assert retrieved is None


class TestSessionManagerEviction:
    """Tests for max_sessions eviction."""

    async def test_max_sessions_eviction(self):
        mgr = SessionManager(ttl_minutes=10, max_sessions=2)
        s1 = await mgr.create("youam.network")
        s2 = await mgr.create("youam.network")
        s3 = await mgr.create("youam.network")

        # Oldest session (s1) should have been evicted
        assert await mgr.get(s1.session_id) is None
        # Newer sessions should still be accessible
        assert await mgr.get(s2.session_id) is s2
        assert await mgr.get(s3.session_id) is s3


class TestSessionManagerCleanup:
    """Tests for cleanup_expired()."""

    async def test_cleanup_expired(self):
        mgr = SessionManager(ttl_minutes=0)
        await mgr.create("youam.network")
        await mgr.create("youam.network")
        await mgr.create("youam.network")

        count = await mgr.cleanup_expired()
        assert count == 3

        # All sessions should be gone
        # Access internal state to verify emptiness
        assert len(mgr._sessions) == 0

    async def test_cleanup_keeps_valid_sessions(self):
        mgr = SessionManager(ttl_minutes=10)
        s1 = await mgr.create("youam.network")

        count = await mgr.cleanup_expired()
        assert count == 0
        assert await mgr.get(s1.session_id) is s1
