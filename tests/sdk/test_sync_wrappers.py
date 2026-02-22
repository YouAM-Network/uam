"""Tests for sync wrappers (SDK-04)."""

from __future__ import annotations

import asyncio

import pytest

from uam.sdk._sync import _run_sync
from uam.sdk.agent import Agent


class TestRunSync:
    """_run_sync bridges async into synchronous contexts."""

    def test_run_sync_no_loop(self):
        """_run_sync works when no event loop is running."""

        async def noop():
            await asyncio.sleep(0)

        _run_sync(noop())  # Should not raise

    def test_run_sync_returns_value(self):
        """_run_sync returns the coroutine's result."""

        async def get_value():
            return 42

        result = _run_sync(get_value())
        assert result == 42

    def test_run_sync_propagates_exception(self):
        """_run_sync propagates exceptions from the coroutine."""

        async def fail():
            raise ValueError("test error")

        with pytest.raises(ValueError, match="test error"):
            _run_sync(fail())

    def test_run_sync_with_async_work(self):
        """_run_sync handles coroutines that do real async work."""

        async def compute():
            await asyncio.sleep(0.01)
            return "done"

        result = _run_sync(compute())
        assert result == "done"


class TestAgentSyncMethods:
    """Agent has sync wrapper methods for all async operations."""

    def test_connect_sync_method_exists(self):
        """Agent has connect_sync, send_sync, inbox_sync, close_sync methods."""
        assert hasattr(Agent, "connect_sync")
        assert hasattr(Agent, "send_sync")
        assert hasattr(Agent, "inbox_sync")
        assert hasattr(Agent, "close_sync")

    def test_sync_methods_are_callable(self):
        """Sync wrapper methods are callable (not coroutines)."""
        agent = Agent("test", auto_register=False)
        assert callable(agent.connect_sync)
        assert callable(agent.send_sync)
        assert callable(agent.inbox_sync)
        assert callable(agent.close_sync)

    def test_inbox_sync_returns_list_via_mock(self):
        """inbox_sync calls _run_sync on the async inbox method.

        We mock the async inbox to return a known list and verify
        that inbox_sync returns the same value.
        """
        import asyncio
        from unittest.mock import AsyncMock
        from uam.sdk.message import ReceivedMessage

        agent = Agent("test", auto_register=False)

        # Mock the async inbox to return a list
        expected = [
            ReceivedMessage(
                message_id="msg-1",
                from_address="alice::test.local",
                to_address="test::test.local",
                content="hello",
                timestamp="2026-02-20T00:00:00Z",
                type="message",
            )
        ]

        async def fake_inbox(limit=50):
            return expected

        agent.inbox = fake_inbox  # type: ignore[assignment]
        agent._connected = True  # Skip connection check

        result = agent.inbox_sync()
        assert result == expected
        assert isinstance(result[0], ReceivedMessage)
