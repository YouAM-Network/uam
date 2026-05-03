"""Phase 44 Wave 0 — failing-by-design concurrency test for MCP _get_agent.

Covers:
  T4.6  MCP-AGENT-SINGLETON  — _get_agent returns same Agent instance under N concurrent calls

Today (Wave 0): src/uam/mcp/server.py:54-79 has a TOCTOU race in _get_agent:

    if _agent is not None and _agent.is_connected:
        return _agent
    name = os.environ.get("UAM_AGENT_NAME")
    ...
    _agent = Agent(name, ...)   # <-- two coroutines can both reach here
    await _agent.connect()
    return _agent

Two concurrent tool calls (Claude Desktop spawning multiple MCP requests
in parallel) can each construct their own Agent and call connect() —
duplicate keypair load, duplicate WS connection, the second overwrites
the first in the module-level cache.

Plan 44-06 contract (per RESEARCH Pattern 5):
  - module-level ``_agent_lock = asyncio.Lock()``
  - double-check pattern inside the lock
  - construction_count == 1 after N concurrent _get_agent calls

NEW FILE created by Plan 44-00.
"""

from __future__ import annotations

import asyncio

import pytest


# ---------------------------------------------------------------------------
# T4.6 — MCP-AGENT-SINGLETON: concurrent _get_agent returns one instance
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_concurrent_get_agent_returns_singleton(monkeypatch):
    """T4.6: 10 concurrent ``_get_agent()`` calls return the SAME Agent
    instance and the Agent constructor is called EXACTLY ONCE.

    Plan 44-06 contract:
      - ``_agent_lock = asyncio.Lock()`` at module level
      - ``_get_agent`` enters the lock with a double-check on
        ``_agent is not None and _agent.is_connected``
      - construction_count == 1 across N concurrent callers

    Today (Wave 0): both the ``_agent is None`` check and the construction
    happen WITHOUT a lock. Two coroutines can both observe ``_agent is None``
    and both build their own Agent. This test FAILS with construction_count
    > 1 OR with N distinct Agent instances returned.
    """
    from uam.mcp import server as mcp_srv

    # Reset module-level singleton for this test.
    mcp_srv._agent = None

    monkeypatch.setenv("UAM_AGENT_NAME", "test-mcp-agent-singleton")

    construction_count = 0

    class CountingFakeAgent:
        """Stand-in for uam.sdk.agent.Agent that:
          - counts how many times the constructor runs
          - simulates a slow connect() so concurrent callers can race
            past the `if _agent is None` guard
        """

        def __init__(self, name, **_kwargs):
            nonlocal construction_count
            construction_count += 1
            self.name = name
            self._is_connected = False

        @property
        def is_connected(self) -> bool:
            return self._is_connected

        async def connect(self) -> None:
            # Simulate a slow handshake — this is what opens the race
            # window for concurrent callers in the buggy code.
            await asyncio.sleep(0.05)
            self._is_connected = True

    # Replace the Agent symbol that _get_agent imports.
    monkeypatch.setattr(mcp_srv, "Agent", CountingFakeAgent)

    # Fire 10 concurrent _get_agent() calls.
    agents = await asyncio.gather(*[mcp_srv._get_agent() for _ in range(10)])

    # All callers must observe the SAME instance.
    assert all(a is agents[0] for a in agents), (
        f"T4.6: concurrent _get_agent() calls returned different Agent "
        f"instances. Got {len({id(a) for a in agents})} distinct instances "
        f"from 10 calls. Plan 44-06 must add `async with _agent_lock:` + "
        f"double-check around the `if _agent is None` guard so only the "
        f"first caller constructs the Agent."
    )

    # The constructor must have run EXACTLY ONCE.
    assert construction_count == 1, (
        f"T4.6: Agent was constructed {construction_count} times, expected 1. "
        f"This is the duplicate-construction race: each duplicate Agent loads "
        f"the keypair, opens a WS connection, and registers — the duplicates "
        f"are immediately abandoned but they consume relay-side resources "
        f"and may produce confusing audit-log entries. Plan 44-06's "
        f"asyncio.Lock + double-check eliminates this."
    )

    # Cleanup — clear the singleton so other tests start fresh.
    mcp_srv._agent = None
