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


# ---------------------------------------------------------------------------
# R-T4.6 — half-construction reset on connect failure (Phase 45 Wave 0)
# ---------------------------------------------------------------------------
#
# Inherited Phase-44 review recommendation: even after Plan 44-06 added the
# asyncio.Lock + double-check, ``_get_agent`` still has a half-construction
# bug — if ``await _agent.connect()`` raises, the module-level ``_agent``
# remains set to the partially-built instance.  The next caller hits the
# fast-path ``if _agent is not None and _agent.is_connected`` check; with the
# stub Agent below, ``is_connected`` returns False so the slow-path tries
# again, but in production code an Agent instance can have ``is_connected ==
# True`` after a failed handshake midway through ``connect()`` (e.g.
# transport opened but registration rejected).  The ONLY safe behavior is
# to ``_agent = None`` in the except branch so the next caller starts from
# a clean slate.
#
# Plan 45 Plan 04 (or wherever R-T4.6 lands) must wrap construct+connect in
# try/except and reset ``_agent = None`` on failure.


@pytest.mark.asyncio
async def test_connect_failure_clears_agent(monkeypatch):
    """R-T4.6: ``_get_agent`` must reset ``_agent = None`` on connect() failure
    so a half-constructed Agent is not cached and reused for the fast-path
    is_connected check.

    Failing-by-design today: ``_get_agent`` does not wrap construct+connect in
    try/except, so when ``connect()`` raises, ``_agent`` retains the
    half-constructed instance.  Plan 45-04 (or the dedicated R-T4.6 plan) must
    add the try/except and reset.

    Contract:
      1. ``_agent`` starts as None.
      2. Caller invokes ``_get_agent``; constructor runs; connect() raises.
      3. The exception propagates to the caller (or is converted to a domain
         error — either is fine).
      4. ``mcp_srv._agent`` MUST be None afterward — NOT the half-constructed
         instance.
    """
    from uam.mcp import server as mcp_srv

    # Reset the singleton for this test
    monkeypatch.setattr(mcp_srv, "_agent", None)
    monkeypatch.setenv("UAM_AGENT_NAME", "test-mcp-agent-half-construct")

    constructed: list[object] = []

    class _StubAgent:
        """Stub that records construction and forces connect() to raise."""

        def __init__(self, *args, **kwargs):
            constructed.append(self)
            self._is_connected = False

        @property
        def is_connected(self) -> bool:
            return self._is_connected

        async def connect(self):
            raise RuntimeError("relay unreachable (simulated)")

    monkeypatch.setattr(mcp_srv, "Agent", _StubAgent)

    # First call must propagate the connect() failure (or convert to a
    # domain-specific error).  Either is acceptable; the contract is on
    # the post-state of mcp_srv._agent.
    raised = False
    try:
        await mcp_srv._get_agent()
    except RuntimeError:
        raised = True
    except Exception:
        raised = True

    assert raised, (
        "connect() failure should propagate (or be converted to a domain error) — "
        "silently swallowing it would hide the failure from the caller"
    )

    assert mcp_srv._agent is None, (
        "After connect() failure, _agent must be None — not the half-constructed "
        f"Agent. Found _agent={mcp_srv._agent!r} (constructed instances: "
        f"{len(constructed)}). Plan 45 R-T4.6 must wrap the construct+connect "
        "block in try/except and reset _agent = None on failure."
    )

    # Cleanup
    mcp_srv._agent = None
