"""Q7 — Graceful shutdown drain (Phase 48 Wave 0).

RED on purpose until 48-06 adds ``DrainingShutdownManager`` +
``DrainBlockMiddleware`` in ``uam.relay.shutdown``. ImportError at module
load is the RED signal.
"""

from __future__ import annotations

import pytest


def _import_shutdown():
    """Lazy import: keeps collection clean before Wave 4 (48-06) lands."""
    from uam.relay.shutdown import (  # NEW module
        DrainingShutdownManager,
        DrainBlockMiddleware,
    )
    return DrainingShutdownManager, DrainBlockMiddleware


pytestmark = pytest.mark.asyncio


class _FakeManager:
    def __init__(self, addresses):
        self._addresses = addresses
        self.sent: list[tuple[str, dict]] = []

    def online_addresses(self):
        return list(self._addresses)

    async def send_to(self, addr, msg):
        self.sent.append((addr, msg))


async def test_begin_drain_broadcasts_shutdown_notice():
    DrainingShutdownManager, _ = _import_shutdown()
    dm = DrainingShutdownManager(drain_seconds=0)  # zero for fast test
    mgr = _FakeManager(["a::r", "b::r"])
    await dm.begin_drain(mgr)
    assert dm.draining.is_set()
    assert len(mgr.sent) == 2
    for _addr, msg in mgr.sent:
        assert msg.get("type") == "shutdown"
        assert "drain_seconds" in msg


async def test_begin_drain_handles_send_failures_gracefully():
    DrainingShutdownManager, _ = _import_shutdown()
    dm = DrainingShutdownManager(drain_seconds=0)

    class _Bad(_FakeManager):
        async def send_to(self, addr, msg):
            raise RuntimeError("ws closed")

    mgr = _Bad(["a::r"])
    # Must not raise — uses gather(..., return_exceptions=True) per RESEARCH.
    await dm.begin_drain(mgr)
    assert dm.draining.is_set()


def test_drain_block_middleware_returns_503_when_draining():
    """Sync test (no asyncio mark) — TestClient runs the loop internally."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    DrainingShutdownManager, DrainBlockMiddleware = _import_shutdown()

    app = FastAPI()
    dm = DrainingShutdownManager(drain_seconds=0)
    app.add_middleware(DrainBlockMiddleware, drain_manager=dm)

    @app.get("/health")
    async def _h():
        return {"ok": True}

    @app.get("/foo")
    async def _f():
        return {"ok": True}

    dm.draining.set()
    client = TestClient(app)
    # /health is whitelisted; passes through.
    assert client.get("/health").status_code == 200
    # All other paths get 503 + Retry-After.
    r = client.get("/foo")
    assert r.status_code == 503
    assert r.headers.get("Retry-After") == "30"
