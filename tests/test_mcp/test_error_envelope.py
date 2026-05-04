"""Q9 — MCP error envelope (Phase 48 Wave 0).

RED on purpose until 48-08 changes ``uam.mcp.server`` tools to return a
structured ``{ok, data|error}`` dict. Today they all return a prose string
("Error sending message: ...") so every ``isinstance(result, dict)``
assertion fails immediately.
"""

from __future__ import annotations

import pytest

from uam.mcp.server import uam_send, uam_inbox, uam_contact_card


pytestmark = pytest.mark.asyncio


async def test_uam_send_error_returns_envelope(tmp_path, monkeypatch):
    """Force the error path (no agent configured). Tool MUST return an
    ``{ok: false, error: {code, message}}`` dict, not a prose string.
    """
    # Point at an empty UAM dir so _get_agent fails fast.
    monkeypatch.setenv("UAM_HOME", str(tmp_path / "empty"))
    # Reset any cached singleton so the env var is honored.
    import uam.mcp.server as _srv
    _srv._agent = None

    result = await uam_send("alice::test", "hello")
    assert isinstance(result, dict), f"Expected dict, got {type(result).__name__}"
    assert result["ok"] is False
    assert "error" in result
    assert "code" in result["error"]
    assert "message" in result["error"]


async def test_uam_inbox_returns_envelope(tmp_path, monkeypatch):
    """Whether success or failure, the result MUST be the envelope shape."""
    monkeypatch.setenv("UAM_HOME", str(tmp_path / "empty"))
    import uam.mcp.server as _srv
    _srv._agent = None

    result = await uam_inbox(limit=10)
    assert isinstance(result, dict)
    assert "ok" in result
    if result["ok"]:
        assert "data" in result
    else:
        assert "error" in result


async def test_uam_contact_card_returns_envelope(tmp_path, monkeypatch):
    monkeypatch.setenv("UAM_HOME", str(tmp_path / "empty"))
    import uam.mcp.server as _srv
    _srv._agent = None

    result = await uam_contact_card()
    assert isinstance(result, dict)
    assert "ok" in result
