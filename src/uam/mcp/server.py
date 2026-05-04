"""UAM MCP server -- exposes Agent messaging as MCP tools.

Provides three tools for any MCP-compatible client (Claude Desktop,
Cursor, CrewAI, LangGraph, etc.):

  - **uam_send**: Send an encrypted, signed message to another agent
  - **uam_inbox**: Retrieve and decrypt pending messages
  - **uam_contact_card**: Get a signed contact card for this agent

Uses the ``mcp`` package (FastMCP) for tool registration and transport.
All tools wrap the existing :class:`uam.sdk.agent.Agent` class with zero
client-specific code (MCP-04).

Configuration via environment variables:

  - ``UAM_AGENT_NAME`` (required) -- the agent name
  - ``UAM_RELAY_URL`` (optional) -- relay URL override
  - ``UAM_DISPLAY_NAME`` (optional) -- display name override
  - ``UAM_TRANSPORT`` (optional, default ``"http"``) -- transport type
  - ``UAM_TRUST_POLICY`` (optional, default ``"auto-accept"``) -- trust policy

Phase 48 (Q9) -- Structured response envelope.
================================================
Every tool returns a dict, never a prose string. Shape:

  Success: ``{"ok": True, "data": <payload>}``
  Failure: ``{"ok": False, "error": {"code": "<stable_code>", "message": "<msg>"}}``

Error codes mirror the HTTP status map in
:mod:`uam.relay.exception_handlers` for cross-surface consistency. The
MCP-only ``"not_configured"`` code is added for the "no agent set up"
path, which has no HTTP analog.
"""

from __future__ import annotations

import asyncio
import logging
import os
from typing import Any

from mcp.server.fastmcp import FastMCP

from uam.sdk.agent import Agent

logger = logging.getLogger(__name__)


# ===========================================================================
# Phase 48 (Q9) -- Structured error envelope.
# ===========================================================================


class NotConfiguredError(Exception):
    """No active UAM agent configured for this MCP session.

    MCP-only sentinel exception; deliberately does NOT inherit from
    UAMError so it cannot accidentally be caught by FastAPI's central
    UAMError handler (which is HTTP-only). T-48-08-03.
    """


def _error_code(exc: Exception) -> str:
    """Resolve a stable error code by walking the exception's MRO.

    Mirrors the HTTP status map in :mod:`uam.relay.exception_handlers`
    so an MCP client and an HTTP client see the SAME ``code`` value for
    the same underlying exception type.

    Returns ``"not_configured"`` for the MCP-only NotConfiguredError,
    ``"network_error"`` for stdlib transport errors, and falls back to
    ``"internal_error"`` for everything else (T-48-08-01: never leaks
    class names of unmapped types into the envelope).
    """
    # Lazy import to avoid pulling protocol.errors at module load time.
    from uam.protocol.errors import (
        ContactCardExpired,
        EnvelopeExpiredError,
        EnvelopeTooLargeError,
        IncompatibleVersionError,
        InvalidAddressError,
        InvalidContactCardError,
        InvalidEnvelopeError,
        KeyPinningError,
        ReplayDetected,
        SignatureVerificationError,
        UAMError,
        ValidationError,
    )

    # Most specific subclasses first; MRO walk picks the first match.
    _MAP: dict[type, str] = {
        ContactCardExpired: "contact_card_expired",
        IncompatibleVersionError: "incompatible_version",
        EnvelopeTooLargeError: "envelope_too_large",
        InvalidContactCardError: "invalid_contact_card",
        InvalidAddressError: "invalid_address",
        InvalidEnvelopeError: "invalid_envelope",
        EnvelopeExpiredError: "envelope_expired",
        ValidationError: "validation_error",
        SignatureVerificationError: "signature_invalid",
        KeyPinningError: "key_pinning_violation",
        ReplayDetected: "replay_detected",
    }
    for cls in type(exc).__mro__:
        if cls in _MAP:
            return _MAP[cls]
    if isinstance(exc, NotConfiguredError):
        return "not_configured"
    if isinstance(exc, (ConnectionError, TimeoutError)):
        return "network_error"
    if isinstance(exc, UAMError):
        return "internal_error"
    return "internal_error"


def _error_envelope(exc: Exception) -> dict[str, Any]:
    """Build the ``{ok: false, error: {code, message}}`` envelope.

    Logs the exception server-side at WARNING; never leaks a traceback
    into the LLM-visible message (T-48-08-01).
    """
    logger.warning("MCP error: %s", exc)
    return {
        "ok": False,
        "error": {
            "code": _error_code(exc),
            "message": str(exc),
        },
    }


def _ok_envelope(data: Any) -> dict[str, Any]:
    """Build the ``{ok: true, data: ...}`` success envelope."""
    return {"ok": True, "data": data}


# Module-level cached Agent instance (lazy-initialized).
# T4.6: protected by an asyncio.Lock so concurrent FastMCP tool calls
# cannot construct duplicate Agent instances.
_agent: Agent | None = None
_agent_lock: asyncio.Lock = asyncio.Lock()  # Python ≥3.10 loop-agnostic at import (Pitfall 5)


async def _get_agent() -> Agent:
    """Return the module-level Agent, connecting lazily on first call (T4.6 atomic).

    Double-check pattern: fast-path returns the cached connected Agent without
    acquiring the lock; slow-path acquires ``_agent_lock``, re-checks the cached
    value, then constructs + connects if needed. Concurrent FastMCP tool
    invocations all share the same Agent instance.

    Raises:
        NotConfiguredError: when ``UAM_AGENT_NAME`` is unset. Mapped to
            error code ``"not_configured"`` by ``_error_code``.
    """
    global _agent

    # Fast-path: cached and still connected → no lock acquisition.
    if _agent is not None and _agent.is_connected:
        return _agent

    async with _agent_lock:
        # Double-check inside lock — another coroutine may have just initialized it.
        if _agent is not None and _agent.is_connected:
            return _agent

        name = os.environ.get("UAM_AGENT_NAME")
        if not name:
            raise NotConfiguredError(
                "UAM_AGENT_NAME environment variable is required. "
                "Set it to the agent name before starting the MCP server."
            )

        # R-T4.6 (Phase 45 / Phase 44 review residual): construct into a
        # local ``candidate`` and only assign to the module-level ``_agent``
        # AFTER ``connect()`` succeeds.  If connect() raises, ``_agent``
        # MUST be reset to None — otherwise a half-constructed Agent (with
        # an open keypair file handle and a contact_book SQLite handle)
        # would be cached and the next caller's fast-path
        # ``is_connected`` check could either short-circuit on a stale
        # half-state or fall through and orphan the previous instance.
        candidate = Agent(
            name,
            relay=os.environ.get("UAM_RELAY_URL"),
            display_name=os.environ.get("UAM_DISPLAY_NAME"),
            transport=os.environ.get("UAM_TRANSPORT", "http"),
            trust_policy=os.environ.get("UAM_TRUST_POLICY", "auto-accept"),
        )
        try:
            await candidate.connect()
        except Exception:
            # Construct succeeded but connect failed; do NOT cache the
            # half-constructed Agent.  Let GC reclaim it and re-raise so
            # the caller sees the failure.
            _agent = None
            raise
        _agent = candidate
        return _agent


# ---------------------------------------------------------------------------
# Tool functions (module-level for direct import in tests)
# ---------------------------------------------------------------------------


async def uam_send(
    to_address: str,
    message: str,
    thread_id: str | None = None,
) -> dict[str, Any]:
    """Send an encrypted, signed UAM message to another agent.

    Args:
        to_address: The recipient's UAM address (e.g. "agent::domain").
        message: The plaintext message content to send.
        thread_id: Optional thread ID for conversation threading.

    Returns:
        Envelope dict.

        Success::

            {"ok": True, "data": {"message_id": "<uuid>"}}

        Failure::

            {"ok": False, "error": {"code": "<stable_code>", "message": "..."}}

        Common error codes: ``invalid_address``, ``not_configured``,
        ``signature_invalid``, ``network_error``, ``internal_error``.
    """
    try:
        agent = await _get_agent()
        message_id = await agent.send(to_address, message, thread_id=thread_id)
        return _ok_envelope({"message_id": str(message_id)})
    except Exception as exc:
        return _error_envelope(exc)


async def uam_inbox(limit: int = 50) -> dict[str, Any]:
    """Retrieve and decrypt pending UAM messages.

    Args:
        limit: Maximum number of messages to retrieve (default 50).

    Returns:
        Envelope dict.

        Success::

            {"ok": True, "data": [{"message_id": ..., "from_address": ...,
                                   "to_address": ..., "content": ...,
                                   "timestamp": ..., "type": ...,
                                   "thread_id": ..., "reply_to": ...,
                                   "media_type": ..., "verified": ...}, ...]}

        Empty inbox: ``{"ok": True, "data": []}``.

        Failure: standard error envelope.
    """
    try:
        agent = await _get_agent()
        messages = await agent.inbox(limit=limit)
        data = [
            {
                "message_id": msg.message_id,
                "from_address": msg.from_address,
                "to_address": msg.to_address,
                "content": msg.content,
                "timestamp": msg.timestamp,
                "type": msg.type,
                "thread_id": msg.thread_id,
                "reply_to": msg.reply_to,
                "media_type": msg.media_type,
                "verified": msg.verified,
            }
            for msg in messages
        ]
        return _ok_envelope(data)
    except Exception as exc:
        return _error_envelope(exc)


async def uam_contact_card() -> dict[str, Any]:
    """Get a signed contact card for this agent.

    Returns the agent's contact card as a structured dict containing
    address, public key, relay endpoint, and a cryptographic signature.
    Share this with other agents so they can verify your identity.

    Returns:
        Envelope dict.

        Success::

            {"ok": True, "data": {"version": ..., "address": ...,
                                  "display_name": ..., "relay": ...,
                                  "public_key": ..., "signature": ...,
                                  ...}}

        Failure: standard error envelope.
    """
    try:
        agent = await _get_agent()
        card = agent.contact_card()
        return _ok_envelope(card)
    except Exception as exc:
        return _error_envelope(exc)


# ---------------------------------------------------------------------------
# Server factory and entry point
# ---------------------------------------------------------------------------


def create_server() -> FastMCP:
    """Create and return a configured FastMCP server with UAM tools.

    This is the testable entry point -- it registers all three module-level
    tool functions on a fresh FastMCP instance without starting any transport.
    """
    mcp = FastMCP("uam")
    mcp.tool()(uam_send)
    mcp.tool()(uam_inbox)
    mcp.tool()(uam_contact_card)
    return mcp


def main() -> None:
    """Entry point for the ``uam-mcp`` console script.

    Creates the FastMCP server and runs it with stdio transport
    (the standard for Claude Desktop and Cursor integration).
    """
    server = create_server()
    server.run(transport="stdio")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    main()
