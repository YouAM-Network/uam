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
"""

from __future__ import annotations

import json
import logging
import os

from mcp.server.fastmcp import FastMCP

from uam.sdk.agent import Agent

logger = logging.getLogger(__name__)


def _safe_error(exc: Exception) -> str:
    """Return a sanitised error string that never leaks credentials.

    Only exposes the exception class name and a generic description.
    The full traceback is logged server-side via logger.exception().
    """
    cls = type(exc).__name__
    # Allow through known-safe error types with their message
    safe_types = ("UAMError", "RuntimeError", "ValueError", "TimeoutError")
    if cls in safe_types:
        return f"{cls}: {exc}"
    return f"{cls}: An internal error occurred. Check server logs for details."


# Module-level cached Agent instance (lazy-initialized)
_agent: Agent | None = None


async def _get_agent() -> Agent:
    """Return the module-level Agent, connecting lazily on first call.

    The Agent is created from environment variables and connected once.
    Subsequent calls return the cached instance.
    """
    global _agent
    if _agent is not None and _agent.is_connected:
        return _agent

    name = os.environ.get("UAM_AGENT_NAME")
    if not name:
        raise RuntimeError(
            "UAM_AGENT_NAME environment variable is required. "
            "Set it to the agent name before starting the MCP server."
        )

    _agent = Agent(
        name,
        relay=os.environ.get("UAM_RELAY_URL"),
        display_name=os.environ.get("UAM_DISPLAY_NAME"),
        transport=os.environ.get("UAM_TRANSPORT", "http"),
        trust_policy=os.environ.get("UAM_TRUST_POLICY", "auto-accept"),
    )
    await _agent.connect()
    return _agent


# ---------------------------------------------------------------------------
# Tool functions (module-level for direct import in tests)
# ---------------------------------------------------------------------------


async def uam_send(
    to_address: str,
    message: str,
    thread_id: str | None = None,
) -> str:
    """Send an encrypted, signed UAM message to another agent.

    Args:
        to_address: The recipient's UAM address (e.g. "agent::domain").
        message: The plaintext message content to send.
        thread_id: Optional thread ID for conversation threading.

    Returns:
        A confirmation string with the message ID, or an error description.
    """
    try:
        agent = await _get_agent()
        message_id = await agent.send(to_address, message, thread_id=thread_id)
        return f"Message sent successfully. ID: {message_id}"
    except Exception as exc:
        logger.exception("uam_send failed")
        return f"Error sending message: {_safe_error(exc)}"


async def uam_inbox(limit: int = 50) -> str:
    """Retrieve and decrypt pending UAM messages.

    Args:
        limit: Maximum number of messages to retrieve (default 50).

    Returns:
        Formatted message list, "No pending messages.", or an error description.
    """
    try:
        agent = await _get_agent()
        messages = await agent.inbox(limit=limit)

        if not messages:
            return "No pending messages."

        total = len(messages)
        parts: list[str] = []
        for i, msg in enumerate(messages, 1):
            parts.append(
                f"--- Message {i}/{total} ---\n"
                f"From: {msg.from_address}\n"
                f"Time: {msg.timestamp}\n"
                f"Type: {msg.type}\n"
                f"Thread: {msg.thread_id or 'none'}\n"
                f"Content: {msg.content}"
            )
        return "\n\n".join(parts)
    except Exception as exc:
        logger.exception("uam_inbox failed")
        return f"Error checking inbox: {_safe_error(exc)}"


async def uam_contact_card() -> str:
    """Get a signed contact card for this agent.

    Returns the agent's contact card as a JSON string containing
    address, public key, relay endpoint, and a cryptographic signature.
    Share this with other agents so they can verify your identity.

    Returns:
        JSON string of the signed contact card, or an error description.
    """
    try:
        agent = await _get_agent()
        card = agent.contact_card()
        return json.dumps(card, indent=2)
    except Exception as exc:
        logger.exception("uam_contact_card failed")
        return f"Error generating contact card: {_safe_error(exc)}"


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
