"""OpenClaw channel plugin for UAM messaging (CLAW-01).

Provides programmatic access to UAM messaging as a native channel.
OpenClaw agents import these functions to send and receive messages
without using the CLI directly.

Usage::

    from uam.plugin.openclaw import UAMChannel

    channel = UAMChannel("my-agent")
    channel.send("other::youam.network", "Hello from OpenClaw!")
    messages = channel.inbox()
"""

from __future__ import annotations

import asyncio
import socket
from pathlib import Path

from uam.protocol import UAMError
from uam.sdk.agent import Agent
from uam.sdk.config import SDKConfig
from uam.sdk.contact_book import ContactBook


class UAMChannel:
    """Native UAM messaging channel for OpenClaw agents.

    Manages agent lifecycle (init, connect, disconnect) automatically.
    Each method creates a short-lived connection, performs the operation,
    and disconnects. This is safe for OpenClaw's stateless skill execution model.
    """

    def __init__(
        self,
        agent_name: str | None = None,
        *,
        relay: str | None = None,
        display_name: str | None = None,
        trust_policy: str = "auto-accept",
    ) -> None:
        self._agent_name = agent_name
        self._relay = relay
        self._display_name = display_name
        self._trust_policy = trust_policy

        # Auto-detect agent name from existing keys if not provided
        if self._agent_name is None:
            self._agent_name = self._detect_agent_name()

    # -- Public API ----------------------------------------------------------

    def send(
        self,
        to_address: str,
        message: str,
        *,
        thread_id: str | None = None,
    ) -> str:
        """Send a UAM message. Returns the message ID.

        Auto-initializes and connects, performs the send, then disconnects.
        """
        agent = self._make_agent()
        try:
            agent.connect_sync()
            msg_id = agent.send_sync(to_address, message, thread_id=thread_id)
            return msg_id
        except UAMError:
            raise
        except Exception as exc:
            raise UAMError(f"UAM channel error: {exc}") from exc
        finally:
            try:
                agent.close_sync()
            except Exception:
                pass

    def inbox(self, limit: int = 20) -> list[dict]:
        """Check UAM inbox. Returns a list of message dicts.

        Each dict contains: message_id, from, content, timestamp, thread_id.
        """
        agent = self._make_agent()
        try:
            agent.connect_sync()
            messages = agent.inbox_sync(limit=limit)
            return [
                {
                    "message_id": m.message_id,
                    "from": m.from_address,
                    "content": m.content,
                    "timestamp": m.timestamp,
                    "thread_id": m.thread_id,
                }
                for m in messages
            ]
        except UAMError:
            raise
        except Exception as exc:
            raise UAMError(f"UAM channel error: {exc}") from exc
        finally:
            try:
                agent.close_sync()
            except Exception:
                pass

    def contact_card(self) -> dict:
        """Get your signed contact card as a JSON-compatible dict."""
        agent = self._make_agent()
        try:
            agent.connect_sync()
            return agent.contact_card()
        except UAMError:
            raise
        except Exception as exc:
            raise UAMError(f"UAM channel error: {exc}") from exc
        finally:
            try:
                agent.close_sync()
            except Exception:
                pass

    def contacts(self) -> list[dict]:
        """List known contacts (offline, no relay connection needed).

        Uses ContactBook directly -- does not create an Agent connection.
        """
        name = self._agent_name or self._auto_name()
        cfg = SDKConfig(name=name)
        book = ContactBook(cfg.data_dir)

        async def _list() -> list[dict]:
            await book.open()
            try:
                return await book.list_contacts()
            finally:
                await book.close()

        try:
            return asyncio.run(_list())
        except UAMError:
            raise
        except Exception as exc:
            raise UAMError(f"UAM channel error: {exc}") from exc

    def is_initialized(self) -> bool:
        """Check if UAM agent keys exist on disk."""
        name = self._agent_name or "_probe"
        cfg = SDKConfig(name=name)
        key_dir = Path(cfg.key_dir)
        if not key_dir.exists():
            return False
        key_files = list(key_dir.glob("*.key"))
        return len(key_files) > 0

    # -- Internal helpers ----------------------------------------------------

    def _auto_name(self) -> str:
        """Generate an agent name from hostname if none is set.

        Caches the result in self._agent_name for subsequent calls.
        """
        if self._agent_name is not None:
            return self._agent_name
        name = socket.gethostname().split(".")[0].lower()
        self._agent_name = name
        return name

    def _detect_agent_name(self) -> str | None:
        """Scan ~/.uam/keys/ for a .key file and return the agent name.

        Same pattern as _find_agent_name() in cli/main.py.
        """
        cfg = SDKConfig(name="_probe")
        key_dir = Path(cfg.key_dir)
        if not key_dir.exists():
            return None
        key_files = sorted(key_dir.glob("*.key"))
        if not key_files:
            return None
        return key_files[0].stem

    def _make_agent(self) -> Agent:
        """Create an Agent instance with this channel's configuration."""
        name = self._agent_name or self._auto_name()
        kwargs: dict = {
            "auto_register": True,
            "trust_policy": self._trust_policy,
        }
        if self._relay is not None:
            kwargs["relay"] = self._relay
        if self._display_name is not None:
            kwargs["display_name"] = self._display_name
        return Agent(name, **kwargs)


# ---------------------------------------------------------------------------
# Module-level convenience functions
# ---------------------------------------------------------------------------


def send_message(
    to_address: str,
    message: str,
    *,
    agent_name: str | None = None,
    **kwargs,
) -> str:
    """Send a UAM message. Auto-initializes agent if needed."""
    channel = UAMChannel(agent_name)
    return channel.send(to_address, message, **kwargs)


def check_inbox(
    *,
    agent_name: str | None = None,
    limit: int = 20,
) -> list[dict]:
    """Check UAM inbox. Auto-initializes agent if needed."""
    channel = UAMChannel(agent_name)
    return channel.inbox(limit=limit)


def get_contact_card(*, agent_name: str | None = None) -> dict:
    """Get your signed contact card."""
    channel = UAMChannel(agent_name)
    return channel.contact_card()


def list_contacts(*, agent_name: str | None = None) -> list[dict]:
    """List known contacts (offline, no relay connection needed)."""
    channel = UAMChannel(agent_name)
    return channel.contacts()
