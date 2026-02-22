"""Tests for the OpenClaw channel plugin (CLAW-01).

All Agent interactions are mocked to avoid network calls.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from uam.protocol import UAMError
from uam.plugin.openclaw import (
    UAMChannel,
    send_message,
    check_inbox,
    get_contact_card,
    list_contacts,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mock_received_message(**overrides):
    """Create a MagicMock that looks like a ReceivedMessage."""
    defaults = {
        "message_id": "msg-001",
        "from_address": "bob::relay.example",
        "content": "hello back",
        "timestamp": "2026-01-01T00:00:00Z",
        "thread_id": None,
    }
    defaults.update(overrides)
    m = MagicMock()
    for k, v in defaults.items():
        setattr(m, k, v)
    return m


# ---------------------------------------------------------------------------
# UAMChannel.send
# ---------------------------------------------------------------------------


@patch("uam.plugin.openclaw.Agent")
def test_uam_channel_send(MockAgent):
    """send() creates an Agent, connects, sends, and closes."""
    agent_instance = MockAgent.return_value
    agent_instance.send_sync.return_value = "msg-123"

    channel = UAMChannel("test")
    result = channel.send("bob::relay.example", "hello")

    MockAgent.assert_called_once_with(
        "test",
        auto_register=True,
        trust_policy="auto-accept",
    )
    agent_instance.connect_sync.assert_called_once()
    agent_instance.send_sync.assert_called_once_with(
        "bob::relay.example", "hello", thread_id=None
    )
    agent_instance.close_sync.assert_called_once()
    assert result == "msg-123"


# ---------------------------------------------------------------------------
# UAMChannel.inbox
# ---------------------------------------------------------------------------


@patch("uam.plugin.openclaw.Agent")
def test_uam_channel_inbox(MockAgent):
    """inbox() creates an Agent, connects, fetches inbox, and closes."""
    agent_instance = MockAgent.return_value
    mock_msg = _mock_received_message()
    agent_instance.inbox_sync.return_value = [mock_msg]

    channel = UAMChannel("test")
    result = channel.inbox(limit=5)

    agent_instance.connect_sync.assert_called_once()
    agent_instance.inbox_sync.assert_called_once_with(limit=5)
    agent_instance.close_sync.assert_called_once()

    assert len(result) == 1
    msg = result[0]
    assert msg["message_id"] == "msg-001"
    assert msg["from"] == "bob::relay.example"
    assert msg["content"] == "hello back"
    assert msg["timestamp"] == "2026-01-01T00:00:00Z"
    assert msg["thread_id"] is None


# ---------------------------------------------------------------------------
# UAMChannel.contact_card
# ---------------------------------------------------------------------------


@patch("uam.plugin.openclaw.Agent")
def test_uam_channel_contact_card(MockAgent):
    """contact_card() creates an Agent, connects, gets card, and closes."""
    agent_instance = MockAgent.return_value
    agent_instance.contact_card.return_value = {"address": "test::relay.example"}

    channel = UAMChannel("test")
    result = channel.contact_card()

    agent_instance.connect_sync.assert_called_once()
    agent_instance.contact_card.assert_called_once()
    agent_instance.close_sync.assert_called_once()
    assert result == {"address": "test::relay.example"}


# ---------------------------------------------------------------------------
# UAMChannel.contacts (offline)
# ---------------------------------------------------------------------------


@patch("uam.plugin.openclaw.ContactBook")
@patch("uam.plugin.openclaw.SDKConfig")
def test_uam_channel_contacts_offline(MockConfig, MockBook):
    """contacts() uses ContactBook directly, no Agent needed."""
    mock_cfg = MockConfig.return_value
    mock_cfg.data_dir = "/tmp/uam-test"

    mock_book = MockBook.return_value

    # Make open/close/list_contacts proper coroutines
    async def _noop():
        pass

    async def _list():
        return [{"address": "alice::relay.example", "display_name": "Alice"}]

    mock_book.open = MagicMock(side_effect=lambda: _noop())
    mock_book.close = MagicMock(side_effect=lambda: _noop())
    mock_book.list_contacts = MagicMock(side_effect=lambda: _list())

    channel = UAMChannel("test")
    result = channel.contacts()

    MockBook.assert_called_once_with("/tmp/uam-test")
    mock_book.open.assert_called_once()
    mock_book.list_contacts.assert_called_once()
    mock_book.close.assert_called_once()

    assert len(result) == 1
    assert result[0]["address"] == "alice::relay.example"


# ---------------------------------------------------------------------------
# UAMChannel.is_initialized
# ---------------------------------------------------------------------------


def test_uam_channel_is_initialized_true(tmp_path):
    """is_initialized() returns True when a .key file exists."""
    # Create a fake key file
    key_dir = tmp_path / "keys"
    key_dir.mkdir()
    (key_dir / "myagent.key").write_text("fake-key")

    with patch("uam.plugin.openclaw.SDKConfig") as MockConfig:
        mock_cfg = MockConfig.return_value
        mock_cfg.key_dir = key_dir

        channel = UAMChannel("myagent")
        assert channel.is_initialized() is True


def test_uam_channel_is_initialized_false(tmp_path):
    """is_initialized() returns False when no .key files exist."""
    key_dir = tmp_path / "keys"
    key_dir.mkdir()

    with patch("uam.plugin.openclaw.SDKConfig") as MockConfig:
        mock_cfg = MockConfig.return_value
        mock_cfg.key_dir = key_dir

        channel = UAMChannel("myagent")
        assert channel.is_initialized() is False


# ---------------------------------------------------------------------------
# Convenience functions
# ---------------------------------------------------------------------------


@patch("uam.plugin.openclaw.UAMChannel")
def test_send_message_convenience(MockChannel):
    """send_message() creates a UAMChannel and calls send()."""
    mock_instance = MockChannel.return_value
    mock_instance.send.return_value = "msg-456"

    result = send_message("bob::relay.example", "hello")

    MockChannel.assert_called_once_with(None)
    mock_instance.send.assert_called_once_with("bob::relay.example", "hello")
    assert result == "msg-456"


@patch("uam.plugin.openclaw.UAMChannel")
def test_check_inbox_convenience(MockChannel):
    """check_inbox() creates a UAMChannel and calls inbox()."""
    mock_instance = MockChannel.return_value
    mock_instance.inbox.return_value = [{"message_id": "msg-789"}]

    result = check_inbox()

    MockChannel.assert_called_once_with(None)
    mock_instance.inbox.assert_called_once_with(limit=20)
    assert result == [{"message_id": "msg-789"}]


# ---------------------------------------------------------------------------
# Auto-name from hostname
# ---------------------------------------------------------------------------


@patch("uam.plugin.openclaw.socket")
@patch("uam.plugin.openclaw.SDKConfig")
def test_uam_channel_auto_name_from_hostname(MockConfig, mock_socket):
    """_auto_name() derives agent name from hostname when none is set."""
    mock_socket.gethostname.return_value = "myhost.local"

    # Make _detect_agent_name return None (no existing keys)
    mock_cfg = MockConfig.return_value
    mock_cfg.key_dir = Path("/nonexistent/keys")

    channel = UAMChannel()  # No agent_name
    assert channel._agent_name is None  # _detect_agent_name found nothing

    name = channel._auto_name()
    assert name == "myhost"
    assert channel._agent_name == "myhost"  # cached


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------


@patch("uam.plugin.openclaw.Agent")
def test_uam_channel_error_handling(MockAgent):
    """send() re-raises UAMError from Agent.connect_sync."""
    agent_instance = MockAgent.return_value
    agent_instance.connect_sync.side_effect = UAMError("connection failed")

    channel = UAMChannel("test")
    with pytest.raises(UAMError, match="connection failed"):
        channel.send("bob::relay.example", "hello")

    agent_instance.close_sync.assert_called_once()
