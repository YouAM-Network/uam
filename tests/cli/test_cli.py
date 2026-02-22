"""CLI tests using click.testing.CliRunner.

Uses UAM_HOME env var to isolate key/data directories per test.
Offline commands (whoami, contacts) need no relay mocking.
Online commands (init, send, inbox) mock the Agent sync wrappers.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from uam.cli.main import cli
from uam.sdk.contact_book import ContactBook
from uam.sdk.key_manager import KeyManager


@pytest.fixture
def runner():
    """Click CliRunner for CLI testing."""
    return CliRunner()


@pytest.fixture
def uam_home(tmp_path: Path) -> Path:
    """Provide an isolated UAM_HOME directory."""
    home = tmp_path / "uam_home"
    home.mkdir()
    return home


# ---------------------------------------------------------------------------
# test_cli_help
# ---------------------------------------------------------------------------


def test_cli_help(runner: CliRunner):
    """--help shows all commands including bridge."""
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    for cmd in ("init", "send", "inbox", "whoami", "contacts", "card", "pending", "approve", "deny", "block", "unblock", "verify-domain", "bridge"):
        assert cmd in result.output


# ---------------------------------------------------------------------------
# test_cli_version
# ---------------------------------------------------------------------------


def test_cli_version(runner: CliRunner):
    """--version prints version string."""
    result = runner.invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert "0.1.0" in result.output


# ---------------------------------------------------------------------------
# test_whoami_no_keys
# ---------------------------------------------------------------------------


def test_whoami_no_keys(runner: CliRunner, uam_home: Path):
    """whoami with no keys exits 1 with helpful message."""
    result = runner.invoke(cli, ["whoami"], env={"UAM_HOME": str(uam_home)})
    assert result.exit_code == 1
    assert "No agent initialized" in result.output


# ---------------------------------------------------------------------------
# test_whoami_with_keys
# ---------------------------------------------------------------------------


def test_whoami_with_keys(runner: CliRunner, uam_home: Path):
    """whoami with existing keys prints address and fingerprint."""
    key_dir = uam_home / "keys"
    key_dir.mkdir(parents=True)

    km = KeyManager(key_dir)
    km.load_or_generate("testagent")

    result = runner.invoke(
        cli,
        ["--name", "testagent", "whoami"],
        env={"UAM_HOME": str(uam_home)},
    )
    assert result.exit_code == 0
    assert "testagent::" in result.output
    assert "Fingerprint:" in result.output
    assert "Key file:" in result.output
    # Fingerprint is 64 hex chars
    for line in result.output.splitlines():
        if line.startswith("Fingerprint:"):
            fp = line.split(":", 1)[1].strip()
            assert len(fp) == 64
            assert all(c in "0123456789abcdef" for c in fp)


# ---------------------------------------------------------------------------
# test_init_command
# ---------------------------------------------------------------------------


def test_init_command(runner: CliRunner, uam_home: Path):
    """init creates agent and prints address (mock relay registration)."""
    fake_address = "testagent::relay.youam.network"

    with patch("uam.cli.main.Agent") as MockAgent:
        instance = MagicMock()
        instance.address = fake_address
        instance._key_manager = MagicMock()
        instance._key_manager.verify_key = KeyManager._make_test_vk()
        MockAgent.return_value = instance

        # Patch public_key_fingerprint to accept mock
        with patch("uam.cli.main.public_key_fingerprint", return_value="a" * 64):
            result = runner.invoke(
                cli,
                ["init", "--name", "testagent"],
                env={"UAM_HOME": str(uam_home)},
            )

    assert result.exit_code == 0
    assert "Initialized agent:" in result.output
    assert fake_address in result.output
    instance.connect_sync.assert_called_once()
    instance.close_sync.assert_called_once()


# ---------------------------------------------------------------------------
# test_init_already_initialized
# ---------------------------------------------------------------------------


def test_init_already_initialized(runner: CliRunner, uam_home: Path):
    """init with existing keys prints 'already initialized'."""
    key_dir = uam_home / "keys"
    key_dir.mkdir(parents=True)
    km = KeyManager(key_dir)
    km.load_or_generate("testagent")

    result = runner.invoke(
        cli,
        ["init", "--name", "testagent"],
        env={"UAM_HOME": str(uam_home)},
    )
    assert result.exit_code == 0
    assert "already initialized" in result.output


# ---------------------------------------------------------------------------
# test_send_no_keys
# ---------------------------------------------------------------------------


def test_send_no_keys(runner: CliRunner, uam_home: Path):
    """send with no keys exits 1 with helpful message."""
    result = runner.invoke(
        cli,
        ["send", "alice::youam.network", "hello"],
        env={"UAM_HOME": str(uam_home)},
    )
    assert result.exit_code == 1
    assert "No agent initialized" in result.output


# ---------------------------------------------------------------------------
# test_inbox_no_keys
# ---------------------------------------------------------------------------


def test_inbox_no_keys(runner: CliRunner, uam_home: Path):
    """inbox with no keys exits 1 with helpful message."""
    result = runner.invoke(
        cli,
        ["inbox"],
        env={"UAM_HOME": str(uam_home)},
    )
    assert result.exit_code == 1
    assert "No agent initialized" in result.output


# ---------------------------------------------------------------------------
# test_contacts_empty
# ---------------------------------------------------------------------------


def test_contacts_empty(runner: CliRunner, uam_home: Path):
    """contacts with empty data dir prints 'No contacts yet'."""
    result = runner.invoke(
        cli,
        ["contacts"],
        env={"UAM_HOME": str(uam_home)},
    )
    assert result.exit_code == 0
    assert "No contacts yet" in result.output


# ---------------------------------------------------------------------------
# test_contacts_with_data
# ---------------------------------------------------------------------------


def test_contacts_with_data(runner: CliRunner, uam_home: Path):
    """contacts with data shows contact address and trust state."""
    # Pre-populate the contact book
    book = ContactBook(uam_home)
    asyncio.run(_populate_contacts(book))

    result = runner.invoke(
        cli,
        ["contacts"],
        env={"UAM_HOME": str(uam_home)},
    )
    assert result.exit_code == 0
    assert "alice::youam.network" in result.output
    assert "trusted" in result.output


async def _populate_contacts(book: ContactBook) -> None:
    """Add a test contact to the book."""
    await book.open()
    await book.add_contact(
        "alice::youam.network",
        "fakepublickey123",
        display_name="Alice",
        trust_state="trusted",
    )
    await book.close()


# ---------------------------------------------------------------------------
# test_card_no_keys
# ---------------------------------------------------------------------------


def test_card_no_keys(runner: CliRunner, uam_home: Path):
    """card with no keys exits 1 with helpful message."""
    result = runner.invoke(
        cli,
        ["card"],
        env={"UAM_HOME": str(uam_home)},
    )
    assert result.exit_code == 1
    assert "No agent initialized" in result.output


# ---------------------------------------------------------------------------
# test_card_success
# ---------------------------------------------------------------------------


def test_card_success(runner: CliRunner, uam_home: Path):
    """card with valid agent prints JSON contact card."""
    key_dir = uam_home / "keys"
    key_dir.mkdir(parents=True)
    km = KeyManager(key_dir)
    km.load_or_generate("testagent")

    with patch("uam.cli.main.Agent") as MockAgent:
        instance = MagicMock()
        instance.contact_card.return_value = {
            "address": "testagent::relay.test",
            "public_key": "TESTKEY",
            "relay": "wss://relay.test/ws",
            "signature": "TESTSIG",
            "timestamp": "2026-02-20T00:00:00Z",
        }
        MockAgent.return_value = instance

        result = runner.invoke(
            cli,
            ["card"],
            env={"UAM_HOME": str(uam_home)},
        )

    assert result.exit_code == 0
    assert "testagent::relay.test" in result.output
    assert "TESTKEY" in result.output
    # Verify output is valid JSON
    parsed = json.loads(result.output)
    assert parsed["address"] == "testagent::relay.test"
    assert parsed["relay"] == "wss://relay.test/ws"
    instance.connect_sync.assert_called_once()
    instance.contact_card.assert_called_once()
    instance.close_sync.assert_called_once()


# ---------------------------------------------------------------------------
# test_send_success (mocked)
# ---------------------------------------------------------------------------


def test_send_success(runner: CliRunner, uam_home: Path):
    """send with valid keys and mocked agent prints confirmation."""
    # Create keys so _find_agent_name works
    key_dir = uam_home / "keys"
    key_dir.mkdir(parents=True)
    km = KeyManager(key_dir)
    km.load_or_generate("testagent")

    with patch("uam.cli.main.Agent") as MockAgent:
        instance = MagicMock()
        instance.send_sync.return_value = "msg-123-abc"
        MockAgent.return_value = instance

        result = runner.invoke(
            cli,
            ["send", "bob::youam.network", "hello bob"],
            env={"UAM_HOME": str(uam_home)},
        )

    assert result.exit_code == 0
    assert "msg-123-abc" in result.output
    assert "bob::youam.network" in result.output
    instance.connect_sync.assert_called_once()
    instance.send_sync.assert_called_once_with("bob::youam.network", "hello bob")


# ---------------------------------------------------------------------------
# test_inbox_success (mocked)
# ---------------------------------------------------------------------------


def test_inbox_success(runner: CliRunner, uam_home: Path):
    """inbox with mocked messages displays them correctly."""
    key_dir = uam_home / "keys"
    key_dir.mkdir(parents=True)
    km = KeyManager(key_dir)
    km.load_or_generate("testagent")

    mock_msg = MagicMock()
    mock_msg.from_address = "alice::youam.network"
    mock_msg.timestamp = "2026-02-20T10:30:00Z"
    mock_msg.content = "Hello, how are you?"

    with patch("uam.cli.main.Agent") as MockAgent:
        instance = MagicMock()
        instance.inbox_sync.return_value = [mock_msg]
        MockAgent.return_value = instance

        result = runner.invoke(
            cli,
            ["inbox"],
            env={"UAM_HOME": str(uam_home)},
        )

    assert result.exit_code == 0
    assert "alice::youam.network" in result.output
    assert "2026-02-20T10:30:00Z" in result.output
    assert "Hello, how are you?" in result.output


# ---------------------------------------------------------------------------
# test_pending_no_keys
# ---------------------------------------------------------------------------


def test_pending_no_keys(runner: CliRunner, uam_home: Path):
    """pending with no keys exits 1 with helpful message."""
    result = runner.invoke(
        cli,
        ["pending"],
        env={"UAM_HOME": str(uam_home)},
    )
    assert result.exit_code == 1
    assert "No agent initialized" in result.output


# ---------------------------------------------------------------------------
# test_pending_empty
# ---------------------------------------------------------------------------


def test_pending_empty(runner: CliRunner, uam_home: Path):
    """pending with no pending requests shows message."""
    key_dir = uam_home / "keys"
    key_dir.mkdir(parents=True)
    km = KeyManager(key_dir)
    km.load_or_generate("testagent")

    with patch("uam.cli.main.Agent") as MockAgent:
        instance = MagicMock()
        instance.pending_sync.return_value = []
        MockAgent.return_value = instance

        result = runner.invoke(
            cli,
            ["pending"],
            env={"UAM_HOME": str(uam_home)},
        )

    assert result.exit_code == 0
    assert "No pending" in result.output


# ---------------------------------------------------------------------------
# test_pending_with_requests
# ---------------------------------------------------------------------------


def test_pending_with_requests(runner: CliRunner, uam_home: Path):
    """pending with items shows address and received time."""
    key_dir = uam_home / "keys"
    key_dir.mkdir(parents=True)
    km = KeyManager(key_dir)
    km.load_or_generate("testagent")

    with patch("uam.cli.main.Agent") as MockAgent:
        instance = MagicMock()
        instance.pending_sync.return_value = [
            {"address": "alice::test.local", "contact_card": "{}", "received_at": "2026-02-20 10:00:00"},
        ]
        MockAgent.return_value = instance

        result = runner.invoke(
            cli,
            ["pending"],
            env={"UAM_HOME": str(uam_home)},
        )

    assert result.exit_code == 0
    assert "alice::test.local" in result.output
    assert "2026-02-20" in result.output


# ---------------------------------------------------------------------------
# test_approve_success
# ---------------------------------------------------------------------------


def test_approve_success(runner: CliRunner, uam_home: Path):
    """approve prints confirmation."""
    key_dir = uam_home / "keys"
    key_dir.mkdir(parents=True)
    km = KeyManager(key_dir)
    km.load_or_generate("testagent")

    with patch("uam.cli.main.Agent") as MockAgent:
        instance = MagicMock()
        MockAgent.return_value = instance

        result = runner.invoke(
            cli,
            ["approve", "alice::test.local"],
            env={"UAM_HOME": str(uam_home)},
        )

    assert result.exit_code == 0
    assert "Approved: alice::test.local" in result.output
    instance.connect_sync.assert_called_once()
    instance.approve_sync.assert_called_once_with("alice::test.local")
    instance.close_sync.assert_called_once()


# ---------------------------------------------------------------------------
# test_approve_no_keys
# ---------------------------------------------------------------------------


def test_approve_no_keys(runner: CliRunner, uam_home: Path):
    """approve with no keys exits 1."""
    result = runner.invoke(
        cli,
        ["approve", "alice::test.local"],
        env={"UAM_HOME": str(uam_home)},
    )
    assert result.exit_code == 1
    assert "No agent initialized" in result.output


# ---------------------------------------------------------------------------
# test_deny_success
# ---------------------------------------------------------------------------


def test_deny_success(runner: CliRunner, uam_home: Path):
    """deny prints confirmation."""
    key_dir = uam_home / "keys"
    key_dir.mkdir(parents=True)
    km = KeyManager(key_dir)
    km.load_or_generate("testagent")

    with patch("uam.cli.main.Agent") as MockAgent:
        instance = MagicMock()
        MockAgent.return_value = instance

        result = runner.invoke(
            cli,
            ["deny", "spammer::evil.com"],
            env={"UAM_HOME": str(uam_home)},
        )

    assert result.exit_code == 0
    assert "Denied: spammer::evil.com" in result.output
    instance.connect_sync.assert_called_once()
    instance.deny_sync.assert_called_once_with("spammer::evil.com")
    instance.close_sync.assert_called_once()


# ---------------------------------------------------------------------------
# test_deny_no_keys
# ---------------------------------------------------------------------------


def test_deny_no_keys(runner: CliRunner, uam_home: Path):
    """deny with no keys exits 1."""
    result = runner.invoke(
        cli,
        ["deny", "alice::test.local"],
        env={"UAM_HOME": str(uam_home)},
    )
    assert result.exit_code == 1
    assert "No agent initialized" in result.output


# ---------------------------------------------------------------------------
# test_block_exact_address
# ---------------------------------------------------------------------------


def test_block_exact_address(runner: CliRunner, uam_home: Path):
    """block stores pattern and prints confirmation."""
    result = runner.invoke(
        cli,
        ["block", "spammer::evil.com"],
        env={"UAM_HOME": str(uam_home)},
    )
    assert result.exit_code == 0
    assert "Blocked: spammer::evil.com" in result.output


# ---------------------------------------------------------------------------
# test_block_domain_pattern
# ---------------------------------------------------------------------------


def test_block_domain_pattern(runner: CliRunner, uam_home: Path):
    """block with domain wildcard stores pattern."""
    result = runner.invoke(
        cli,
        ["block", "*::evil.com"],
        env={"UAM_HOME": str(uam_home)},
    )
    assert result.exit_code == 0
    assert "Blocked: *::evil.com" in result.output


# ---------------------------------------------------------------------------
# test_unblock_success
# ---------------------------------------------------------------------------


def test_unblock_success(runner: CliRunner, uam_home: Path):
    """unblock removes pattern and prints confirmation."""
    # First block, then unblock
    runner.invoke(cli, ["block", "spammer::evil.com"], env={"UAM_HOME": str(uam_home)})
    result = runner.invoke(
        cli,
        ["unblock", "spammer::evil.com"],
        env={"UAM_HOME": str(uam_home)},
    )
    assert result.exit_code == 0
    assert "Unblocked: spammer::evil.com" in result.output


# ---------------------------------------------------------------------------
# test_verify_domain_success
# ---------------------------------------------------------------------------


def test_verify_domain_success(runner: CliRunner, uam_home: Path):
    """verify-domain with successful verification prints 'Verified!'."""
    key_dir = uam_home / "keys"
    key_dir.mkdir(parents=True)
    km = KeyManager(key_dir)
    km.load_or_generate("testagent")

    with patch("uam.cli.main.Agent") as MockAgent:
        instance = MagicMock()
        instance.public_key = "TESTPUBKEY123"
        instance._config = MagicMock()
        instance._config.relay_url = "https://relay.test"
        instance.verify_domain_sync.return_value = True
        instance.address = "testagent::relay.test"
        MockAgent.return_value = instance

        result = runner.invoke(
            cli,
            ["verify-domain", "example.com"],
            env={"UAM_HOME": str(uam_home)},
        )

    assert result.exit_code == 0
    assert "_uam.example.com" in result.output
    assert "TESTPUBKEY123" in result.output
    assert ".well-known/uam.json" in result.output
    assert "Polling for verification" in result.output
    assert "Verified!" in result.output
    assert "Tier 2" in result.output
    instance.connect_sync.assert_called_once()
    instance.close_sync.assert_called_once()


# ---------------------------------------------------------------------------
# test_verify_domain_timeout
# ---------------------------------------------------------------------------


def test_verify_domain_timeout(runner: CliRunner, uam_home: Path):
    """verify-domain with timeout prints 'timed out'."""
    key_dir = uam_home / "keys"
    key_dir.mkdir(parents=True)
    km = KeyManager(key_dir)
    km.load_or_generate("testagent")

    with patch("uam.cli.main.Agent") as MockAgent:
        instance = MagicMock()
        instance.public_key = "TESTPUBKEY123"
        instance._config = MagicMock()
        instance._config.relay_url = "https://relay.test"
        instance.verify_domain_sync.return_value = False
        instance.address = "testagent::relay.test"
        MockAgent.return_value = instance

        result = runner.invoke(
            cli,
            ["verify-domain", "example.com", "--timeout", "5"],
            env={"UAM_HOME": str(uam_home)},
        )

    assert result.exit_code == 0
    assert "timed out" in result.output
    assert "5s" in result.output
    instance.verify_domain_sync.assert_called_once_with(
        "example.com", timeout=5, poll_interval=10
    )


# ---------------------------------------------------------------------------
# test_verify_domain_no_keys
# ---------------------------------------------------------------------------


def test_verify_domain_no_keys(runner: CliRunner, uam_home: Path):
    """verify-domain with no keys exits 1 with helpful message."""
    result = runner.invoke(
        cli,
        ["verify-domain", "example.com"],
        env={"UAM_HOME": str(uam_home)},
    )
    assert result.exit_code == 1
    assert "No agent initialized" in result.output


# ---------------------------------------------------------------------------
# test_verify_domain_custom_poll_interval
# ---------------------------------------------------------------------------


def test_verify_domain_custom_poll_interval(runner: CliRunner, uam_home: Path):
    """verify-domain passes --poll-interval to verify_domain_sync."""
    key_dir = uam_home / "keys"
    key_dir.mkdir(parents=True)
    km = KeyManager(key_dir)
    km.load_or_generate("testagent")

    with patch("uam.cli.main.Agent") as MockAgent:
        instance = MagicMock()
        instance.public_key = "KEY"
        instance._config = MagicMock()
        instance._config.relay_url = "https://relay.test"
        instance.verify_domain_sync.return_value = True
        instance.address = "testagent::relay.test"
        MockAgent.return_value = instance

        result = runner.invoke(
            cli,
            ["verify-domain", "example.com", "--timeout", "60", "--poll-interval", "5"],
            env={"UAM_HOME": str(uam_home)},
        )

    assert result.exit_code == 0
    instance.verify_domain_sync.assert_called_once_with(
        "example.com", timeout=60, poll_interval=5
    )


# ---------------------------------------------------------------------------
# test_verify_domain_uam_error
# ---------------------------------------------------------------------------


def test_verify_domain_uam_error(runner: CliRunner, uam_home: Path):
    """verify-domain handles UAMError gracefully."""
    key_dir = uam_home / "keys"
    key_dir.mkdir(parents=True)
    km = KeyManager(key_dir)
    km.load_or_generate("testagent")

    from uam.protocol import UAMError

    with patch("uam.cli.main.Agent") as MockAgent:
        instance = MagicMock()
        instance.connect_sync.side_effect = UAMError("Connection failed")
        MockAgent.return_value = instance

        result = runner.invoke(
            cli,
            ["verify-domain", "example.com"],
            env={"UAM_HOME": str(uam_home)},
        )

    assert result.exit_code == 1
    assert "Error:" in result.output


# ---------------------------------------------------------------------------
# test_bridge_a2a_import
# ---------------------------------------------------------------------------


SAMPLE_A2A_CARD_FOR_CLI = {
    "name": "Weather Agent",
    "description": "Provides weather forecasts",
    "url": "https://weather.example.com/a2a",
    "version": "0.1",
    "capabilities": {"streaming": True, "pushNotifications": False},
    "skills": [
        {
            "id": "forecast",
            "name": "Weather Forecast",
            "description": "Get weather forecasts for any location",
            "tags": ["weather", "forecast"],
            "examples": ["What's the weather in Paris?"],
        }
    ],
}


def test_bridge_a2a_import(runner: CliRunner, uam_home: Path, monkeypatch):
    """uam bridge a2a import fetches and imports A2A agent card."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = SAMPLE_A2A_CARD_FOR_CLI
    mock_response.raise_for_status = MagicMock()

    monkeypatch.setattr("uam.cli.main.httpx.get", lambda *a, **kw: mock_response)
    monkeypatch.setattr("uam.cli.main._find_agent_name", lambda *a, **kw: "testuser")

    result = runner.invoke(
        cli,
        ["bridge", "a2a", "import", "https://weather.example.com"],
        env={"UAM_HOME": str(uam_home)},
    )

    assert result.exit_code == 0, f"CLI failed: {result.output}"
    assert "Imported A2A agent" in result.output
    assert "Weather Agent" in result.output


def test_bridge_a2a_import_bad_url(runner: CliRunner, uam_home: Path, monkeypatch):
    """uam bridge a2a import with unreachable URL shows error."""
    import httpx as httpx_mod

    monkeypatch.setattr(
        "uam.cli.main.httpx.get",
        MagicMock(side_effect=httpx_mod.ConnectError("Connection refused")),
    )

    result = runner.invoke(
        cli,
        ["bridge", "a2a", "import", "https://nonexistent.example.com"],
        env={"UAM_HOME": str(uam_home)},
    )

    assert result.exit_code != 0
    assert "Error" in result.output


# ---------------------------------------------------------------------------
# Helpers for test_init_command mock
# ---------------------------------------------------------------------------

# Add a static test helper to KeyManager for generating a verify key
# without persisting (used only in tests)
def _make_test_vk():
    """Generate a VerifyKey for test mocking."""
    from nacl.signing import SigningKey
    return SigningKey.generate().verify_key

KeyManager._make_test_vk = staticmethod(_make_test_vk)
