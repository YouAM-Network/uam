"""CLI tests for TOFU trust visibility and contact management commands.

Tests: trust indicators in contacts display, fingerprint output,
verify trust upgrade, remove contact deletion, error handling.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from click.testing import CliRunner
from nacl.signing import SigningKey

from uam.cli.main import cli
from uam.protocol.crypto import public_key_fingerprint, serialize_verify_key
from uam.sdk.contact_book import ContactBook


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


@pytest.fixture
def alice_keys():
    """Generate a deterministic-ish keypair for Alice test contact."""
    sk = SigningKey.generate()
    vk = sk.verify_key
    pk_str = serialize_verify_key(vk)
    fp = public_key_fingerprint(vk)
    return {"signing_key": sk, "verify_key": vk, "public_key": pk_str, "fingerprint": fp}


async def _add_contact(
    uam_home: Path,
    address: str,
    public_key: str,
    trust_state: str = "trusted",
    trust_source: str | None = None,
) -> None:
    """Add a test contact to the contact book at uam_home."""
    book = ContactBook(uam_home)
    await book.open()
    await book.add_contact(
        address, public_key, trust_state=trust_state, trust_source=trust_source
    )
    await book.close()


# ---------------------------------------------------------------------------
# Trust indicator tests in `uam contacts` display
# ---------------------------------------------------------------------------


def test_contacts_shows_provisional_indicator(
    runner: CliRunner, uam_home: Path, alice_keys: dict
):
    """contacts command shows 'provisional (!)' for provisional contacts."""
    asyncio.run(
        _add_contact(uam_home, "alice::relay.test", alice_keys["public_key"], "provisional")
    )
    result = runner.invoke(cli, ["contacts"], env={"UAM_HOME": str(uam_home)})
    assert result.exit_code == 0
    assert "provisional (!)" in result.output


def test_contacts_shows_pinned_indicator(
    runner: CliRunner, uam_home: Path, alice_keys: dict
):
    """contacts command shows 'pinned [P]' for pinned contacts."""
    asyncio.run(
        _add_contact(uam_home, "alice::relay.test", alice_keys["public_key"], "pinned")
    )
    result = runner.invoke(cli, ["contacts"], env={"UAM_HOME": str(uam_home)})
    assert result.exit_code == 0
    assert "pinned [P]" in result.output


def test_contacts_shows_verified_indicator(
    runner: CliRunner, uam_home: Path, alice_keys: dict
):
    """contacts command shows 'verified [V]' for verified contacts."""
    asyncio.run(
        _add_contact(uam_home, "alice::relay.test", alice_keys["public_key"], "verified")
    )
    result = runner.invoke(cli, ["contacts"], env={"UAM_HOME": str(uam_home)})
    assert result.exit_code == 0
    assert "verified [V]" in result.output


# ---------------------------------------------------------------------------
# uam contact fingerprint
# ---------------------------------------------------------------------------


def test_contact_fingerprint_known_address(
    runner: CliRunner, uam_home: Path, alice_keys: dict
):
    """contact fingerprint shows Fingerprint: and Full: for known contact."""
    asyncio.run(
        _add_contact(uam_home, "alice::relay.test", alice_keys["public_key"], "pinned")
    )
    result = runner.invoke(
        cli, ["contact", "fingerprint", "alice::relay.test"],
        env={"UAM_HOME": str(uam_home)},
    )
    assert result.exit_code == 0
    assert "Fingerprint:" in result.output
    assert "Full:" in result.output
    # Verify hex content is present
    assert alice_keys["fingerprint"][:16] in result.output
    assert alice_keys["fingerprint"] in result.output


def test_contact_fingerprint_unknown_address(runner: CliRunner, uam_home: Path):
    """contact fingerprint for unknown address exits 1 with error."""
    result = runner.invoke(
        cli, ["contact", "fingerprint", "unknown::relay.test"],
        env={"UAM_HOME": str(uam_home)},
    )
    assert result.exit_code == 1
    assert "not found" in result.output.lower()


def test_contact_fingerprint_length(
    runner: CliRunner, uam_home: Path, alice_keys: dict
):
    """Short fingerprint is 16 hex chars, full fingerprint is 64 hex chars."""
    asyncio.run(
        _add_contact(uam_home, "alice::relay.test", alice_keys["public_key"], "trusted")
    )
    result = runner.invoke(
        cli, ["contact", "fingerprint", "alice::relay.test"],
        env={"UAM_HOME": str(uam_home)},
    )
    assert result.exit_code == 0

    lines = result.output.strip().splitlines()
    fp_line = [l for l in lines if l.startswith("Fingerprint:")][0]
    full_line = [l for l in lines if l.startswith("Full:")][0]

    short_fp = fp_line.split(":", 1)[1].strip()
    full_fp = full_line.split(":", 1)[1].strip()

    assert len(short_fp) == 16
    assert all(c in "0123456789abcdef" for c in short_fp)
    assert len(full_fp) == 64
    assert all(c in "0123456789abcdef" for c in full_fp)


# ---------------------------------------------------------------------------
# uam contact verify
# ---------------------------------------------------------------------------


def test_contact_verify_upgrades_trust(
    runner: CliRunner, uam_home: Path, alice_keys: dict
):
    """contact verify upgrades a provisional contact to verified."""
    asyncio.run(
        _add_contact(
            uam_home, "alice::relay.test", alice_keys["public_key"], "provisional"
        )
    )
    result = runner.invoke(
        cli, ["contact", "verify", "alice::relay.test"],
        env={"UAM_HOME": str(uam_home)},
    )
    assert result.exit_code == 0
    assert "verified" in result.output.lower()

    # Confirm trust_state was actually updated in the database
    async def _check():
        book = ContactBook(uam_home)
        await book.open()
        state = await book.get_trust_state("alice::relay.test")
        await book.close()
        return state

    assert asyncio.run(_check()) == "verified"


def test_contact_verify_unknown_address(runner: CliRunner, uam_home: Path):
    """contact verify for unknown address exits 1."""
    result = runner.invoke(
        cli, ["contact", "verify", "unknown::relay.test"],
        env={"UAM_HOME": str(uam_home)},
    )
    assert result.exit_code == 1
    assert "not found" in result.output.lower()


# ---------------------------------------------------------------------------
# uam contact remove
# ---------------------------------------------------------------------------


def test_contact_remove_deletes_contact(
    runner: CliRunner, uam_home: Path, alice_keys: dict
):
    """contact remove deletes the contact from the book."""
    asyncio.run(
        _add_contact(uam_home, "alice::relay.test", alice_keys["public_key"], "pinned")
    )
    result = runner.invoke(
        cli, ["contact", "remove", "alice::relay.test"],
        env={"UAM_HOME": str(uam_home)},
    )
    assert result.exit_code == 0
    assert "removed" in result.output.lower()
    assert "re-resolve" in result.output.lower()

    # Confirm contact is gone
    async def _check():
        book = ContactBook(uam_home)
        await book.open()
        pk = await book.get_public_key("alice::relay.test")
        await book.close()
        return pk

    assert asyncio.run(_check()) is None


def test_contact_remove_unknown_address(runner: CliRunner, uam_home: Path):
    """contact remove for unknown address exits 1."""
    result = runner.invoke(
        cli, ["contact", "remove", "unknown::relay.test"],
        env={"UAM_HOME": str(uam_home)},
    )
    assert result.exit_code == 1
    assert "not found" in result.output.lower()
