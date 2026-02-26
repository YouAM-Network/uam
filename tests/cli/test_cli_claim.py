"""Tests for CLI claim support (Phase 40): init --claim, card --vcf, vCard parser.

Tests cover:
- vCard 3.0 parser: line unfolding, field extraction, claim info extraction
- NOTE fallback: round-tripped vCards with stripped X- fields
- init --claim: successful claim, error cases
- card --vcf: stdout output and file output
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from uam.cards.vcard_parser import extract_claim_info, parse_vcard, unfold_lines
from uam.cli.main import cli
from uam.sdk.key_manager import KeyManager


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def uam_home(tmp_path: Path) -> Path:
    home = tmp_path / "uam_home"
    home.mkdir()
    return home


# Fake JPEG bytes to avoid Pillow dependency in tests
FAKE_JPEG = b"\xff\xd8\xff\xe0" + b"\x00" * 100

# Minimal reservation vCard for testing
RESERVATION_VCARD = (
    "BEGIN:VCARD\r\n"
    "VERSION:3.0\r\n"
    "FN:scout (Reserved - youam.network)\r\n"
    "N:;scout;;;\r\n"
    "ORG:youam.network\r\n"
    "TITLE:UAM Agent -- Reserved\r\n"
    "NOTE:UAM Reservation Card\\n\\nClaim this address:\\n"
    "  uam init --claim scout.vcf\\n\\n"
    "Claim Token: tok_abc123\\nExpires: 2026-03-01T00:00:00Z\\n"
    "Relay: https://relay.youam.network\r\n"
    "X-UAM-ADDRESS:scout::youam.network\r\n"
    "X-UAM-CLAIM-TOKEN:tok_abc123\r\n"
    "X-UAM-RELAY:https://relay.youam.network\r\n"
    "X-UAM-CARD-TYPE:reservation\r\n"
    "END:VCARD\r\n"
)


# ---------------------------------------------------------------------------
# vCard Parser Tests
# ---------------------------------------------------------------------------


def test_unfold_lines_basic():
    """Folded lines (continuation with leading SPACE) are unfolded correctly."""
    folded = "X-UAM-ADDRESS:scout::you\r\n am.network\r\n"
    result = unfold_lines(folded)
    assert "scout::youam.network" in result
    # No continuation characters remain
    assert "\n " not in result


def test_parse_vcard_extracts_fields():
    """parse_vcard returns a dict with expected fields from a minimal vCard."""
    fields = parse_vcard(RESERVATION_VCARD)
    assert fields["FN"] == "scout (Reserved - youam.network)"
    assert fields["X-UAM-CLAIM-TOKEN"] == "tok_abc123"
    assert fields["X-UAM-RELAY"] == "https://relay.youam.network"
    assert fields["X-UAM-ADDRESS"] == "scout::youam.network"
    assert "NOTE" in fields


def test_extract_claim_info_from_x_fields():
    """extract_claim_info gets claim_token, relay_url, address, agent_name from X-UAM-* fields."""
    info = extract_claim_info(RESERVATION_VCARD)
    assert info["claim_token"] == "tok_abc123"
    assert info["relay_url"] == "https://relay.youam.network"
    assert info["address"] == "scout::youam.network"
    assert info["agent_name"] == "scout"


def test_extract_claim_info_note_fallback():
    """NOTE fallback path works when X-UAM-CLAIM-TOKEN is missing."""
    # vCard WITHOUT X-UAM-CLAIM-TOKEN but WITH NOTE containing claim info
    vcf_no_x = (
        "BEGIN:VCARD\r\n"
        "VERSION:3.0\r\n"
        "FN:scout (Reserved - youam.network)\r\n"
        "NOTE:UAM Reservation Card\\n\\n"
        "Claim Token: tok_fallback999\\n"
        "Relay: https://relay.youam.network\r\n"
        "END:VCARD\r\n"
    )
    info = extract_claim_info(vcf_no_x)
    assert info["claim_token"] == "tok_fallback999"
    assert info["relay_url"] == "https://relay.youam.network"
    assert info["agent_name"] == "scout"
    assert "youam.network" in info["address"]


def test_extract_claim_info_missing_token_raises():
    """extract_claim_info raises ValueError when no claim token is found anywhere."""
    vcf_no_token = (
        "BEGIN:VCARD\r\n"
        "VERSION:3.0\r\n"
        "FN:scout\r\n"
        "NOTE:Just a regular note\r\n"
        "END:VCARD\r\n"
    )
    with pytest.raises(ValueError, match="claim token"):
        extract_claim_info(vcf_no_token)


# ---------------------------------------------------------------------------
# Round-trip Test
# ---------------------------------------------------------------------------


def test_round_trip_reservation_vcard():
    """Generated reservation vCard can be parsed back by extract_claim_info."""
    from uam.cards.vcard import generate_reservation_vcard

    vcf_text = generate_reservation_vcard(
        agent_name="roundtrip",
        relay_domain="youam.network",
        claim_token="tok_roundtrip_42",
        expires_at="2026-03-15T12:00:00Z",
        card_image_jpeg=FAKE_JPEG,
    )

    info = extract_claim_info(vcf_text)
    assert info["claim_token"] == "tok_roundtrip_42"
    assert info["relay_url"] == "https://relay.youam.network"
    assert info["address"] == "roundtrip::youam.network"
    assert info["agent_name"] == "roundtrip"


# ---------------------------------------------------------------------------
# init --claim Tests
# ---------------------------------------------------------------------------


def test_init_claim_success(runner: CliRunner, uam_home: Path, tmp_path: Path):
    """init --claim successfully claims an address from a reservation vCard."""
    vcf_path = tmp_path / "scout.vcf"
    vcf_path.write_text(RESERVATION_VCARD, encoding="utf-8")

    mock_resp = MagicMock()
    mock_resp.json.return_value = {
        "address": "scout::youam.network",
        "token": "bearer-token-123",
        "relay": "wss://relay.youam.network/ws",
    }
    mock_resp.raise_for_status = MagicMock()

    with patch("uam.cli.main.httpx.post", return_value=mock_resp) as mock_post, \
         patch(
             "uam.cards.vcard.generate_identity_vcard",
             return_value="BEGIN:VCARD\r\nFN:mock\r\nEND:VCARD\r\n",
         ):
        result = runner.invoke(
            cli,
            ["init", "--claim", str(vcf_path)],
            env={"UAM_HOME": str(uam_home)},
        )

    assert result.exit_code == 0, f"Failed: {result.output}"
    assert "Claimed address: scout::youam.network" in result.output
    assert "Identity vCard saved:" in result.output

    # Token file exists
    token_path = uam_home / "keys" / "scout.token"
    assert token_path.exists()
    assert token_path.read_text() == "bearer-token-123"

    # Key file exists
    key_path = uam_home / "keys" / "scout.key"
    assert key_path.exists()


def test_init_claim_file_not_found(runner: CliRunner, uam_home: Path):
    """init --claim with nonexistent file exits with error."""
    result = runner.invoke(
        cli,
        ["init", "--claim", "/nonexistent/file.vcf"],
        env={"UAM_HOME": str(uam_home)},
    )
    # click.Path(exists=True) causes a non-zero exit
    assert result.exit_code != 0


def test_init_claim_already_initialized(runner: CliRunner, uam_home: Path, tmp_path: Path):
    """init --claim with existing keys for the agent exits 1 with 'already initialized'."""
    # Pre-create keys for agent "scout"
    key_dir = uam_home / "keys"
    key_dir.mkdir(parents=True)
    km = KeyManager(key_dir)
    km.load_or_generate("scout")

    vcf_path = tmp_path / "scout.vcf"
    vcf_path.write_text(RESERVATION_VCARD, encoding="utf-8")

    result = runner.invoke(
        cli,
        ["init", "--claim", str(vcf_path)],
        env={"UAM_HOME": str(uam_home)},
    )
    assert result.exit_code == 1
    assert "already initialized" in result.output


def test_init_claim_relay_error(runner: CliRunner, uam_home: Path, tmp_path: Path):
    """init --claim with relay returning 410 (expired) exits 1 with 'Claim failed'."""
    vcf_path = tmp_path / "scout.vcf"
    vcf_path.write_text(RESERVATION_VCARD, encoding="utf-8")

    # Create a mock response that raises HTTPStatusError
    mock_resp = MagicMock()
    mock_resp.status_code = 410
    mock_resp.json.return_value = {"detail": "Reservation expired"}

    import httpx as httpx_mod

    http_error = httpx_mod.HTTPStatusError(
        "410 Gone",
        request=MagicMock(),
        response=mock_resp,
    )
    mock_resp.raise_for_status.side_effect = http_error

    with patch("uam.cli.main.httpx.post", return_value=mock_resp):
        result = runner.invoke(
            cli,
            ["init", "--claim", str(vcf_path)],
            env={"UAM_HOME": str(uam_home)},
        )

    assert result.exit_code == 1
    assert "Claim failed" in result.output


# ---------------------------------------------------------------------------
# card --vcf Tests
# ---------------------------------------------------------------------------


def test_card_vcf_stdout(runner: CliRunner, uam_home: Path):
    """card --vcf outputs identity vCard to stdout."""
    key_dir = uam_home / "keys"
    key_dir.mkdir(parents=True)
    km = KeyManager(key_dir)
    km.load_or_generate("testagent")

    mock_vcf = "BEGIN:VCARD\r\nFN:testagent (youam.network)\r\nEND:VCARD\r\n"

    with patch("uam.cards.vcard.generate_identity_vcard", return_value=mock_vcf):
        result = runner.invoke(
            cli,
            ["--name", "testagent", "card", "--vcf"],
            env={"UAM_HOME": str(uam_home)},
        )

    assert result.exit_code == 0, f"Failed: {result.output}"
    assert "BEGIN:VCARD" in result.output
    assert "testagent" in result.output


def test_card_vcf_output_file(runner: CliRunner, uam_home: Path, tmp_path: Path):
    """card --vcf --output saves vCard to file."""
    key_dir = uam_home / "keys"
    key_dir.mkdir(parents=True)
    km = KeyManager(key_dir)
    km.load_or_generate("testagent")

    mock_vcf = "BEGIN:VCARD\r\nFN:testagent (youam.network)\r\nEND:VCARD\r\n"
    out_file = tmp_path / "test.vcf"

    with patch("uam.cards.vcard.generate_identity_vcard", return_value=mock_vcf):
        result = runner.invoke(
            cli,
            ["--name", "testagent", "card", "--vcf", "--output", str(out_file)],
            env={"UAM_HOME": str(uam_home)},
        )

    assert result.exit_code == 0, f"Failed: {result.output}"
    assert "saved" in result.output
    assert out_file.exists()
    content = out_file.read_text(encoding="utf-8")
    assert "BEGIN:VCARD" in content


def test_card_vcf_no_keys(runner: CliRunner, uam_home: Path):
    """card --vcf with no keys exits 1 with 'No agent initialized'."""
    result = runner.invoke(
        cli,
        ["card", "--vcf"],
        env={"UAM_HOME": str(uam_home)},
    )
    assert result.exit_code == 1
    assert "No agent initialized" in result.output
