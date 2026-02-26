"""Tests for uam.cards.image and uam.cards.avatars modules."""

from __future__ import annotations

import io
from unittest.mock import patch, MagicMock

import httpx
import pytest
from PIL import Image

from uam.cards.image import render_card
from uam.cards.avatars import fetch_avatar


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_test_png(size: int = 200) -> bytes:
    """Create a minimal valid RGBA PNG for test avatar_bytes."""
    img = Image.new("RGBA", (size, size), (100, 150, 200, 255))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


_TEST_AVATAR = _make_test_png()

JPEG_MAGIC = b"\xff\xd8"
MAX_SIZE = 200_000


# ---------------------------------------------------------------------------
# Card rendering tests
# ---------------------------------------------------------------------------


class TestRenderReservationCard:
    def test_produces_jpeg(self):
        result = render_card("scout", "youam.network", "reservation", avatar_bytes=_TEST_AVATAR)
        assert result[:2] == JPEG_MAGIC
        assert 0 < len(result) < MAX_SIZE

    def test_with_expires_at(self):
        result = render_card(
            "scout",
            "youam.network",
            "reservation",
            expires_at="2026-02-26T12:00:00Z",
            avatar_bytes=_TEST_AVATAR,
        )
        assert result[:2] == JPEG_MAGIC
        assert 0 < len(result) < MAX_SIZE


class TestRenderIdentityCard:
    def test_produces_jpeg(self):
        result = render_card("scout", "youam.network", "identity", avatar_bytes=_TEST_AVATAR)
        assert result[:2] == JPEG_MAGIC
        assert 0 < len(result) < MAX_SIZE

    def test_with_fingerprint(self):
        result = render_card(
            "scout",
            "youam.network",
            "identity",
            fingerprint="a1b2c3d4e5f6g7h8i9j0",
            avatar_bytes=_TEST_AVATAR,
        )
        assert result[:2] == JPEG_MAGIC
        assert 0 < len(result) < MAX_SIZE


class TestCardVariants:
    def test_reservation_and_identity_are_different(self):
        res = render_card("scout", "youam.network", "reservation", avatar_bytes=_TEST_AVATAR)
        ident = render_card("scout", "youam.network", "identity", avatar_bytes=_TEST_AVATAR)
        assert res != ident, "Reservation and identity cards must produce different bytes"

    def test_long_agent_name_does_not_crash(self):
        long_name = "a" * 50
        long_domain = "my-very-long-custom-relay-domain.example.com"
        result = render_card(long_name, long_domain, "identity", avatar_bytes=_TEST_AVATAR)
        assert result[:2] == JPEG_MAGIC
        assert 0 < len(result) < MAX_SIZE

    @patch("uam.cards.image.fetch_avatar", return_value=None)
    def test_render_card_without_avatar_fallback(self, mock_fetch):
        """When avatar_bytes is None and fetch returns None, fallback to letter circle."""
        result = render_card("scout", "youam.network", "reservation")
        assert result[:2] == JPEG_MAGIC
        assert 0 < len(result) < MAX_SIZE
        mock_fetch.assert_called_once()

    def test_jpeg_size_under_200kb_various_names(self):
        """Generate cards for multiple name lengths; all must be under 200KB."""
        for name_len in (1, 20, 50):
            name = "x" * name_len
            res = render_card(name, "youam.network", "reservation", avatar_bytes=_TEST_AVATAR)
            assert len(res) < MAX_SIZE, f"Reservation card for {name_len}-char name too large: {len(res)}"
            ident = render_card(name, "youam.network", "identity", avatar_bytes=_TEST_AVATAR)
            assert len(ident) < MAX_SIZE, f"Identity card for {name_len}-char name too large: {len(ident)}"


# ---------------------------------------------------------------------------
# Avatar fetch tests
# ---------------------------------------------------------------------------


class TestFetchAvatar:
    @patch("uam.cards.avatars.httpx.get")
    def test_deterministic_same_url(self, mock_get):
        """Same address produces same URL (deterministic)."""
        mock_resp = MagicMock()
        mock_resp.content = b"fake-png-bytes"
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        result1 = fetch_avatar("scout")
        result2 = fetch_avatar("scout")

        assert result1 == result2
        # Both calls used the same URL
        call_urls = [call.args[0] for call in mock_get.call_args_list]
        assert call_urls[0] == call_urls[1]

    @patch("uam.cards.avatars.httpx.get", side_effect=httpx.TimeoutException("timeout"))
    def test_returns_none_on_timeout(self, mock_get):
        result = fetch_avatar("scout")
        assert result is None

    @patch("uam.cards.avatars.httpx.get")
    def test_returns_none_on_http_error(self, mock_get):
        mock_get.side_effect = httpx.HTTPStatusError(
            "500",
            request=MagicMock(),
            response=MagicMock(),
        )
        result = fetch_avatar("scout")
        assert result is None

    @patch("uam.cards.avatars.httpx.get")
    def test_custom_style_parameter(self, mock_get):
        """Avatar style is passed through to the DiceBear URL."""
        mock_resp = MagicMock()
        mock_resp.content = b"fake-png-bytes"
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        fetch_avatar("scout", style="identicon")
        url = mock_get.call_args[0][0]
        assert "identicon" in url
        assert "seed=scout" in url
