"""Tests for viral onboarding endpoint (Phase 42).

Covers:
- VIRAL-01: User-Agent detection (curl/wget/httpie -> sh script, browser -> 302)
- VIRAL-02: Script content (two-stage wrapper, full installer with interactive flow)
- VIRAL-03: Auto-branding per relay (domain from config, no hardcoding)
- VIRAL-04: Identity vCards include X-UAM-SIGNUP, identity card images render curl command
"""

from __future__ import annotations

import io

import pytest
from PIL import Image
from unittest.mock import patch

from uam.cards.vcard import generate_identity_vcard
from uam.cards.image import render_card


# Minimal JPEG stub for tests that need card_image_jpeg (avoids Pillow/DiceBear)
JPEG_STUB = b"\xff\xd8\xff\xe0" + b"\x00" * 100

# Minimal valid PNG for render_card avatar_bytes
def _make_test_png(size: int = 200) -> bytes:
    img = Image.new("RGBA", (size, size), (100, 150, 200, 255))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


_TEST_AVATAR = _make_test_png()


# ---------------------------------------------------------------------------
# VIRAL-01: User-Agent detection
# ---------------------------------------------------------------------------


class TestNewEndpointUserAgent:
    """GET /new -- User-Agent detection routes curl/wget to sh script, browsers to 302."""

    def test_new_curl_returns_shell_script(self, client):
        """curl User-Agent gets 200 with text/plain POSIX sh script."""
        resp = client.get("/new", headers={"User-Agent": "curl/8.4.0"})
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/plain")
        assert resp.text.startswith("#!/bin/sh")
        assert "mktemp" in resp.text
        assert "/new/install.sh" in resp.text

    def test_new_wget_returns_shell_script(self, client):
        """wget User-Agent gets 200 with POSIX sh script."""
        resp = client.get("/new", headers={"User-Agent": "Wget/1.21"})
        assert resp.status_code == 200
        assert resp.text.startswith("#!/bin/sh")

    def test_new_browser_redirects(self, client):
        """Browser User-Agent gets 302 redirect to /reserve."""
        resp = client.get(
            "/new",
            headers={
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
            },
            follow_redirects=False,
        )
        assert resp.status_code == 302
        assert "/reserve" in resp.headers["location"]

    def test_new_empty_useragent_redirects(self, client):
        """Empty or absent User-Agent redirects (non-CLI behavior)."""
        resp = client.get("/new", headers={"User-Agent": ""}, follow_redirects=False)
        assert resp.status_code == 302

    def test_new_httpie_returns_script(self, client):
        """HTTPie User-Agent gets 200 with POSIX sh script."""
        resp = client.get("/new", headers={"User-Agent": "HTTPie/3.2"})
        assert resp.status_code == 200
        assert resp.text.startswith("#!/bin/sh")


# ---------------------------------------------------------------------------
# VIRAL-02: Script content
# ---------------------------------------------------------------------------


class TestInstallShContent:
    """GET /new/install.sh -- full interactive installer script content."""

    def test_install_sh_returns_full_script(self, client):
        """Installer returns 200 text/plain with expected content markers."""
        resp = client.get("/new/install.sh")
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/plain")
        assert resp.text.startswith("#!/bin/sh")
        # Interactive prompt
        assert "Choose" in resp.text or "name" in resp.text.lower()
        # Availability check API call
        assert "/api/v1/reserve/check/" in resp.text
        # Reservation creation API call
        assert "/api/v1/reserve" in resp.text
        # Claim command
        assert "uam init --claim" in resp.text
        # pip installation step
        assert "pip" in resp.text

    def test_wrapper_script_two_stage_pattern(self, client):
        """Wrapper uses mktemp + trap + rm for safe two-stage download."""
        resp = client.get("/new", headers={"User-Agent": "curl/8.4.0"})
        assert resp.status_code == 200
        text = resp.text
        assert "mktemp" in text
        assert "trap" in text
        assert "rm" in text


# ---------------------------------------------------------------------------
# VIRAL-03: Auto-branding
# ---------------------------------------------------------------------------


class TestAutoBranding:
    """Scripts are branded per relay config -- no hardcoded domains."""

    def test_wrapper_script_auto_branded(self, client):
        """Wrapper script contains the relay domain from config (test.local).

        The comment header and branding line use the relay_domain setting.
        The download URL uses relay_http_url (a separate config value).
        Both are parameterized from Settings -- no hardcoded domains in the template.
        """
        resp = client.get("/new", headers={"User-Agent": "curl/8.4.0"})
        assert resp.status_code == 200
        # The relay fixture uses UAM_RELAY_DOMAIN=test.local
        assert "test.local" in resp.text
        # The script comment header is branded with the relay domain
        assert "UAM Quick Setup -- test.local" in resp.text

    def test_installer_script_auto_branded(self, client):
        """Full installer contains relay domain and relay HTTP URL."""
        resp = client.get("/new/install.sh")
        assert resp.status_code == 200
        text = resp.text
        assert "test.local" in text
        # Contains the relay HTTP URL for API calls
        # (relay.test.local is from default Settings pattern)
        assert "relay" in text.lower()


# ---------------------------------------------------------------------------
# POSIX compliance
# ---------------------------------------------------------------------------


class TestPosixCompliance:
    """Scripts use POSIX sh -- no bashisms allowed."""

    def test_wrapper_script_posix_compliant(self, client):
        """Wrapper has no bash-only constructs."""
        resp = client.get("/new", headers={"User-Agent": "curl/8.4.0"})
        text = resp.text
        assert "[[" not in text
        assert "read -p" not in text
        assert "echo -e" not in text
        assert "=~" not in text

    def test_installer_script_posix_compliant(self, client):
        """Installer has no bash-only constructs and uses command -v."""
        resp = client.get("/new/install.sh")
        text = resp.text
        assert "[[" not in text
        assert "read -p" not in text
        assert "echo -e" not in text
        assert "=~" not in text
        assert "command -v" in text


# ---------------------------------------------------------------------------
# VIRAL-04: Identity cards as growth vectors (confirmation from Phase 38)
# ---------------------------------------------------------------------------


class TestViral04Confirmation:
    """Confirm VIRAL-04: identity vCards have X-UAM-SIGNUP, identity cards render curl command."""

    def test_viral04_vcard_has_signup_url(self):
        """Identity vCard includes X-UAM-SIGNUP:https://<domain>/new."""
        vcard_text = generate_identity_vcard(
            agent_name="test",
            relay_domain="example.com",
            card_image_jpeg=JPEG_STUB,
        )
        assert "X-UAM-SIGNUP:https://example.com/new" in vcard_text

    def test_viral04_card_image_has_curl_command(self):
        """Identity card image renders successfully (code path includes curl command).

        The render_card function for identity type draws the text
        ``curl <relay_domain>/new | sh`` on the card (image.py lines 232-235).
        We cannot read pixels, but the code path is exercised and produces valid JPEG.
        """
        result = render_card(
            "test",
            "example.com",
            "identity",
            avatar_bytes=_TEST_AVATAR,
        )
        # Valid JPEG output proves the identity card rendering path succeeded
        assert isinstance(result, bytes)
        assert len(result) > 0
        assert result[:2] == b"\xff\xd8"  # JPEG magic bytes
