"""Tests for webhook URL validation with SSRF prevention.

Covers validate_webhook_url() and async_validate_webhook_url():
- HTTPS-only enforcement
- Hostname presence check
- Cloud metadata endpoint blocking (Google, AWS, 169.254.x.x)
- Private IP rejection via is_public_ip()
- Malformed URL handling
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from uam.relay.webhook_validator import async_validate_webhook_url, validate_webhook_url


class TestValidateWebhookUrl:
    """validate_webhook_url() unit tests."""

    def test_rejects_http_url(self):
        """HTTP URLs are rejected -- webhooks must use HTTPS."""
        ok, reason = validate_webhook_url("http://example.com/hook")
        assert ok is False
        assert "HTTPS" in reason

    @patch("uam.relay.webhook_validator.is_public_ip", return_value=True)
    def test_accepts_https_url(self, _mock_ip):
        """Valid HTTPS URL with public IP passes validation."""
        ok, reason = validate_webhook_url("https://example.com/hook")
        assert ok is True
        assert reason == ""

    def test_rejects_no_hostname(self):
        """URL without a hostname is rejected."""
        ok, reason = validate_webhook_url("https:///path")
        assert ok is False
        assert "hostname" in reason.lower()

    def test_rejects_metadata_google(self):
        """Google Cloud metadata endpoint is blocked."""
        ok, reason = validate_webhook_url(
            "https://metadata.google.internal/computeMetadata/v1/"
        )
        assert ok is False
        assert "locked" in reason.lower() or "metadata" in reason.lower()

    def test_rejects_metadata_aws(self):
        """AWS metadata endpoint hostname is blocked."""
        ok, reason = validate_webhook_url(
            "https://metadata.amazonaws.com/latest/meta-data/"
        )
        assert ok is False
        assert "locked" in reason.lower() or "metadata" in reason.lower()

    def test_rejects_169_254_ip(self):
        """Link-local metadata IP address is blocked."""
        ok, reason = validate_webhook_url(
            "https://169.254.169.254/latest/meta-data/"
        )
        assert ok is False
        assert "locked" in reason.lower() or "169.254" in reason.lower()

    @patch("uam.relay.webhook_validator.is_public_ip", return_value=False)
    def test_rejects_private_ip(self, _mock_ip):
        """URL resolving to a private IP is rejected."""
        ok, reason = validate_webhook_url("https://internal.example.com/hook")
        assert ok is False
        assert "private" in reason.lower() or "non-routable" in reason.lower()

    def test_handles_malformed_url_empty(self):
        """Empty string is rejected."""
        ok, reason = validate_webhook_url("")
        assert ok is False

    def test_handles_malformed_url_garbage(self):
        """Random garbage string is rejected."""
        ok, reason = validate_webhook_url("not-a-url-at-all")
        assert ok is False

    def test_handles_malformed_url_no_scheme(self):
        """URL without scheme is rejected (parsed scheme is empty)."""
        ok, reason = validate_webhook_url("example.com/hook")
        assert ok is False


class TestAsyncValidateWebhookUrl:
    """async_validate_webhook_url() async wrapper tests."""

    @pytest.mark.asyncio
    @patch("uam.relay.webhook_validator.is_public_ip", return_value=True)
    async def test_async_accepts_valid_url(self, _mock_ip):
        """Async wrapper returns same result as sync for valid URL."""
        ok, reason = await async_validate_webhook_url("https://example.com/hook")
        assert ok is True
        assert reason == ""

    @pytest.mark.asyncio
    async def test_async_rejects_http(self):
        """Async wrapper correctly rejects HTTP URL."""
        ok, reason = await async_validate_webhook_url("http://example.com/hook")
        assert ok is False
        assert "HTTPS" in reason
