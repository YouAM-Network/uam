"""Tests for uam.sdk.dns_verifier module."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from uam.sdk.dns_verifier import (
    extract_public_key,
    generate_txt_record,
    is_public_ip,
    parse_uam_txt,
    query_uam_txt,
    resolve_key_via_https,
    verify_via_https,
)


# ---------------------------------------------------------------------------
# parse_uam_txt
# ---------------------------------------------------------------------------


class TestParseUamTxt:
    def test_valid_record(self):
        result = parse_uam_txt(
            "v=uam1; key=ed25519:ABC123; relay=https://relay.youam.network"
        )
        assert result == {
            "v": "uam1",
            "key": "ed25519:ABC123",
            "relay": "https://relay.youam.network",
        }

    def test_empty_string(self):
        assert parse_uam_txt("") == {}

    def test_missing_tags(self):
        result = parse_uam_txt("v=uam1")
        assert result == {"v": "uam1"}

    def test_extra_whitespace(self):
        result = parse_uam_txt("  v = uam1 ;  key = ed25519:ABC123  ")
        assert result == {"v": "uam1", "key": "ed25519:ABC123"}

    def test_unknown_tags_preserved(self):
        result = parse_uam_txt("v=uam1; key=ed25519:ABC; custom=foo")
        assert result["custom"] == "foo"

    def test_case_insensitive_tags(self):
        result = parse_uam_txt("V=uam1; KEY=ed25519:ABC")
        assert result["v"] == "uam1"
        assert result["key"] == "ed25519:ABC"

    def test_semicolons_only(self):
        assert parse_uam_txt(";;;") == {}

    def test_no_value(self):
        # Tag without = is ignored (no partition match)
        result = parse_uam_txt("v=uam1; orphan; key=ed25519:ABC")
        assert "orphan" not in result
        assert result["v"] == "uam1"

    def test_value_with_equals(self):
        # relay URL may contain = (e.g. query params)
        result = parse_uam_txt("v=uam1; relay=https://example.com?a=1")
        assert result["relay"] == "https://example.com?a=1"


# ---------------------------------------------------------------------------
# extract_public_key
# ---------------------------------------------------------------------------


class TestExtractPublicKey:
    def test_valid_ed25519_prefix(self):
        tags = {"key": "ed25519:ABC123base64"}
        assert extract_public_key(tags) == "ABC123base64"

    def test_missing_prefix(self):
        tags = {"key": "rsa:ABC123"}
        assert extract_public_key(tags) is None

    def test_empty_string(self):
        tags = {"key": ""}
        assert extract_public_key(tags) is None

    def test_missing_key_tag(self):
        tags = {"v": "uam1"}
        assert extract_public_key(tags) is None

    def test_ed25519_prefix_only(self):
        tags = {"key": "ed25519:"}
        assert extract_public_key(tags) == ""


# ---------------------------------------------------------------------------
# generate_txt_record
# ---------------------------------------------------------------------------


class TestGenerateTxtRecord:
    def test_correct_format(self):
        result = generate_txt_record("ABC123", "https://relay.youam.network")
        assert result == "v=uam1; key=ed25519:ABC123; relay=https://relay.youam.network"

    def test_roundtrip_with_parse(self):
        txt = generate_txt_record("MyKey123", "https://relay.example.com")
        tags = parse_uam_txt(txt)
        assert tags["v"] == "uam1"
        assert extract_public_key(tags) == "MyKey123"
        assert tags["relay"] == "https://relay.example.com"


# ---------------------------------------------------------------------------
# is_public_ip
# ---------------------------------------------------------------------------


class TestIsPublicIp:
    @patch("uam.sdk.dns_verifier.socket.getaddrinfo")
    def test_private_10_x(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [
            (2, 1, 0, "", ("10.0.0.1", 0)),
        ]
        assert is_public_ip("internal.example.com") is False

    @patch("uam.sdk.dns_verifier.socket.getaddrinfo")
    def test_private_192_168(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [
            (2, 1, 0, "", ("192.168.1.1", 0)),
        ]
        assert is_public_ip("home.example.com") is False

    @patch("uam.sdk.dns_verifier.socket.getaddrinfo")
    def test_private_172_16(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [
            (2, 1, 0, "", ("172.16.0.1", 0)),
        ]
        assert is_public_ip("private.example.com") is False

    @patch("uam.sdk.dns_verifier.socket.getaddrinfo")
    def test_loopback(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [
            (2, 1, 0, "", ("127.0.0.1", 0)),
        ]
        assert is_public_ip("localhost") is False

    @patch("uam.sdk.dns_verifier.socket.getaddrinfo")
    def test_link_local(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [
            (2, 1, 0, "", ("169.254.1.1", 0)),
        ]
        assert is_public_ip("link-local.example.com") is False

    @patch("uam.sdk.dns_verifier.socket.getaddrinfo")
    def test_public_ip(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = [
            (2, 1, 0, "", ("93.184.216.34", 0)),
        ]
        assert is_public_ip("example.com") is True

    @patch("uam.sdk.dns_verifier.socket.getaddrinfo")
    def test_mixed_public_private(self, mock_getaddrinfo):
        """If any IP is private, return False."""
        mock_getaddrinfo.return_value = [
            (2, 1, 0, "", ("93.184.216.34", 0)),
            (2, 1, 0, "", ("10.0.0.1", 0)),
        ]
        assert is_public_ip("mixed.example.com") is False

    @patch("uam.sdk.dns_verifier.socket.getaddrinfo")
    def test_resolution_failure(self, mock_getaddrinfo):
        import socket
        mock_getaddrinfo.side_effect = socket.gaierror("DNS resolution failed")
        assert is_public_ip("nonexistent.example.com") is False

    @patch("uam.sdk.dns_verifier.socket.getaddrinfo")
    def test_empty_results(self, mock_getaddrinfo):
        mock_getaddrinfo.return_value = []
        assert is_public_ip("empty.example.com") is False


# ---------------------------------------------------------------------------
# query_uam_txt
# ---------------------------------------------------------------------------


class TestQueryUamTxt:
    async def test_success(self):
        """Mocked DNS resolution returning a valid UAM TXT record."""
        mock_rdata = MagicMock()
        mock_rdata.strings = [b"v=uam1; key=ed25519:ABC123; relay=https://relay.youam.network"]

        mock_answer = MagicMock()
        mock_answer.__iter__ = MagicMock(return_value=iter([mock_rdata]))

        with patch("uam.sdk.dns_verifier.dns.asyncresolver.Resolver") as MockResolver:
            resolver_instance = MockResolver.return_value
            resolver_instance.resolve = AsyncMock(return_value=mock_answer)

            results = await query_uam_txt("example.com", timeout=5.0)

        assert len(results) == 1
        assert results[0].startswith("v=uam1")

    async def test_nxdomain(self):
        """NXDOMAIN returns empty list."""
        import dns.resolver

        with patch("uam.sdk.dns_verifier.dns.asyncresolver.Resolver") as MockResolver:
            resolver_instance = MockResolver.return_value
            resolver_instance.resolve = AsyncMock(
                side_effect=dns.resolver.NXDOMAIN()
            )

            results = await query_uam_txt("nonexistent.example.com")

        assert results == []

    async def test_timeout(self):
        """DNS timeout returns empty list."""
        import dns.exception

        with patch("uam.sdk.dns_verifier.dns.asyncresolver.Resolver") as MockResolver:
            resolver_instance = MockResolver.return_value
            resolver_instance.resolve = AsyncMock(
                side_effect=dns.exception.Timeout()
            )

            results = await query_uam_txt("slow.example.com")

        assert results == []

    async def test_no_answer(self):
        """NoAnswer returns empty list."""
        import dns.resolver

        with patch("uam.sdk.dns_verifier.dns.asyncresolver.Resolver") as MockResolver:
            resolver_instance = MockResolver.return_value
            resolver_instance.resolve = AsyncMock(
                side_effect=dns.resolver.NoAnswer()
            )

            results = await query_uam_txt("noanswer.example.com")

        assert results == []

    async def test_filters_non_uam_records(self):
        """Only records starting with v=uam1 are returned."""
        mock_rdata_uam = MagicMock()
        mock_rdata_uam.strings = [b"v=uam1; key=ed25519:ABC"]

        mock_rdata_spf = MagicMock()
        mock_rdata_spf.strings = [b"v=spf1 include:example.com ~all"]

        mock_answer = MagicMock()
        mock_answer.__iter__ = MagicMock(
            return_value=iter([mock_rdata_uam, mock_rdata_spf])
        )

        with patch("uam.sdk.dns_verifier.dns.asyncresolver.Resolver") as MockResolver:
            resolver_instance = MockResolver.return_value
            resolver_instance.resolve = AsyncMock(return_value=mock_answer)

            results = await query_uam_txt("example.com")

        assert len(results) == 1
        assert "v=uam1" in results[0]

    async def test_multi_string_concatenation(self):
        """Multi-string TXT records are concatenated."""
        mock_rdata = MagicMock()
        mock_rdata.strings = [b"v=uam1; key=ed25519:", b"ABCDEF123"]

        mock_answer = MagicMock()
        mock_answer.__iter__ = MagicMock(return_value=iter([mock_rdata]))

        with patch("uam.sdk.dns_verifier.dns.asyncresolver.Resolver") as MockResolver:
            resolver_instance = MockResolver.return_value
            resolver_instance.resolve = AsyncMock(return_value=mock_answer)

            results = await query_uam_txt("example.com")

        assert len(results) == 1
        assert "ABCDEF123" in results[0]


# ---------------------------------------------------------------------------
# verify_via_https
# ---------------------------------------------------------------------------


class TestVerifyViaHttps:
    @patch("uam.sdk.dns_verifier.is_public_ip", return_value=True)
    async def test_success(self, mock_ip):
        response_json = {
            "v": "uam1",
            "agents": {
                "alice": {
                    "key": "ed25519:ABC123",
                    "relay": "https://relay.youam.network",
                }
            },
        }
        mock_response = httpx.Response(200, json=response_json)

        with patch("uam.sdk.dns_verifier.httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            client_instance.get = AsyncMock(return_value=mock_response)
            client_instance.__aenter__ = AsyncMock(return_value=client_instance)
            client_instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = client_instance

            result = await verify_via_https("alice", "example.com", "ABC123")

        assert result is True

    @patch("uam.sdk.dns_verifier.is_public_ip", return_value=False)
    async def test_ssrf_rejection(self, mock_ip):
        """Private IPs should be rejected."""
        result = await verify_via_https("alice", "10.0.0.1", "ABC123")
        assert result is False

    @patch("uam.sdk.dns_verifier.is_public_ip", return_value=True)
    async def test_404(self, mock_ip):
        mock_response = httpx.Response(404)

        with patch("uam.sdk.dns_verifier.httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            client_instance.get = AsyncMock(return_value=mock_response)
            client_instance.__aenter__ = AsyncMock(return_value=client_instance)
            client_instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = client_instance

            result = await verify_via_https("alice", "example.com", "ABC123")

        assert result is False

    @patch("uam.sdk.dns_verifier.is_public_ip", return_value=True)
    async def test_wrong_key(self, mock_ip):
        response_json = {
            "v": "uam1",
            "agents": {
                "alice": {
                    "key": "ed25519:WRONGKEY",
                }
            },
        }
        mock_response = httpx.Response(200, json=response_json)

        with patch("uam.sdk.dns_verifier.httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            client_instance.get = AsyncMock(return_value=mock_response)
            client_instance.__aenter__ = AsyncMock(return_value=client_instance)
            client_instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = client_instance

            result = await verify_via_https("alice", "example.com", "ABC123")

        assert result is False

    @patch("uam.sdk.dns_verifier.is_public_ip", return_value=True)
    async def test_invalid_json(self, mock_ip):
        mock_response = httpx.Response(200, text="not json", headers={"content-type": "text/plain"})

        with patch("uam.sdk.dns_verifier.httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            client_instance.get = AsyncMock(return_value=mock_response)
            client_instance.__aenter__ = AsyncMock(return_value=client_instance)
            client_instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = client_instance

            result = await verify_via_https("alice", "example.com", "ABC123")

        assert result is False

    @patch("uam.sdk.dns_verifier.is_public_ip", return_value=True)
    async def test_agent_not_found(self, mock_ip):
        response_json = {
            "v": "uam1",
            "agents": {
                "bob": {"key": "ed25519:ABC123"},
            },
        }
        mock_response = httpx.Response(200, json=response_json)

        with patch("uam.sdk.dns_verifier.httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            client_instance.get = AsyncMock(return_value=mock_response)
            client_instance.__aenter__ = AsyncMock(return_value=client_instance)
            client_instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = client_instance

            result = await verify_via_https("alice", "example.com", "ABC123")

        assert result is False

    @patch("uam.sdk.dns_verifier.is_public_ip", return_value=True)
    async def test_wrong_version(self, mock_ip):
        response_json = {
            "v": "uam2",
            "agents": {"alice": {"key": "ed25519:ABC123"}},
        }
        mock_response = httpx.Response(200, json=response_json)

        with patch("uam.sdk.dns_verifier.httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            client_instance.get = AsyncMock(return_value=mock_response)
            client_instance.__aenter__ = AsyncMock(return_value=client_instance)
            client_instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = client_instance

            result = await verify_via_https("alice", "example.com", "ABC123")

        assert result is False

    @patch("uam.sdk.dns_verifier.is_public_ip", return_value=True)
    async def test_http_error(self, mock_ip):
        with patch("uam.sdk.dns_verifier.httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            client_instance.get = AsyncMock(
                side_effect=httpx.ConnectError("Connection refused")
            )
            client_instance.__aenter__ = AsyncMock(return_value=client_instance)
            client_instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = client_instance

            result = await verify_via_https("alice", "example.com", "ABC123")

        assert result is False


# ---------------------------------------------------------------------------
# resolve_key_via_https
# ---------------------------------------------------------------------------


class TestResolveKeyViaHttps:
    @patch("uam.sdk.dns_verifier.is_public_ip", return_value=True)
    async def test_success(self, mock_ip):
        response_json = {
            "v": "uam1",
            "agents": {
                "alice": {
                    "key": "ed25519:ABC123",
                }
            },
        }
        mock_response = httpx.Response(200, json=response_json)

        with patch("uam.sdk.dns_verifier.httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            client_instance.get = AsyncMock(return_value=mock_response)
            client_instance.__aenter__ = AsyncMock(return_value=client_instance)
            client_instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = client_instance

            result = await resolve_key_via_https("alice", "example.com")

        assert result == "ABC123"

    @patch("uam.sdk.dns_verifier.is_public_ip", return_value=False)
    async def test_ssrf_rejection(self, mock_ip):
        result = await resolve_key_via_https("alice", "10.0.0.1")
        assert result is None

    @patch("uam.sdk.dns_verifier.is_public_ip", return_value=True)
    async def test_agent_not_found(self, mock_ip):
        response_json = {
            "v": "uam1",
            "agents": {},
        }
        mock_response = httpx.Response(200, json=response_json)

        with patch("uam.sdk.dns_verifier.httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            client_instance.get = AsyncMock(return_value=mock_response)
            client_instance.__aenter__ = AsyncMock(return_value=client_instance)
            client_instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = client_instance

            result = await resolve_key_via_https("alice", "example.com")

        assert result is None
