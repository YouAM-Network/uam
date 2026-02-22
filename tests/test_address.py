"""Tests for uam.protocol.address module."""

from __future__ import annotations

import pytest

from uam.protocol.address import Address, parse_address
from uam.protocol.errors import InvalidAddressError


class TestValidAddresses:
    def test_standard_address(self):
        addr = parse_address("alice::youam.network")
        assert addr.agent == "alice"
        assert addr.domain == "youam.network"

    def test_minimal_address(self):
        addr = parse_address("a::b")
        assert addr.agent == "a"
        assert addr.domain == "b"

    def test_hyphenated_agent(self):
        addr = parse_address("my-agent::example.com")
        assert addr.agent == "my-agent"

    def test_underscore_agent(self):
        addr = parse_address("agent_1::relay.youam.network")
        assert addr.agent == "agent_1"
        assert addr.domain == "relay.youam.network"

    def test_single_char_agent(self):
        addr = parse_address("a::youam.network")
        assert addr.agent == "a"

    def test_max_length_agent(self):
        agent = "a" * 64
        addr = parse_address(f"{agent}::youam.network")
        assert addr.agent == agent
        assert len(addr.agent) == 64


class TestNormalization:
    def test_case_normalization(self):
        addr = parse_address("Alice::YOUAM.Network")
        assert addr.agent == "alice"
        assert addr.domain == "youam.network"

    def test_whitespace_stripping(self):
        addr = parse_address("  alice::youam.network  ")
        assert addr.agent == "alice"
        assert addr.domain == "youam.network"


class TestInvalidAddresses:
    def test_bare_name(self):
        with pytest.raises(InvalidAddressError):
            parse_address("alice")

    def test_missing_domain(self):
        with pytest.raises(InvalidAddressError):
            parse_address("alice::")

    def test_missing_agent(self):
        with pytest.raises(InvalidAddressError):
            parse_address("::domain")

    def test_empty_string(self):
        with pytest.raises(InvalidAddressError):
            parse_address("")

    def test_double_colon_only(self):
        with pytest.raises(InvalidAddressError):
            parse_address("::")

    def test_agent_starts_with_hyphen(self):
        with pytest.raises(InvalidAddressError):
            parse_address("-agent::domain")

    def test_agent_ends_with_hyphen(self):
        with pytest.raises(InvalidAddressError):
            parse_address("agent-::domain")

    def test_spaces_in_agent(self):
        with pytest.raises(InvalidAddressError):
            parse_address("my agent::domain")

    def test_agent_too_long(self):
        agent = "a" * 65
        with pytest.raises(InvalidAddressError):
            parse_address(f"{agent}::youam.network")

    def test_full_address_too_long(self):
        agent = "a" * 60
        domain = "d" * 70  # 60 + "::" + 70 = 132 > 128
        with pytest.raises(InvalidAddressError, match="exceeds 128"):
            parse_address(f"{agent}::{domain}")

    def test_error_includes_raw_input(self):
        with pytest.raises(InvalidAddressError, match="bad-input"):
            parse_address("bad-input")


class TestAddressProperties:
    def test_full_property(self):
        addr = parse_address("alice::youam.network")
        assert addr.full == "alice::youam.network"

    def test_str_returns_full(self):
        addr = parse_address("alice::youam.network")
        assert str(addr) == "alice::youam.network"

    def test_frozen(self):
        addr = parse_address("alice::youam.network")
        with pytest.raises(AttributeError):
            addr.agent = "bob"  # type: ignore[misc]

    def test_equality(self):
        a = parse_address("alice::youam.network")
        b = parse_address("alice::youam.network")
        assert a == b

    def test_inequality(self):
        a = parse_address("alice::youam.network")
        b = parse_address("bob::youam.network")
        assert a != b
