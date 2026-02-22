"""Tests for uam.protocol.types module."""

from __future__ import annotations

import re

from uam.protocol.types import (
    UAM_VERSION,
    MAX_ENVELOPE_SIZE,
    MessageType,
    b64_encode,
    b64_decode,
    utc_timestamp,
)


class TestConstants:
    def test_uam_version(self):
        assert UAM_VERSION == "0.1"

    def test_max_envelope_size(self):
        assert MAX_ENVELOPE_SIZE == 65536


class TestMessageType:
    def test_message_equals_string(self):
        assert MessageType.MESSAGE == "message"

    def test_handshake_request_equals_string(self):
        assert MessageType.HANDSHAKE_REQUEST == "handshake.request"

    def test_handshake_accept(self):
        assert MessageType.HANDSHAKE_ACCEPT == "handshake.accept"

    def test_handshake_deny(self):
        assert MessageType.HANDSHAKE_DENY == "handshake.deny"

    def test_receipt_delivered(self):
        assert MessageType.RECEIPT_DELIVERED == "receipt.delivered"

    def test_receipt_read(self):
        assert MessageType.RECEIPT_READ == "receipt.read"

    def test_receipt_failed(self):
        assert MessageType.RECEIPT_FAILED == "receipt.failed"

    def test_session_request(self):
        assert MessageType.SESSION_REQUEST == "session.request"

    def test_session_accept(self):
        assert MessageType.SESSION_ACCEPT == "session.accept"

    def test_session_decline(self):
        assert MessageType.SESSION_DECLINE == "session.decline"

    def test_session_end(self):
        assert MessageType.SESSION_END == "session.end"

    def test_all_eleven_members_exist(self):
        assert len(MessageType) == 11


class TestBase64:
    def test_roundtrip(self):
        data = b"hello, world!"
        assert b64_decode(b64_encode(data)) == data

    def test_roundtrip_binary(self):
        data = bytes(range(256))
        assert b64_decode(b64_encode(data)) == data

    def test_encode_no_padding(self):
        encoded = b64_encode(b"a")
        assert "=" not in encoded

    def test_decode_with_padding(self):
        # Standard base64 of b"a" is "YQ=="
        assert b64_decode("YQ==") == b"a"

    def test_decode_without_padding(self):
        assert b64_decode("YQ") == b"a"

    def test_empty_bytes(self):
        assert b64_decode(b64_encode(b"")) == b""


class TestUtcTimestamp:
    def test_format(self):
        ts = utc_timestamp()
        pattern = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$"
        assert re.match(pattern, ts), f"Timestamp {ts!r} does not match expected format"

    def test_ends_with_z(self):
        assert utc_timestamp().endswith("Z")

    def test_millisecond_precision(self):
        ts = utc_timestamp()
        # After the last dot, before Z, there should be exactly 3 digits
        fractional = ts.split(".")[-1]
        assert fractional == fractional[:3] + "Z"
