"""Core types, constants, and utility functions for UAM protocol."""

from __future__ import annotations

import base64
from datetime import datetime, timezone
from enum import Enum


# Protocol version
UAM_VERSION = "0.1"

# Maximum envelope size in bytes (64 KB)
MAX_ENVELOPE_SIZE = 65536


class MessageType(str, Enum):
    """All UAM message types.

    Using ``str, Enum`` so that ``MessageType.MESSAGE == "message"`` is True.
    """

    MESSAGE = "message"
    HANDSHAKE_REQUEST = "handshake.request"
    HANDSHAKE_ACCEPT = "handshake.accept"
    HANDSHAKE_DENY = "handshake.deny"
    RECEIPT_DELIVERED = "receipt.delivered"
    RECEIPT_READ = "receipt.read"
    RECEIPT_FAILED = "receipt.failed"
    SESSION_REQUEST = "session.request"
    SESSION_ACCEPT = "session.accept"
    SESSION_DECLINE = "session.decline"
    SESSION_END = "session.end"


def b64_encode(data: bytes) -> str:
    """URL-safe base64 encode *data*, stripping padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64_decode(s: str) -> bytes:
    """URL-safe base64 decode *s*, tolerating missing padding."""
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def utc_timestamp() -> str:
    """Return a canonical UTC timestamp: ``YYYY-MM-DDTHH:MM:SS.mmmZ``."""
    ts = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
    # isoformat gives "+00:00" suffix; replace with "Z" for UAM canonical form
    return ts.replace("+00:00", "Z")
