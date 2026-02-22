"""UAM address parsing and validation.

A UAM address has the form ``agent::domain`` (e.g. ``alice::youam.network``).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from uam.protocol.errors import InvalidAddressError

# Agent: 1-64 chars, lowercase alphanumeric + hyphen + underscore.
# Cannot start or end with hyphen.
# Domain: standard DNS-style, 1-255 chars.
_ADDRESS_RE = re.compile(
    r"^(?P<agent>[a-z0-9][a-z0-9_-]{0,62}[a-z0-9]|[a-z0-9])::(?P<domain>[a-z0-9](?:[a-z0-9.-]{0,253}[a-z0-9])?)$"
)


@dataclass(frozen=True)
class Address:
    """A parsed UAM address (always lowercase)."""

    agent: str
    domain: str

    @property
    def full(self) -> str:
        """Return the fully-qualified address string."""
        return f"{self.agent}::{self.domain}"

    def __str__(self) -> str:
        return self.full


# Spec limits
_MAX_AGENT_LEN = 64
_MAX_ADDRESS_LEN = 128


def parse_address(raw: str) -> Address:
    """Parse and validate a UAM address string.

    Strips whitespace, lowercases, and validates format.
    Enforces max lengths: agent <= 64 chars, full address <= 128 chars.

    Raises:
        InvalidAddressError: If *raw* is not a valid ``agent::domain`` address.
    """
    normalized = raw.strip().lower()
    if len(normalized) > _MAX_ADDRESS_LEN:
        raise InvalidAddressError(
            f"Address exceeds {_MAX_ADDRESS_LEN} characters: {raw!r}"
        )
    m = _ADDRESS_RE.match(normalized)
    if not m:
        raise InvalidAddressError(f"Invalid UAM address: {raw!r}")
    agent = m.group("agent")
    if len(agent) > _MAX_AGENT_LEN:
        raise InvalidAddressError(
            f"Agent name exceeds {_MAX_AGENT_LEN} characters: {raw!r}"
        )
    return Address(agent=agent, domain=m.group("domain"))
