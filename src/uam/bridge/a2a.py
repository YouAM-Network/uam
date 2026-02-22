"""A2A-UAM bidirectional contact card conversion and bridge metadata.

Converts between Google A2A Agent Card dicts and UAM ContactCard dataclass
instances, preserving A2A-specific fields in ``A2ABridgeMetadata`` so nothing
is silently dropped during lossy cross-protocol conversion.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

from uam.protocol.contact import ContactCard
from uam.protocol.errors import InvalidContactCardError
from uam.protocol.types import UAM_VERSION

# A2A fields that have no UAM ContactCard equivalent.  Only keys that are
# present *and* non-None in the source card are stored.
_A2A_EXTRA_KEYS = (
    "skills",
    "capabilities",
    "defaultInputModes",
    "defaultOutputModes",
    "securitySchemes",
    "authentication",
    "provider",
    "interfaces",
    "extensions",
    "version",  # A2A protocol version, NOT UAM version
)


@dataclass(frozen=True)
class A2ABridgeMetadata:
    """Metadata captured during A2A -> UAM conversion (A2A-04).

    Preserves A2A-specific fields that have no direct UAM equivalent so
    that information is never silently dropped.
    """

    source_protocol: str  # always "a2a"
    source_url: str | None  # original .well-known/agent.json URL
    a2a_fields: dict  # fields preserved from A2A with no UAM mapping


# ---------------------------------------------------------------------------
# A2A -> UAM
# ---------------------------------------------------------------------------


def contact_from_a2a(
    a2a_card: dict,
    *,
    source_url: str | None = None,
) -> tuple[ContactCard, A2ABridgeMetadata]:
    """Convert an A2A Agent Card dict to a UAM ContactCard (A2A-01, A2A-04).

    Args:
        a2a_card: Parsed JSON from ``.well-known/agent.json``.
        source_url: The URL the card was fetched from (recorded in metadata).

    Returns:
        ``(ContactCard, A2ABridgeMetadata)`` tuple.

    Raises:
        InvalidContactCardError: If the A2A card is missing ``name``.
    """
    name = a2a_card.get("name")
    if not name:
        raise InvalidContactCardError("A2A Agent Card missing required 'name' field")

    description = a2a_card.get("description")
    url = a2a_card.get("url")

    # Derive UAM address from name + url hostname
    if url:
        hostname = urlparse(url).hostname or "a2a.bridge"
        address = f"{name}::{hostname}"
    else:
        address = f"{name}::a2a.bridge"

    # Build bridge metadata -- only include keys actually present and non-None
    a2a_fields: dict = {}
    for key in _A2A_EXTRA_KEYS:
        val = a2a_card.get(key)
        if val is not None:
            a2a_fields[key] = val

    metadata = A2ABridgeMetadata(
        source_protocol="a2a",
        source_url=source_url,
        a2a_fields=a2a_fields,
    )

    card = ContactCard(
        version=UAM_VERSION,
        address=address,
        display_name=name,
        description=description,
        system="a2a",
        connection_endpoint=url,
        relay="bridge://a2a",
        public_key="",
        signature="",
    )

    return card, metadata


# ---------------------------------------------------------------------------
# UAM -> A2A
# ---------------------------------------------------------------------------


def contact_to_a2a(
    uam_card: ContactCard,
    *,
    base_url: str | None = None,
) -> dict:
    """Convert a UAM ContactCard to an A2A-compatible Agent Card dict (A2A-02).

    Args:
        uam_card: The UAM contact card.
        base_url: Explicit URL to use for the ``"url"`` field.  If ``None``,
            falls back to ``uam_card.connection_endpoint`` or derives from
            the address domain.

    Returns:
        A dict suitable for serving as ``.well-known/agent.json``.
    """
    # Determine URL
    url = base_url or uam_card.connection_endpoint
    if not url:
        # Derive from address domain part
        parts = uam_card.address.split("::")
        domain = parts[1] if len(parts) > 1 else "localhost"
        url = f"https://{domain}"

    # Derive provider from address domain
    parts = uam_card.address.split("::")
    domain = parts[1] if len(parts) > 1 else "unknown"

    result: dict = {
        "name": uam_card.display_name,
        "url": url,
        "version": "0.1",
        "capabilities": {
            "streaming": False,
            "pushNotifications": False,
        },
        "skills": [
            {
                "id": "uam-messaging",
                "name": "UAM Messaging",
                "description": "Send and receive encrypted messages via UAM protocol",
                "tags": ["messaging", "uam", "encrypted"],
                "examples": [f"Send a message to {uam_card.address}"],
            }
        ],
        "defaultInputModes": ["text/plain"],
        "defaultOutputModes": ["text/plain"],
        "provider": {
            "organization": domain,
            "url": url,
        },
    }

    if uam_card.description is not None:
        result["description"] = uam_card.description

    return result


# ---------------------------------------------------------------------------
# Serialization helpers
# ---------------------------------------------------------------------------


def bridge_metadata_to_dict(meta: A2ABridgeMetadata) -> dict:
    """Serialize ``A2ABridgeMetadata`` to a plain dict for JSON storage."""
    return {
        "source_protocol": meta.source_protocol,
        "source_url": meta.source_url,
        "a2a_fields": meta.a2a_fields,
    }


def bridge_metadata_from_dict(d: dict) -> A2ABridgeMetadata:
    """Deserialize ``A2ABridgeMetadata`` from a plain dict."""
    return A2ABridgeMetadata(
        source_protocol=d["source_protocol"],
        source_url=d.get("source_url"),
        a2a_fields=d.get("a2a_fields", {}),
    )
