"""UAM contact cards -- self-signed agent identity documents.

A contact card advertises an agent's address, public key, relay endpoint,
and optional metadata.  The card is signed by the agent's own signing key
so that any recipient can verify authenticity using the embedded public key.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from nacl.signing import SigningKey

from uam.protocol.address import parse_address
from uam.protocol.crypto import (
    canonicalize,
    deserialize_verify_key,
    public_key_fingerprint,
    serialize_verify_key,
    sign_message,
    verify_signature,
)
from uam.protocol.errors import InvalidContactCardError
from uam.protocol.types import UAM_VERSION


@dataclass(frozen=True)
class ContactCard:
    """A self-signed agent identity card (SDK-07)."""

    version: str
    address: str
    display_name: str
    description: Optional[str]
    system: Optional[str]
    connection_endpoint: Optional[str]
    relay: str
    public_key: str
    signature: str
    verified_domain: Optional[str] = None
    payload_formats: Optional[list[str]] = None
    fingerprint: Optional[str] = None


def _build_signable_dict(card: ContactCard) -> dict:
    """Build the dict used for signature computation.

    Includes all fields except ``signature``.
    Excludes ``None``-valued optional fields.
    """
    d: dict = {
        "version": card.version,
        "address": card.address,
        "display_name": card.display_name,
        "relay": card.relay,
        "public_key": card.public_key,
    }
    if card.description is not None:
        d["description"] = card.description
    if card.system is not None:
        d["system"] = card.system
    if card.connection_endpoint is not None:
        d["connection_endpoint"] = card.connection_endpoint
    if card.verified_domain is not None:
        d["verified_domain"] = card.verified_domain
    return d


def contact_card_to_dict(card: ContactCard) -> dict:
    """Serialize a contact card to a plain dict.

    Excludes ``None``-valued optional fields.
    """
    d = _build_signable_dict(card)
    d["signature"] = card.signature
    if card.payload_formats is not None:
        d["payload_formats"] = card.payload_formats
    if card.fingerprint is not None:
        d["fingerprint"] = card.fingerprint
    return d


def contact_card_from_dict(d: dict, *, verify: bool = True) -> ContactCard:
    """Deserialize a contact card from a dict.

    When *verify* is ``True`` (the default), the card's signature is
    checked immediately after deserialization.  Pass ``verify=False``
    to skip verification (e.g. when building test fixtures).

    Raises:
        InvalidContactCardError: If required fields are missing.
        SignatureVerificationError: If *verify* is True and the signature is invalid.
    """
    required = {"version", "address", "display_name", "relay", "public_key", "signature"}
    missing = required - set(d.keys())
    if missing:
        raise InvalidContactCardError(f"Missing required fields: {sorted(missing)}")

    card = ContactCard(
        version=d["version"],
        address=d["address"],
        display_name=d["display_name"],
        description=d.get("description"),
        system=d.get("system"),
        connection_endpoint=d.get("connection_endpoint"),
        relay=d["relay"],
        public_key=d["public_key"],
        signature=d["signature"],
        verified_domain=d.get("verified_domain"),
        payload_formats=d.get("payload_formats"),
        fingerprint=d.get("fingerprint"),
    )

    if verify:
        verify_contact_card(card)

    return card


def create_contact_card(
    address: str,
    display_name: str,
    relay: str,
    signing_key: SigningKey,
    *,
    description: str | None = None,
    system: str | None = None,
    connection_endpoint: str | None = None,
    verified_domain: str | None = None,
    payload_formats: list[str] | None = None,
) -> ContactCard:
    """Create a self-signed contact card.

    *payload_formats* defaults to ``["text/plain", "text/markdown"]`` when
    not specified.  The *fingerprint* is always auto-computed as the SHA-256
    hex digest of the Ed25519 public key bytes.

    Raises:
        InvalidAddressError: If *address* is not valid.
    """
    # Validate address
    parse_address(address)

    # Derive public key and fingerprint
    public_key = serialize_verify_key(signing_key.verify_key)
    fp = public_key_fingerprint(signing_key.verify_key)

    # Default payload formats
    if payload_formats is None:
        payload_formats = ["text/plain", "text/markdown"]

    # Build temporary card without signature
    temp_card = ContactCard(
        version=UAM_VERSION,
        address=address,
        display_name=display_name,
        description=description,
        system=system,
        connection_endpoint=connection_endpoint,
        relay=relay,
        public_key=public_key,
        signature="",  # placeholder
        verified_domain=verified_domain,
        payload_formats=payload_formats,
        fingerprint=fp,
    )

    # Sign (payload_formats and fingerprint are NOT in signable dict)
    signable = _build_signable_dict(temp_card)
    signature = sign_message(canonicalize(signable), signing_key)

    # Return final card
    return ContactCard(
        version=UAM_VERSION,
        address=address,
        display_name=display_name,
        description=description,
        system=system,
        connection_endpoint=connection_endpoint,
        relay=relay,
        public_key=public_key,
        signature=signature,
        verified_domain=verified_domain,
        payload_formats=payload_formats,
        fingerprint=fp,
    )


def verify_contact_card(card: ContactCard) -> None:
    """Verify a contact card's signature using its embedded public key.

    Raises:
        InvalidContactCardError: If the address is invalid.
        SignatureVerificationError: If the signature is invalid.
    """
    # Validate address format
    try:
        parse_address(card.address)
    except Exception as exc:
        raise InvalidContactCardError(f"Invalid address in contact card: {exc}") from exc

    # Deserialize the embedded public key
    vk = deserialize_verify_key(card.public_key)

    # Verify signature
    signable = _build_signable_dict(card)
    verify_signature(canonicalize(signable), card.signature, vk)
