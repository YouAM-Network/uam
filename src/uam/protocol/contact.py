"""UAM contact cards -- self-signed agent identity documents.

A contact card advertises an agent's address, public key, relay endpoint,
and optional metadata.  The card is signed by the agent's own signing key
so that any recipient can verify authenticity using the embedded public key.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
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

logger = logging.getLogger(__name__)


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
    # CARD-04: Multi-relay support.  Outside signature scope so intermediaries
    # (e.g., relay operators) can update the relay list without invalidating
    # the card's signature.  Presence of this field signals v0.2 capability;
    # the version string stays at UAM_VERSION ("0.1") for now.
    relays: Optional[list[str]] = None
    # Phase 48 (Q2) -- ISO-8601 UTC expiry. ``None`` = transitional (treated
    # as ``imported_at + 365d`` by ``check_card_expiry``). Included in
    # ``_build_signable_dict`` so an attacker cannot extend a captured
    # card's expiry by editing this field.
    not_after: Optional[str] = None


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
    # Phase 48 (Q2) -- include not_after BEFORE verified_domain so the trailing
    # verified_domain block remains the last addition (mirrors historical
    # ordering documented in 48-00 SUMMARY hint).
    if card.not_after is not None:
        d["not_after"] = card.not_after
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
    if card.relays is not None:
        d["relays"] = card.relays
    if card.not_after is not None:
        d["not_after"] = card.not_after
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
        relays=d.get("relays"),
        not_after=d.get("not_after"),  # Phase 48 (Q2)
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
    relays: list[str] | None = None,
    not_after: str | None = None,
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
        relays=relays,
        not_after=not_after,
    )

    # Sign (payload_formats and fingerprint are NOT in signable dict; not_after IS)
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
        relays=relays,
        not_after=not_after,
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


def check_card_expiry(
    card: ContactCard,
    *,
    now: Optional[datetime] = None,
    transitional_ttl: timedelta = timedelta(days=365),
    imported_at: Optional[datetime] = None,
) -> None:
    """Raise :class:`ContactCardExpired` if the card has expired.

    Phase 48 (Q2) -- Transitional behavior: cards without ``not_after`` are
    treated as ``imported_at + transitional_ttl`` (default 365 days). A
    WARNING is logged on every transitional encounter so operators see the
    upgrade pressure.

    Args:
        card: The contact card to check.
        now: Optional override for the current UTC time (defaults to now).
        transitional_ttl: How long to treat a card-without-``not_after`` as
            valid after import (default 365d).
        imported_at: When this card was first imported. Required to apply
            the transitional TTL; if absent, transitional cards are
            considered valid indefinitely (only a WARNING is emitted).

    Raises:
        ContactCardExpired: When the card's ``not_after`` is past, or when
            the transitional TTL has elapsed since ``imported_at``.
        ValidationError: When ``not_after`` is present but is not a parseable
            ISO-8601 timestamp.
    """
    from uam.protocol.errors import ContactCardExpired, ValidationError

    now = now or datetime.now(tz=timezone.utc)

    if card.not_after is not None:
        # Tolerate trailing 'Z' (Python's fromisoformat accepts it on 3.11+
        # but we replace defensively for older runtimes / consistency).
        iso = card.not_after.replace("Z", "+00:00")
        try:
            not_after = datetime.fromisoformat(iso)
        except ValueError as exc:
            raise ValidationError(
                f"contact card {card.address!r} has invalid not_after "
                f"{card.not_after!r}: {exc}"
            ) from exc
        if now > not_after:
            raise ContactCardExpired(card.address, card.not_after)
        return

    # Transitional path: absent not_after.
    logger.warning(
        "Contact card for %s has no not_after; treating as transitional "
        "(TTL %s). Card SHOULD be re-issued with an explicit not_after.",
        card.address,
        transitional_ttl,
    )
    if imported_at is not None and now > imported_at + transitional_ttl:
        raise ContactCardExpired(
            card.address,
            (imported_at + transitional_ttl).isoformat().replace("+00:00", "Z"),
        )
