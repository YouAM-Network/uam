"""Hand-rolled vCard 3.0 generator with RFC 2426 line folding.

Produces cross-platform-compatible .vcf files with embedded PHOTO from card
images and dual-channel data encoding (human-readable NOTE + machine-parseable
X-UAM-* fields).

vCard 3.0 chosen over 4.0 because Outlook rejects v4.0 and iCloud has import
failures with it. The vobject library is intentionally avoided due to known
base64 PHOTO encoding bugs (issue #46).
"""

from __future__ import annotations

import base64
import datetime

from uam.cards.image import render_card


# ---------------------------------------------------------------------------
# Line folding (RFC 2426)
# ---------------------------------------------------------------------------


def fold_line(line: str) -> str:
    """Fold a vCard content line per RFC 2426.

    Lines longer than 75 octets (bytes) are split at the 75th octet.
    Continuation lines start with a single SPACE character.  Every line
    (including continuations) ends with CRLF.

    Returns the folded line(s) as a single string with CRLF endings.
    """
    encoded = line.encode("utf-8")
    if len(encoded) <= 75:
        return line + "\r\n"

    parts: list[str] = []
    # First line: up to 75 bytes
    first = encoded[:75].decode("utf-8", errors="ignore")
    parts.append(first)
    offset = len(first.encode("utf-8"))

    # Continuation lines: SPACE + up to 74 bytes of content (75 total)
    while offset < len(encoded):
        chunk_bytes = encoded[offset : offset + 74]
        chunk = chunk_bytes.decode("utf-8", errors="ignore")
        parts.append(" " + chunk)
        offset += len(chunk.encode("utf-8"))

    return "\r\n".join(parts) + "\r\n"


def fold_base64(property_prefix: str, b64_data: str) -> str:
    """Fold a base64 PHOTO property across multiple lines.

    First line: ``{property_prefix}{first_chunk}`` (total 75 chars).
    Subsequent lines: SPACE + 74 chars of data (75 total with leading space).
    All lines terminated with CRLF.
    """
    first_len = 75 - len(property_prefix)
    parts: list[str] = []
    parts.append(property_prefix + b64_data[:first_len])

    offset = first_len
    while offset < len(b64_data):
        chunk = b64_data[offset : offset + 74]
        parts.append(" " + chunk)
        offset += 74

    return "\r\n".join(parts) + "\r\n"


# ---------------------------------------------------------------------------
# Reservation vCard
# ---------------------------------------------------------------------------


def generate_reservation_vcard(
    agent_name: str,
    relay_domain: str,
    claim_token: str,
    *,
    expires_at: str | None = None,
    card_image_jpeg: bytes | None = None,
    avatar_style: str = "bottts-neutral",
) -> str:
    """Generate a vCard 3.0 for an address reservation.

    The vCard contains human-readable NOTE with claim instructions and
    machine-parseable X-UAM-* fields for automated claiming.

    Args:
        agent_name: The reserved agent name (e.g. "scout").
        relay_domain: The relay domain (e.g. "youam.network").
        claim_token: Secret token required to claim this reservation.
        expires_at: Optional expiration timestamp string.
        card_image_jpeg: Pre-rendered JPEG bytes for the PHOTO property.
            If None, ``render_card()`` is called to generate the image.
        avatar_style: DiceBear avatar style for card image generation.

    Returns:
        Complete vCard 3.0 string with CRLF line endings.
    """
    if card_image_jpeg is None:
        card_image_jpeg = render_card(
            agent_name,
            relay_domain,
            "reservation",
            expires_at=expires_at,
            avatar_style=avatar_style,
        )

    b64_photo = base64.b64encode(card_image_jpeg).decode("ascii")
    rev = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # NOTE content -- newlines encoded as literal \n for vCard
    note_text = (
        "UAM Reservation Card\\n\\n"
        f"Claim this address:\\n"
        f"  uam init --claim {agent_name}.vcf\\n\\n"
        f"Claim Token: {claim_token}\\n"
        f"Expires: {expires_at}\\n"
        f"Relay: https://relay.{relay_domain}"
    )
    # Escape commas and semicolons in NOTE
    note_text = note_text.replace(",", "\\,").replace(";", "\\;")

    lines: list[str] = []
    lines.append(fold_line("BEGIN:VCARD"))
    lines.append(fold_line("VERSION:3.0"))
    lines.append(fold_line(f"FN:{agent_name} (Reserved - {relay_domain})"))
    lines.append(fold_line(f"N:;{agent_name};;;"))
    lines.append(fold_line(f"ORG:{relay_domain}"))
    lines.append(fold_line("TITLE:UAM Agent -- Reserved"))
    lines.append(fold_line(f"NOTE:{note_text}"))
    lines.append(fold_line(f"URL:https://{relay_domain}"))
    lines.append(fold_line(f"X-UAM-ADDRESS:{agent_name}::{relay_domain}"))
    lines.append(fold_line(f"X-UAM-CLAIM-TOKEN:{claim_token}"))
    lines.append(fold_line(f"X-UAM-RELAY:https://relay.{relay_domain}"))
    lines.append(fold_line("X-UAM-CARD-TYPE:reservation"))
    lines.append(fold_base64("PHOTO;ENCODING=b;TYPE=JPEG:", b64_photo))
    lines.append(fold_line(f"UID:reservation-{agent_name}::{relay_domain}"))
    lines.append(fold_line(f"REV:{rev}"))
    lines.append(fold_line("PRODID:-//UAM//vCard Generator//EN"))
    lines.append(fold_line("END:VCARD"))

    return "".join(lines)


# ---------------------------------------------------------------------------
# Identity vCard
# ---------------------------------------------------------------------------


def generate_identity_vcard(
    agent_name: str,
    relay_domain: str,
    *,
    public_key_b64: str | None = None,
    fingerprint: str | None = None,
    card_image_jpeg: bytes | None = None,
    avatar_style: str = "bottts-neutral",
) -> str:
    """Generate a vCard 3.0 for an established agent identity.

    The vCard contains human-readable NOTE with address/fingerprint info and
    a viral ``curl ... | sh`` onboarding command, plus machine-parseable
    X-UAM-* fields for programmatic use.

    Args:
        agent_name: The agent's name (e.g. "scout").
        relay_domain: The relay domain (e.g. "youam.network").
        public_key_b64: Optional base64-encoded public key.
        fingerprint: Optional key fingerprint string.
        card_image_jpeg: Pre-rendered JPEG bytes for the PHOTO property.
            If None, ``render_card()`` is called to generate the image.
        avatar_style: DiceBear avatar style for card image generation.

    Returns:
        Complete vCard 3.0 string with CRLF line endings.
    """
    if card_image_jpeg is None:
        card_image_jpeg = render_card(
            agent_name,
            relay_domain,
            "identity",
            fingerprint=fingerprint,
            avatar_style=avatar_style,
        )

    b64_photo = base64.b64encode(card_image_jpeg).decode("ascii")
    rev = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # NOTE content
    note_text = (
        "UAM Agent Contact Card\\n\\n"
        f"Address: {agent_name}::{relay_domain}\\n"
        f"Fingerprint: {fingerprint}\\n"
        f"Relay: https://relay.{relay_domain}\\n\\n"
        f"Get your own agent address:\\n"
        f"  curl {relay_domain}/new | sh"
    )
    note_text = note_text.replace(",", "\\,").replace(";", "\\;")

    lines: list[str] = []
    lines.append(fold_line("BEGIN:VCARD"))
    lines.append(fold_line("VERSION:3.0"))
    lines.append(fold_line(f"FN:{agent_name} ({relay_domain})"))
    lines.append(fold_line(f"N:;{agent_name};;;"))
    lines.append(fold_line(f"ORG:{relay_domain}"))
    lines.append(fold_line("TITLE:UAM Agent"))
    lines.append(fold_line(f"NOTE:{note_text}"))
    lines.append(fold_line(f"URL:https://{relay_domain}/card/{agent_name}"))
    lines.append(fold_line(f"X-UAM-ADDRESS:{agent_name}::{relay_domain}"))
    lines.append(fold_line(f"X-UAM-RELAY:https://relay.{relay_domain}"))
    lines.append(fold_line(f"X-UAM-FINGERPRINT:{fingerprint or ''}"))
    lines.append(fold_line(f"X-UAM-PUBLIC-KEY:{public_key_b64 or ''}"))
    lines.append(fold_line(f"X-UAM-SIGNUP:https://{relay_domain}/new"))
    lines.append(fold_line("X-UAM-CARD-TYPE:identity"))
    lines.append(fold_base64("PHOTO;ENCODING=b;TYPE=JPEG:", b64_photo))
    lines.append(fold_line(f"UID:{agent_name}::{relay_domain}"))
    lines.append(fold_line(f"REV:{rev}"))
    lines.append(fold_line("PRODID:-//UAM//vCard Generator//EN"))
    lines.append(fold_line("END:VCARD"))

    return "".join(lines)
