"""Hand-rolled vCard 3.0 parser with RFC 2426 line unfolding.

Extracts UAM-specific fields from reservation vCards, with fallback parsing
for round-tripped cards (Apple Contacts re-export).
"""

from __future__ import annotations

from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Line unfolding (RFC 2426)
# ---------------------------------------------------------------------------


def unfold_lines(text: str) -> str:
    """Unfold vCard continuation lines per RFC 2426.

    RFC 2426 specifies that long lines are folded by inserting a CRLF
    immediately followed by a single whitespace character (SPACE or TAB).
    This function reverses that process: any newline followed by a SPACE
    or TAB is removed, joining the continuation back to the previous line.

    Line endings are normalized to ``\\n`` before unfolding.
    """
    # Normalize line endings: \r\n -> \n, bare \r -> \n
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    # Unfold: newline followed by a single SPACE or TAB means continuation
    result: list[str] = []
    i = 0
    while i < len(text):
        if text[i] == "\n" and i + 1 < len(text) and text[i + 1] in (" ", "\t"):
            # Skip the newline and the leading whitespace character
            i += 2
        else:
            result.append(text[i])
            i += 1
    return "".join(result)


# ---------------------------------------------------------------------------
# vCard field parsing
# ---------------------------------------------------------------------------


def parse_vcard(text: str) -> dict[str, str]:
    """Parse a vCard 3.0 text blob into a property-name -> value dict.

    Applies line unfolding first, then extracts properties between
    ``BEGIN:VCARD`` and ``END:VCARD``.  Property parameters (e.g.
    ``PHOTO;ENCODING=b;TYPE=JPEG``) are stripped -- only the base
    property name is used as the key.

    For duplicate properties the later value overwrites the earlier one.

    Returns:
        Dict mapping uppercase property names to their string values.
    """
    text = unfold_lines(text)
    fields: dict[str, str] = {}
    in_vcard = False

    for line in text.split("\n"):
        line = line.strip()
        if not line:
            continue

        if line.upper() == "BEGIN:VCARD":
            in_vcard = True
            continue
        if line.upper() == "END:VCARD":
            break
        if not in_vcard:
            continue

        # Split on first colon to get property_part:value
        colon_idx = line.find(":")
        if colon_idx < 0:
            continue

        prop_part = line[:colon_idx]
        value = line[colon_idx + 1:]

        # Strip parameters (e.g. "PHOTO;ENCODING=b;TYPE=JPEG" -> "PHOTO")
        semicolon_idx = prop_part.find(";")
        if semicolon_idx >= 0:
            prop_name = prop_part[:semicolon_idx]
        else:
            prop_name = prop_part

        fields[prop_name.upper()] = value

    return fields


# ---------------------------------------------------------------------------
# UAM claim info extraction
# ---------------------------------------------------------------------------


def extract_claim_info(vcard_text: str) -> dict:
    """Extract UAM claim information from a reservation vCard.

    **Primary path:** Reads ``X-UAM-CLAIM-TOKEN``, ``X-UAM-RELAY``, and
    ``X-UAM-ADDRESS`` directly from the parsed vCard fields.

    **Fallback path:** If ``X-UAM-CLAIM-TOKEN`` is missing (happens when
    Apple Contacts re-exports and strips custom X- fields), the ``NOTE``
    field is parsed for ``Claim Token: ...`` and ``Relay: ...`` lines.

    Returns:
        Dict with keys ``claim_token``, ``relay_url``, ``address``,
        and ``agent_name``.

    Raises:
        ValueError: If the claim token or relay URL cannot be extracted
            from either the X-UAM fields or the NOTE fallback.
    """
    fields = parse_vcard(vcard_text)

    claim_token: str | None = fields.get("X-UAM-CLAIM-TOKEN")
    relay_url: str | None = fields.get("X-UAM-RELAY")
    address: str | None = fields.get("X-UAM-ADDRESS")

    # Fallback: parse NOTE field if X-UAM-CLAIM-TOKEN is missing
    if not claim_token:
        note_raw = fields.get("NOTE", "")
        # Unescape vCard NOTE encoding: \\n -> newline, \\, -> comma, \\; -> semicolon
        note_text = note_raw.replace("\\n", "\n").replace("\\,", ",").replace("\\;", ";")

        for line in note_text.split("\n"):
            line = line.strip()
            if line.startswith("Claim Token: "):
                claim_token = line[len("Claim Token: "):]
            elif line.startswith("Relay: "):
                relay_url = line[len("Relay: "):]

        # Build address from FN + relay domain if not already set
        if not address and relay_url:
            fn = fields.get("FN", "")
            agent_name = _extract_agent_name(fn)
            if agent_name:
                # Extract domain from relay URL: "https://relay.youam.network" -> "youam.network"
                parsed = urlparse(relay_url)
                hostname = parsed.hostname or ""
                if hostname.startswith("relay."):
                    domain = hostname[len("relay."):]
                else:
                    domain = hostname
                address = f"{agent_name}::{domain}"

    if not claim_token:
        raise ValueError("Could not extract claim token from vCard")
    if not relay_url:
        raise ValueError("Could not extract relay URL from vCard")
    if not address:
        raise ValueError("Could not extract address from vCard")

    # Extract agent name from address (before ::)
    agent_name = address.split("::")[0] if "::" in address else _extract_agent_name(fields.get("FN", ""))

    return {
        "claim_token": claim_token,
        "relay_url": relay_url,
        "address": address,
        "agent_name": agent_name,
    }


def _extract_agent_name(fn: str) -> str:
    """Extract agent name from a vCard FN field.

    The FN format is typically ``"scout (Reserved - youam.network)"`` or
    ``"scout (youam.network)"``.  Returns the part before the first `` (``
    or the full value if no parenthesis is found.
    """
    paren_idx = fn.find(" (")
    if paren_idx >= 0:
        return fn[:paren_idx].strip()
    return fn.strip()
