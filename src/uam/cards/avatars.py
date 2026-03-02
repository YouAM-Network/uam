"""Local avatar generation for UAM agent cards.

Uses the bundled SVG avatar engine to generate deterministic avatars from
agent addresses. The same address always produces the same avatar image
because the address is used as the SHA-256 seed for component selection.

Supported styles correspond to bundled asset library names (e.g. "bots",
"crustaceans"). The engine composites SVG layers and rasterizes to PNG
locally -- no HTTP calls are made.
"""

from __future__ import annotations

import logging

from uam.cards.avatar_engine import generate_avatar

logger = logging.getLogger(__name__)


def fetch_avatar(
    address: str,
    style: str = "bots",
    size: int = 200,
) -> bytes | None:
    """Generate a local avatar PNG for the given address.

    Args:
        address: Agent address used as the deterministic seed.
        style: Asset library name (default: bots).
        size: Avatar image size in pixels (default: 200).

    Returns:
        Raw PNG bytes on success, or None if the engine fails (unknown
        style, missing library, or any other error).  Returning None
        preserves the contract that image.py relies on -- None triggers
        the letter-circle fallback renderer.
    """
    try:
        return generate_avatar(address, style, size)
    except Exception:
        logger.warning(
            "Avatar engine failed for address=%r style=%r, falling back to letter-circle",
            address,
            style,
            exc_info=True,
        )
        return None
