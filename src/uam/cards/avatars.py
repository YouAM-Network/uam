"""DiceBear avatar fetching for UAM agent cards.

Uses the DiceBear HTTP API (https://www.dicebear.com/) to generate
deterministic avatars from agent addresses. The same address always
produces the same avatar image because the address is used as the
random seed parameter.

Supported styles include: bottts-neutral, identicon, shapes, thumbs,
adventurer-neutral, fun-emoji, etc. See https://www.dicebear.com/styles/
for the full list.
"""

from __future__ import annotations

import httpx


def fetch_avatar(
    address: str,
    style: str = "bottts-neutral",
    size: int = 200,
) -> bytes | None:
    """Fetch a DiceBear avatar PNG for the given address.

    Args:
        address: Agent address used as the deterministic seed.
        style: DiceBear avatar style name (default: bottts-neutral).
        size: Avatar image size in pixels (default: 200).

    Returns:
        Raw PNG bytes on success, or None on HTTP error / timeout.
    """
    url = f"https://api.dicebear.com/9.x/{style}/png?seed={address}&size={size}"
    try:
        resp = httpx.get(url, timeout=10.0)
        resp.raise_for_status()
        return resp.content
    except (httpx.TimeoutException, httpx.HTTPStatusError, httpx.ConnectError):
        return None
