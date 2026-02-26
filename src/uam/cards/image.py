"""Card image renderer for UAM agent cards.

Generates 600x600 JPEG card images with DiceBear avatars, agent address
text, and distinct visual styles for reservation and identity card types.

Reservation cards use a navy+gold color scheme with "RESERVED" badge.
Identity cards use a teal+cyan color scheme with "AI Agent" badge and
include the viral onboarding command.
"""

from __future__ import annotations

import io
import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

from uam.cards.avatars import fetch_avatar

# ---------------------------------------------------------------------------
# Color schemes
# ---------------------------------------------------------------------------

_SCHEMES = {
    "reservation": {
        "bg": "#1a1a2e",
        "accent": "#e2b714",
        "badge": "RESERVED",
    },
    "identity": {
        "bg": "#0d2137",
        "accent": "#00d4ff",
        "badge": "AI Agent",
    },
}

# Card dimensions
_WIDTH = 600
_HEIGHT = 600

# Font directory (bundled with package)
_FONT_DIR = Path(__file__).parent / "fonts"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load_font(weight: str, size: int) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    """Load an Inter TTF font by weight and size, falling back to default."""
    name = f"Inter-{weight}.ttf"
    path = _FONT_DIR / name
    try:
        return ImageFont.truetype(str(path), size)
    except (OSError, IOError):
        print(f"[cards] Warning: could not load font {path}, using default", file=sys.stderr)
        return ImageFont.load_default(size)


def _measure_text(
    draw: ImageDraw.ImageDraw,
    text: str,
    font: ImageFont.FreeTypeFont | ImageFont.ImageFont,
) -> tuple[int, int]:
    """Return (width, height) of rendered text."""
    bbox = draw.textbbox((0, 0), text, font=font)
    return bbox[2] - bbox[0], bbox[3] - bbox[1]


def _fit_text(
    draw: ImageDraw.ImageDraw,
    text: str,
    max_width: int,
    weight: str,
    start_size: int,
    min_size: int = 18,
) -> tuple[ImageFont.FreeTypeFont | ImageFont.ImageFont, str]:
    """Reduce font size until text fits within max_width.

    Returns (font, possibly_truncated_text).
    """
    size = start_size
    font = _load_font(weight, size)
    w, _ = _measure_text(draw, text, font)

    while w > max_width and size > min_size:
        size -= 2
        font = _load_font(weight, size)
        w, _ = _measure_text(draw, text, font)

    # Last resort: truncate with ellipsis
    if w > max_width:
        while w > max_width and len(text) > 4:
            text = text[:-4] + "..."
            w, _ = _measure_text(draw, text, font)

    return font, text


def _paste_avatar(canvas: Image.Image, avatar_bytes: bytes) -> None:
    """Composite a PNG avatar onto the canvas, centered at y=80."""
    try:
        avatar = Image.open(io.BytesIO(avatar_bytes))
        avatar = avatar.resize((200, 200), Image.LANCZOS)

        # Center horizontally
        x = (_WIDTH - 200) // 2
        y = 80

        if avatar.mode == "RGBA":
            canvas.paste(avatar, (x, y), avatar)
        else:
            canvas.paste(avatar, (x, y))
    except Exception:
        pass  # If avatar loading fails, skip silently


def _draw_letter_circle(
    draw: ImageDraw.ImageDraw,
    canvas: Image.Image,
    letter: str,
    accent: str,
) -> None:
    """Draw a colored circle with the first letter as avatar fallback."""
    x = (_WIDTH - 200) // 2
    y = 80
    draw.ellipse([x, y, x + 200, y + 200], fill=accent)
    font = _load_font("Bold", 80)
    tw, th = _measure_text(draw, letter.upper(), font)
    tx = x + (200 - tw) // 2
    ty = y + (200 - th) // 2 - 5
    draw.text((tx, ty), letter.upper(), fill="#ffffff", font=font)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def render_card(
    agent_name: str,
    relay_domain: str,
    card_type: str,
    *,
    fingerprint: str | None = None,
    expires_at: str | None = None,
    avatar_style: str = "bottts-neutral",
    avatar_bytes: bytes | None = None,
) -> bytes:
    """Generate a 600x600 JPEG card image.

    Args:
        agent_name: The agent's name (e.g. "scout").
        relay_domain: The relay domain (e.g. "youam.network").
        card_type: Either "reservation" or "identity".
        fingerprint: Optional key fingerprint (shown on identity cards).
        expires_at: Optional expiration timestamp (shown on reservation cards).
        avatar_style: DiceBear avatar style name.
        avatar_bytes: Pre-fetched avatar PNG bytes (skips HTTP call if provided).

    Returns:
        Raw JPEG bytes (always under 200KB at 600x600).
    """
    scheme = _SCHEMES.get(card_type, _SCHEMES["reservation"])
    bg_color = scheme["bg"]
    accent = scheme["accent"]
    badge_text = scheme["badge"]

    # Create canvas
    canvas = Image.new("RGB", (_WIDTH, _HEIGHT), bg_color)
    draw = ImageDraw.Draw(canvas)

    # --- Top bar (y=20-60): relay domain right-aligned ---
    font_small = _load_font("Regular", 16)
    domain_text = relay_domain
    dw, _ = _measure_text(draw, domain_text, font_small)
    draw.text((_WIDTH - dw - 30, 25), domain_text, fill=accent, font=font_small)

    # --- Avatar (y=80-280): 200x200 centered ---
    if avatar_bytes is None:
        avatar_bytes = fetch_avatar(agent_name, style=avatar_style)

    if avatar_bytes:
        _paste_avatar(canvas, avatar_bytes)
    else:
        letter = agent_name[0] if agent_name else "?"
        _draw_letter_circle(draw, canvas, letter, accent)

    # --- Agent address (y=300-340): centered, bold, white ---
    address_text = f"{agent_name}::{relay_domain}"
    font_addr, address_text = _fit_text(draw, address_text, 540, "Bold", 28)
    aw, _ = _measure_text(draw, address_text, font_addr)
    draw.text(((_WIDTH - aw) // 2, 305), address_text, fill="#ffffff", font=font_addr)

    # --- Badge (y=360-390): accent color, centered ---
    font_badge = _load_font("Bold", 18)
    bw, _ = _measure_text(draw, badge_text, font_badge)
    draw.text(((_WIDTH - bw) // 2, 365), badge_text, fill=accent, font=font_badge)

    # --- Bottom section (y=420-560) ---
    font_body = _load_font("Regular", 15)
    font_mono = _load_font("Bold", 14)

    if card_type == "reservation":
        # "Claim with:" label
        label = "Claim with:"
        lw, _ = _measure_text(draw, label, font_body)
        draw.text(((_WIDTH - lw) // 2, 425), label, fill="#aaaaaa", font=font_body)

        # Command text
        cmd = f"uam init --claim {agent_name}.vcf"
        font_cmd, cmd = _fit_text(draw, cmd, 520, "Bold", 16, min_size=12)
        cw, _ = _measure_text(draw, cmd, font_cmd)
        draw.text(((_WIDTH - cw) // 2, 455), cmd, fill="#ffffff", font=font_cmd)

        # Expiry
        if expires_at:
            exp_text = f"Expires: {expires_at}"
            font_exp, exp_text = _fit_text(draw, exp_text, 520, "Regular", 13, min_size=10)
            ew, _ = _measure_text(draw, exp_text, font_exp)
            draw.text(((_WIDTH - ew) // 2, 490), exp_text, fill="#888888", font=font_exp)

    elif card_type == "identity":
        # "Get your own:" label
        label = "Get your own:"
        lw, _ = _measure_text(draw, label, font_body)
        draw.text(((_WIDTH - lw) // 2, 425), label, fill="#aaaaaa", font=font_body)

        # Viral command
        cmd = f"curl {relay_domain}/new | sh"
        font_cmd, cmd = _fit_text(draw, cmd, 520, "Bold", 16, min_size=12)
        cw, _ = _measure_text(draw, cmd, font_cmd)
        draw.text(((_WIDTH - cw) // 2, 455), cmd, fill="#ffffff", font=font_cmd)

        # Fingerprint
        if fingerprint:
            fp_display = f"fp: {fingerprint[:16]}..." if len(fingerprint) > 16 else f"fp: {fingerprint}"
            font_fp, fp_display = _fit_text(draw, fp_display, 520, "Regular", 13, min_size=10)
            fw, _ = _measure_text(draw, fp_display, font_fp)
            draw.text(((_WIDTH - fw) // 2, 490), fp_display, fill="#888888", font=font_fp)

    # --- Footer (y=570-595): relay domain small muted ---
    footer_text = relay_domain
    font_footer = _load_font("Regular", 12)
    ftw, _ = _measure_text(draw, footer_text, font_footer)
    draw.text(((_WIDTH - ftw) // 2, 575), footer_text, fill="#555555", font=font_footer)

    # --- Encode as JPEG ---
    return _encode_jpeg(canvas)


def _encode_jpeg(canvas: Image.Image, max_bytes: int = 200_000) -> bytes:
    """Encode canvas to JPEG, reducing quality if needed to stay under max_bytes."""
    for quality in (85, 75, 65):
        buf = io.BytesIO()
        canvas.save(buf, format="JPEG", quality=quality)
        data = buf.getvalue()
        if len(data) <= max_bytes:
            return data
    # Last resort: return whatever we have
    return data
