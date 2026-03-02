"""Card image renderer for UAM agent cards.

Generates 600x600 JPEG card images with locally-generated avatars, agent
address text, and distinct visual styles for reservation and identity card types.

Reservation cards use a dark zinc + violet scheme matching the frontend design.
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
        "bg": "#18181b",
        "accent": "#8b5cf6",
        "accent2": "#10b981",
        "badge": "Reserved",
    },
    "identity": {
        "bg": "#0d2137",
        "accent": "#00d4ff",
        "accent2": None,
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


def _draw_gradient_bar(
    canvas: Image.Image,
    y: int,
    height: int,
    color_left: str,
    color_mid: str,
    color_right: str,
) -> None:
    """Draw a horizontal 3-stop gradient bar across the full canvas width."""
    from PIL import ImageColor

    c1 = ImageColor.getrgb(color_left)
    c2 = ImageColor.getrgb(color_mid)
    c3 = ImageColor.getrgb(color_right)

    half = _WIDTH // 2
    for x in range(half):
        t = x / half
        r = int(c1[0] + (c2[0] - c1[0]) * t)
        g = int(c1[1] + (c2[1] - c1[1]) * t)
        b = int(c1[2] + (c2[2] - c1[2]) * t)
        for dy in range(height):
            canvas.putpixel((x, y + dy), (r, g, b))

    for x in range(half, _WIDTH):
        t = (x - half) / (_WIDTH - half)
        r = int(c2[0] + (c3[0] - c2[0]) * t)
        g = int(c2[1] + (c3[1] - c2[1]) * t)
        b = int(c2[2] + (c3[2] - c2[2]) * t)
        for dy in range(height):
            canvas.putpixel((x, y + dy), (r, g, b))


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
    avatar_style: str = "bots",
    avatar_bytes: bytes | None = None,
    bg_color: str | None = None,
    accent_color: str | None = None,
    badge_text: str | None = None,
) -> bytes:
    """Generate a 600x600 JPEG card image.

    Args:
        agent_name: The agent's name (e.g. "scout").
        relay_domain: The relay domain (e.g. "youam.network").
        card_type: Either "reservation" or "identity".
        fingerprint: Optional key fingerprint (shown on identity cards).
        expires_at: Optional expiration timestamp (shown on reservation cards).
        avatar_style: Local avatar engine style name.
        avatar_bytes: Pre-fetched avatar PNG bytes (skips HTTP call if provided).
        bg_color: Override background color (hex, e.g. "#18181b").
        accent_color: Override accent color (hex, e.g. "#8b5cf6").
        badge_text: Override badge text (e.g. "AI Agent").

    Returns:
        Raw JPEG bytes (always under 200KB at 600x600).
    """
    scheme = _SCHEMES.get(card_type, _SCHEMES["reservation"])
    bg = bg_color or scheme["bg"]
    accent = accent_color or scheme["accent"]
    accent2 = scheme.get("accent2")
    badge = badge_text if badge_text is not None else scheme["badge"]

    # Derive short namespace: "youam.network" -> "youam"
    namespace = relay_domain.split(".")[0] if "." in relay_domain else relay_domain

    # Create canvas
    canvas = Image.new("RGB", (_WIDTH, _HEIGHT), bg)
    draw = ImageDraw.Draw(canvas)

    # --- Top gradient bar (y=0, 4px) ---
    if accent2:
        _draw_gradient_bar(canvas, 0, 4, accent, accent2, accent)
    else:
        draw.rectangle([0, 0, _WIDTH, 4], fill=accent)

    # --- Avatar (y=80-280): 200x200 centered ---
    if avatar_bytes is None:
        avatar_bytes = fetch_avatar(agent_name, style=avatar_style)

    if avatar_bytes:
        _paste_avatar(canvas, avatar_bytes)
    else:
        letter = agent_name[0] if agent_name else "?"
        _draw_letter_circle(draw, canvas, letter, accent)

    # --- Agent name + namespace (y=300-340): centered ---
    # Name in white bold, ::namespace in muted accent
    font_name = _load_font("Bold", 32)
    suffix = f"::{namespace}"
    font_suffix = _load_font("Bold", 32)

    nw, _ = _measure_text(draw, agent_name, font_name)
    sw, _ = _measure_text(draw, suffix, font_suffix)
    total_w = nw + sw

    # Scale down if too wide
    if total_w > 540:
        font_name = _load_font("Bold", 24)
        font_suffix = _load_font("Bold", 24)
        nw, _ = _measure_text(draw, agent_name, font_name)
        sw, _ = _measure_text(draw, suffix, font_suffix)
        total_w = nw + sw

    start_x = (_WIDTH - total_w) // 2
    draw.text((start_x, 305), agent_name, fill="#ffffff", font=font_name)
    # Muted accent at ~60% opacity: blend with bg
    from PIL import ImageColor
    accent_rgb = ImageColor.getrgb(accent)
    bg_rgb = ImageColor.getrgb(bg)
    muted = tuple(int(a * 0.6 + b * 0.4) for a, b in zip(accent_rgb, bg_rgb))
    muted_hex = f"#{muted[0]:02x}{muted[1]:02x}{muted[2]:02x}"
    draw.text((start_x + nw, 305), suffix, fill=muted_hex, font=font_suffix)

    # --- Badge pill (y=360-390): accent text with rounded bg ---
    font_badge = _load_font("Bold", 16)
    bw, bh = _measure_text(draw, badge, font_badge)
    pad_x, pad_y = 16, 6
    pill_w = bw + pad_x * 2
    pill_h = bh + pad_y * 2
    pill_x = (_WIDTH - pill_w) // 2
    pill_y = 365
    # Pill background: accent at 10% over bg
    pill_bg = tuple(int(a * 0.1 + b * 0.9) for a, b in zip(accent_rgb, bg_rgb))
    pill_bg_hex = f"#{pill_bg[0]:02x}{pill_bg[1]:02x}{pill_bg[2]:02x}"
    # Pill border: accent at 20% over bg
    pill_border = tuple(int(a * 0.2 + b * 0.8) for a, b in zip(accent_rgb, bg_rgb))
    pill_border_hex = f"#{pill_border[0]:02x}{pill_border[1]:02x}{pill_border[2]:02x}"
    draw.rounded_rectangle(
        [pill_x, pill_y, pill_x + pill_w, pill_y + pill_h],
        radius=pill_h // 2,
        fill=pill_bg_hex,
        outline=pill_border_hex,
    )
    draw.text((pill_x + pad_x, pill_y + pad_y), badge, fill=accent, font=font_badge)

    # --- Bottom section (y=430-560) ---
    font_body = _load_font("Regular", 15)

    if card_type == "reservation":
        # Dark box with claim command
        box_y = 440
        box_h = 60
        box_margin = 40
        box_bg = tuple(max(0, c - 10) for c in bg_rgb)
        box_bg_hex = f"#{box_bg[0]:02x}{box_bg[1]:02x}{box_bg[2]:02x}"
        draw.rounded_rectangle(
            [box_margin, box_y, _WIDTH - box_margin, box_y + box_h],
            radius=12,
            fill=box_bg_hex,
        )

        cmd = f"uam init --claim {agent_name}.vcf"
        font_cmd, cmd = _fit_text(draw, cmd, _WIDTH - box_margin * 2 - 40, "Bold", 14, min_size=10)
        cw, ch = _measure_text(draw, cmd, font_cmd)
        draw.text(
            ((_WIDTH - cw) // 2, box_y + (box_h - ch) // 2),
            cmd, fill="#a1a1aa", font=font_cmd,
        )

        # Expiry
        if expires_at:
            exp_text = f"Expires: {expires_at}"
            font_exp, exp_text = _fit_text(draw, exp_text, 520, "Regular", 13, min_size=10)
            ew, _ = _measure_text(draw, exp_text, font_exp)
            draw.text(((_WIDTH - ew) // 2, box_y + box_h + 15), exp_text, fill="#555555", font=font_exp)

    elif card_type == "identity":
        # "Get your own:" label
        label = "Get your own:"
        lw, _ = _measure_text(draw, label, font_body)
        draw.text(((_WIDTH - lw) // 2, 440), label, fill="#aaaaaa", font=font_body)

        # Viral command
        cmd = f"curl {relay_domain}/new | sh"
        font_cmd, cmd = _fit_text(draw, cmd, 520, "Bold", 16, min_size=12)
        cw, _ = _measure_text(draw, cmd, font_cmd)
        draw.text(((_WIDTH - cw) // 2, 470), cmd, fill="#ffffff", font=font_cmd)

        # Fingerprint
        if fingerprint:
            fp_display = f"fp: {fingerprint[:16]}..." if len(fingerprint) > 16 else f"fp: {fingerprint}"
            font_fp, fp_display = _fit_text(draw, fp_display, 520, "Regular", 13, min_size=10)
            fw, _ = _measure_text(draw, fp_display, font_fp)
            draw.text(((_WIDTH - fw) // 2, 505), fp_display, fill="#888888", font=font_fp)

    # --- Footer (y=570-595): relay domain small muted ---
    footer_text = relay_domain
    font_footer = _load_font("Regular", 12)
    ftw, _ = _measure_text(draw, footer_text, font_footer)
    draw.text(((_WIDTH - ftw) // 2, 575), footer_text, fill="#3f3f46", font=font_footer)

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
