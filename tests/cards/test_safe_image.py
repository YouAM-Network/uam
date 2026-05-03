"""T5.3 — safe_image_open + _paste_avatar hardening (Wave 0, failing-by-design).

Tests will RED until Plan 45-05 lands:
  - ``src/uam/cards/safe_image.py`` exposing:
      * ``safe_image_open(data: bytes, max_bytes: int = 256_000) -> Image``
        — validates size cap, format allowlist (PNG/JPEG only), and lets
        Pillow's ``DecompressionBombError`` raise on >MAX_IMAGE_PIXELS.
      * ``UnsupportedImageFormatError`` exception class
      * ``ImageTooLargeError`` exception class
      * Sets ``Image.MAX_IMAGE_PIXELS = 4_000_000`` at import time.
  - ``src/uam/cards/image.py::_paste_avatar`` swaps the raw ``Image.open``
    callsite for ``safe_image_open`` and falls through silently on raise
    (the surrounding code path renders the letter-circle fallback).

Per RESEARCH § Pattern 4 the goal is defense-in-depth against malicious
avatar bytes: a bombed PNG (huge declared dimensions) that decodes to GBs
of pixels, a TIFF / GIF / WEBP with parser bugs, or a multi-MB upload that
OOMs the renderer.  The triple-check (size, format, decompression bomb) is
applied at the ONE callsite that touches untrusted bytes.
"""

from __future__ import annotations

import io

import pytest
from PIL import Image
from PIL.Image import DecompressionBombError


# ---------------------------------------------------------------------------
# Module-level: Image.MAX_IMAGE_PIXELS must be capped on import
# ---------------------------------------------------------------------------


def test_max_image_pixels_set():
    """Importing ``uam.cards.safe_image`` sets ``Image.MAX_IMAGE_PIXELS = 4_000_000``.

    Pillow's default is 178956970 (~178MP) — far too high for a 600x600
    avatar pipeline.  Capping at 4MP (= 2000x2000) lets DecompressionBombError
    fire on attempts to decode anything bigger.
    """
    from uam.cards import safe_image  # type: ignore[import-not-found]  # noqa: F401
    assert Image.MAX_IMAGE_PIXELS == 4_000_000, (
        f"Image.MAX_IMAGE_PIXELS = {Image.MAX_IMAGE_PIXELS}; expected 4_000_000 "
        "after importing uam.cards.safe_image"
    )


# ---------------------------------------------------------------------------
# safe_image_open — size cap
# ---------------------------------------------------------------------------


def test_oversize_rejected():
    """``safe_image_open`` raises ``ImageTooLargeError`` for bytes > max_bytes.

    Default cap is 256KB; 257KB of zeros must reject before Pillow even
    starts parsing (cheap upfront check).
    """
    from uam.cards.safe_image import safe_image_open, ImageTooLargeError  # type: ignore[import-not-found]
    big = b"\x00" * (256 * 1024 + 1)
    with pytest.raises(ImageTooLargeError):
        safe_image_open(big)


# ---------------------------------------------------------------------------
# safe_image_open — format allowlist
# ---------------------------------------------------------------------------


def test_tiff_rejected():
    """``safe_image_open`` raises ``UnsupportedImageFormatError`` for TIFF.

    TIFF is not in the PNG/JPEG allowlist — the format has had multiple CVE
    parser bugs over the years and we never serve TIFF avatars.
    """
    from uam.cards.safe_image import (  # type: ignore[import-not-found]
        safe_image_open,
        UnsupportedImageFormatError,
    )
    img = Image.new("RGB", (10, 10), color="red")
    buf = io.BytesIO()
    img.save(buf, format="TIFF")
    tiff_bytes = buf.getvalue()
    with pytest.raises(UnsupportedImageFormatError):
        safe_image_open(tiff_bytes)


def test_gif_rejected():
    """``safe_image_open`` raises ``UnsupportedImageFormatError`` for GIF.

    GIF is animated by default; even single-frame GIFs aren't in the
    PNG/JPEG allowlist for avatars.
    """
    from uam.cards.safe_image import (  # type: ignore[import-not-found]
        safe_image_open,
        UnsupportedImageFormatError,
    )
    img = Image.new("RGB", (10, 10), color="green")
    buf = io.BytesIO()
    img.save(buf, format="GIF")
    with pytest.raises(UnsupportedImageFormatError):
        safe_image_open(buf.getvalue())


# ---------------------------------------------------------------------------
# safe_image_open — decompression bomb
# ---------------------------------------------------------------------------


def test_decompression_bomb_rejected():
    """``safe_image_open`` raises ``DecompressionBombError`` on >4MP images.

    Build a 2500x2000 = 5MP PNG.  The PNG file itself is small (~10KB —
    flat color compresses well), so the size cap doesn't catch it.  But the
    pixel-count exceeds MAX_IMAGE_PIXELS (4MP cap), so Pillow raises
    DecompressionBombError on im.load() / im.copy().
    """
    from uam.cards.safe_image import safe_image_open  # type: ignore[import-not-found]
    img = Image.new("RGB", (2500, 2000), color="blue")  # 5MP > 4MP cap
    buf = io.BytesIO()
    img.save(buf, format="PNG", optimize=True)
    bomb_bytes = buf.getvalue()
    # The PNG itself is small (~10KB) so size cap doesn't trigger; allow
    # generous max_bytes so the test exercises the pixel-count check, not
    # the byte-count check.
    with pytest.raises((DecompressionBombError, ValueError)):
        safe_image_open(bomb_bytes, max_bytes=2 * 1024 * 1024)


# ---------------------------------------------------------------------------
# safe_image_open — happy path
# ---------------------------------------------------------------------------


def test_valid_inputs_accepted():
    """``safe_image_open`` accepts legitimate small PNG and JPEG."""
    from uam.cards.safe_image import safe_image_open  # type: ignore[import-not-found]

    # Valid PNG (200x200 = 40K pixels — well under 4MP cap)
    png_buf = io.BytesIO()
    Image.new("RGBA", (200, 200), color=(255, 0, 0, 255)).save(png_buf, format="PNG")
    img1 = safe_image_open(png_buf.getvalue())
    assert img1.size == (200, 200)

    # Valid JPEG (600x600 = 360K pixels)
    jpg_buf = io.BytesIO()
    Image.new("RGB", (600, 600), color=(0, 255, 0)).save(jpg_buf, format="JPEG")
    img2 = safe_image_open(jpg_buf.getvalue(), max_bytes=512 * 1024)
    assert img2.size == (600, 600)


# ---------------------------------------------------------------------------
# _paste_avatar integration — silently fall through on rejection
# ---------------------------------------------------------------------------


def test_paste_avatar_falls_back():
    """``_paste_avatar`` does NOT crash on rejected avatar bytes — the card
    render proceeds (the letter-circle fallback runs elsewhere in the
    pipeline) and the canvas is left unchanged at the avatar position.

    Today (Wave 0): ``_paste_avatar`` already wraps the Image.open call in a
    bare ``try/except: pass``, so this test passes for the wrong reason —
    Pillow's exceptions are swallowed but a bombed PNG that gets past
    Image.open() into resize() can still OOM the process.  Plan 45-05's
    safe_image_open closes that gap by validating BEFORE Pillow starts
    decoding.

    The contract this test pins: bad bytes do not raise OUT of _paste_avatar.
    """
    from uam.cards import image as image_module
    canvas = Image.new("RGB", (600, 600), color="white")

    bad_bytes = b"this is not an image"
    # Should not raise:
    image_module._paste_avatar(canvas, bad_bytes)
    # Center pixel is still white (avatar would have been pasted at y=80,
    # so position (300, 400) is below the avatar zone — but (300, 100) is
    # IN the avatar zone and should remain white because nothing was pasted).
    assert canvas.getpixel((300, 100)) == (255, 255, 255), (
        "canvas mutated despite _paste_avatar receiving invalid bytes"
    )


def test_paste_avatar_uses_safe_image_open():
    """``_paste_avatar`` must call ``safe_image_open`` (not raw ``Image.open``).

    Plan 45-05 contract: the raw ``Image.open(io.BytesIO(avatar_bytes))`` line
    in image.py:107 gets replaced with
    ``safe_image_open(avatar_bytes)`` so size/format/bomb checks fire before
    any decoding work.
    """
    import inspect
    from uam.cards import image as image_module
    src = inspect.getsource(image_module._paste_avatar)
    assert "safe_image_open" in src, (
        "_paste_avatar still uses raw Image.open — T5.3 not closed"
    )
    # Defense in depth: the raw Image.open call must be GONE from _paste_avatar.
    # (Other callsites in image.py for Image.new etc. are fine.)
    assert "Image.open(" not in src, (
        "_paste_avatar still has a raw Image.open call; replace with safe_image_open"
    )
