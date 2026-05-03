"""Safe Pillow image opening with size + format + decompression-bomb guards (T5.3 — Phase 45).

Pillow's default MAX_IMAGE_PIXELS is ~89MP; we tighten to 4MP since our use case
is at most 600x600 cards = 360k pixels. 4MP gives ~10x headroom. Doubling this
triggers DecompressionBombError instead of just a warning.

Format whitelist rationale: the avatar pipeline produces PNG (CairoSVG → PNG)
or JPEG (uploaded card.jpg); TIFF/WEBP/GIF/EPS/BLP have ongoing CVE histories
(CVE-2023-50447 ImageMath, CVE-2023-4863 libwebp, multiple TIFF parser CVEs)
and are NEVER expected from the legitimate pipeline.

Anti-pattern (do NOT do):
  - try: Image.open(bytes); .load(); except Exception: pass  # malloc happens before exception
  - Image.open(bytes) without max_bytes check  # huge attacker bytes consume memory

Future maintainers: if you need to decode untrusted image bytes ANYWHERE in
``src/uam/``, route them through ``safe_image_open`` here. A bare
``PIL.Image.open(...)`` call on attacker-controlled data is a security bug
(see REVIEW-periphery.md CRIT-1 / Phase 45 T5.3).

References:
  - REVIEW-periphery.md CRIT-1
  - https://pillow.readthedocs.io/en/stable/reference/Image.html (MAX_IMAGE_PIXELS)
"""
from __future__ import annotations

import io

from PIL import Image

# Set BEFORE any Image.open is called in this process. Pillow respects
# changes to this attribute at runtime, but setting it at module import
# guarantees every code path that imports safe_image gets the tightened cap.
Image.MAX_IMAGE_PIXELS = 4_000_000


DEFAULT_MAX_BYTES = 256 * 1024  # 256 KB
DEFAULT_ALLOWED_FORMATS = ("PNG", "JPEG")


class UnsupportedImageFormatError(ValueError):
    """Raised when the input image's format is not in the allow-list."""


class ImageTooLargeError(ValueError):
    """Raised when the input bytes exceed the size cap."""


def safe_image_open(
    data: bytes,
    *,
    max_bytes: int = DEFAULT_MAX_BYTES,
    allowed_formats: tuple[str, ...] = DEFAULT_ALLOWED_FORMATS,
) -> Image.Image:
    """Decode an image with strict guards.

    Raises:
        ImageTooLargeError: if len(data) > max_bytes.
        UnsupportedImageFormatError: if the decoded format is not allowed.
        PIL.Image.DecompressionBombError: if the image has > MAX_IMAGE_PIXELS.

    Returns a copy of the decoded image so the caller can use it after the
    underlying file handle / buffer is released.
    """
    if len(data) > max_bytes:
        raise ImageTooLargeError(
            f"image bytes {len(data)} > max {max_bytes}"
        )
    with Image.open(io.BytesIO(data)) as im:
        im.load()  # force decode (raises DecompressionBombError if too big)
        if im.format not in allowed_formats:
            raise UnsupportedImageFormatError(
                f"format {im.format!r} not in {allowed_formats}"
            )
        # Defense-in-depth: explicit pixel-count check (covers cases where
        # MAX_IMAGE_PIXELS only triggers a Warning rather than an Error).
        if im.size[0] * im.size[1] > Image.MAX_IMAGE_PIXELS:
            from PIL.Image import DecompressionBombError
            raise DecompressionBombError(
                f"image dims {im.size} exceed MAX_IMAGE_PIXELS"
            )
        return im.copy()
