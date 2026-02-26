"""Tests for uam.cards.vcard -- vCard 3.0 generation and RFC 2426 line folding."""

from __future__ import annotations

import base64
import io
import re

import pytest
from PIL import Image

from uam.cards.vcard import (
    fold_line,
    fold_base64,
    generate_reservation_vcard,
    generate_identity_vcard,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def tiny_jpeg():
    """Create a minimal JPEG for testing (avoids HTTP calls for avatar)."""
    img = Image.new("RGB", (10, 10), (100, 150, 200))
    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=50)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Line folding tests
# ---------------------------------------------------------------------------


class TestFoldLine:
    def test_fold_line_short_line_unchanged(self):
        """Lines under 75 chars pass through with just CRLF appended."""
        short = "FN:scout (youam.network)"
        result = fold_line(short)
        assert result == short + "\r\n"

    def test_fold_line_exactly_75_chars(self):
        """Line of exactly 75 chars is not folded."""
        line = "X" * 75
        result = fold_line(line)
        assert result == line + "\r\n"
        # Should be a single line (no continuation)
        assert result.count("\r\n") == 1

    def test_fold_line_76_chars_folds(self):
        """Line of 76 chars is folded into two lines."""
        line = "X" * 76
        result = fold_line(line)
        parts = result.split("\r\n")
        # Two content lines + empty trailing element from split
        assert len(parts) == 3
        assert parts[2] == ""  # trailing after final CRLF
        assert len(parts[0].encode("utf-8")) == 75
        assert parts[1].startswith(" ")

    def test_fold_line_long_line_multi_fold(self):
        """200-char line folds into multiple continuation lines, each <= 75 bytes."""
        line = "X" * 200
        result = fold_line(line)
        parts = result.split("\r\n")
        for i, part in enumerate(parts):
            if part:  # skip empty trailing
                assert len(part.encode("utf-8")) <= 75, (
                    f"Line {i} is {len(part.encode('utf-8'))} bytes: {part[:40]}..."
                )

    def test_fold_line_crlf_endings(self):
        """Output uses CRLF line endings."""
        result = fold_line("X" * 200)
        assert "\r\n" in result
        # No bare \n that isn't preceded by \r
        bare_lf = re.findall(r"(?<!\r)\n", result)
        assert len(bare_lf) == 0

    def test_fold_line_continuation_starts_with_space(self):
        """Continuation lines start with exactly one space."""
        result = fold_line("Y" * 160)
        parts = result.split("\r\n")
        for part in parts[1:]:
            if part:  # skip empty trailing
                assert part[0] == " ", f"Continuation line doesn't start with space: {part[:20]}"
                assert part[1] != " ", f"Continuation line has extra space: {part[:20]}"


class TestFoldBase64:
    def test_fold_base64_first_line_length(self):
        """First line is exactly 75 chars (prefix + data)."""
        prefix = "PHOTO;ENCODING=b;TYPE=JPEG:"
        data = "A" * 300
        result = fold_base64(prefix, data)
        first_line = result.split("\r\n")[0]
        assert len(first_line) == 75

    def test_fold_base64_continuation_lines(self):
        """All continuation lines are SPACE + 74 chars = 75 total."""
        prefix = "PHOTO;ENCODING=b;TYPE=JPEG:"
        data = "B" * 500
        result = fold_base64(prefix, data)
        parts = result.split("\r\n")
        for i, part in enumerate(parts):
            if part and i > 0:  # skip first line and trailing empty
                assert part.startswith(" ")
                assert len(part) <= 75


# ---------------------------------------------------------------------------
# Reservation vCard tests
# ---------------------------------------------------------------------------


class TestReservationVCard:
    def test_reservation_vcard_contains_required_fields(self, tiny_jpeg):
        """All required vCard fields are present."""
        vcf = generate_reservation_vcard(
            "scout", "youam.network", "tok123",
            card_image_jpeg=tiny_jpeg,
        )
        required = [
            "BEGIN:VCARD",
            "VERSION:3.0",
            "END:VCARD",
            "FN:",
            "N:",
            "ORG:",
            "TITLE:",
            "NOTE:",
            "URL:",
            "X-UAM-ADDRESS:",
            "X-UAM-CLAIM-TOKEN:",
            "X-UAM-RELAY:",
            "X-UAM-CARD-TYPE:reservation",
            "PHOTO;ENCODING=b;TYPE=JPEG:",
            "UID:",
            "REV:",
            "PRODID:",
        ]
        for field in required:
            assert field in vcf, f"Missing required field: {field}"

    def test_reservation_vcard_fn_contains_reserved(self, tiny_jpeg):
        """FN field contains 'Reserved' marker."""
        vcf = generate_reservation_vcard(
            "scout", "youam.network", "tok123",
            card_image_jpeg=tiny_jpeg,
        )
        assert "Reserved" in vcf

    def test_reservation_vcard_title_contains_reserved(self, tiny_jpeg):
        """TITLE field contains 'Reserved' marker."""
        vcf = generate_reservation_vcard(
            "scout", "youam.network", "tok123",
            card_image_jpeg=tiny_jpeg,
        )
        assert "TITLE:UAM Agent -- Reserved" in vcf

    def test_reservation_vcard_claim_token_in_x_field(self, tiny_jpeg):
        """X-UAM-CLAIM-TOKEN carries the exact token value."""
        token = "secret-claim-token-xyz"
        vcf = generate_reservation_vcard(
            "scout", "youam.network", token,
            card_image_jpeg=tiny_jpeg,
        )
        assert f"X-UAM-CLAIM-TOKEN:{token}" in vcf

    def test_reservation_vcard_note_contains_instructions(self, tiny_jpeg):
        """NOTE contains claim instructions and the claim token."""
        token = "my-token-456"
        vcf = generate_reservation_vcard(
            "scout", "youam.network", token,
            card_image_jpeg=tiny_jpeg,
        )
        assert "uam init --claim" in vcf
        assert token in vcf

    def test_reservation_vcard_all_lines_max_75_bytes(self, tiny_jpeg):
        """Every line in the output is <= 75 bytes (UTF-8 encoded)."""
        vcf = generate_reservation_vcard(
            "scout", "youam.network", "tok123",
            card_image_jpeg=tiny_jpeg,
        )
        for i, line in enumerate(vcf.split("\r\n")):
            byte_len = len(line.encode("utf-8"))
            assert byte_len <= 75, (
                f"Line {i} is {byte_len} bytes: {line[:50]}..."
            )

    def test_reservation_vcard_crlf_line_endings(self, tiny_jpeg):
        """CRLF is used throughout. No bare LF without preceding CR."""
        vcf = generate_reservation_vcard(
            "scout", "youam.network", "tok123",
            card_image_jpeg=tiny_jpeg,
        )
        assert "\r\n" in vcf
        bare_lf = re.findall(r"(?<!\r)\n", vcf)
        assert len(bare_lf) == 0, f"Found {len(bare_lf)} bare LF characters"


# ---------------------------------------------------------------------------
# Identity vCard tests
# ---------------------------------------------------------------------------


class TestIdentityVCard:
    def test_identity_vcard_contains_required_fields(self, tiny_jpeg):
        """All required identity vCard fields are present."""
        vcf = generate_identity_vcard(
            "scout", "youam.network",
            fingerprint="abc123",
            card_image_jpeg=tiny_jpeg,
        )
        required = [
            "BEGIN:VCARD",
            "VERSION:3.0",
            "END:VCARD",
            "FN:",
            "N:",
            "ORG:",
            "TITLE:UAM Agent",
            "NOTE:",
            "URL:",
            "X-UAM-ADDRESS:",
            "X-UAM-RELAY:",
            "X-UAM-FINGERPRINT:",
            "X-UAM-PUBLIC-KEY:",
            "X-UAM-SIGNUP:",
            "X-UAM-CARD-TYPE:identity",
            "PHOTO;ENCODING=b;TYPE=JPEG:",
            "UID:",
            "REV:",
            "PRODID:",
        ]
        for field in required:
            assert field in vcf, f"Missing required field: {field}"

    def test_identity_vcard_title_not_reserved(self, tiny_jpeg):
        """TITLE is 'UAM Agent' (no 'Reserved')."""
        vcf = generate_identity_vcard(
            "scout", "youam.network",
            card_image_jpeg=tiny_jpeg,
        )
        # Check exact title line is present
        assert "TITLE:UAM Agent\r\n" in vcf

    def test_identity_vcard_note_contains_viral_command(self, tiny_jpeg):
        """NOTE contains curl viral signup command with relay domain."""
        vcf = generate_identity_vcard(
            "scout", "youam.network",
            card_image_jpeg=tiny_jpeg,
        )
        assert "curl" in vcf
        assert "youam.network" in vcf
        assert "/new" in vcf

    def test_identity_vcard_signup_url(self, tiny_jpeg):
        """X-UAM-SIGNUP contains the relay domain."""
        vcf = generate_identity_vcard(
            "scout", "youam.network",
            card_image_jpeg=tiny_jpeg,
        )
        assert "X-UAM-SIGNUP:https://youam.network/new" in vcf

    def test_identity_vcard_fingerprint_in_output(self, tiny_jpeg):
        """X-UAM-FINGERPRINT carries the fingerprint value."""
        vcf = generate_identity_vcard(
            "scout", "youam.network",
            fingerprint="deadbeef1234",
            card_image_jpeg=tiny_jpeg,
        )
        assert "X-UAM-FINGERPRINT:deadbeef1234" in vcf

    def test_identity_vcard_all_lines_max_75_bytes(self, tiny_jpeg):
        """Every line is <= 75 bytes."""
        vcf = generate_identity_vcard(
            "scout", "youam.network",
            fingerprint="abc123",
            public_key_b64="c29tZWtleWRhdGE=",
            card_image_jpeg=tiny_jpeg,
        )
        for i, line in enumerate(vcf.split("\r\n")):
            byte_len = len(line.encode("utf-8"))
            assert byte_len <= 75, (
                f"Line {i} is {byte_len} bytes: {line[:50]}..."
            )

    def test_identity_vcard_crlf_line_endings(self, tiny_jpeg):
        """CRLF throughout, no bare LF."""
        vcf = generate_identity_vcard(
            "scout", "youam.network",
            card_image_jpeg=tiny_jpeg,
        )
        assert "\r\n" in vcf
        bare_lf = re.findall(r"(?<!\r)\n", vcf)
        assert len(bare_lf) == 0


# ---------------------------------------------------------------------------
# PHOTO embedding tests
# ---------------------------------------------------------------------------


class TestPhotoEmbedding:
    def test_photo_base64_is_valid(self, tiny_jpeg):
        """PHOTO base64 data decodes to a valid JPEG (starts with FF D8)."""
        vcf = generate_reservation_vcard(
            "scout", "youam.network", "tok",
            card_image_jpeg=tiny_jpeg,
        )
        # Extract PHOTO data: find the PHOTO line and unfold continuations
        lines = vcf.split("\r\n")
        photo_idx = None
        for i, line in enumerate(lines):
            if line.startswith("PHOTO;"):
                photo_idx = i
                break
        assert photo_idx is not None, "PHOTO property not found"

        # Get the base64 data from the first PHOTO line (after the colon)
        b64_data = lines[photo_idx].split(":", 1)[1]

        # Collect continuation lines
        j = photo_idx + 1
        while j < len(lines) and lines[j].startswith(" "):
            b64_data += lines[j][1:]  # strip leading space
            j += 1

        # Decode and verify JPEG magic bytes
        raw = base64.b64decode(b64_data)
        assert raw[:2] == b"\xff\xd8", f"Not a valid JPEG: starts with {raw[:2].hex()}"

    def test_photo_folding_continuation_lines(self, tiny_jpeg):
        """PHOTO property spans multiple lines; continuations start with one space."""
        vcf = generate_reservation_vcard(
            "scout", "youam.network", "tok",
            card_image_jpeg=tiny_jpeg,
        )
        lines = vcf.split("\r\n")
        photo_idx = None
        for i, line in enumerate(lines):
            if line.startswith("PHOTO;"):
                photo_idx = i
                break
        assert photo_idx is not None

        # There must be continuation lines (JPEG base64 is always long)
        continuation_count = 0
        j = photo_idx + 1
        while j < len(lines) and lines[j].startswith(" "):
            # Each continuation starts with exactly one space
            assert lines[j][0] == " "
            if len(lines[j]) > 1:
                assert lines[j][1] != " ", "Extra leading space in continuation"
            continuation_count += 1
            j += 1

        assert continuation_count > 0, "PHOTO should have continuation lines for base64 data"

    def test_photo_roundtrip_identity(self, tiny_jpeg):
        """PHOTO roundtrip on identity vCard also produces valid JPEG."""
        vcf = generate_identity_vcard(
            "scout", "youam.network",
            card_image_jpeg=tiny_jpeg,
        )
        lines = vcf.split("\r\n")
        photo_idx = next(i for i, l in enumerate(lines) if l.startswith("PHOTO;"))
        b64_data = lines[photo_idx].split(":", 1)[1]
        j = photo_idx + 1
        while j < len(lines) and lines[j].startswith(" "):
            b64_data += lines[j][1:]
            j += 1
        raw = base64.b64decode(b64_data)
        assert raw[:2] == b"\xff\xd8"
        assert raw == tiny_jpeg, "Decoded PHOTO should match original JPEG bytes"
