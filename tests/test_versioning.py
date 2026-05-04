"""Q4 — Version negotiation tests (Phase 48 Wave 0).

These tests are RED on purpose: they import from ``uam.protocol.versioning``,
a module that does not exist yet. Wave 1 (48-03) will create it with
``SUPPORTED_MAJOR_VERSIONS``, ``parse_version`` and ``check_version``.

Contract pinned here:
  - parse_version("M.m") returns (major: str, minor: str)
  - parse_version raises ValidationError on bad shape OR non-string
  - check_version accepts any minor for a supported major
  - check_version raises IncompatibleVersionError on unknown major and the
    exception carries .version + .supported
"""

from __future__ import annotations

import pytest


def test_supported_major_versions_includes_0():
    from uam.protocol.versioning import SUPPORTED_MAJOR_VERSIONS  # NEW in Wave 1
    assert "0" in SUPPORTED_MAJOR_VERSIONS


def test_parse_version_returns_major_minor_strings():
    from uam.protocol.versioning import parse_version  # NEW in Wave 1
    assert parse_version("0.1") == ("0", "1")
    assert parse_version("1.42") == ("1", "42")


@pytest.mark.parametrize("bad", ["", "1", "1.2.3", "1.x", "abc", "0.", ".1"])
def test_parse_version_raises_validation_error_on_bad_shape(bad):
    from uam.protocol.errors import ValidationError  # NEW in Wave 1
    from uam.protocol.versioning import parse_version
    with pytest.raises(ValidationError):
        parse_version(bad)


def test_parse_version_raises_validation_error_on_non_string():
    from uam.protocol.errors import ValidationError
    from uam.protocol.versioning import parse_version
    with pytest.raises(ValidationError):
        parse_version(0.1)  # type: ignore[arg-type]


def test_check_version_accepts_supported_major():
    from uam.protocol.versioning import check_version  # NEW in Wave 1
    check_version("0.1")   # current UAM_VERSION
    check_version("0.99")  # unknown MINOR is permissive


def test_check_version_rejects_unknown_major():
    from uam.protocol.errors import IncompatibleVersionError  # NEW in Wave 1
    from uam.protocol.versioning import check_version
    with pytest.raises(IncompatibleVersionError):
        check_version("1.0")
    with pytest.raises(IncompatibleVersionError):
        check_version("99.0")


def test_check_version_includes_supported_in_exception():
    from uam.protocol.errors import IncompatibleVersionError
    from uam.protocol.versioning import SUPPORTED_MAJOR_VERSIONS, check_version
    with pytest.raises(IncompatibleVersionError) as ei:
        check_version("99.0")
    exc = ei.value
    assert exc.version == "99.0"
    assert exc.supported == SUPPORTED_MAJOR_VERSIONS
