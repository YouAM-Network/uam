"""Version negotiation for the UAM wire protocol (Phase 48 Q4).

Policy:
- Reject unknown MAJOR versions (:class:`IncompatibleVersionError`).
- Permit unknown MINOR versions (forward-compat: callers should treat
  unknown fields as opaque pass-through).

Today only ``"0"`` is supported; when the codebase ships ``"1.0"``,
append ``"1"`` to :data:`SUPPORTED_MAJOR_VERSIONS` for the bridging
window then drop ``"0"``. See ``docs/FORWARD_COMPAT.md`` (added in
48-09) for the cutover policy.
"""

from __future__ import annotations

from uam.protocol.errors import IncompatibleVersionError, ValidationError

# Major versions this implementation accepts on the wire.
SUPPORTED_MAJOR_VERSIONS: tuple[str, ...] = ("0",)


def parse_version(version_str: str) -> tuple[str, str]:
    """Parse ``"MAJOR.MINOR"`` string.

    Raises:
        ValidationError: input is not a string, or shape is not exactly
            two non-empty dot-separated digit groups.
    """
    if not isinstance(version_str, str):
        raise ValidationError(
            f"version must be str, got {type(version_str).__name__}"
        )
    parts = version_str.split(".")
    if len(parts) != 2 or not all(p != "" and p.isdigit() for p in parts):
        raise ValidationError(f"invalid version shape: {version_str!r}")
    return parts[0], parts[1]


def check_version(version_str: str) -> None:
    """Reject unknown MAJOR. Permit unknown MINOR (forward-compat).

    Raises:
        IncompatibleVersionError: MAJOR not in
            :data:`SUPPORTED_MAJOR_VERSIONS`.
        ValidationError: bad version shape (delegated from
            :func:`parse_version`).
    """
    major, _minor = parse_version(version_str)
    if major not in SUPPORTED_MAJOR_VERSIONS:
        raise IncompatibleVersionError(version_str, SUPPORTED_MAJOR_VERSIONS)
    # Unknown MINOR is allowed — caller should treat unknown fields as opaque.
