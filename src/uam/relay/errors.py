"""Relay-side error types as UAMError subclasses (Phase 48 Q1).

These are SERVER-driven errors (the relay decides the request is bad), as
opposed to PROTOCOL errors (the wire payload is malformed) which live in
``uam.protocol.errors``.

Note on Spoofing (T-48-01-05): routes that want to obscure resource
existence MUST raise ``NotFoundError`` unconditionally. ``ForbiddenError``
is only for principals known to lack the role; raising it implicitly
confirms the resource exists.
"""

from __future__ import annotations

from uam.protocol.errors import UAMError


class RelayError(UAMError):
    """Base for relay-side errors (server-driven, non-protocol)."""


class ForbiddenError(RelayError):
    """Authenticated principal lacks permission for the resource.

    Use only when the caller's identity is established and the role is
    insufficient. For unauthenticated requests, prefer raising
    ``HTTPException(401)`` from the route. For obscuring resource
    existence, prefer ``NotFoundError``.
    """


class NotFoundError(RelayError):
    """Resource not found (or hidden from this principal)."""


class ConflictError(RelayError):
    """Resource state conflicts with the request (e.g. already-claimed token)."""


class RateLimitError(RelayError):
    """Caller exceeded a rate-limit window."""
