"""Central FastAPI exception handler for UAMError hierarchy (Phase 48 Q1).

Maps every UAMError subclass to a consistent (status_code, error_code) pair.
Walks MRO so subclasses inherit their parent's mapping.

Response envelope: ``{"error": <code>, "detail": <message>, "request_id": <id>}``.

Until 48-05 (Q6) ships ``request_id_var``, ``_safe_get_request_id`` falls
back to a freshly generated UUID4 so the envelope shape stays consistent.
Once 48-05 lands, the contextvar takes precedence (set by RequestIDMiddleware).

Usage:
    from uam.relay.exception_handlers import register_uam_handler
    register_uam_handler(app)

Threat model (T-48-01-02): handler returns ONLY {error, detail, request_id}.
NEVER raw tracebacks. Server-side logger emits exception details for diagnostics.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

from fastapi import FastAPI
from starlette.requests import Request
from starlette.responses import JSONResponse

from uam.protocol.errors import (
    ContactCardExpired,
    EnvelopeExpiredError,
    EnvelopeTooLargeError,
    IncompatibleVersionError,
    InvalidAddressError,
    InvalidContactCardError,
    InvalidEnvelopeError,
    KeyPinningError,
    ReplayDetected,
    SignatureVerificationError,
    UAMError,
    ValidationError,
)
from uam.relay.errors import (
    ConflictError,
    ForbiddenError,
    NotFoundError,
    RateLimitError,
)

logger = logging.getLogger(__name__)

# Mapping table — most specific first; MRO walk in _resolve_status will
# find the closest match. Order in this dict is insertion order (Py3.7+).
#
# IMPORTANT: when adding new mappings, place MORE specific subclasses
# BEFORE their parents so the MRO walk picks them up first.
_STATUS_MAP: dict[type[Exception], tuple[int, str]] = {
    # Specific 400 cases (subclasses of ValidationError / ProtocolError)
    ContactCardExpired: (400, "contact_card_expired"),
    IncompatibleVersionError: (400, "incompatible_version"),
    EnvelopeTooLargeError: (413, "envelope_too_large"),
    InvalidContactCardError: (400, "invalid_contact_card"),
    InvalidAddressError: (400, "invalid_address"),
    InvalidEnvelopeError: (400, "invalid_envelope"),
    EnvelopeExpiredError: (400, "envelope_expired"),
    # ValidationError catches the broad case (parent of ContactCardExpired)
    ValidationError: (400, "validation_error"),
    # Auth / signature
    SignatureVerificationError: (401, "signature_invalid"),
    KeyPinningError: (401, "key_pinning_violation"),
    # Replay -> conflict
    ReplayDetected: (409, "replay_detected"),
    # Relay-side
    ForbiddenError: (403, "forbidden"),
    NotFoundError: (404, "not_found"),
    ConflictError: (409, "conflict"),
    RateLimitError: (429, "rate_limit"),
}


def _resolve_status(exc: UAMError) -> tuple[int, str]:
    """Walk the exception's MRO to find the closest mapped (status, code).

    Returns ``(500, "internal_error")`` for unmapped UAMError subclasses
    (T-48-01-04: catch-all does not leak class name).
    """
    for cls in type(exc).__mro__:
        if cls in _STATUS_MAP:
            return _STATUS_MAP[cls]
    return (500, "internal_error")


def _safe_get_request_id() -> Any:
    """Read request_id contextvar if available; tolerant of import-order
    cycles.

    48-05 (Q6) introduces ``uam.relay.logging_config.request_id_var`` and
    the RequestIDMiddleware that sets it per-request. Until then, this
    function returns a freshly generated UUID4 so the response envelope
    stays consistent. Once 48-05 ships, the contextvar takes precedence
    (the middleware sets it before the handler reads it).
    """
    try:
        from uam.relay.logging_config import request_id_var  # noqa: WPS433
        rid = request_id_var.get()
        if rid:
            return rid
    except Exception:
        pass
    # Fallback: synthesise an id so the envelope shape is stable even
    # before 48-05 wires the contextvar middleware.
    return str(uuid.uuid4())


def register_uam_handler(app: FastAPI) -> None:
    """Register the central UAMError handler on a FastAPI app.

    Idempotent: re-registering on the same app is harmless (FastAPI just
    replaces the prior handler for the same exception type).

    Coexists with the existing ``http_exception_handler`` and
    ``validation_exception_handler`` because Starlette's ``HTTPException``
    and Pydantic's ``RequestValidationError`` are NOT ``UAMError``
    subclasses — there is no overlap.
    """

    @app.exception_handler(UAMError)
    async def _handle_uam_error(request: Request, exc: UAMError) -> JSONResponse:
        status, code = _resolve_status(exc)
        # Log at WARNING for 4xx, ERROR (with traceback) for 5xx.
        if status >= 500:
            logger.exception("UAMError -> %d %s: %s", status, code, exc)
        else:
            logger.warning("UAMError -> %d %s: %s", status, code, exc)
        return JSONResponse(
            status_code=status,
            content={
                "error": code,
                "detail": str(exc),
                "request_id": _safe_get_request_id(),
            },
        )
