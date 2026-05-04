"""Request-ID middleware (Phase 48 Q6 / 48-05).

Sets :data:`uam.relay.logging_config.request_id_var` per request so that:

- :class:`uam.relay.logging_config.JSONFormatter` populates the
  ``request_id`` field in log lines emitted during the request scope.
- The central UAMError handler from Phase 48 Q1
  (:func:`uam.relay.exception_handlers._safe_get_request_id`) returns the
  same id in the error envelope, providing client-server log correlation.

Sanitization: incoming ``X-Request-ID`` is matched against
:data:`uam.relay.logging_config._REQUEST_ID_PATTERN`
(``^[A-Za-z0-9-]{1,64}$``). Anything that fails is replaced with a freshly
generated UUIDv7. This is the T-48-05-01 mitigation against CRLF /
JSON-breaker / oversize log-injection attacks.

ContextVar lifecycle: ``set`` returns a token; ``reset(token)`` is called
in a ``finally`` block so the var never leaks across requests handled by
the same async task (T-48-05-03 mitigation).
"""
from __future__ import annotations

import logging

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from uam.relay.logging_config import _REQUEST_ID_PATTERN, request_id_var

logger = logging.getLogger(__name__)

try:
    from uuid6 import uuid7  # already in pyproject.toml (>=2025.0.1)

    def _gen_rid() -> str:
        return str(uuid7())

except ImportError:  # pragma: no cover — defensive; uuid6 is a hard dep.
    import uuid

    def _gen_rid() -> str:
        return str(uuid.uuid4())


class RequestIDMiddleware(BaseHTTPMiddleware):
    """Set ``request_id_var`` from incoming ``X-Request-ID`` or a fresh UUIDv7.

    Echoes the (sanitized or generated) value back as the response
    ``X-Request-ID`` header so clients can correlate against server logs.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        incoming = request.headers.get("X-Request-ID", "")
        if incoming and _REQUEST_ID_PATTERN.match(incoming):
            rid = incoming
        else:
            rid = _gen_rid()
        token = request_id_var.set(rid)
        try:
            response = await call_next(request)
            response.headers["X-Request-ID"] = rid
            return response
        finally:
            # CRITICAL — reset to avoid contextvar leak across requests
            # handled by the same async task (T-48-05-03).
            request_id_var.reset(token)
