"""Structured logging + request-ID contextvar (Phase 48 Q6).

Activated by ``UAM_LOG_FORMAT=json``. Default (env unset / any other value)
leaves logging behavior unchanged per RESEARCH OQ4 — opt-in JSON, not
opt-out, so existing operators keep their current plain-text logs.

``request_id_var`` is a module-level ``ContextVar`` read by:

- :class:`JSONFormatter` (this module) — populates the ``request_id`` field
  in every emitted JSON log line.
- :func:`uam.relay.exception_handlers._safe_get_request_id` (Phase 48 Q1) —
  populates the ``request_id`` field in error response envelopes. Q1 imports
  this lazily, so once Q6 ships the contextvar takes precedence over Q1's
  UUID4 fallback (the middleware sets it before the handler reads it).

Threat model (Phase 48-05 T-48-05-01): ``_REQUEST_ID_PATTERN`` is the
log-injection mitigation. Any value that does not match is replaced with a
freshly generated UUIDv7 by ``RequestIDMiddleware``.
"""
from __future__ import annotations

import json
import logging
import os
import re
from contextvars import ContextVar

# Sanitize against log-injection: ASCII alphanumeric + dash, max 64 chars.
# This rejects CRLF (\r, \n), control chars, JSON-breaking quotes, spaces,
# angle brackets, and oversized payloads. RFC 7239 / RFC 9110 do not
# constrain X-Request-ID syntax, so we pick a conservative whitelist.
_REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9-]{1,64}$")

# ContextVar — propagates across ``await`` boundaries and into
# ``asyncio.create_task`` children so background work logged inside a
# request scope still sees the originating request id.
request_id_var: ContextVar[str | None] = ContextVar("request_id", default=None)


class JSONFormatter(logging.Formatter):
    """Emit log records as single-line JSON with ``request_id`` from contextvar.

    Schema:
        ``{"ts", "level", "logger", "msg", "request_id", ["fields"], ["exc"]}``

    - ``ts`` is ISO-8601 with microseconds, UTC ``Z`` suffix.
    - ``request_id`` is ``None`` when the contextvar is unset (e.g. logs
      emitted from background tasks not spawned inside a request scope).
    - ``fields`` is included only when the LogRecord has an attached
      ``fields`` attribute (extra structured payload).
    - ``exc`` is included only when ``record.exc_info`` is set.
    """

    def format(self, record: logging.LogRecord) -> str:
        out: dict[str, object] = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S.%fZ"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
            "request_id": request_id_var.get(),
        }
        # Optional structured payload via ``logger.info("msg", extra={"fields": {...}})``.
        if hasattr(record, "fields"):
            out["fields"] = getattr(record, "fields")
        if record.exc_info:
            out["exc"] = self.formatException(record.exc_info)
        return json.dumps(out, separators=(",", ":"), default=str)


def configure_logging() -> None:
    """Configure root logger based on ``UAM_LOG_FORMAT`` env var.

    - ``UAM_LOG_FORMAT=json`` → attach a single ``StreamHandler`` with
      :class:`JSONFormatter` to the root logger (any prior JSONFormatter
      handler is removed first to avoid double-emission).
    - Any other value (including unset) → also strip any pre-existing
      JSONFormatter handler, then return without attaching a new one.
      Non-JSON handlers (e.g. the basicConfig stderr handler from
      ``create_app``) are left untouched, preserving existing plain-text
      log behaviour per RESEARCH OQ4 (backward-compat: opt-in JSON,
      not opt-out).

    Idempotent: calling twice in JSON mode produces ONE handler, not two
    (any prior JSONFormatter handler is removed before the new one is
    attached). In default mode, any pre-existing JSONFormatter handler is
    also removed so the function is symmetric — it owns the JSON-handler
    lifecycle regardless of mode (this also keeps the Wave 0 contract test
    isolation-clean when both modes run in the same process).
    """
    root = logging.getLogger()
    # Always strip any prior JSONFormatter handler so we own the lifecycle
    # symmetrically. Non-JSON handlers (e.g. the basicConfig stderr
    # handler from create_app) are left untouched.
    for h in list(root.handlers):
        if isinstance(h.formatter, JSONFormatter):
            root.removeHandler(h)

    fmt = os.environ.get("UAM_LOG_FORMAT", "").lower()
    if fmt != "json":
        return
    handler = logging.StreamHandler()
    handler.setFormatter(JSONFormatter())
    root.addHandler(handler)
