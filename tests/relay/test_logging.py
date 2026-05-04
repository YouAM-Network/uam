"""Q6 — JSON log formatter (Phase 48 Wave 0).

RED on purpose until 48-05 creates ``uam.relay.logging_config`` with
``JSONFormatter`` + ``configure_logging`` + ``request_id_var`` (a
``contextvars.ContextVar``).
"""

from __future__ import annotations

import json
import logging

import pytest


def _import_logging_config():
    """Lazy import: keeps collection clean before Wave 1 (48-05) lands."""
    from uam.relay.logging_config import (  # NEW module
        JSONFormatter,
        configure_logging,
        request_id_var,
    )
    return JSONFormatter, configure_logging, request_id_var


def _make_record(level=logging.INFO, msg="hello %s", args=("world",), exc_info=None):
    return logging.LogRecord(
        name="uam.test",
        level=level,
        pathname=__file__,
        lineno=1,
        msg=msg,
        args=args,
        exc_info=exc_info,
    )


def test_json_formatter_emits_valid_json():
    JSONFormatter, _, _ = _import_logging_config()
    fmt = JSONFormatter()
    out = fmt.format(_make_record())
    parsed = json.loads(out)
    assert parsed["msg"] == "hello world"
    assert parsed["level"] == "INFO"
    assert parsed["logger"] == "uam.test"
    assert "ts" in parsed
    assert "request_id" in parsed  # may be None when no context


def test_json_formatter_includes_request_id_from_contextvar():
    JSONFormatter, _, request_id_var = _import_logging_config()
    token = request_id_var.set("test-rid-abc123")
    try:
        parsed = json.loads(JSONFormatter().format(_make_record()))
        assert parsed["request_id"] == "test-rid-abc123"
    finally:
        request_id_var.reset(token)


def test_configure_logging_json_attaches_json_handler(monkeypatch):
    JSONFormatter, configure_logging, _ = _import_logging_config()
    monkeypatch.setenv("UAM_LOG_FORMAT", "json")
    configure_logging()
    root = logging.getLogger()
    assert any(isinstance(h.formatter, JSONFormatter) for h in root.handlers)


def test_configure_logging_default_does_not_attach_json(monkeypatch):
    JSONFormatter, configure_logging, _ = _import_logging_config()
    monkeypatch.delenv("UAM_LOG_FORMAT", raising=False)
    configure_logging()
    root = logging.getLogger()
    # Plain mode is the default per RESEARCH OQ4.
    assert not any(isinstance(h.formatter, JSONFormatter) for h in root.handlers)


def test_json_formatter_serializes_exception():
    JSONFormatter, _, _ = _import_logging_config()
    try:
        raise ValueError("boom")
    except ValueError:
        import sys
        record = _make_record(level=logging.ERROR, msg="caught", args=(),
                              exc_info=sys.exc_info())
    parsed = json.loads(JSONFormatter().format(record))
    assert "exc" in parsed
    assert "ValueError" in parsed["exc"]
