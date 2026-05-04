"""Q10 — Landing security headers + demo-route gating (Phase 48 Wave 0).

RED on purpose until 48-09:
  - converts ``landing/next.config.js`` -> ``landing/next.config.mjs`` with
    a ``headers()`` function returning CSP / HSTS / X-Content-Type-Options /
    Referrer-Policy / Permissions-Policy
  - adds ``landing/middleware.ts`` that gates ``/api/demo/*`` routes by
    ``UAM_LANDING_ENV`` (refuses non-demo environments)
  - adds ``landing/Dockerfile`` that drops to a non-root USER

These are file-presence + content-grep assertions; no Node runtime needed.
"""

from __future__ import annotations

import pathlib

import pytest


# tests/landing/test_security_headers.py -> ../../landing/
LANDING = pathlib.Path(__file__).resolve().parents[2] / "landing"


def test_next_config_mjs_exists():
    assert (LANDING / "next.config.mjs").exists(), (
        "48-09 must convert landing/next.config.js -> landing/next.config.mjs"
    )


def test_next_config_declares_csp_header():
    cfg = (LANDING / "next.config.mjs").read_text()
    assert "Content-Security-Policy" in cfg
    assert "default-src 'self'" in cfg


def test_next_config_declares_hsts_header():
    cfg = (LANDING / "next.config.mjs").read_text()
    assert "Strict-Transport-Security" in cfg
    assert "max-age=" in cfg


def test_next_config_declares_x_content_type_options():
    cfg = (LANDING / "next.config.mjs").read_text()
    assert "X-Content-Type-Options" in cfg
    assert "nosniff" in cfg


def test_next_config_declares_referrer_policy():
    cfg = (LANDING / "next.config.mjs").read_text()
    assert "Referrer-Policy" in cfg


def test_next_config_declares_permissions_policy():
    cfg = (LANDING / "next.config.mjs").read_text()
    assert "Permissions-Policy" in cfg


def test_middleware_gates_demo_routes():
    mw = LANDING / "middleware.ts"
    assert mw.exists(), "48-09 must add landing/middleware.ts"
    src = mw.read_text()
    assert "/api/demo/" in src
    assert "UAM_LANDING_ENV" in src
    assert "demo" in src


def test_dockerfile_runs_as_non_root():
    df = LANDING / "Dockerfile"
    assert df.exists(), "48-09 must add landing/Dockerfile"
    src = df.read_text()
    assert "USER " in src
    # Must not be USER root or USER 0.
    assert "USER root" not in src
    assert "USER 0\n" not in src
