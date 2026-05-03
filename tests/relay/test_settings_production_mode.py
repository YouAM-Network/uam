"""Failing-by-design production-mode required-secrets tests for ``relay/config.py`` (T6.5 Wave 0).

Today's ``Settings`` is hand-rolled with ``os.getenv(name, default)`` for every
field and a single ``_require("UAM_TOKEN_PEPPER")`` gate. There is no concept of
``UAM_ENV=production`` and no fail-fast for fields that MUST be set in prod
(trusted proxies, explicit relay domain, non-wildcard CORS, etc.).

These tests RED at HEAD because the production gate doesn't exist. They GREEN
after Plan 46-05 lands the pydantic-settings rewrite with:

  - ``UAM_ENV: Literal["development", "production"] = "development"``
  - ``model_validator(mode="after")`` that requires UAM_TRUSTED_PROXIES,
    UAM_RELAY_DOMAIN != default, and UAM_CORS_ORIGINS != "*" when env=="production"
  - ``model_config = ConfigDict(extra="forbid", env_prefix="UAM_")``

Anti-pattern guard (per 46-00-PLAN action notes):
  Tests MUST run Settings() in a SUBPROCESS with a clean env. Importing
  ``uam.relay.config`` in the same Python process as pytest caches the module —
  a second import sees the first env. Subprocess gives a clean import every time.
"""

from __future__ import annotations

import os
import subprocess
import sys

import pytest


def _run_settings_in_subprocess(env: dict[str, str]) -> tuple[int, str, str]:
    """Instantiate ``Settings()`` in a clean Python subprocess with *env*.

    Returns ``(returncode, stdout, stderr)``.
    """
    code = (
        "import sys; "
        "sys.path.insert(0, 'src'); "
        "from uam.relay.config import Settings; "
        "s = Settings(); "
        "_ = s.token_pepper; "  # force eager validation if lazy
        "print('OK', flush=True)"
    )
    # Strip ALL inherited UAM_* env so the subprocess sees only what we pass.
    clean_env: dict[str, str] = {
        k: v for k, v in os.environ.items() if not k.startswith("UAM_")
    }
    clean_env.update(env)
    # Make sure subprocess sees the package source.
    clean_env["PYTHONPATH"] = os.pathsep.join(
        [os.path.abspath("src"), clean_env.get("PYTHONPATH", "")]
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        env=clean_env,
        capture_output=True,
        text=True,
        timeout=15,
    )
    return result.returncode, result.stdout, result.stderr


# ---------------------------------------------------------------------------
# UAM_ENV=production required-secrets gate
# ---------------------------------------------------------------------------


class TestProductionMode:
    def test_production_requires_trusted_proxies(self):
        """UAM_ENV=production + missing UAM_TRUSTED_PROXIES -> nonzero exit.

        Today: PASSES (no gate). After 46-05: ValidationError with mention of
        trusted_proxies / UAM_TRUSTED_PROXIES.
        """
        env = {
            "UAM_ENV": "production",
            "UAM_TOKEN_PEPPER": "x" * 32,
            "UAM_RELAY_DOMAIN": "actual-prod.example.com",
            "UAM_CORS_ORIGINS": "https://app.example.com",
            # UAM_TRUSTED_PROXIES intentionally missing
        }
        rc, _stdout, stderr = _run_settings_in_subprocess(env)
        assert rc != 0, (
            f"Expected nonzero exit (missing UAM_TRUSTED_PROXIES in prod); "
            f"got 0. stderr={stderr!r}"
        )
        assert (
            "UAM_TRUSTED_PROXIES" in stderr
            or "trusted_proxies" in stderr.lower()
        ), f"Expected stderr to mention trusted_proxies; got: {stderr!r}"

    def test_production_refuses_cors_wildcard(self):
        """UAM_ENV=production + UAM_CORS_ORIGINS=* -> nonzero exit.

        Today: PASSES (cors='*' is the default in dev and not gated in prod).
        After 46-05: ValidationError mentioning cors or wildcard.
        """
        env = {
            "UAM_ENV": "production",
            "UAM_TOKEN_PEPPER": "x" * 32,
            "UAM_RELAY_DOMAIN": "actual-prod.example.com",
            "UAM_TRUSTED_PROXIES": "10.0.0.0/8",  # set explicitly
            "UAM_CORS_ORIGINS": "*",  # WILDCARD — must refuse in prod
        }
        rc, _stdout, stderr = _run_settings_in_subprocess(env)
        assert rc != 0, f"Expected refusal for CORS=*; got success. stderr={stderr!r}"
        assert (
            "cors" in stderr.lower()
            or "wildcard" in stderr.lower()
            or "*" in stderr
        ), f"Expected stderr to mention cors/wildcard; got: {stderr!r}"

    def test_production_requires_explicit_relay_domain(self):
        """UAM_ENV=production + default UAM_RELAY_DOMAIN -> nonzero exit.

        Default is "youam.network" — operators forking the project must set
        their own explicit value before going to production.
        """
        env = {
            "UAM_ENV": "production",
            "UAM_TOKEN_PEPPER": "x" * 32,
            "UAM_TRUSTED_PROXIES": "10.0.0.0/8",
            "UAM_CORS_ORIGINS": "https://app.example.com",
            # UAM_RELAY_DOMAIN missing -> defaults to "youam.network" -> must refuse
        }
        rc, _stdout, stderr = _run_settings_in_subprocess(env)
        assert rc != 0, (
            f"Expected refusal for default relay_domain in prod; got success. "
            f"stderr={stderr!r}"
        )
        assert (
            "relay_domain" in stderr.lower()
            or "UAM_RELAY_DOMAIN" in stderr
        ), f"Expected stderr to mention relay_domain; got: {stderr!r}"

    def test_development_mode_lenient(self):
        """UAM_ENV unset (default development) -> Settings() succeeds with only token_pepper."""
        env = {
            # No UAM_ENV -> defaults to "development"
            "UAM_TOKEN_PEPPER": "x" * 32,
        }
        rc, stdout, stderr = _run_settings_in_subprocess(env)
        assert rc == 0, (
            f"Expected success in development mode; got error. "
            f"stdout={stdout!r} stderr={stderr!r}"
        )
        assert "OK" in stdout


# ---------------------------------------------------------------------------
# extra='forbid' for unknown UAM_* env vars
# ---------------------------------------------------------------------------


class TestExtraForbid:
    @pytest.mark.xfail(
        reason=(
            "extra='forbid' for unknown UAM_* env vars requires the "
            "pydantic-settings.BaseSettings migration deferred to Phase 48 "
            "(per 46-RESEARCH OQ1). Plan 46-05 added the minimal UAM_ENV "
            "production gate to the existing hand-rolled Settings; full "
            "BaseSettings rewrite (which gives extra='forbid' for free) is "
            "Phase 48 territory."
        ),
        strict=True,
    )
    def test_unknown_uam_env_var_rejected(self):
        """UAM_THIS_IS_NOT_A_REAL_SETTING=foo -> nonzero exit.

        Catches typos like UAM_TOKN_PEPPER (missing E) silently shadowing the
        real UAM_TOKEN_PEPPER. After 46-05 the pydantic-settings rewrite uses
        ``extra='forbid'`` to reject any UAM_-prefixed env var that doesn't
        map to a declared field.

        XFAIL ACCEPTABLE NOTE: pydantic-settings env_prefix loads UAM_* into
        model fields by default, so 'forbid' may catch this. If 46-05 chooses
        a less strict approach (e.g. WARN instead of REFUSE), this test should
        be relaxed to assert a warning rather than a nonzero exit.
        """
        env = {
            "UAM_ENV": "development",
            "UAM_TOKEN_PEPPER": "x" * 32,
            "UAM_THIS_IS_NOT_A_REAL_SETTING": "oops",
        }
        rc, _stdout, stderr = _run_settings_in_subprocess(env)
        assert rc != 0, (
            f"Expected refusal for unknown UAM_THIS_IS_NOT_A_REAL_SETTING; got success. "
            f"stderr={stderr!r}"
        )
