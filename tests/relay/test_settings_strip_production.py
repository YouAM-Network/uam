"""Failing-by-design test for R-T6.5-01: _is_production() must .strip() before .lower().

Phase 46 review found that ``_is_production()`` does ``os.getenv(...).lower() ==
"production"`` — there is no ``.strip()`` call. An operator who sets
``UAM_ENV='production '`` (trailing whitespace, common copy-paste typo) ends up
in development mode silently while believing they are in production.

These tests use SUBPROCESS isolation because ``uam.relay.config`` caches
imported settings in-process; a clean subprocess gives a fresh import each
time so the env-var values are honored.
"""

from __future__ import annotations

import os
import subprocess
import sys


def _run_settings_in_subprocess(env: dict[str, str]) -> tuple[int, str]:
    """Instantiate Settings() in a clean subprocess with the given env."""
    code = (
        "import sys; sys.path.insert(0, 'src'); "
        "from uam.relay.config import Settings; "
        "s = Settings(); _ = s.token_pepper; print('OK', flush=True)"
    )
    clean_env = {k: v for k, v in os.environ.items() if not k.startswith("UAM_")}
    clean_env.update(env)
    clean_env["PYTHONPATH"] = os.pathsep.join([
        os.path.abspath("src"), clean_env.get("PYTHONPATH", "")
    ])
    result = subprocess.run(
        [sys.executable, "-c", code],
        env=clean_env, capture_output=True, text=True, timeout=10,
    )
    return result.returncode, result.stderr


def _baseline_required_env() -> dict[str, str]:
    """Just enough env to satisfy non-T6.5-related Settings constructor checks."""
    return {
        "UAM_TOKEN_PEPPER": "x" * 32,
        "UAM_RELAY_DOMAIN": "actual-prod.example.com",
        "UAM_CORS_ORIGINS": "https://app.example.com",
        # UAM_TRUSTED_PROXIES intentionally NOT set — used to trigger the prod gate
    }


class TestStripBeforeLower:
    """R-T6.5-01: trailing whitespace in UAM_ENV must NOT bypass production gate."""

    def test_trailing_space_triggers_production_gate(self):
        """UAM_ENV='production ' MUST be treated as production (currently bypassed)."""
        env = _baseline_required_env()
        env["UAM_ENV"] = "production "  # trailing space — operator typo
        rc, stderr = _run_settings_in_subprocess(env)
        assert rc != 0, (
            f"R-T6.5-01: UAM_ENV='production ' (trailing space) bypasses production gate. "
            f"Expected nonzero exit (missing UAM_TRUSTED_PROXIES); got 0. "
            f"Fix: change `_is_production()` to `.strip().lower() == 'production'`. "
            f"stderr={stderr}"
        )
        assert "UAM_TRUSTED_PROXIES" in stderr or "trusted_proxies" in stderr.lower()

    def test_leading_space_triggers_production_gate(self):
        """UAM_ENV=' production' MUST be treated as production."""
        env = _baseline_required_env()
        env["UAM_ENV"] = " production"  # leading space
        rc, stderr = _run_settings_in_subprocess(env)
        assert rc != 0, f"Leading-space bypass; stderr={stderr}"

    def test_tab_whitespace_triggers_production_gate(self):
        """UAM_ENV='production\\t' MUST be treated as production."""
        env = _baseline_required_env()
        env["UAM_ENV"] = "production\t"
        rc, stderr = _run_settings_in_subprocess(env)
        assert rc != 0, f"Tab-whitespace bypass; stderr={stderr}"

    def test_clean_production_still_triggers(self):
        """Control: UAM_ENV='production' (no whitespace) MUST fire the gate.

        This control test is GREEN at HEAD — confirms the gate works for the
        non-typo case. If this test fails, the production gate is ENTIRELY broken.
        """
        env = _baseline_required_env()
        env["UAM_ENV"] = "production"
        rc, stderr = _run_settings_in_subprocess(env)
        assert rc != 0, f"Production gate fundamentally broken; stderr={stderr}"

    def test_development_unaffected(self):
        """Control: UAM_ENV='development' (or unset) must remain lenient."""
        env = {"UAM_TOKEN_PEPPER": "x" * 32}  # only the strict-required field
        # No UAM_ENV at all -> defaults to development
        rc, stderr = _run_settings_in_subprocess(env)
        assert rc == 0, f"Development mode broken; stderr={stderr}"
