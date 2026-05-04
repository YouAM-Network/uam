"""Q8 — CLI friendly_handler decorator + exit codes (Phase 48 Wave 0).

RED on purpose until 48-07 adds:
  - ``uam.cli.errors`` module with ``friendly_handler`` decorator and
    EXIT_USER_ERROR / EXIT_PROTOCOL_ERROR / EXIT_NETWORK_ERROR constants
  - ``--debug``, ``--json`` (or ``json_output``), ``--quiet`` options on the
    main CLI group in ``uam.cli.main``
"""

from __future__ import annotations

import pytest


def _import_cli_errors():
    """Lazy import: keeps collection clean before Wave 1 (48-07) lands."""
    from uam.cli.errors import (  # NEW module in 48-07
        friendly_handler,
        EXIT_USER_ERROR,
        EXIT_PROTOCOL_ERROR,
        EXIT_NETWORK_ERROR,
    )
    return friendly_handler, EXIT_USER_ERROR, EXIT_PROTOCOL_ERROR, EXIT_NETWORK_ERROR


def test_exit_codes_distinct():
    _, user, proto, net = _import_cli_errors()
    assert {user, proto, net} == {1, 2, 3}


def test_user_error_returns_exit_code_1():
    import click
    from click.testing import CliRunner
    friendly_handler, EXIT_USER_ERROR, _, _ = _import_cli_errors()
    from uam.protocol.errors import ValidationError  # NEW in Wave 1

    @click.command()
    @friendly_handler
    def _cmd(ctx):
        raise ValidationError("bad arg")

    runner = CliRunner()
    result = runner.invoke(_cmd, [], catch_exceptions=False, obj={"debug": False})
    assert result.exit_code == EXIT_USER_ERROR
    assert "bad arg" in result.output


def test_protocol_error_returns_exit_code_2():
    import click
    from click.testing import CliRunner
    friendly_handler, _, EXIT_PROTOCOL_ERROR, _ = _import_cli_errors()
    from uam.protocol.errors import SignatureVerificationError

    @click.command()
    @friendly_handler
    def _cmd(ctx):
        raise SignatureVerificationError("bad sig")

    runner = CliRunner()
    result = runner.invoke(_cmd, [], catch_exceptions=False, obj={"debug": False})
    assert result.exit_code == EXIT_PROTOCOL_ERROR


def test_network_error_returns_exit_code_3():
    import click
    from click.testing import CliRunner
    friendly_handler, _, _, EXIT_NETWORK_ERROR = _import_cli_errors()

    @click.command()
    @friendly_handler
    def _cmd(ctx):
        raise ConnectionError("dns fail")

    runner = CliRunner()
    result = runner.invoke(_cmd, [], catch_exceptions=False, obj={"debug": False})
    assert result.exit_code == EXIT_NETWORK_ERROR


def test_debug_flag_shows_traceback():
    import click
    from click.testing import CliRunner
    friendly_handler, _, _, _ = _import_cli_errors()
    from uam.protocol.errors import ValidationError

    @click.command()
    @friendly_handler
    def _cmd(ctx):
        raise ValidationError("bad")

    runner = CliRunner()
    result = runner.invoke(_cmd, [], catch_exceptions=False, obj={"debug": True})
    assert "Traceback" in result.output


def test_cli_group_has_debug_json_quiet_options():
    """Wave 1 must add --debug / --json / --quiet to the top-level group."""
    from uam.cli.main import cli
    param_names = {p.name for p in cli.params}
    assert "debug" in param_names
    # accept either --json (param name "json") or "json_output"
    assert "json_output" in param_names or "json" in param_names
    assert "quiet" in param_names
