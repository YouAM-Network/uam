"""Friendly error handling for CLI commands (Phase 48 Q8).

Exit code conventions:

- 0: success
- 1: user error (bad input, validation)
- 2: protocol error (signature, key pinning, other UAMError)
- 3: network error (connection, timeout)

Stable exit codes are a public contract — scripts and CI pipelines depend on
them. Subclasses of the mapped exception types inherit their parent's exit
code via ``isinstance`` matching, so future additions to the
:mod:`uam.protocol.errors` hierarchy do not need to update this module.

Usage::

    from uam.cli.errors import friendly_handler

    @cli.command()
    @friendly_handler
    def my_command(ctx):
        # ... command body ...
"""
from __future__ import annotations

import functools
import sys
import traceback

import click

from uam.protocol.errors import (
    InvalidAddressError,
    KeyPinningError,
    SignatureVerificationError,
    UAMError,
    ValidationError,
)

EXIT_SUCCESS = 0
EXIT_USER_ERROR = 1
EXIT_PROTOCOL_ERROR = 2
EXIT_NETWORK_ERROR = 3


def friendly_handler(fn):
    """Wrap a Click command body with friendly error handling.

    Honors ``--debug`` from ``ctx.obj["debug"]`` to print a full traceback in
    addition to the friendly one-line message. Without ``--debug`` only the
    one-line message reaches stderr (T-48-07-01: avoid leaking tracebacks to
    scripted callers by default).

    Exit codes:

    - 1 (``EXIT_USER_ERROR``): :class:`ValidationError`,
      :class:`InvalidAddressError`
    - 2 (``EXIT_PROTOCOL_ERROR``): :class:`SignatureVerificationError`,
      :class:`KeyPinningError`, any other :class:`UAMError`
    - 3 (``EXIT_NETWORK_ERROR``): :class:`ConnectionError`,
      :class:`TimeoutError`

    Unhandled exceptions still bubble — Click's default handler will show
    them. ``friendly_handler`` intentionally does NOT catch bare
    ``Exception`` so that bugs remain visible during development.
    """

    @functools.wraps(fn)
    @click.pass_context
    def wrapper(ctx, *args, **kwargs):
        debug = bool((ctx.obj or {}).get("debug", False))
        try:
            return fn(ctx, *args, **kwargs)
        except (ValidationError, InvalidAddressError) as exc:
            click.echo(f"Error: {exc}", err=True)
            if debug:
                traceback.print_exc()
            sys.exit(EXIT_USER_ERROR)
        except (SignatureVerificationError, KeyPinningError) as exc:
            click.echo(f"Error: {exc}", err=True)
            if debug:
                traceback.print_exc()
            sys.exit(EXIT_PROTOCOL_ERROR)
        except UAMError as exc:
            click.echo(f"Error: {exc}", err=True)
            if debug:
                traceback.print_exc()
            sys.exit(EXIT_PROTOCOL_ERROR)
        except (ConnectionError, TimeoutError) as exc:
            click.echo(f"Network error: {exc}", err=True)
            if debug:
                traceback.print_exc()
            sys.exit(EXIT_NETWORK_ERROR)

    return wrapper
