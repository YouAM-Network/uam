"""Background thread event loop for sync wrappers (SDK-04).

Provides _run_sync() which bridges async coroutines into synchronous
calling contexts without "event loop already running" errors.

Two strategies:
  - No event loop running: uses asyncio.run() (simplest path)
  - Event loop already running (Jupyter, etc.): dispatches to a
    background daemon thread with its own event loop
"""

from __future__ import annotations

import asyncio
import threading
from typing import Coroutine, TypeVar

T = TypeVar("T")

_loop: asyncio.AbstractEventLoop | None = None
_thread: threading.Thread | None = None
_lock = threading.Lock()


def _get_loop() -> asyncio.AbstractEventLoop:
    """Get or create a background event loop running in a daemon thread."""
    global _loop, _thread
    with _lock:
        if _loop is None or _loop.is_closed():
            _loop = asyncio.new_event_loop()
            _thread = threading.Thread(target=_loop.run_forever, daemon=True)
            _thread.start()
    return _loop


def _run_sync(coro: Coroutine[..., ..., T]) -> T:
    """Run an async coroutine from synchronous code.

    If no event loop is running, uses ``asyncio.run()``.
    If an event loop is already running (e.g., Jupyter), dispatches
    to a background daemon thread via ``run_coroutine_threadsafe()``.
    """
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop is None:
        # No loop running -- simplest path
        return asyncio.run(coro)
    else:
        # Loop already running (Jupyter, etc.) -- use background thread
        bg_loop = _get_loop()
        future = asyncio.run_coroutine_threadsafe(coro, bg_loop)
        return future.result()
