"""Failing-by-design test for R-T6.1-01: BodySize must enforce streaming cap when CL is forged.

Per Phase 46 REVIEW-phase46.md § T6.1 Bypass attempt 1: forged Content-Length=0
with a 5000-byte actual body bypasses the middleware-layer cap because
``if cl is None:`` short-circuits whenever ANY CL header is present.

This test uses raw ASGI dicts (NOT TestClient) because TestClient's HTTP adapter
sanitizes Content-Length to match actual body length, masking the bug.
"""

from __future__ import annotations

import pytest

from uam.relay.middleware.body_size import BodySizeLimitMiddleware


async def _echo_app(scope, receive, send):
    """Inner ASGI app — reads body, echoes total bytes."""
    if scope["type"] != "http":
        return
    total = 0
    while True:
        msg = await receive()
        if msg["type"] == "http.request":
            total += len(msg.get("body", b""))
            if not msg.get("more_body"):
                break
    body = f"got {total}".encode()
    await send({
        "type": "http.response.start", "status": 200,
        "headers": [(b"content-type", b"text/plain"),
                    (b"content-length", str(len(body)).encode())],
    })
    await send({"type": "http.response.body", "body": body, "more_body": False})


def _capture_response():
    state = {"status": None, "body": b""}
    async def send(msg):
        if msg["type"] == "http.response.start":
            state["status"] = msg["status"]
        elif msg["type"] == "http.response.body":
            state["body"] += msg.get("body", b"")
    return state, send


def _scope(headers: list[tuple[bytes, bytes]]):
    return {
        "type": "http", "method": "POST", "path": "/x",
        "headers": headers, "scheme": "http", "server": ("test", 80),
        "client": ("1.2.3.4", 12345),
    }


@pytest.mark.asyncio
async def test_forged_content_length_zero_with_large_body_returns_413():
    """R-T6.1-01: Content-Length=0 + actual 5000-byte body MUST return 413, not 200.

    RED at HEAD because body_size.py:54 ``if cl is None:`` skips the streaming
    cap whenever CL is present (any value). GREEN after 47-04 changes the
    condition to ``if cl is None or cl <= self.max_bytes:`` (defense-in-depth).
    """
    middleware = BodySizeLimitMiddleware(_echo_app, max_bytes=1024)
    scope = _scope([(b"content-length", b"0")])  # FORGED — actual body is 5000 bytes

    body_chunk = b"x" * 5000
    sent = [False]
    async def receive():
        if not sent[0]:
            sent[0] = True
            return {"type": "http.request", "body": body_chunk, "more_body": False}
        return {"type": "http.disconnect"}

    state, send = _capture_response()
    await middleware(scope, receive, send)
    assert state["status"] == 413, (
        f"R-T6.1-01: forged CL=0 with {len(body_chunk)}-byte body bypassed cap=1024. "
        f"Got status {state['status']}, body={state['body']!r}. "
        f"Expected 413 (defense-in-depth: streaming cap MUST run when CL is present)."
    )


@pytest.mark.asyncio
async def test_forged_content_length_small_with_large_body_returns_413():
    """R-T6.1-01: CL=100 + actual 5000-byte body MUST return 413."""
    middleware = BodySizeLimitMiddleware(_echo_app, max_bytes=1024)
    scope = _scope([(b"content-length", b"100")])
    body_chunk = b"x" * 5000
    sent = [False]
    async def receive():
        if not sent[0]:
            sent[0] = True
            return {"type": "http.request", "body": body_chunk, "more_body": False}
        return {"type": "http.disconnect"}
    state, send = _capture_response()
    await middleware(scope, receive, send)
    assert state["status"] == 413


@pytest.mark.asyncio
async def test_normal_request_within_cap_passes():
    """Sanity: CL=4000 + body=4000 + cap=10240 -> 200 (regression check)."""
    middleware = BodySizeLimitMiddleware(_echo_app, max_bytes=10240)
    body = b"x" * 4000
    scope = _scope([(b"content-length", str(len(body)).encode())])
    sent = [False]
    async def receive():
        if not sent[0]:
            sent[0] = True
            return {"type": "http.request", "body": body, "more_body": False}
        return {"type": "http.disconnect"}
    state, send = _capture_response()
    await middleware(scope, receive, send)
    assert state["status"] == 200, f"Sanity broken; status={state['status']}"
    assert state["body"] == b"got 4000"
