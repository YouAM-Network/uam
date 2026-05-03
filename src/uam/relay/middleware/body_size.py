"""HTTP body size cap (Phase 32 Task 4).

Pure ASGI middleware that rejects HTTP requests whose body exceeds
``max_bytes``:

* If ``Content-Length`` is present and > max_bytes, respond 413 before
  the inner app is invoked.
* If ``Content-Length`` is absent (chunked / streaming), wrap the
  receive callable to accumulate a byte count and abort with 413 once
  the running total exceeds max_bytes.

Bytes are counted, not buffered, so memory use on the abort path stays
bounded even for hostile multi-gigabyte uploads.
"""

from __future__ import annotations

import json
from typing import Awaitable, Callable


Scope = dict
Message = dict
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]


class BodySizeLimitMiddleware:
    def __init__(self, app, max_bytes: int) -> None:  # noqa: ANN001
        self.app = app
        self.max_bytes = int(max_bytes)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        # 1) Content-Length fast path.
        headers = scope.get("headers") or []
        cl: int | None = None
        for name, value in headers:
            if name.lower() == b"content-length":
                try:
                    cl = int(value)
                except ValueError:
                    cl = None
                break

        if cl is not None and cl > self.max_bytes:
            await _send_413(send, cl, self.max_bytes)
            return

        # 2) Streaming path: wrap receive to enforce running-byte cap.
        if cl is None:
            total = 0
            rejected = False

            async def _limited_receive() -> Message:
                nonlocal total, rejected
                message = await receive()
                if rejected:
                    return message
                if message.get("type") == "http.request":
                    body = message.get("body", b"") or b""
                    total += len(body)
                    if total > self.max_bytes:
                        rejected = True
                        # Drop the body and signal end-of-stream so the inner
                        # app (if it ever runs) sees no data.
                        return {"type": "http.request", "body": b"", "more_body": False}
                return message

            # We need to catch the rejection and return 413 ourselves;
            # wrap `send` too so we can intercept.
            response_started = False

            async def _gated_send(message: Message) -> None:
                nonlocal response_started
                if rejected:
                    # The inner app tried to respond after we already
                    # decided to reject -- swallow their messages.
                    return
                response_started = True
                await send(message)

            # Drive the inner app.
            try:
                await self.app(scope, _limited_receive, _gated_send)
            finally:
                if rejected and not response_started:
                    await _send_413(send, None, self.max_bytes)
            return

        # 3) Content-Length present and within limit -- passthrough.
        await self.app(scope, receive, send)


async def _send_413(send: Send, observed: int | None, limit: int) -> None:
    detail = f"request body exceeds limit of {limit} bytes"
    if observed is not None:
        detail = f"request body {observed} bytes exceeds limit of {limit} bytes"
    payload = json.dumps({"error": "payload_too_large", "detail": detail}).encode(
        "utf-8"
    )
    await send(
        {
            "type": "http.response.start",
            "status": 413,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(payload)).encode("ascii")),
            ],
        }
    )
    await send(
        {
            "type": "http.response.body",
            "body": payload,
            "more_body": False,
        }
    )
