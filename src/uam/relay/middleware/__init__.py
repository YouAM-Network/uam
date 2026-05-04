"""HTTP middleware: body-size cap + trusted-proxy IP rewriting (Phase 46 T6.1).

Restored from Phase 32 archive (commits 434b7290 + 1a3b9974) after the v3.0 migration
left this directory with only stale .pyc files. Registered in create_app() with
TrustedProxyMiddleware as the OUTERMOST layer so every downstream middleware AND
every route's request.client.host sees the real client IP.
"""

from uam.relay.middleware.body_size import BodySizeLimitMiddleware
from uam.relay.middleware.proxy_headers import TrustedProxyMiddleware
from uam.relay.middleware.request_id import RequestIDMiddleware

__all__ = [
    "BodySizeLimitMiddleware",
    "TrustedProxyMiddleware",
    "RequestIDMiddleware",
]
