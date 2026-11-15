"""Request id binding and the access line (contract items L1 and L3).

The broker sends its correlation id as ``X-Request-ID`` on every request. It
is bound once at the HTTP edge into structlog's context variables, so every
line written while serving the request, this module's and the app's, carries
it as ``request_id``.
"""

from __future__ import annotations

import time
import uuid
from typing import TYPE_CHECKING

import structlog
from starlette.datastructures import Headers

if TYPE_CHECKING:
    import httpx2
    from starlette.types import ASGIApp, Message, Receive, Scope, Send

HEALTH_PATHS = frozenset({"/healthz", "/readyz"})
MAX_REQUEST_ID_CHARS = 128
REQUEST_ID_HEADER = "X-Request-ID"
REDEEM_PATH_SUFFIX = "/redeem"

logger = structlog.get_logger(__name__)


class RequestLogMiddleware:
    """Bind ``X-Request-ID`` for the request and write its access line.

    The broker's id is authoritative; one is generated only when the header is
    absent, so every line still carries an id. A health or readiness probe
    that succeeds writes no access line; a failing one does.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        header = Headers(scope=scope).get(REQUEST_ID_HEADER.lower(), "")
        structlog.contextvars.bind_contextvars(
            request_id=header[:MAX_REQUEST_ID_CHARS] or uuid.uuid4().hex
        )
        status_code = 500
        started = time.perf_counter()

        async def send_and_note_status(message: Message) -> None:
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message["status"]
            await send(message)

        try:
            await self.app(scope, receive, send_and_note_status)
        finally:
            if scope["path"] not in HEALTH_PATHS or status_code >= 400:
                logger.info(
                    "http.request",
                    method=scope["method"],
                    path=scope["path"],
                    status=status_code,
                    duration_ms=round((time.perf_counter() - started) * 1000, 1),
                )
            structlog.contextvars.clear_contextvars()


async def forward_request_id_to_redeem(request: httpx2.Request) -> None:
    """Send the inbound request's id on the broker's ticket redeem call.

    Only the redeem call is made on behalf of the inbound request; the JWKS
    fetch is shared by all requests and carries no id.
    """
    request_id = structlog.contextvars.get_contextvars().get("request_id")
    if request_id and request.url.path.endswith(REDEEM_PATH_SUFFIX):
        request.headers[REQUEST_ID_HEADER] = request_id
