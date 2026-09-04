"""FastAPI application: a single auth-translating reverse-proxy route plus
health probes.

Per request: verify the inbound AF Broker Identity Token, redeem a krb5
ticket for its subject at the broker, and forward the request body/headers
to ``settings.target_url`` via ``curl --negotiate`` authenticated with that
ticket. No MCP/JSON-RPC parsing happens here — see proxy_call.py's
docstring for why transparent byte-level forwarding was chosen. Authorization
is a prerequisite the af-mcp-platform aggregator has already enforced before
this service ever sees a call; a valid token proves the call genuinely came
from the broker, and this service applies no capability logic of its own.
"""

from __future__ import annotations

import asyncio
import shutil
import uuid
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING

import httpx2
import structlog
from af_credentials.proxy import (
    ProxyClient,
    ProxyNotAvailableError,
    ProxyRedeemError,
)
from af_credentials.verifier import BrokerTokenVerifier
from fastapi import FastAPI, HTTPException, Request, Response, status

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

from atlas_search_mcp_bridge.config import Settings, get_settings
from atlas_search_mcp_bridge.logging import configure_logging
from atlas_search_mcp_bridge.proxy_call import (
    UpstreamCallError,
    UpstreamTimeoutError,
    call_upstream,
)

logger = structlog.get_logger(__name__)


def _extract_bearer(request: Request) -> str:
    """Return the bearer token from the request's Authorization header.

    Raises:
        HTTPException: 401 if the header is missing or not a Bearer scheme.
    """
    auth = request.headers.get("authorization", "") or ""
    if not auth.lower().startswith("bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Bearer token in Authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return auth[len("bearer ") :].strip()


async def _proxy_request(request: Request, full_path: str) -> Response:  # noqa: ARG001
    # `full_path` must be named exactly this to bind to the route's
    # `/{full_path:path}` template (FastAPI matches path params by function
    # parameter name) -- unused otherwise, since this is a fixed-target
    # proxy: the inbound path is not itself interpreted.
    settings: Settings = request.app.state.settings
    verifier: BrokerTokenVerifier = request.app.state.verifier
    proxy_client: ProxyClient = request.app.state.proxy_client
    request_id = request.headers.get("x-request-id") or str(uuid.uuid4())

    token = _extract_bearer(request)

    claims = await verifier.verify(token)
    if claims is None:
        logger.info(
            "audit", outcome="denied", reason="invalid_token", request_id=request_id
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired AF Broker Identity Token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        # TicketHandle is a plain (sync) context manager -- see
        # af_credentials.proxy.TicketHandle -- mirroring ami-mcp's own
        # `with await self._proxy_client.proxy_file(bearer) as handle:` usage.
        with await proxy_client.ticket_file(token) as handle:
            body = await request.body()
            try:
                upstream = await asyncio.to_thread(
                    call_upstream,
                    method=request.method,
                    body=body,
                    headers=dict(request.headers),
                    target_url=settings.target_url,
                    ccache_path=handle.path,
                    timeout=settings.curl_timeout_seconds,
                    curl_bin=settings.curl_bin,
                )
            except UpstreamTimeoutError as exc:
                logger.info(
                    "audit",
                    outcome="error",
                    reason="upstream_timeout",
                    subject=claims.sub,
                    request_id=request_id,
                    # Same text the caller gets in the HTTPException detail
                    # below -- not a new exposure, just also captured
                    # server-side so `kubectl logs` alone can diagnose a
                    # failure without reproducing it live.
                    exc_detail=str(exc),
                )
                raise HTTPException(
                    status_code=status.HTTP_504_GATEWAY_TIMEOUT,
                    detail=str(exc),
                ) from exc
            except UpstreamCallError as exc:
                logger.info(
                    "audit",
                    outcome="error",
                    reason="upstream_call_failed",
                    subject=claims.sub,
                    request_id=request_id,
                    exc_detail=str(exc),
                )
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail=str(exc),
                ) from exc
    except ProxyNotAvailableError as exc:
        logger.info(
            "audit",
            outcome="denied",
            reason="no_krb5_ticket",
            subject=claims.sub,
            request_id=request_id,
            exc_detail=exc.detail,
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=exc.detail,
        ) from exc
    except ProxyRedeemError as exc:
        logger.info(
            "audit",
            outcome="error",
            reason="redeem_failed",
            subject=claims.sub,
            request_id=request_id,
            exc_detail=exc.detail,
        )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=exc.detail,
        ) from exc

    logger.info(
        "audit",
        outcome="forwarded",
        subject=claims.sub,
        status_code=upstream.status_code,
        request_id=request_id,
    )
    return Response(
        content=upstream.body,
        status_code=upstream.status_code,
        media_type=upstream.content_type,
    )


async def _readyz(request: Request) -> Response:
    """Ready only when curl is executable and the broker JWKS is fetchable.

    Deliberately does NOT probe the real CERN OpenSearch target — a
    CERN-side outage must not flap this pod's readiness (same rationale as
    krb5-token-service's readyz not checking KDC reachability).
    """
    settings: Settings = request.app.state.settings
    http_client: httpx2.AsyncClient = request.app.state.http_client
    problems: list[str] = []
    if shutil.which(settings.curl_bin) is None:
        problems.append(f"curl binary not found or not executable: {settings.curl_bin}")
    try:
        response = await http_client.get(settings.broker_jwks_url, timeout=5.0)
        response.raise_for_status()
    except httpx2.HTTPError:
        problems.append(f"broker JWKS endpoint unreachable: {settings.broker_jwks_url}")

    if problems:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="; ".join(problems),
        )
    return Response(content='{"status": "ready"}', media_type="application/json")


@asynccontextmanager
async def _lifespan(application: FastAPI) -> AsyncIterator[None]:
    try:
        yield
    finally:
        await application.state.http_client.aclose()


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the application; tests pass explicit Settings, production uses env."""
    if settings is None:
        settings = get_settings()
    configure_logging(settings.log_level)

    application = FastAPI(
        title="atlas-search-mcp-bridge",
        description=(
            "Auth-translation reverse proxy: AF Broker Identity Token in, "
            "Kerberos SPNEGO Negotiate out, for CERN's ATLAS OpenSearch MCP endpoint"
        ),
        version="0.1.1",
        lifespan=_lifespan,
    )
    application.state.settings = settings
    # Shared across the verifier, the proxy client, and readyz's own JWKS
    # reachability check -- one client, one place for tests to redirect all
    # three at once via httpx2.MockTransport (see tests/test_app.py).
    application.state.http_client = httpx2.AsyncClient()
    application.state.verifier = BrokerTokenVerifier(
        settings.broker_jwks_url,
        settings.broker_issuer,
        settings.expected_audience,
        http_client=application.state.http_client,
    )
    application.state.proxy_client = ProxyClient(
        settings.broker_url, kind="krb5", http_client=application.state.http_client
    )

    application.add_api_route("/healthz", lambda: {"status": "ok"}, methods=["GET"])
    application.add_api_route("/readyz", _readyz, methods=["GET"])
    # Catch-all: this bridge is a transparent proxy for exactly one upstream
    # target (settings.target_url) — the inbound path is whatever
    # `atlas_search_service.url` in services.yaml points the aggregator at,
    # and is not otherwise interpreted.
    application.add_api_route(
        "/{full_path:path}",
        _proxy_request,
        methods=["GET", "POST", "DELETE"],
    )
    return application


app = create_app()
