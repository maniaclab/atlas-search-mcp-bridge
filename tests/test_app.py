"""App-level integration tests: token verification -> ticket redemption ->
upstream forwarding, wired together exactly as app.py does it, but with the
broker and curl both faked out (see test_e2e.py for the fuller version using
a genuine ccache byte format).
"""

from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

import httpx
import httpx2
import pytest
import structlog
from af_credentials.proxy import ProxyClient
from af_credentials.verifier import BrokerTokenVerifier

from atlas_search_mcp_bridge.app import create_app

if TYPE_CHECKING:
    from collections.abc import Callable

    from atlas_search_mcp_bridge.config import Settings
    from tests.conftest import FakeCurl

_CCACHE_BYTES = b"fake-ccache-bytes-for-app-tests"


def _redeem_body(*, status_code: int = 200, detail: str = "error") -> dict[str, Any]:
    if status_code != 200:
        return {"detail": detail}
    return {
        "ccache_b64": base64.b64encode(_CCACHE_BYTES).decode(),
        "principal": "gstark@CERN.CH",
        "realm": "CERN.CH",
        "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
        "remaining_seconds": 3600,
        "renew_until": None,
    }


def _make_broker_client(
    jwks: list[dict[str, Any]], *, redeem_status: int = 200
) -> httpx2.AsyncClient:
    def handler(request: httpx2.Request) -> httpx2.Response:
        if request.url.path.endswith("/.well-known/jwks.json"):
            return httpx2.Response(200, json={"keys": jwks})
        if request.url.path.endswith("/v1/credentials/krb5/redeem"):
            return httpx2.Response(
                redeem_status, json=_redeem_body(status_code=redeem_status)
            )
        return httpx2.Response(404, json={"detail": "not found"})

    return httpx2.AsyncClient(transport=httpx2.MockTransport(handler))


def _wire_app(
    settings: Settings, jwks: list[dict[str, Any]], *, redeem_status: int = 200
) -> tuple[Any, httpx2.AsyncClient]:
    app = create_app(settings)
    broker_client = _make_broker_client(jwks, redeem_status=redeem_status)
    app.state.http_client = broker_client
    app.state.verifier = BrokerTokenVerifier(
        settings.broker_jwks_url,
        settings.broker_issuer,
        settings.expected_audience,
        http_client=broker_client,
    )
    app.state.proxy_client = ProxyClient(
        settings.broker_url, kind="krb5", http_client=broker_client
    )
    return app, broker_client


@pytest.fixture
async def app_client(
    settings: Settings, jwks: list[dict[str, Any]], fake_curl: FakeCurl
) -> httpx.AsyncClient:
    settings.curl_bin = str(fake_curl.path)
    app, _ = _wire_app(settings, jwks)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        yield client


async def test_missing_authorization_header_is_401(
    app_client: httpx.AsyncClient,
) -> None:
    response = await app_client.post("/mcp", content=b"{}")
    assert response.status_code == 401


async def test_malformed_authorization_scheme_is_401(
    app_client: httpx.AsyncClient,
) -> None:
    response = await app_client.post(
        "/mcp", content=b"{}", headers={"Authorization": "Basic deadbeef"}
    )
    assert response.status_code == 401


async def test_invalid_token_is_401(
    app_client: httpx.AsyncClient, make_token: Callable[..., str]
) -> None:
    token = make_token(audience="some-other-service")
    response = await app_client.post(
        "/mcp", content=b"{}", headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 401


async def test_valid_token_forwards_request_and_returns_upstream_response(
    app_client: httpx.AsyncClient, make_token: Callable[..., str]
) -> None:
    token = make_token()
    response = await app_client.post(
        "/mcp",
        content=b'{"jsonrpc": "2.0", "method": "tools/list", "id": 1}',
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
    )
    assert response.status_code == 200
    assert response.json() == {"jsonrpc": "2.0", "result": {}}


async def test_no_krb5_ticket_available_is_404(
    settings: Settings,
    jwks: list[dict[str, Any]],
    fake_curl: FakeCurl,
    make_token: Callable[..., str],
) -> None:
    settings.curl_bin = str(fake_curl.path)
    app, _ = _wire_app(settings, jwks, redeem_status=404)
    token = make_token()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post(
            "/mcp", content=b"{}", headers={"Authorization": f"Bearer {token}"}
        )
    assert response.status_code == 404


async def test_broker_redeem_error_is_502(
    settings: Settings,
    jwks: list[dict[str, Any]],
    fake_curl: FakeCurl,
    make_token: Callable[..., str],
) -> None:
    settings.curl_bin = str(fake_curl.path)
    app, _ = _wire_app(settings, jwks, redeem_status=500)
    token = make_token()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post(
            "/mcp", content=b"{}", headers={"Authorization": f"Bearer {token}"}
        )
    assert response.status_code == 502


async def test_upstream_curl_failure_is_502(
    app_client: httpx.AsyncClient,
    make_token: Callable[..., str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FAKE_CURL_EXIT_CODE", "35")
    monkeypatch.setenv("FAKE_CURL_STDERR", "curl: (35) SSL connect error")
    token = make_token()
    response = await app_client.post(
        "/mcp", content=b"{}", headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 502


async def test_upstream_curl_failure_logs_exc_detail_for_diagnosis(
    app_client: httpx.AsyncClient,
    make_token: Callable[..., str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The audit log must carry enough of the curl failure to diagnose it
    # from `kubectl logs` alone, without reproducing the call live -- an
    # outcome/reason pair alone doesn't say *why* curl failed.
    monkeypatch.setenv("FAKE_CURL_EXIT_CODE", "35")
    monkeypatch.setenv("FAKE_CURL_STDERR", "curl: (35) SSL connect error")
    token = make_token()
    with structlog.testing.capture_logs() as captured:
        response = await app_client.post(
            "/mcp", content=b"{}", headers={"Authorization": f"Bearer {token}"}
        )
    assert response.status_code == 502
    audit_entries = [e for e in captured if e.get("reason") == "upstream_call_failed"]
    assert len(audit_entries) == 1
    assert "SSL connect error" in audit_entries[0]["exc_detail"]


async def test_upstream_timeout_is_504(
    app_client: httpx.AsyncClient,
    make_token: Callable[..., str],
    monkeypatch: pytest.MonkeyPatch,
    settings: Settings,
) -> None:
    monkeypatch.setenv(
        "FAKE_CURL_SLEEP_SECONDS", str(settings.curl_timeout_seconds + 5)
    )
    token = make_token()
    response = await app_client.post(
        "/mcp", content=b"{}", headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 504


async def test_authorization_header_never_forwarded_upstream(
    app_client: httpx.AsyncClient, make_token: Callable[..., str], fake_curl: FakeCurl
) -> None:
    token = make_token()
    await app_client.post(
        "/mcp", content=b"{}", headers={"Authorization": f"Bearer {token}"}
    )
    argv = " ".join(fake_curl.args_file.read_text().splitlines())
    assert token not in argv


async def test_healthz_always_ok(app_client: httpx.AsyncClient) -> None:
    response = await app_client.get("/healthz")
    assert response.status_code == 200


async def test_readyz_ok_when_curl_present_and_jwks_fetchable(
    app_client: httpx.AsyncClient,
) -> None:
    response = await app_client.get("/readyz")
    assert response.status_code == 200
