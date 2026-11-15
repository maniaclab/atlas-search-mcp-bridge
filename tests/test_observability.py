"""Observability contract: request id (L1), JSON logs (L2), probe noise (L3),
and a cached broker JWKS (U7), exercised through the real app with a stub broker.
"""

from __future__ import annotations

import io
import json
import logging
import logging.config
from typing import TYPE_CHECKING, Any

import httpx
import httpx2
import pytest
import uvicorn.config

from atlas_search_mcp_bridge.app import create_app
from atlas_search_mcp_bridge.logging import configure_logging
from tests.test_app import _redeem_body

if TYPE_CHECKING:
    from collections.abc import Callable

    from atlas_search_mcp_bridge.config import Settings
    from tests.conftest import FakeCurl


class StubBroker:
    """Stands in for the broker and records every request it receives."""

    def __init__(self, jwks: list[dict[str, Any]]) -> None:
        self.jwks = jwks
        self.requests: list[httpx2.Request] = []
        self.jwks_up = True

    def __call__(self, request: httpx2.Request) -> httpx2.Response:
        self.requests.append(request)
        if request.url.path.endswith("/.well-known/jwks.json"):
            if not self.jwks_up:
                return httpx2.Response(503)
            return httpx2.Response(200, json={"keys": self.jwks})
        if request.url.path.endswith("/v1/credentials/krb5/redeem"):
            return httpx2.Response(200, json=_redeem_body())
        return httpx2.Response(404)

    def fetches(self, suffix: str) -> list[httpx2.Request]:
        return [r for r in self.requests if r.url.path.endswith(suffix)]


@pytest.fixture
def broker(jwks: list[dict[str, Any]]) -> StubBroker:
    return StubBroker(jwks)


@pytest.fixture
def log_stream() -> io.StringIO:
    return io.StringIO()


@pytest.fixture
async def client(
    settings: Settings,
    broker: StubBroker,
    fake_curl: FakeCurl,
    log_stream: io.StringIO,
) -> httpx.AsyncClient:
    settings.curl_bin = str(fake_curl.path)
    app = create_app(settings, broker_transport=httpx2.MockTransport(broker))
    # Redirect the JSON log lines from stdout so each test reads only its own.
    configure_logging(settings.log_level, stream=log_stream)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        yield client


def _log_lines(stream: io.StringIO) -> list[dict[str, Any]]:
    """Every log line written so far, each of which must be a JSON object."""
    return [json.loads(line) for line in stream.getvalue().splitlines() if line.strip()]


async def _call(
    client: httpx.AsyncClient, token: str, **headers: str
) -> httpx.Response:
    return await client.post(
        "/mcp",
        content=b'{"jsonrpc": "2.0", "method": "tools/list", "id": 1}',
        headers={"Authorization": f"Bearer {token}", **headers},
    )


# L1 ----------------------------------------------------------------------


async def test_every_line_of_a_request_carries_the_brokers_request_id(
    client: httpx.AsyncClient,
    make_token: Callable[..., str],
    log_stream: io.StringIO,
) -> None:
    response = await _call(client, make_token(), **{"X-Request-ID": "abc"})
    assert response.status_code == 200
    lines = _log_lines(log_stream)
    assert {line["event"] for line in lines} >= {"audit", "http.request"}
    assert [line["request_id"] for line in lines] == ["abc"] * len(lines)


async def test_a_request_id_is_generated_when_the_header_is_absent(
    client: httpx.AsyncClient,
    make_token: Callable[..., str],
    log_stream: io.StringIO,
) -> None:
    await _call(client, make_token())
    ids = {line["request_id"] for line in _log_lines(log_stream)}
    assert len(ids) == 1
    assert ids != {""}


async def test_an_oversized_request_id_is_truncated_to_128_characters(
    client: httpx.AsyncClient,
    make_token: Callable[..., str],
    log_stream: io.StringIO,
) -> None:
    await _call(client, make_token(), **{"X-Request-ID": "x" * 300})
    assert {line["request_id"] for line in _log_lines(log_stream)} == {"x" * 128}


async def test_redeem_call_carries_the_inbound_request_id(
    client: httpx.AsyncClient, make_token: Callable[..., str], broker: StubBroker
) -> None:
    await _call(client, make_token(), **{"X-Request-ID": "abc"})
    redeems = broker.fetches("/v1/credentials/krb5/redeem")
    assert [r.headers.get("x-request-id") for r in redeems] == ["abc"]


async def test_jwks_fetch_does_not_carry_a_request_id(
    client: httpx.AsyncClient, make_token: Callable[..., str], broker: StubBroker
) -> None:
    await _call(client, make_token(), **{"X-Request-ID": "abc"})
    jwks_requests = broker.fetches("/.well-known/jwks.json")
    assert [r.headers.get("x-request-id") for r in jwks_requests] == [None]


# L2 ----------------------------------------------------------------------


async def test_audit_line_has_the_standard_fields(
    client: httpx.AsyncClient,
    make_token: Callable[..., str],
    log_stream: io.StringIO,
) -> None:
    await _call(client, make_token(sub="gstark"), **{"X-Request-ID": "abc"})
    (audit,) = [line for line in _log_lines(log_stream) if line["event"] == "audit"]
    assert audit["outcome"] == "ok"
    assert audit["subject"] == "gstark"
    assert audit["duration_ms"] >= 0
    assert {"timestamp", "level", "logger", "request_id"} <= audit.keys()


async def test_uvicorn_lifecycle_lines_are_json(
    log_stream: io.StringIO,
) -> None:
    # uvicorn installs its own plain-text handlers before importing the app.
    logging.config.dictConfig(uvicorn.config.LOGGING_CONFIG)
    configure_logging("INFO", stream=log_stream)
    logging.getLogger("uvicorn.error").info("Started server process [1]")
    (line,) = _log_lines(log_stream)
    assert line["event"] == "Started server process [1]"
    assert line["level"] == "info"


# L3 ----------------------------------------------------------------------


async def test_successful_probes_write_no_access_line(
    client: httpx.AsyncClient,
    log_stream: io.StringIO,
) -> None:
    assert (await client.get("/healthz")).status_code == 200
    assert (await client.get("/readyz")).status_code == 200
    assert _log_lines(log_stream) == []


async def test_failing_probe_is_logged(
    client: httpx.AsyncClient,
    settings: Settings,
    log_stream: io.StringIO,
) -> None:
    settings.curl_bin = "/nonexistent/curl"
    assert (await client.get("/readyz")).status_code == 503
    (line,) = _log_lines(log_stream)
    assert (line["event"], line["path"], line["status"]) == (
        "http.request",
        "/readyz",
        503,
    )


async def test_proxied_request_keeps_its_access_line(
    client: httpx.AsyncClient,
    make_token: Callable[..., str],
    log_stream: io.StringIO,
) -> None:
    await _call(client, make_token())
    (access,) = [
        line for line in _log_lines(log_stream) if line["event"] == "http.request"
    ]
    assert (access["method"], access["path"], access["status"]) == (
        "POST",
        "/mcp",
        200,
    )


# U7 ----------------------------------------------------------------------


async def test_jwks_is_fetched_once_for_many_authenticated_requests(
    client: httpx.AsyncClient, make_token: Callable[..., str], broker: StubBroker
) -> None:
    for _ in range(5):
        assert (await _call(client, make_token())).status_code == 200
    assert len(broker.fetches("/.well-known/jwks.json")) == 1


async def test_readiness_probes_do_not_fetch_the_jwks_again(
    client: httpx.AsyncClient, make_token: Callable[..., str], broker: StubBroker
) -> None:
    await _call(client, make_token())
    for _ in range(5):
        assert (await client.get("/readyz")).status_code == 200
    assert len(broker.fetches("/.well-known/jwks.json")) == 1


async def test_repeated_readiness_probes_fetch_the_jwks_once(
    client: httpx.AsyncClient, broker: StubBroker
) -> None:
    for _ in range(5):
        assert (await client.get("/readyz")).status_code == 200
    assert len(broker.fetches("/.well-known/jwks.json")) == 1


async def test_readiness_survives_a_broker_outage_once_keys_are_held(
    client: httpx.AsyncClient, make_token: Callable[..., str], broker: StubBroker
) -> None:
    await _call(client, make_token())
    broker.jwks_up = False
    assert (await client.get("/readyz")).status_code == 200
    assert (await _call(client, make_token())).status_code == 200


async def test_readiness_fails_when_no_keys_were_ever_loaded(
    client: httpx.AsyncClient, broker: StubBroker
) -> None:
    broker.jwks_up = False
    assert (await client.get("/readyz")).status_code == 503
