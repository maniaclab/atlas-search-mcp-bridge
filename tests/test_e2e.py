"""Integration test: the full verify -> redeem -> forward pipeline wired
together against a fake broker (JWKS + krb5/redeem) and a fake curl,
using a REAL FILE-ccache v4 byte string (tests/ccache_fixtures.py) so the
ccache actually written to KRB5CCNAME is the genuine wire format a real
kinit/broker would produce -- not an arbitrary placeholder.

True e2e against real CERN infrastructure (a live broker + a real linked
krb5 identity + the real OpenSearch cluster) is out of scope here: there is
no real CERN credential available in this environment. That is reserved for
a manual, CI-gated run against the dev deployment.
"""

from __future__ import annotations

import base64
import json
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any

import httpx
import httpx2
import pytest
from af_credentials.proxy import ProxyClient
from af_credentials.verifier import BrokerTokenVerifier

from atlas_search_mcp_bridge.app import create_app
from tests.ccache_fixtures import build_ccache

if TYPE_CHECKING:
    from collections.abc import Callable

    from atlas_search_mcp_bridge.config import Settings
    from tests.conftest import FakeCurl


@pytest.fixture
def real_ccache_bytes() -> bytes:
    now = int(time.time())
    return build_ccache(
        username="gstark",
        realm="CERN.CH",
        authtime=now,
        endtime=now + 86400,
        renew_till=now + 604800,
    )


async def test_full_pipeline_writes_real_ccache_to_krb5ccname(
    settings: Settings,
    jwks: list[dict[str, Any]],
    fake_curl: FakeCurl,
    make_token: Callable[..., str],
    real_ccache_bytes: bytes,
) -> None:
    settings.curl_bin = str(fake_curl.path)

    def broker_handler(request: httpx2.Request) -> httpx2.Response:
        if request.url.path.endswith("/.well-known/jwks.json"):
            return httpx2.Response(200, json={"keys": jwks})
        if request.url.path.endswith("/v1/credentials/krb5/redeem"):
            return httpx2.Response(
                200,
                json={
                    "ccache_b64": base64.b64encode(real_ccache_bytes).decode(),
                    "principal": "gstark@CERN.CH",
                    "realm": "CERN.CH",
                    "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
                    "remaining_seconds": 3600,
                    "renew_until": (datetime.now(UTC) + timedelta(days=7)).isoformat(),
                },
            )
        return httpx2.Response(404, json={"detail": "not found"})

    broker_client = httpx2.AsyncClient(transport=httpx2.MockTransport(broker_handler))

    app = create_app(settings)
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

    token = make_token(sub="gstark")
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post(
            "/mcp",
            content=b'{"jsonrpc": "2.0", "method": "tools/call", "id": 7}',
            headers={"Authorization": f"Bearer {token}"},
        )

    assert response.status_code == 200

    # The ccache curl actually saw via KRB5CCNAME (captured by the fake curl
    # AT INVOCATION TIME, before the caller's own cleanup deletes it) must
    # be byte-for-byte what the broker redeemed -- proving the handle.path
    # plumbing (app.py -> ProxyClient.ticket_file -> proxy_call.call_upstream)
    # round-trips the real ccache wire format, not just some opaque token.
    assert fake_curl.ccache_dump_file.read_bytes() == real_ccache_bytes

    # And the ccache handle must have been deleted once the request
    # completed -- ticket material never outlives one call.
    env_dump = fake_curl.env_dump_file.read_text()
    ccache_path = json.loads(env_dump)["KRB5CCNAME"]
    assert ccache_path
    assert not Path(ccache_path).exists()
