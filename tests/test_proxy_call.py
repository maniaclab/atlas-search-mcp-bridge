"""Unit tests for proxy_call.py — the curl-invocation wrapper.

Uses a real (fake) executable on the invocation path (see conftest.fake_curl)
rather than mocking subprocess.run, so the actual argv-building and
header/body-file parsing logic is exercised end-to-end.
"""

from __future__ import annotations

import base64
import json
from typing import TYPE_CHECKING

import pytest

from atlas_search_mcp_bridge.proxy_call import (
    UpstreamCallError,
    UpstreamTimeoutError,
    call_upstream,
    forwardable_headers,
)
from tests.conftest import header_block

if TYPE_CHECKING:
    from pathlib import Path

    from tests.conftest import FakeCurl


def test_forwardable_headers_drops_authorization_and_hop_by_hop() -> None:
    headers = {
        "Authorization": "Bearer secret-token",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Host": "aggregator.internal",
        "Connection": "keep-alive",
        "Content-Length": "42",
    }
    result = forwardable_headers(headers)
    assert result == {"Content-Type": "application/json", "Accept": "application/json"}


def test_call_upstream_pipes_body_via_stdin_not_argv(
    tmp_path: Path, fake_curl: FakeCurl
) -> None:
    ccache_path = tmp_path / "krb5cc-test"
    ccache_path.write_bytes(b"fake-ccache-bytes")
    body = b'{"jsonrpc": "2.0", "method": "tools/list", "id": 1}'

    call_upstream(
        method="POST",
        body=body,
        headers={"Content-Type": "application/json", "Authorization": "Bearer x"},
        target_url="https://opensearch.test/mcp",
        ccache_path=ccache_path,
        timeout=5,
        curl_bin=str(fake_curl.path),
    )

    argv = fake_curl.args_file.read_text().splitlines()
    assert "--negotiate" in argv
    assert "-u" in argv
    assert ":" in argv
    assert "--data-binary" in argv
    assert "@-" in argv
    # The body must never appear as a literal argv token.
    assert body.decode() not in argv
    assert fake_curl.stdin_file.read_bytes() == body
    # Authorization must never be forwarded — curl performs its own SPNEGO
    # exchange instead.
    joined = " ".join(argv)
    assert "Authorization" not in joined


def test_call_upstream_sets_krb5ccname_env(tmp_path: Path, fake_curl: FakeCurl) -> None:
    """The fake curl script dumps its own os.environ["KRB5CCNAME"] to a file —
    proves call_upstream sets it via subprocess.run(..., env=...) for real,
    without patching subprocess itself."""
    ccache_path = tmp_path / "krb5cc-test"
    ccache_path.write_bytes(b"fake-ccache-bytes")

    call_upstream(
        method="POST",
        body=b"{}",
        headers={},
        target_url="https://opensearch.test/mcp",
        ccache_path=ccache_path,
        timeout=5,
        curl_bin=str(fake_curl.path),
    )

    recorded_env = json.loads(fake_curl.env_dump_file.read_text())
    assert recorded_env["KRB5CCNAME"] == str(ccache_path)


def test_call_upstream_returns_status_and_body_from_final_response(
    tmp_path: Path, fake_curl: FakeCurl, monkeypatch: pytest.MonkeyPatch
) -> None:
    ccache_path = tmp_path / "krb5cc-test"
    ccache_path.write_bytes(b"fake-ccache-bytes")
    body = base64.b64encode(b'{"jsonrpc": "2.0", "result": {"ok": true}}').decode()
    monkeypatch.setenv("FAKE_CURL_BODY_B64", body)

    response = call_upstream(
        method="POST",
        body=b"{}",
        headers={},
        target_url="https://opensearch.test/mcp",
        ccache_path=ccache_path,
        timeout=5,
        curl_bin=str(fake_curl.path),
    )

    assert response.status_code == 200
    assert response.content_type == "application/json"
    assert response.body == b'{"jsonrpc": "2.0", "result": {"ok": true}}'


def test_call_upstream_parses_last_of_two_header_blocks(
    tmp_path: Path, fake_curl: FakeCurl, monkeypatch: pytest.MonkeyPatch
) -> None:
    """curl's own --negotiate SPNEGO exchange writes an initial 401 challenge
    block to -D before the real, negotiated response's block — only the
    final block describes what actually reached -o."""
    ccache_path = tmp_path / "krb5cc-test"
    ccache_path.write_bytes(b"fake-ccache-bytes")
    two_blocks = header_block(
        "HTTP/1.1 401 Unauthorized", {"WWW-Authenticate": "Negotiate"}
    ) + header_block("HTTP/1.1 200 OK", {"Content-Type": "application/json"})
    monkeypatch.setenv(
        "FAKE_CURL_HEADER_BLOCKS_B64", base64.b64encode(two_blocks.encode()).decode()
    )

    response = call_upstream(
        method="POST",
        body=b"{}",
        headers={},
        target_url="https://opensearch.test/mcp",
        ccache_path=ccache_path,
        timeout=5,
        curl_bin=str(fake_curl.path),
    )

    assert response.status_code == 200
    assert response.content_type == "application/json"


def test_call_upstream_raises_on_nonzero_exit(
    tmp_path: Path, fake_curl: FakeCurl, monkeypatch: pytest.MonkeyPatch
) -> None:
    ccache_path = tmp_path / "krb5cc-test"
    ccache_path.write_bytes(b"fake-ccache-bytes")
    monkeypatch.setenv("FAKE_CURL_EXIT_CODE", "35")
    monkeypatch.setenv("FAKE_CURL_STDERR", "curl: (35) SSL connect error")

    with pytest.raises(UpstreamCallError, match="curl exited 35"):
        call_upstream(
            method="POST",
            body=b"{}",
            headers={},
            target_url="https://opensearch.test/mcp",
            ccache_path=ccache_path,
            timeout=5,
            curl_bin=str(fake_curl.path),
        )


def test_call_upstream_raises_timeout(
    tmp_path: Path, fake_curl: FakeCurl, monkeypatch: pytest.MonkeyPatch
) -> None:
    ccache_path = tmp_path / "krb5cc-test"
    ccache_path.write_bytes(b"fake-ccache-bytes")
    monkeypatch.setenv("FAKE_CURL_SLEEP_SECONDS", "3")

    with pytest.raises(UpstreamTimeoutError):
        call_upstream(
            method="POST",
            body=b"{}",
            headers={},
            target_url="https://opensearch.test/mcp",
            ccache_path=ccache_path,
            timeout=0.2,
            curl_bin=str(fake_curl.path),
        )


def test_call_upstream_omits_data_binary_for_empty_body(
    tmp_path: Path, fake_curl: FakeCurl
) -> None:
    ccache_path = tmp_path / "krb5cc-test"
    ccache_path.write_bytes(b"fake-ccache-bytes")

    call_upstream(
        method="GET",
        body=b"",
        headers={},
        target_url="https://opensearch.test/mcp",
        ccache_path=ccache_path,
        timeout=5,
        curl_bin=str(fake_curl.path),
    )

    argv = fake_curl.args_file.read_text().splitlines()
    assert "--data-binary" not in argv
    assert "GET" in argv
