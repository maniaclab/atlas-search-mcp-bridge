"""Shared fixtures: RSA keypair, stubbed JWKS fetch, a broker-token factory,
and a fake ``curl`` executable installed on PATH.

Mirrors krb5-token-service's tests/conftest.py conventions closely.
"""

from __future__ import annotations

import base64
import json
import stat
import time
import uuid
from typing import TYPE_CHECKING, Any, NamedTuple

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from atlas_search_mcp_bridge.config import Settings
from tests.fake_curl_script import FAKE_CURL_SOURCE

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

TEST_KID = "test-signing-key"


@pytest.fixture(scope="session")
def rsa_private_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="session")
def other_rsa_private_key() -> rsa.RSAPrivateKey:
    """A second keypair NOT in the served JWKS — for wrong-signature tests."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="session")
def jwks(rsa_private_key: rsa.RSAPrivateKey) -> list[dict[str, Any]]:
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(rsa_private_key.public_key()))
    jwk.update({"kid": TEST_KID, "alg": "RS256", "use": "sig"})
    return [jwk]


@pytest.fixture
def settings() -> Settings:
    return Settings(
        _env_file=None,
        broker_url="https://broker.test",
        broker_issuer="https://broker.test",
        expected_audience="atlas-search-mcp-bridge",
        target_url="https://opensearch.test/os/_plugins/_ml/mcp",
        curl_timeout_seconds=5,
    )


@pytest.fixture
def make_token(
    rsa_private_key: rsa.RSAPrivateKey, settings: Settings
) -> Callable[..., str]:
    """Factory for AF Broker Identity Tokens with controllable claims."""

    def _make(
        *,
        sub: str = "af-user-subject",
        issuer: str | None = None,
        audience: str | None = None,
        key: rsa.RSAPrivateKey | None = None,
        kid: str | None = TEST_KID,
        expires_in: int = 300,
        omit: tuple[str, ...] = (),
        extra: dict[str, Any] | None = None,
    ) -> str:
        now = int(time.time())
        claims: dict[str, Any] = {
            "iss": issuer or settings.broker_issuer,
            "sub": sub,
            "aud": audience or settings.expected_audience,
            "exp": now + expires_in,
            "iat": now,
            "jti": str(uuid.uuid4()),
        }
        if extra:
            claims.update(extra)
        for claim in omit:
            claims.pop(claim, None)
        headers = {"kid": kid} if kid is not None else None
        return jwt.encode(
            claims, key or rsa_private_key, algorithm="RS256", headers=headers
        )

    return _make


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def header_block(status_line: str, headers: dict[str, str] | None = None) -> str:
    """Build one CRLF-terminated HTTP header block, e.g. curl's own -D output for one response."""
    lines = [status_line]
    for name, value in (headers or {}).items():
        lines.append(f"{name}: {value}")
    return "\r\n".join(lines) + "\r\n\r\n"


class FakeCurl(NamedTuple):
    path: Path
    args_file: Path
    stdin_file: Path
    env_dump_file: Path
    ccache_dump_file: Path


@pytest.fixture
def fake_curl(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> FakeCurl:
    """Install a fake ``curl`` on PATH; defaults to a single 200 OK JSON response.

    Configure via ``monkeypatch.setenv("FAKE_CURL_...", ...)`` in individual
    tests — see fake_curl_script.py's module docstring for the full list.
    """
    bin_dir = tmp_path / "fake-bin"
    bin_dir.mkdir(exist_ok=True)
    script = bin_dir / "curl"
    script.write_text(FAKE_CURL_SOURCE)
    script.chmod(script.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    args_file = tmp_path / "curl_args.txt"
    stdin_file = tmp_path / "curl_stdin.bin"
    env_dump_file = tmp_path / "curl_env.json"
    ccache_dump_file = tmp_path / "curl_ccache.dump"

    monkeypatch.setenv("FAKE_CURL_ARGS_FILE", str(args_file))
    monkeypatch.setenv("FAKE_CURL_STDIN_FILE", str(stdin_file))
    monkeypatch.setenv("FAKE_CURL_ENV_DUMP_FILE", str(env_dump_file))
    monkeypatch.setenv("FAKE_CURL_CCACHE_DUMP_FILE", str(ccache_dump_file))
    monkeypatch.setenv(
        "FAKE_CURL_HEADER_BLOCKS_B64",
        _b64(
            header_block(
                "HTTP/1.1 200 OK", {"Content-Type": "application/json"}
            ).encode()
        ),
    )
    monkeypatch.setenv("FAKE_CURL_BODY_B64", _b64(b'{"jsonrpc": "2.0", "result": {}}'))
    return FakeCurl(
        path=script,
        args_file=args_file,
        stdin_file=stdin_file,
        env_dump_file=env_dump_file,
        ccache_dump_file=ccache_dump_file,
    )
