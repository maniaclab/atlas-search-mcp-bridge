from __future__ import annotations

from atlas_search_mcp_bridge.config import Settings


def test_broker_jwks_url_derived_from_broker_url() -> None:
    settings = Settings(_env_file=None, broker_url="http://broker.internal:8080")
    assert (
        settings.broker_jwks_url == "http://broker.internal:8080/.well-known/jwks.json"
    )


def test_broker_jwks_url_strips_trailing_slash() -> None:
    settings = Settings(_env_file=None, broker_url="http://broker.internal:8080/")
    assert (
        settings.broker_jwks_url == "http://broker.internal:8080/.well-known/jwks.json"
    )


def test_defaults() -> None:
    settings = Settings(_env_file=None)
    assert settings.expected_audience == "atlas-search-mcp-bridge"
    assert (
        settings.target_url
        == "https://os-search-atlas-physics-dev.cern.ch/os/_plugins/_ml/mcp"
    )
    assert settings.curl_bin == "curl"
    assert settings.curl_timeout_seconds == 30
