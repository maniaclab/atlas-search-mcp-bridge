from __future__ import annotations

from functools import lru_cache
from typing import Any

from pydantic import Field
from pydantic_settings import BaseSettings

# pydantic-settings matches env vars to field names case-insensitively, so the
# uppercase env var names (BROKER_URL, ...) map to these fields without
# explicit aliases.


class Settings(BaseSettings):
    # See krb5_token_service.config.Settings for why __init__ is overridden
    # with a plain **data signature: pydantic-settings' BaseSettings exposes
    # private (_cli_parse_args, ...) parameters that FastAPI's Depends cannot
    # turn into a request model otherwise.
    def __init__(self, **data: Any) -> None:
        super().__init__(**data)

    # The broker this bridge redeems krb5 tickets from and verifies AF
    # Broker Identity Tokens against. Also the base for the JWKS URL
    # (broker_jwks_url property below) — production deployments reach the
    # broker's in-cluster Service, same hairpin reasoning as
    # krb5-token-service's brokerJwksUrl.
    broker_url: str = "http://localhost:8080"

    # Required `iss` claim on inbound AF Broker Identity Tokens.
    broker_issuer: str = "https://mcp.af.uchicago.edu"

    # Required `aud` claim — this service's own identity in the protocol.
    # Must equal the `audience:` set on the `atlas_search_service` entry in
    # af-mcp-platform's services.yaml.
    expected_audience: str = "atlas-search-mcp-bridge"

    # The real CERN OpenSearch MCP endpoint this deployment forwards to.
    # One deployment serves exactly one cluster (dev or prod) — see the
    # design doc's "one bridge deployment per cluster" rationale.
    target_url: str = "https://os-search-atlas-physics-dev.cern.ch/os/_plugins/_ml/mcp"

    # Wall-clock bound on the curl subprocess forwarding a request upstream.
    curl_timeout_seconds: int = Field(default=30, gt=0)

    # Path to (or PATH-resolved name of) the curl binary. Configurable so
    # tests can substitute a fake executable.
    curl_bin: str = "curl"

    log_level: str = "INFO"

    model_config = {"env_file": ".env", "extra": "ignore"}

    @property
    def broker_jwks_url(self) -> str:
        return f"{self.broker_url.rstrip('/')}/.well-known/jwks.json"


@lru_cache
def get_settings() -> Settings:
    """Return a process-wide cached Settings instance.

    Use as a FastAPI dependency (``Depends(get_settings)``) so ``.env`` is read
    once at first access rather than re-instantiated on every request.
    """
    return Settings()
