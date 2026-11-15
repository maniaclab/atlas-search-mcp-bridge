"""Broker token verification with a cached, rate-limited JWKS (contract item U7)."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

import httpx2
import structlog
from af_credentials.verifier import BrokerTokenVerifier

if TYPE_CHECKING:
    from typing import Any

logger = structlog.get_logger(__name__)


class CachedBrokerTokenVerifier(BrokerTokenVerifier):
    """A ``BrokerTokenVerifier`` that fetches the broker JWKS rarely.

    Verification is served from memory. The key set is refetched when
    *cache_ttl* lapses, or early when a token names an unknown ``kid`` (a key
    rotation), and either kind of refetch happens at most once per
    *min_refetch* seconds so a forged ``kid`` cannot turn every request into a
    fetch. A failed refetch keeps the keys already held; with none held the
    failure propagates, as the base class documents.
    """

    def __init__(
        self,
        jwks_url: str,
        issuer: str,
        audience: str,
        *,
        cache_ttl: float = 3600.0,
        min_refetch: float = 30.0,
        http_client: httpx2.AsyncClient | None = None,
    ) -> None:
        super().__init__(
            jwks_url,
            issuer,
            audience,
            cache_ttl=cache_ttl,
            http_client=http_client,
        )
        self._min_refetch = min_refetch
        self._attempted_at = float("-inf")

    async def ensure_keys_loaded(self) -> None:
        """Fetch the JWKS only if none was ever loaded; raise if that fails.

        Readiness uses this so a probe never costs a fetch once keys are held.
        """
        if not self._keys_by_kid:
            await self._refresh_rate_limited()

    async def _get_key(self, kid: str) -> dict[str, Any] | None:
        now = time.monotonic()
        stale = self._fetched_at is None or (now - self._fetched_at) > self._cache_ttl
        if stale or kid not in self._keys_by_kid:
            await self._refresh_rate_limited()
        return self._keys_by_kid.get(kid)

    async def _refresh_rate_limited(self) -> None:
        now = time.monotonic()
        if now - self._attempted_at < self._min_refetch and self._keys_by_kid:
            return
        self._attempted_at = now
        try:
            await self._refresh()
        except httpx2.HTTPError:
            if not self._keys_by_kid:
                raise
            logger.warning("jwks.refetch_failed", exc_info=True)
