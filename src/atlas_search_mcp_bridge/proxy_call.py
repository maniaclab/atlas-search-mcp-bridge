"""Forwards one HTTP request upstream via ``curl --negotiate``, authenticated
by a Kerberos ccache redeemed from the broker.

This is the auth-translation core of the bridge: byte-level, transparent
proxying (see the module's design doc,
flux_apps/docs/plans/2026-09-04-atlas-search-mcp-bridge-design.md) with no
MCP/JSON-RPC awareness at all. ``curl`` performs the full SPNEGO handshake
(initial unauthenticated request, 401 challenge, Negotiate retry) itself;
this module only has to point it at the right ccache and interpret its
output.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, NamedTuple

if TYPE_CHECKING:
    from collections.abc import Mapping

# Headers that must never be forwarded upstream verbatim: hop-by-hop headers
# (RFC 9110 §7.6.1) plus Authorization (this bridge's whole job is to swap
# it for a Negotiate challenge/response curl performs itself) and Host
# (curl sets its own from target_url).
_DROPPED_HEADERS = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "authorization",
        "host",
        "content-length",  # curl recomputes this for --data-binary
    }
)


class UpstreamCallError(Exception):
    """curl exited non-zero, or its output could not be parsed as an HTTP response."""

    def __init__(self, detail: str) -> None:
        super().__init__(detail)
        self.detail = detail


class UpstreamTimeoutError(UpstreamCallError):
    """The upstream request did not complete within the configured timeout."""


class UpstreamResponse(NamedTuple):
    status_code: int
    content_type: str | None
    body: bytes


def forwardable_headers(headers: Mapping[str, str]) -> dict[str, str]:
    """Headers to forward upstream: drop hop-by-hop headers, Authorization, and Host."""
    return {k: v for k, v in headers.items() if k.lower() not in _DROPPED_HEADERS}


def call_upstream(
    *,
    method: str,
    body: bytes,
    headers: Mapping[str, str],
    target_url: str,
    ccache_path: Path,
    timeout: float,
    curl_bin: str = "curl",
) -> UpstreamResponse:
    """Forward *method*/*body*/*headers* to *target_url* via ``curl --negotiate``.

    *ccache_path* is exported as ``KRB5CCNAME`` for curl's own GSSAPI layer
    to use — this function never touches ticket material itself. Runs
    synchronously; callers on an event loop should offload via
    ``asyncio.to_thread`` (mirrors krb5-token-service's own subprocess
    pattern for kinit).

    Raises ``UpstreamTimeoutError`` if curl does not finish within *timeout*,
    or ``UpstreamCallError`` for a non-zero curl exit or an unparseable
    response.
    """
    with tempfile.TemporaryDirectory(prefix="atlas-search-bridge-") as tmpdir:
        header_file = Path(tmpdir) / "headers"
        body_file = Path(tmpdir) / "body"

        curl_headers: list[str] = []
        for name, value in forwardable_headers(headers).items():
            curl_headers += ["-H", f"{name}: {value}"]

        cmd = [
            curl_bin,
            "-s",
            "--negotiate",
            "-u",
            ":",
            "-D",
            str(header_file),
            "-o",
            str(body_file),
            "-X",
            method,
            target_url,
            *curl_headers,
            "--max-time",
            str(timeout),
        ]
        # Only attach a request body for methods/calls that actually carry
        # one -- passing --data-binary on a bodyless GET/DELETE would force
        # curl to treat stdin as data regardless, which is harmless for curl
        # itself but pointlessly pipes an empty stream through every call.
        if body:
            cmd += ["--data-binary", "@-"]

        env = os.environ.copy()
        env["KRB5CCNAME"] = str(ccache_path)

        try:
            # curl's own --max-time is the real enforcement boundary; the
            # small buffer here is a hard backstop in case curl itself hangs
            # past it (e.g. stuck in a DNS resolver call --max-time doesn't
            # cover), not the primary timeout mechanism.
            result = subprocess.run(
                cmd,
                input=body,
                env=env,
                timeout=timeout + 2,
                capture_output=True,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise UpstreamTimeoutError(
                f"upstream request to {target_url} timed out after {timeout}s"
            ) from exc

        if result.returncode != 0:
            stderr = result.stderr.decode(errors="replace").strip()
            raise UpstreamCallError(
                f"curl exited {result.returncode} calling {target_url}: {stderr[:200]}"
            )

        if not header_file.exists():
            raise UpstreamCallError(
                f"curl produced no response headers for {target_url}"
            )

        status_code, content_type = _parse_last_header_block(
            header_file.read_text(errors="replace")
        )
        response_body = body_file.read_bytes() if body_file.exists() else b""
        return UpstreamResponse(
            status_code=status_code, content_type=content_type, body=response_body
        )


def _parse_last_header_block(raw: str) -> tuple[int, str | None]:
    """Parse curl's ``-D`` dump, returning the FINAL response's status and content-type.

    curl's SPNEGO negotiation (the initial unauthenticated request, its 401
    challenge, and the Negotiate retry) can write more than one header block
    to this file — only the last one describes the response actually
    delivered to ``-o``.
    """
    normalized = raw.replace("\r\n", "\n")
    blocks = [block for block in normalized.split("\n\n") if block.strip()]
    if not blocks:
        raise UpstreamCallError("no response headers received from upstream")

    last = blocks[-1]
    lines = last.splitlines()
    status_line = lines[0]
    parts = status_line.split(None, 2)
    if len(parts) < 2 or not parts[1].isdigit():
        raise UpstreamCallError(
            f"unparseable status line from upstream: {status_line!r}"
        )
    status_code = int(parts[1])

    content_type: str | None = None
    for line in lines[1:]:
        if ":" not in line:
            continue
        name, _, value = line.partition(":")
        if name.strip().lower() == "content-type":
            content_type = value.strip()
    return status_code, content_type
