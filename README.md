# atlas-search-mcp-bridge

Auth-translation reverse proxy for the UChicago ATLAS Analysis Facility MCP
platform. A sibling of
[krb5-token-service](https://github.com/maniaclab/krb5-token-service),
following the same scaffolding and the same AF Broker Identity Token
protocol.

## Why this service exists

CERN's OpenSearch cluster exposes an MCP endpoint
(`_plugins/_ml/mcp`) behind Apache's SPNEGO gate (Negotiate-only — no Basic
or Bearer auth passthrough). [af-mcp-platform](https://github.com/maniaclab/af-mcp-platform)'s
aggregator, however, only ever injects an `Authorization: Bearer <AF Broker
Identity Token>` for a service marked `auth_type: "krb5"` — the same "mint
and inject, let the backend redeem" shape as `auth_type: "x509"` — and
expects the target backend to redeem the actual credential itself. CERN's
OpenSearch cluster is a third-party service with no idea what an AF Broker
Identity Token is, so something has to sit in between.

This service is that something: a thin, stateless reverse proxy with **no
MCP/JSON-RPC awareness at all**. Per request, it:

1. Verifies the inbound `Authorization: Bearer` token against the broker's
   published JWKS ([af_credentials.verifier.BrokerTokenVerifier](https://github.com/maniaclab/af-credentials)).
2. Redeems a Kerberos ticket for that token's subject from the broker
   ([af_credentials.proxy.ProxyClient](https://github.com/maniaclab/af-credentials),
   `kind="krb5"`) — materialized as a private, 0600 ccache file.
3. Forwards the exact request body/headers (`Authorization` dropped, hop-by-hop
   headers stripped) to the real CERN OpenSearch endpoint via
   `curl --negotiate`, with `KRB5CCNAME` pointed at that ccache. curl performs
   the full SPNEGO handshake (401 challenge, Negotiate retry) itself.
4. Returns curl's response — status, content-type, body — verbatim. The
   ccache file is deleted the moment the call finishes, success or failure.

```
af-mcp-platform aggregator          atlas-search-mcp-bridge              CERN OpenSearch
        |  POST /mcp                        |                                  |
        |  Authorization: Bearer <AF token>  |                                  |
        +----------------------------------->|                                  |
        |                          verify token (broker JWKS)                   |
        |                          redeem krb5 ticket:                          |
        |                          ProxyClient(kind="krb5").ticket_file(token)  |
        |                          -> POST {broker}/v1/credentials/krb5/redeem  |
        |                          -> private 0600 ccache file                  |
        |                          curl -s --negotiate -u : -X <method> <url>   |
        |                            --data-binary @- (body piped via stdin)    |
        |                            env: KRB5CCNAME=<ccache path>              |
        |                                                                       +--->|
        |                                                                       |<---+
        |                          ccache file deleted (handle.close())         |
        |<------------------------------------------------------------------------- |
        |  response body/status/content-type forwarded verbatim                |
```

One deployment serves exactly one CERN cluster (`dev` or `prod`) —
`TARGET_URL` is a deploy-time config value, not a per-request parameter,
mirroring how `af-mcp-platform`'s `rucio_atlas_service`/`rucio_escape_service`
are two separate aggregator entries rather than one parameterized one.

Transparent byte-level proxying (rather than parsing and re-emitting
individual JSON-RPC messages) is deliberate: it makes no assumption about
OpenSearch's actual session/streaming semantics.

## Configuration

Env-driven (`src/atlas_search_mcp_bridge/config.py`):

| Variable | Default | Meaning |
| --- | --- | --- |
| `BROKER_URL` | `http://localhost:8080` | The broker this bridge redeems tickets from and verifies tokens against. Also the base for the JWKS URL (`{BROKER_URL}/.well-known/jwks.json`). |
| `BROKER_ISSUER` | `https://mcp.af.uchicago.edu` | Required `iss` claim on inbound AF Broker Identity Tokens. |
| `EXPECTED_AUDIENCE` | `atlas-search-mcp-bridge` | Required `aud` claim — must equal `atlas_search_service`'s `audience:` in af-mcp-platform's `services.yaml`. |
| `TARGET_URL` | the dev OpenSearch host | The real CERN OpenSearch MCP endpoint this deployment forwards to. |
| `CURL_TIMEOUT_SECONDS` | `30` | Wall-clock bound on the curl subprocess. |
| `CURL_BIN` | `curl` | Path to (or PATH-resolved name of) the curl binary. |
| `LOG_LEVEL` | `INFO` | |

## API

| Endpoint | Auth | Behavior |
| --- | --- | --- |
| `GET`/`POST`/`DELETE` `/{path}` | `Authorization: Bearer <AF Broker Identity Token>` | Verifies the token, redeems a krb5 ticket for its subject, forwards the request to `TARGET_URL` via `curl --negotiate`. 401 on a missing/invalid/expired token; 404 if the caller has no linked/mintable krb5 credential (`ProxyNotAvailableError`); 502 if the broker's redeem call itself fails (`ProxyRedeemError`) or curl fails; 504 if curl times out. |
| `GET /healthz` | none | Always 200. |
| `GET /readyz` | none | 200 only when curl is executable and the broker JWKS is fetchable — deliberately does **not** probe the real CERN OpenSearch target (a CERN-side outage must not flap this pod's readiness). |

## Development

```
pixi run -e dev test        # unit + integration tests
pixi run -e dev lint-all    # ruff + mypy + pre-commit
pixi run -e service serve   # dev server at http://localhost:8080
```

True e2e against real CERN infrastructure (a live broker, a real linked krb5
identity, and the real OpenSearch cluster) is not exercised by the automated
test suite — there is no real CERN credential available in CI. It is
reserved for a manual, gated run against the dev deployment.
