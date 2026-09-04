FROM ghcr.io/prefix-dev/pixi:latest AS builder

WORKDIR /app
COPY . .

# Install only the service feature, not dev. curl/klist come from
# conda-forge's `curl`/`krb5` packages (see pixi.toml) -- like
# krb5-token-service's `krb5` package, the Kerberos-aware curl binary rides
# in the same pixi environment as the Python service, so no extra
# package-manager step is needed in the runtime stage below.
RUN pixi install --frozen --environment service

# Capture pixi's full activation (PATH, and anything else the environment
# needs) as a static entrypoint script, so the final image needs no pixi
# binary at runtime.
RUN echo '#!/bin/bash' > /app/entrypoint.sh && \
    pixi shell-hook --manifest-path /app/pixi.toml --environment service -s bash >> /app/entrypoint.sh && \
    echo 'exec "$@"' >> /app/entrypoint.sh && \
    chmod +x /app/entrypoint.sh

# Final stage: debian:bookworm-slim, matching krb5-token-service's
# Containerfile layout (and staying binary-compatible with the pixi-built
# environment copied from the builder stage). ca-certificates is needed at
# runtime for httpx2 to verify the broker's JWKS TLS endpoint and for curl
# to verify the CERN OpenSearch TLS endpoint.
FROM debian:bookworm-slim
WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Keep the same absolute path as the builder stage: the entrypoint script's
# activation exports (and any console-script shebangs, e.g. uvicorn) are
# baked in at this exact path, and relocating the env directory breaks them.
COPY --from=builder /app/.pixi/envs/service /app/.pixi/envs/service
COPY --from=builder /app/src /app/src
COPY --from=builder /app/entrypoint.sh /app/entrypoint.sh
# Baked in, same as krb5-token-service's own etc/krb5.conf: curl's GSSAPI
# layer needs to know CERN.CH's KDC to build a service ticket for the
# target SPN from the ccache's TGT -- without a krb5.conf naming it, every
# --negotiate call fails regardless of how valid the ccache itself is.
COPY etc/krb5.conf /app/etc/krb5.conf

ENV PYTHONPATH="/app/src" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    KRB5_CONFIG=/app/etc/krb5.conf

# This service holds no standing secret between requests: it receives a
# bearer identity token, redeems a per-request ccache from the broker, and
# deletes it as soon as one call finishes. No on-disk user credential, no
# elevated capability -- a single unprivileged uid for its whole lifetime,
# same posture as krb5-token-service.
USER 1000:1000

EXPOSE 8080
ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["uvicorn", "atlas_search_mcp_bridge.app:app", "--host", "0.0.0.0", "--port", "8080"]
