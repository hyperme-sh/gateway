# syntax=docker/dockerfile:1
# Build only the context produced by scripts/prepare-runtime-context.py.
FROM python:3.13-alpine@sha256:9ef1a599f863231c3d91e941389bfdc4a2d6070557243d54df1a4e57015b960e AS builder
COPY --from=ghcr.io/astral-sh/uv:0.11.26@sha256:3d868e555f8f1dbc324afa005066cd11e1053fc4743b9808ca8025283e65efa5 /uv /usr/local/bin/uv
WORKDIR /app
ENV UV_HTTP_TIMEOUT=120
COPY requirements.txt /packages/requirements.txt
COPY wheels/ /packages/wheels/
RUN uv venv --python /usr/local/bin/python /app/.venv \
    && uv pip sync --python /app/.venv/bin/python --require-hashes /packages/requirements.txt \
    && uv pip install --python /app/.venv/bin/python --no-index --no-deps /packages/wheels/*.whl \
    && uv pip check --python /app/.venv/bin/python

FROM python:3.13-alpine@sha256:9ef1a599f863231c3d91e941389bfdc4a2d6070557243d54df1a4e57015b960e
RUN apk add --no-cache ca-certificates iproute2 wireguard-tools nftables
WORKDIR /app
COPY --from=builder /app/.venv /app/.venv
COPY docker-entrypoint.sh /docker-entrypoint.sh
ARG SOURCE_SHA
ARG BUILT_AT
LABEL org.opencontainers.image.source="https://github.com/hyperme-sh/hypermesh-gateway" \
      org.opencontainers.image.revision="${SOURCE_SHA}"
ENV PATH="/app/.venv/bin:${PATH}" PYTHONPATH="" PYTHONDONTWRITEBYTECODE=1 \
    GIT_SHA=${SOURCE_SHA} HYPERMESH_GATEWAY_SOURCE_SHA=${SOURCE_SHA} BUILT_AT=${BUILT_AT}
# WireGuard uses the existing deployment's NET_ADMIN and tun contract.
# This image neither grants capabilities nor publishes host ports.
ENTRYPOINT ["/bin/sh", "/docker-entrypoint.sh"]
CMD ["/app/.venv/bin/python", "-I", "-m", "hypermesh_gateway_service.main"]
