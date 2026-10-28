# Build the reviewed locked runtime; no dependency resolution at startup.
FROM ghcr.io/astral-sh/uv:0.13.6 AS uv
FROM python:3.12-alpine AS build
COPY --from=uv /uv /usr/local/bin/uv
RUN --mount=type=secret,id=ca_bundle,target=/etc/ssl/cert.pem \
    apk add --no-cache build-base
WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
RUN --mount=type=secret,id=ca_bundle \
    if [ -f /run/secrets/ca_bundle ]; then export SSL_CERT_FILE=/run/secrets/ca_bundle; fi; \
    uv sync --frozen --extra wpad --no-dev --no-install-project
COPY src ./src
RUN --mount=type=secret,id=ca_bundle \
    if [ -f /run/secrets/ca_bundle ]; then export SSL_CERT_FILE=/run/secrets/ca_bundle; fi; \
    uv sync --frozen --extra wpad --no-dev --no-editable

FROM python:3.12-alpine
RUN --mount=type=secret,id=ca_bundle,target=/etc/ssl/cert.pem \
    apk add --no-cache libstdc++ \
    && addgroup -g 10001 app \
    && adduser -D -u 10001 -G app app
WORKDIR /app
COPY --from=build /app/.venv /app/.venv
ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1
USER 10001:10001
ENTRYPOINT ["mcp-atlassian"]
