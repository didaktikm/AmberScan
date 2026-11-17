FROM oven/bun:1.4.2 AS frontend
WORKDIR /build
COPY frontend/package.json frontend/bun.lock ./
RUN bun install --frozen-lockfile
COPY frontend/ ./
RUN bun run build

FROM ghcr.io/astral-sh/uv:0.13.6 AS uv

FROM python:3.12.11-slim-bookworm AS dependencies
COPY --from=uv /uv /usr/local/bin/uv
WORKDIR /app
ENV UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project --python /usr/local/bin/python

FROM python:3.12.11-slim-bookworm AS application
ARG APP_VERSION=0.5.3
LABEL org.opencontainers.image.version="${APP_VERSION}"
RUN groupadd --gid 10001 workbench && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin workbench
WORKDIR /app
ENV PATH=/app/.venv/bin:$PATH \
    PYTHONPATH=/app/src \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    WEB_DIST_DIR=/app/frontend/dist
COPY --from=dependencies /app/.venv /app/.venv
COPY --from=frontend /build/dist /app/frontend/dist
COPY src/ /app/src/
USER 10001:10001
EXPOSE 8080
CMD ["python", "-m", "uvicorn", "workbench.api:create_app", "--factory", "--host", "0.0.0.0", "--port", "8080", "--no-access-log", "--no-proxy-headers"]

# Offline administrative image: matches the PostgreSQL server's client tools.
# It is never used by the web/worker services and has no public setup endpoint.
FROM postgres:17.5-bookworm AS maintenance
ARG APP_VERSION=0.5.3
LABEL org.opencontainers.image.version="${APP_VERSION}"
COPY --from=dependencies /usr/local /usr/local
COPY --from=application /app /app
WORKDIR /app
ENV PATH=/app/.venv/bin:$PATH \
    PYTHONPATH=/app/src \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
USER 10001:10001
ENTRYPOINT ["python", "-m", "workbench.admin"]
CMD ["--help"]

FROM application AS runtime
