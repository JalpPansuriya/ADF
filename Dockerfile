# Checkpoint Service image.
FROM python:3.12-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Dependency layer first so source edits do not invalidate the pip cache.
COPY pyproject.toml ./
COPY checkpoint_service/__init__.py ./checkpoint_service/__init__.py
RUN pip install --no-cache-dir -e .

COPY checkpoint_service/ ./checkpoint_service/
COPY alembic.ini ./
COPY migrations/ ./migrations/
COPY sensitive_scopes.yaml ./

# Run as a non-root user: the API is network-exposed and holds the signing key.
RUN useradd --create-home --shell /usr/sbin/nologin adf \
    && chown -R adf:adf /app
USER adf

EXPOSE 8000

# entrypoint.sh applies migrations before serving, so a fresh volume comes up
# with the correct schema instead of failing on first request.
COPY --chown=adf:adf docker-entrypoint.sh /app/docker-entrypoint.sh
ENTRYPOINT ["/bin/sh", "/app/docker-entrypoint.sh"]
CMD ["uvicorn", "checkpoint_service.main:app", "--host", "0.0.0.0", "--port", "8000"]
