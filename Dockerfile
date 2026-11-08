FROM python:3.12-slim

# System dependencies for CairoSVG (libcairo2) and Pillow
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        libcairo2-dev \
        libffi-dev \
        libjpeg62-turbo-dev \
        libpng-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install uv for fast dependency resolution
COPY --from=ghcr.io/astral-sh/uv:0.13.6@sha256:af22a52f5eafef3d78e551599d405c02df61919d18028f0cea8eda93bc9986d0 /uv /usr/local/bin/uv

# Install dependencies
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

# Copy source and Alembic migrations
COPY src/ src/
COPY alembic.ini ./
COPY alembic/ alembic/

ENV PYTHONPATH=src
EXPOSE 8000

# --no-sync: run the environment built above; touch nothing at boot.
# --ws-max-size: refuse an oversized frame before it is read into memory (the
# relay's own limit on an envelope is 64 KB). PORT is set by the platform (Railway).
CMD ["sh", "-c", "exec uv run --no-sync uvicorn uam.relay.app:create_app --factory --host 0.0.0.0 --port ${PORT:-8000} --ws-max-size 131072"]
