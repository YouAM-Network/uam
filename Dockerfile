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
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Install dependencies
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

# Copy source
COPY src/ src/
COPY Procfile ./

ENV PYTHONPATH=src
EXPOSE 8000

CMD ["uv", "run", "uvicorn", "uam.relay.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
