# UAM Relay - Production Docker Image
# Multi-stage build for minimal image size

# ---- Stage 1: Builder ----
FROM python:3.12-slim AS builder

WORKDIR /build

# Copy package definition and source
COPY pyproject.toml ./
COPY src/ ./src/

# Install the package with relay extras
RUN pip install --no-cache-dir --prefix=/install ".[relay]"

# ---- Stage 2: Runtime ----
FROM python:3.12-slim AS runtime

# Install curl for healthcheck
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r uam && useradd -r -g uam -d /app -s /sbin/nologin uam

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local
COPY --from=builder /build/src /app/src

# Set PYTHONPATH so uvicorn can find the uam package
ENV PYTHONPATH=/app/src

# Default environment variables
ENV UAM_HOST=0.0.0.0
ENV UAM_PORT=8000
ENV UAM_DB_PATH=/app/data/relay.db
ENV UAM_RELAY_KEY_PATH=/app/data/relay_key.pem

# Create data directory for database and key files
RUN mkdir -p /app/data && chown -R uam:uam /app

# Expose the relay port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Run as non-root user
USER uam

# Start the relay
CMD ["uvicorn", "uam.relay.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
