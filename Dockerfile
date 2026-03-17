FROM python:3.13-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install UV
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Copy project files
COPY pyproject.toml ./
COPY src/ src/
COPY rules/ rules/
COPY config/ config/

# Install dependencies
RUN uv sync --no-dev

# Create data directories
RUN mkdir -p /data /run/claude-edr

# Expose dashboard port
EXPOSE 7400

# Override dashboard host to 0.0.0.0 for Docker networking
ENV CLAUDE_EDR_DASHBOARD_HOST=0.0.0.0

# Run the daemon
CMD ["uv", "run", "claude-edr", "start"]
