# Argus Dockerfile - Optimized for Raspberry Pi
FROM python:3.11-slim

# Build arguments for version info (can be overridden by CI)
ARG ARGUS_VERSION=
ARG ARGUS_COMMIT=
ARG ARGUS_BRANCH=
ARG ARGUS_BUILD_DATE=

# Set working directory
WORKDIR /app

# Install system dependencies including git for version detection
RUN apt-get update && apt-get install -y \
    nmap \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy .git for version detection
COPY .git ./.git

# Copy application code
COPY app/ ./app/
COPY templates/ ./templates/
COPY static/ ./static/
COPY scan_cli.py .
COPY config.yaml.example ./config.yaml

# Create data directory
RUN mkdir -p /app/data

# Make CLI executable
RUN chmod +x scan_cli.py

# Generate version info if not provided via build args
RUN if [ -z "$ARGUS_VERSION" ] && [ -d .git ]; then \
        ARGUS_VERSION=$(git describe --tags --always 2>/dev/null || echo "dev-$(git rev-parse --short HEAD 2>/dev/null || echo 'unknown')"); \
        ARGUS_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo ""); \
        ARGUS_BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo ""); \
        ARGUS_BUILD_DATE=$(date -u +'%Y.%m.%d'); \
    fi && \
    echo "ARGUS_VERSION=${ARGUS_VERSION:-dev}" > /app/.version && \
    echo "ARGUS_COMMIT=${ARGUS_COMMIT}" >> /app/.version && \
    echo "ARGUS_BRANCH=${ARGUS_BRANCH}" >> /app/.version && \
    echo "ARGUS_BUILD_DATE=${ARGUS_BUILD_DATE:-$(date -u +'%Y.%m.%d')}" >> /app/.version

# Clean up .git to reduce image size
RUN rm -rf .git

# Environment variables
ENV PYTHONUNBUFFERED=1
ENV DATABASE_URL=sqlite:///./data/argus.db

# Version info (from build args or generated)
ENV ARGUS_VERSION=${ARGUS_VERSION}
ENV ARGUS_COMMIT=${ARGUS_COMMIT}
ENV ARGUS_BRANCH=${ARGUS_BRANCH}
ENV ARGUS_BUILD_DATE=${ARGUS_BUILD_DATE}

# Expose web UI port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Start FastAPI application (scheduler runs in-process via APScheduler)
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
