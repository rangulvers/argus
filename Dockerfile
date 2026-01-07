# Argus Dockerfile - Optimized for Raspberry Pi
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    nmap \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

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

# Environment variables
ENV PYTHONUNBUFFERED=1
ENV DATABASE_URL=sqlite:///./data/argus.db

# Expose web UI port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Start FastAPI application (scheduler runs in-process via APScheduler)
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
