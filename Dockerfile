# Argus Dockerfile - Optimized for Raspberry Pi
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    nmap \
    cron \
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

# Setup cron for weekly scans (default: Sunday 2 AM)
# This will be configured via environment variable or config
RUN echo "0 2 * * 0 cd /app && /usr/local/bin/python scan_cli.py scan --detect-changes >> /var/log/argus-cron.log 2>&1" > /etc/cron.d/argus-scan
RUN chmod 0644 /etc/cron.d/argus-scan
RUN crontab /etc/cron.d/argus-scan

# Create log file
RUN touch /var/log/argus-cron.log

# Environment variables
ENV PYTHONUNBUFFERED=1
ENV DATABASE_URL=sqlite:///./data/argus.db

# Expose web UI port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Create entrypoint script
RUN echo '#!/bin/bash\n\
set -e\n\
\n\
# Start cron in background\n\
cron\n\
\n\
# Initialize database\n\
python -c "from app.database import init_db; init_db()"\n\
\n\
# Start FastAPI application\n\
exec uvicorn app.main:app --host 0.0.0.0 --port 8080\n\
' > /entrypoint.sh && chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
