# Use specific Python version with security updates
FROM python:3.11.7-slim-bookworm

# Create non-root user for security
RUN groupadd -r discordbot && useradd -r -g discordbot -d /app -s /bin/bash discordbot

# Set working directory
WORKDIR /app

# Install system dependencies and security updates
RUN apt-get update && apt-get install -y \
    gcc \
    && apt-get upgrade -y \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Copy requirements first for better layer caching
COPY requirements.txt .

# Install Python dependencies with security flags
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir --require-hashes --only-binary=all -r requirements.txt || \
    pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY bot.py .
COPY gunicorn.conf.py .

# Create necessary directories with proper permissions
RUN mkdir -p /app/logs && \
    mkdir -p /app/data && \
    chown -R discordbot:discordbot /app

# Set file permissions
RUN chmod 644 bot.py && \
    chmod 644 gunicorn.conf.py && \
    chmod 755 /app/logs && \
    chmod 755 /app/data

# Switch to non-root user
USER discordbot

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/health || exit 1

# Security: Remove write permissions from Python files
RUN find /app -name "*.py" -exec chmod 444 {} \;

# Expose port
EXPOSE 5000

# Run with Gunicorn for production
CMD ["gunicorn", "--config", "gunicorn.conf.py", "bot:app"]