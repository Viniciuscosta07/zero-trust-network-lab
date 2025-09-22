FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Install system dependencies including WireGuard
RUN apt-get update && apt-get install -y \
    gcc \
    libffi-dev \
    libssl-dev \
    wireguard-tools \
    iptables \
    iproute2 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY ../../requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p /app/logs /app/config /etc/wireguard

# Set permissions for WireGuard
RUN chmod 700 /etc/wireguard

# Expose ports
EXPOSE 8002 51820/udp

# Set environment variables
ENV FLASK_APP=app.py
ENV FLASK_ENV=production
ENV PYTHONPATH=/app

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8002/health || exit 1

# Run the application
CMD ["python", "app.py"]
