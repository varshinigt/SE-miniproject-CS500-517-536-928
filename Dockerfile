# Multi-stage container for Pocket Packet Sniffer on Raspberry Pi / Linux (NFR-PORT-01)
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies for capture, monitor mode and wireless analysis
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    tcpdump \
    wireless-tools \
    iw \
    bluez \
    net-tools \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python requirements
COPY requirements.txt requirements-dashboard.txt ./
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt -r requirements-dashboard.txt

# Copy project source tree and default data directory
COPY src/ /app/src/
COPY data/ /app/data/

ENV PYTHONUNBUFFERED=1
ENV PPS_DB_PATH=/app/data/sniffer.db

EXPOSE 8000
EXPOSE 5555/udp

# Default command starts the live monitoring dashboard API
CMD ["uvicorn", "src.dashboard.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
