FROM python:3.9-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    wget \
    curl \
    git \
    nmap \
    nikto \
    whatweb \
    dirb \
    gobuster \
    net-tools \
    default-jre \
    perl \
    libssl-dev \
    libffi-dev \
    build-essential \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Nuclei
RUN wget -q https://github.com/projectdiscovery/nuclei/releases/download/v3.1.0/nuclei_3.1.0_linux_amd64.zip \
    && unzip nuclei_3.1.0_linux_amd64.zip \
    && mv nuclei /usr/local/bin/ \
    && rm nuclei_3.1.0_linux_amd64.zip

# Install SQLMap
RUN git clone https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap \
    && ln -s /opt/sqlmap/sqlmap.py /usr/local/bin/sqlmap

# Install testssl.sh
RUN git clone https://github.com/drwetter/testssl.sh.git /opt/testssl.sh \
    && ln -s /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY orchestrator.py .
COPY dashboard.py .
COPY scanner.py .
COPY requirements.txt .

# Create necessary directories
RUN mkdir -p scan_results templates static

# Create dashboard template
RUN mkdir -p templates && \
    echo '<!DOCTYPE html><html><head><title>Security Scanner</title></head><body><h1>Security Scanner Dashboard</h1></body></html>' > templates/dashboard.html

# Expose port
EXPOSE 5000

# Start the application
CMD ["python", "dashboard.py"]