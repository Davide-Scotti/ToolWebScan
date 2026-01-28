FROM python:3.9-slim

WORKDIR /app

# Install system dependencies - RIMUOVI nikto dalla lista APT
RUN apt-get update && apt-get install -y \
    wget \
    curl \
    git \
    nmap \
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
    sqlmap \
    && rm -rf /var/lib/apt/lists/*

# Installa Nikto da GitHub (invece che da APT)
RUN git clone https://github.com/sullo/nikto.git /opt/nikto \
    && ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto \
    && chmod +x /usr/local/bin/nikto

# Installa testssl.sh da GitHub
RUN git clone https://github.com/drwetter/testssl.sh.git /opt/testssl.sh \
    && ln -s /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh \
    && chmod +x /usr/local/bin/testssl.sh

# Installa nuclei
RUN wget -q https://github.com/projectdiscovery/nuclei/releases/download/v3.1.0/nuclei_3.1.0_linux_amd64.zip \
    && unzip nuclei_3.1.0_linux_amd64.zip \
    && mv nuclei /usr/local/bin/ \
    && chmod +x /usr/local/bin/nuclei \
    && rm nuclei_3.1.0_linux_amd64.zip

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