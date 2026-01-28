FROM ubuntu:22.04

LABEL maintainer="Security Scanner"
LABEL description="Complete security scanning environment with multiple tools"

# Evita prompt interattivi
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Europe/Rome

# Update e installazione dipendenze base
RUN apt-get update && apt-get install -y \
    wget \
    curl \
    git \
    python3 \
    python3-pip \
    default-jdk \
    perl \
    libnet-ssleay-perl \
    openssl \
    libssl-dev \
    libcrypt-ssleay-perl \
    libwhisker2-perl \
    nmap \
    unzip \
    bsdmainutils \
    dnsutils \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

# Installazione Python dependencies
RUN pip3 install --no-cache-dir \
    requests \
    beautifulsoup4 \
    colorama \
    flask \
    flask-cors \
    python-dateutil

# ========================================
# OWASP ZAP Installation
# ========================================
RUN wget -q https://github.com/zaproxy/zaproxy/releases/download/v2.14.0/ZAP_2.14.0_Linux.tar.gz -O /tmp/zap.tar.gz && \
    tar -xzf /tmp/zap.tar.gz -C /opt && \
    rm /tmp/zap.tar.gz && \
    ln -s /opt/ZAP_*/zap.sh /usr/local/bin/zap.sh

# ========================================
# Nuclei Installation
# ========================================
RUN wget -q https://github.com/projectdiscovery/nuclei/releases/download/v3.1.0/nuclei_3.1.0_linux_amd64.zip -O /tmp/nuclei.zip && \
    unzip /tmp/nuclei.zip -d /usr/local/bin && \
    chmod +x /usr/local/bin/nuclei && \
    rm /tmp/nuclei.zip

# Download Nuclei templates
RUN nuclei -update-templates

# ========================================
# Nikto Installation
# ========================================
RUN git clone https://github.com/sullo/nikto.git /opt/nikto && \
    ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto && \
    chmod +x /usr/local/bin/nikto

# ========================================
# SQLMap Installation
# ========================================
RUN git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap && \
    ln -s /opt/sqlmap/sqlmap.py /usr/local/bin/sqlmap && \
    chmod +x /usr/local/bin/sqlmap

# ========================================
# Testssl.sh Installation
# ========================================
RUN git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl && \
    ln -s /opt/testssl/testssl.sh /usr/local/bin/testssl.sh && \
    chmod +x /usr/local/bin/testssl.sh

# ========================================
# Wapiti Installation
# ========================================
RUN pip3 install --no-cache-dir wapiti3

# ========================================
# Directory setup
# ========================================
WORKDIR /scanner

# Copy orchestrator e dashboard
COPY orchestrator.py /scanner/
COPY dashboard.py /scanner/
COPY requirements.txt /scanner/

# Install additional Python requirements
RUN pip3 install --no-cache-dir -r requirements.txt

# Create results directory
RUN mkdir -p /scanner/scan_results /scanner/static /scanner/templates

# ========================================
# Environment variables
# ========================================
ENV PYTHONUNBUFFERED=1
ENV PATH="/opt/ZAP_*:${PATH}"

# Expose port for dashboard
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/health || exit 1

# Default command
CMD ["python3", "dashboard.py"]