FROM ubuntu:22.04

LABEL maintainer="Security Scanner"
LABEL description="Security scanning environment (without ZAP)"

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Europe/Rome

# Update e installazione dipendenze base
RUN apt-get update && apt-get install -y \
    wget \
    curl \
    git \
    python3 \
    python3-pip \
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
# Nuclei Installation
# ========================================
RUN wget -q https://github.com/projectdiscovery/nuclei/releases/download/v3.1.0/nuclei_3.1.0_linux_amd64.zip -O /tmp/nuclei.zip && \
    unzip /tmp/nuclei.zip -d /usr/local/bin && \
    chmod +x /usr/local/bin/nuclei && \
    rm /tmp/nuclei.zip

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

COPY orchestrator.py /scanner/
COPY dashboard.py /scanner/
COPY requirements.txt /scanner/

RUN pip3 install --no-cache-dir -r requirements.txt

RUN mkdir -p /scanner/scan_results /scanner/static /scanner/templates

ENV PYTHONUNBUFFERED=1

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/health || exit 1

CMD ["python3", "dashboard.py"]
EOF