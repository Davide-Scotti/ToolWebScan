FROM python:3.9-slim

WORKDIR /app

# Install system dependencies + security tools
RUN apt-get update && apt-get install -y \
    wget \
    curl \
    git \
    nmap \
    perl \
    && rm -rf /var/lib/apt/lists/*

# Install Nikto
RUN git clone https://github.com/sullo/nikto.git /opt/nikto \
    && ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto

# Install testssl.sh
RUN git clone https://github.com/drwetter/testssl.sh.git /opt/testssl.sh \
    && ln -s /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh

# Copy Python requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY orchestrator.py .
COPY webapp_scanner.py .
COPY dashboard.py .
COPY dashboard_template.html .

# Create directories
RUN mkdir -p scan_results templates static

# Expose port
EXPOSE 5000

# Run dashboard
CMD ["python", "dashboard.py"]