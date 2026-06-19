FROM python:3.12-slim

RUN groupadd -r dashboard && useradd -m -u 1000 -g dashboard dashboard

RUN apt-get update && apt-get install -y --no-install-recommends \
    openssl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# OpenSearch client — installed separately because the hash-locked requirements.txt
# still pins the incompatible elasticsearch client. See requirements.in.
RUN pip install --no-cache-dir "opensearch-py>=2.4.0,<3"

COPY src/ src/
COPY infra/docker/dashboard/entrypoint.sh /entrypoint.sh

USER dashboard

ENV PYTHONPATH=/app
ENV DWITP_AUDIT_LOG=/var/log/dwitp/audit.log
ENV DASHBOARD_HTTPS_CERT=/app/certs/cert.pem
ENV DASHBOARD_HTTPS_KEY=/app/certs/key.pem

ENTRYPOINT ["/bin/bash", "/entrypoint.sh"]
