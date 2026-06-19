FROM python:3.12-slim

RUN groupadd -r ganalytics && useradd -m -u 1000 -g ganalytics ganalytics

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# networkx for the SNA metrics — installed separately because requirements.txt is
# hash-locked and does not pin it yet. See requirements.in. scipy is required by
# networkx's pagerank implementation.
RUN pip install --no-cache-dir "networkx>=3.2,<4" "scipy>=1.11,<2"

COPY src/ src/

USER ganalytics

ENV PYTHONPATH=/app
ENV DWITP_AUDIT_LOG=/var/log/dwitp/audit.log

CMD ["python", "-m", "src.graph_analytics.main"]
