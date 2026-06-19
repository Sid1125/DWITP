FROM python:3.12-slim

RUN groupadd -r dbwriter && useradd -m -u 1000 -g dbwriter dbwriter

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# OpenSearch client — installed separately because the hash-locked requirements.txt
# still pins the incompatible elasticsearch client. See requirements.in.
RUN pip install --no-cache-dir "opensearch-py>=2.4.0,<3"

COPY src/ src/

USER dbwriter

ENV PYTHONPATH=/app
ENV DWITP_AUDIT_LOG=/var/log/dwitp/audit.log

CMD ["python", "-m", "src.db_writer.main"]
