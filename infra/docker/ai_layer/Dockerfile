FROM python:3.12-slim

RUN groupadd -r ai && useradd -m -u 1000 -g ai ai

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ src/

USER ai

ENV PYTHONPATH=/app
ENV DWITP_AUDIT_LOG=/var/log/dwitp/audit.log

CMD ["python", "-m", "src.ai_layer.main"]
