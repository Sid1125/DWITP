FROM python:3.12-slim

RUN groupadd -r sanitizer && useradd -m -u 1000 -g sanitizer sanitizer

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ src/

USER sanitizer

ENV PYTHONPATH=/app
ENV DWITP_AUDIT_LOG=/var/log/dwitp/audit.log

CMD ["python", "-m", "src.sanitizer.main"]
