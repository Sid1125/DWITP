FROM python:3.12-slim

RUN groupadd -r analysis && useradd -m -u 1000 -g analysis analysis

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN python -m spacy download en_core_web_sm

COPY src/ src/

USER analysis

ENV PYTHONPATH=/app
ENV DWITP_AUDIT_LOG=/var/log/dwitp/audit.log

CMD ["python", "-m", "src.analysis.main"]
