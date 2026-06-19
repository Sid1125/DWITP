FROM python:3.12-slim

RUN groupadd -r tgcollector && useradd -m -u 1000 -g tgcollector tgcollector

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# Telethon (MTProto client) — installed separately because requirements.txt is
# hash-locked and does not pin it yet. See requirements.in. Read-only usage only.
RUN pip install --no-cache-dir "telethon>=1.34,<2"

COPY src/ src/

# Persistent state dir (per-group message high-water marks). Owned by uid 1000 so
# the named volume mounted here stays writable under the read-only rootfs.
RUN mkdir -p /var/lib/dwitp && chown 1000:tgcollector /var/lib/dwitp

USER tgcollector

ENV PYTHONPATH=/app
ENV DWITP_AUDIT_LOG=/var/log/dwitp/audit.log
ENV COLLECTOR_STATE_FILE=/var/lib/dwitp/tg_highwater.json

CMD ["python", "-m", "src.telegram_collector.main"]
