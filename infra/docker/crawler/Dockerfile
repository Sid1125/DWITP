FROM python:3.12-slim

RUN groupadd -r crawler && useradd -m -u 1000 -g crawler crawler

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ src/

# Persistent state dir (crawl-once seen-URL set). Owned by uid 1000 so the
# named volume mounted here inherits that ownership and stays writable under the
# read-only rootfs. Distinct from /var/log/dwitp, which is ephemeral tmpfs.
RUN mkdir -p /var/lib/dwitp && chown 1000:crawler /var/lib/dwitp

USER crawler

ENV PYTHONPATH=/app
ENV DWITP_AUDIT_LOG=/var/log/dwitp/audit.log
ENV SEEN_URLS_FILE=/var/lib/dwitp/seen_urls.txt

CMD ["python", "-m", "src.crawler.main"]
