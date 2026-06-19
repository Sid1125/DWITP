FROM postgres:16-alpine

# Inject SSL include into the default config template so every new cluster
# automatically enables TLS with certs from the shared tls_data volume.
RUN echo "include '/etc/postgresql/ssl.conf'" \
    >> /usr/local/share/postgresql/postgresql.conf.sample

COPY infra/docker/postgres/ssl.conf /etc/postgresql/ssl.conf
COPY infra/docker/postgres/enable-mtls.sh /docker-entrypoint-initdb.d/20-enable-mtls.sh
COPY infra/docker/postgres/entrypoint.sh /usr/local/bin/dwitp-entrypoint.sh
RUN chmod +x /usr/local/bin/dwitp-entrypoint.sh

ENTRYPOINT ["/usr/local/bin/dwitp-entrypoint.sh"]
CMD ["postgres"]
