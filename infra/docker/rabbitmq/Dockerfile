FROM rabbitmq:3.13-alpine

RUN for i in 1 2 3 4 5; do apk add --no-cache openssl && break || [ "$i" = 5 ] && exit 1; sleep 3; done

COPY infra/tls/gen-ca.sh /usr/local/bin/gen-ca.sh
COPY infra/tls/gen-cert.sh /usr/local/bin/gen-cert.sh
COPY infra/tls/entrypoint-tls.sh /usr/local/bin/entrypoint-tls.sh
COPY infra/docker/rabbitmq/entrypoint.sh /usr/local/bin/rabbitmq-entrypoint.sh

RUN chmod +x /usr/local/bin/gen-ca.sh /usr/local/bin/gen-cert.sh \
    /usr/local/bin/entrypoint-tls.sh /usr/local/bin/rabbitmq-entrypoint.sh

ENTRYPOINT ["rabbitmq-entrypoint.sh"]
CMD ["rabbitmq-server"]
