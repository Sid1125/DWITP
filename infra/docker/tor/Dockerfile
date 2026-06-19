FROM alpine:3.20

RUN for i in 1 2 3 4 5; do apk add --no-cache tor && break || [ "$i" = 5 ] && exit 1; sleep 3; done \
    && adduser -D -u 1000 toruser \
    && chown -R toruser:toruser /etc/tor

COPY torrc /etc/tor/torrc.template
COPY entrypoint.sh /entrypoint.sh

USER toruser

EXPOSE 9050 9051

ENTRYPOINT ["/bin/sh", "/entrypoint.sh"]
