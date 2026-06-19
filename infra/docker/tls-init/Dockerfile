FROM alpine:3.19

RUN for i in 1 2 3 4 5; do apk add --no-cache openssl bash && break || [ "$i" = 5 ] && exit 1; sleep 3; done

COPY init.sh /init.sh
RUN chmod +x /init.sh

VOLUME ["/etc/dwitp/tls"]
CMD ["/init.sh"]
