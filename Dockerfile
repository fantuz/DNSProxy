# Debian's multi-architecture index; update deliberately when refreshing the base.
ARG DEBIAN_IMAGE=debian:13-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2
FROM ${DEBIAN_IMAGE} AS build
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential pkg-config libcurl4-openssl-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY dnsp-modern.c dnsp-platform.h dnsp-service.h dnsp-policy.h modern.mk VERSION ./
RUN make -f modern.mk dnsp-modern \
        CFLAGS="$(dpkg-buildflags --get CFLAGS) -Werror" \
        CPPFLAGS="$(dpkg-buildflags --get CPPFLAGS)" \
        LDFLAGS="$(dpkg-buildflags --get LDFLAGS) -Wl,-z,now" \
    && strip --strip-unneeded dnsp-modern \
    && ./dnsp-modern --version

FROM ${DEBIAN_IMAGE} AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
ARG IMAGE_VERSION=source
ARG IMAGE_REVISION=unknown
ARG IMAGE_CREATED
LABEL org.opencontainers.image.title="DNSProxy" \
      org.opencontainers.image.description="DNS over UDP/TCP to DNS-over-HTTPS resolver" \
      org.opencontainers.image.source="https://github.com/fantuz/DNSProxy" \
      org.opencontainers.image.url="https://github.com/fantuz/DNSProxy" \
      org.opencontainers.image.version="${IMAGE_VERSION}" \
      org.opencontainers.image.revision="${IMAGE_REVISION}" \
      org.opencontainers.image.created="${IMAGE_CREATED}" \
      org.opencontainers.image.licenses="MIT"
COPY --from=build /src/dnsp-modern /usr/local/bin/dnsp-modern
COPY LICENSE /usr/share/doc/dnsp-modern/LICENSE
COPY --chmod=0555 packaging/container/healthcheck.sh /usr/local/bin/dnsp-healthcheck
USER 10001:10001
EXPOSE 5300/udp 5300/tcp
ENV DNSP_HEALTH_PORT=9153
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/dnsp-healthcheck"]
ENTRYPOINT ["/usr/local/bin/dnsp-modern"]
CMD ["-l", "0.0.0.0", "-p", "5300", "-m", "9153", "-s", "https://cloudflare-dns.com/dns-query", "--bootstrap-address", "1.1.1.1", "--cache-entries", "256"]
