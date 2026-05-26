# Stage 1: Build
FROM docker.io/library/golang:1.26-alpine AS builder
RUN apk add --no-cache git
WORKDIR /app
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /app/vless-sub-server ./cmd/vless-sub-server

# Stage 2: Download Xray geo dat files + CA certs
FROM docker.io/library/alpine:3.21 AS geo-builder
ARG XRAY_VERSION=26.2.6
RUN --mount=type=cache,target=/etc/apk/cache \
    apk add --no-cache curl unzip ca-certificates && \
    mkdir -p /tmp/geo && \
    curl -fsSL "https://github.com/XTLS/Xray-core/releases/download/v${XRAY_VERSION}/Xray-linux-64.zip" \
    -o /tmp/xray.zip && \
    unzip -o /tmp/xray.zip -d /tmp/geo geosite.dat geoip.dat && \
    rm /tmp/xray.zip

# Stage 3.5: Download GeoLite2 databases (optional)
FROM docker.io/library/alpine:3.21 AS mmdb-builder
ARG MAXMIND_LICENSE_KEY=""
RUN if [ -n "$MAXMIND_LICENSE_KEY" ]; then \
      apk add --no-cache curl && \
      mkdir -p /tmp/geoip && \
      cd /tmp/geoip && \
      curl -fsSL "https://download.maxmind.com/app/geoip_download?license_key=${MAXMIND_LICENSE_KEY}&edition_id=GeoLite2-City&suffix=tar.gz" | tar xz && \
      curl -fsSL "https://download.maxmind.com/app/geoip_download?license_key=${MAXMIND_LICENSE_KEY}&edition_id=GeoLite2-ASN&suffix=tar.gz" | tar xz && \
      find /tmp/geoip -name 'GeoLite2-City.mmdb' -exec mv {} /tmp/geoip/GeoLite2-City.mmdb \; && \
      find /tmp/geoip -name 'GeoLite2-ASN.mmdb' -exec mv {} /tmp/geoip/GeoLite2-ASN.mmdb \; && \
      rm -rf /tmp/geoip/GeoLite2-City-* /tmp/geoip/GeoLite2-ASN-*; \
    else \
      mkdir -p /tmp/geoip; \
    fi

# Stage 3: Runtime (scratch — zero OS overhead)
FROM scratch
COPY --from=builder /app/vless-sub-server /usr/local/bin/vless-sub-server
COPY --from=geo-builder /tmp/geo/geosite.dat /usr/local/share/xray/geosite.dat
COPY --from=geo-builder /tmp/geo/geoip.dat /usr/local/share/xray/geoip.dat
COPY --from=mmdb-builder /tmp/geoip/*.mmdb /usr/local/share/xray/
COPY --from=geo-builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

ENV PORT=8080
# SUBSCRIPTION_URLS is required — set at runtime: docker run -e SUBSCRIPTION_URLS=https://...
ENV REFRESH_INTERVAL=30m
ENV GEO_DAT_DIR=/usr/local/share/xray
ENV MAX_CONCURRENT=50
ENV DNS_CACHE_TTL=10m

EXPOSE 8080
USER 1000:1000
ENTRYPOINT ["/usr/local/bin/vless-sub-server"]