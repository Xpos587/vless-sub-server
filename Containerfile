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

# Stage 2: Download Xray geo dat files
FROM docker.io/library/alpine:3.21 AS geo-builder
ARG XRAY_VERSION=26.2.6
RUN apk add --no-cache curl unzip
RUN mkdir -p /tmp/geo && \
    curl -fsSL "https://github.com/XTLS/Xray-core/releases/download/v${XRAY_VERSION}/Xray-linux-64.zip" \
    -o /tmp/xray.zip && \
    unzip -o /tmp/xray.zip -d /tmp/geo geosite.dat geoip.dat && \
    rm /tmp/xray.zip

# Stage 3: Runtime (distroless)
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /app/vless-sub-server /usr/local/bin/vless-sub-server
COPY --from=geo-builder /tmp/geo/geosite.dat /usr/local/share/xray/geosite.dat
COPY --from=geo-builder /tmp/geo/geoip.dat /usr/local/share/xray/geoip.dat

ENV PORT=8080
ENV REFRESH_INTERVAL=30m
ENV GEO_DAT_DIR=/usr/local/share/xray
ENV SOCKS_START_PORT=10801

EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/vless-sub-server"]