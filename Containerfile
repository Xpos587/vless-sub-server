# Stage 1: Build Bun app
FROM docker.io/library/oven/bun:1.2-alpine AS builder
WORKDIR /app

COPY package.json bun.lock* ./
RUN --mount=type=cache,target=/root/.bun/install/cache \
    bun install --frozen-lockfile --production

COPY tsconfig.json ./
COPY src/ ./src/
RUN bun build ./src/server.ts --compile --outfile /app/vless-sub-server

# Stage 2: Download Xray
FROM docker.io/library/alpine:3.21 AS xray-builder
ARG XRAY_VERSION=26.2.6
RUN apk add --no-cache curl unzip
RUN curl -fsSL \
    "https://github.com/XTLS/Xray-core/releases/download/v${XRAY_VERSION}/Xray-linux-64.zip" \
    -o /tmp/xray.zip \
    && unzip -o /tmp/xray.zip -d /tmp/xray xray \
    && chmod +x /tmp/xray/xray \
    && rm /tmp/xray.zip

# Stage 3: Runtime
FROM docker.io/library/alpine:3.21
RUN apk add --no-cache ca-certificates curl tini \
    && adduser -D -u 1000 appuser

COPY --from=xray-builder /tmp/xray/xray /usr/local/bin/xray
COPY --from=builder /app/vless-sub-server /usr/local/bin/vless-sub-server

# Config via env vars
ENV PORT=8080
ENV REFRESH_INTERVAL_MS=1800000

EXPOSE 8080

USER appuser

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["/usr/local/bin/vless-sub-server"]