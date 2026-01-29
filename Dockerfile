# TorForge Docker Image
# Multi-stage build for minimal image size

# Build stage
FROM golang:1.23-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git make gcc musl-dev linux-headers

WORKDIR /app

# Copy go mod files first for caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build
RUN make build

# Runtime stage
FROM alpine:latest

# Install runtime dependencies
RUN apk add --no-cache \
    tor \
    iptables \
    ip6tables \
    iproute2 \
    ca-certificates \
    tini

# Create directories
RUN mkdir -p /var/lib/torforge /var/log/torforge /etc/torforge

# Copy binary from builder
COPY --from=builder /app/build/torforge /usr/local/bin/torforge

# Copy default config
COPY configs/example-config.yaml /etc/torforge/torforge.yaml

# Set permissions
RUN chmod +x /usr/local/bin/torforge

# Use tini as init
ENTRYPOINT ["/sbin/tini", "--"]

# Default command
CMD ["torforge", "tor"]

# Expose ports
EXPOSE 9050 9040 5353 8080

# Labels
LABEL maintainer="0xJerry"
LABEL version="1.1.2"
LABEL description="TorForge - Advanced Transparent Tor Proxy"
