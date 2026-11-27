FROM golang:bookworm AS builder
ENV GOTOOLCHAIN=auto
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/vpn-server ./cmd/vpn-server && \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/vpn-client ./cmd/vpn-client && \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/vpnctl ./cmd/vpnctl && \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/vpn-tls-gateway ./cmd/vpn-tls-gateway

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates iproute2 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /out/vpn-server /usr/local/bin/vpn-server
COPY --from=builder /out/vpn-client /usr/local/bin/vpn-client
COPY --from=builder /out/vpnctl /usr/local/bin/vpnctl
COPY --from=builder /out/vpn-tls-gateway /usr/local/bin/vpn-tls-gateway
RUN mkdir -p /etc/vpn /var/lib/vpn-server /run
EXPOSE 51820/udp 9090/tcp
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/vpnctl", "status", "--socket", "/run/vpn.sock"]
ENTRYPOINT ["/usr/local/bin/vpn-server"]
CMD ["-config", "/etc/vpn/server.yaml"]
