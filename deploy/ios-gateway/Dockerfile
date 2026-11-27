FROM vpn-server:latest

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      wireguard-tools \
      nftables \
      qrencode \
      curl && \
    rm -rf /var/lib/apt/lists/*

COPY deploy/ios-gateway/entrypoint.sh /usr/local/bin/ios-entrypoint.sh
RUN chmod +x /usr/local/bin/ios-entrypoint.sh

EXPOSE 51821/udp
HEALTHCHECK --interval=10s --timeout=3s --start-period=8s --retries=3 \
    CMD /bin/sh -c 'wg show wg0 >/dev/null 2>&1 && ip link show tun-gw0 >/dev/null 2>&1'

ENTRYPOINT ["/usr/local/bin/ios-entrypoint.sh"]
