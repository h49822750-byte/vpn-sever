#!/usr/bin/env bash
set -euo pipefail

PUBLIC_ENDPOINT="${PUBLIC_ENDPOINT:-203.0.113.10:51821}"
WG_PORT="${WG_PORT:-51821}"
WG_PORT_RANGE_END="${WG_PORT_RANGE_END:-51840}"
DNS_SERVERS="${DNS_SERVERS:-1.1.1.1, 8.8.8.8}"
STATE_DIR="${STATE_DIR:-/etc/vpn-ios}"
VPN_CLIENT_CONFIG="${VPN_CLIENT_CONFIG:-/etc/vpn/ios-gateway-client.yaml}"

mkdir -p "${STATE_DIR}"
umask 077

if [[ ! -f "${STATE_DIR}/server.key" ]]; then
  echo "[ios-gateway] Generating new WireGuard server and iPhone keypairs..."
  wg genkey > "${STATE_DIR}/server.key"
  wg pubkey < "${STATE_DIR}/server.key" > "${STATE_DIR}/server.pub"
  wg genkey > "${STATE_DIR}/iphone.key"
  wg pubkey < "${STATE_DIR}/iphone.key" > "${STATE_DIR}/iphone.pub"
  wg genpsk > "${STATE_DIR}/iphone.psk"
fi

SRV_PRIV="$(cat "${STATE_DIR}/server.key")"
SRV_PUB="$(cat "${STATE_DIR}/server.pub")"
CLI_PRIV="$(cat "${STATE_DIR}/iphone.key")"
CLI_PUB="$(cat "${STATE_DIR}/iphone.pub")"
PSK="$(cat "${STATE_DIR}/iphone.psk")"

cat > "${STATE_DIR}/iphone-wireguard.conf" <<EOF
[Interface]
PrivateKey = ${CLI_PRIV}
Address = 10.100.1.2/24
DNS = ${DNS_SERVERS}
MTU = 1280

[Peer]
PublicKey = ${SRV_PUB}
PresharedKey = ${PSK}
Endpoint = ${PUBLIC_ENDPOINT}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF

qrencode -t png -s 8 -m 2 -o "${STATE_DIR}/iphone-qr.png" < "${STATE_DIR}/iphone-wireguard.conf"
qrencode -t utf8 < "${STATE_DIR}/iphone-wireguard.conf" > "${STATE_DIR}/iphone-qr.txt"

echo "[ios-gateway] Starting vpn-client bridge to vpn-server (for 10.100.0.0/24 subnet)..."
/usr/local/bin/vpn-client -config "${VPN_CLIENT_CONFIG}" &
VPN_CLI_PID=$!

cleanup() {
  echo "[ios-gateway] Shutting down..."
  kill "${VPN_CLI_PID}" 2>/dev/null || true
  for u in 0 1 2 3 4 5; do
    ip link del "wg${u}" 2>/dev/null || true
  done
}
trap cleanup SIGINT SIGTERM EXIT

for _ in $(seq 1 50); do
  if ip addr show dev tun-gw0 2>/dev/null | grep -q "inet 10.100.0."; then
    break
  fi
  sleep 0.2
done

if ! ip addr show dev tun-gw0 2>/dev/null | grep -q "inet 10.100.0."; then
  echo "[ios-gateway] ERROR: tun-gw0 failed to come up" >&2
  exit 1
fi

setup_wg_unit() {
  local ifname="$1"
  local port="$2"
  local conf_file="$3"
  shift 3

  ip link del "${ifname}" 2>/dev/null || true
  ip link add dev "${ifname}" type wireguard
  ip addr add 10.100.1.1/32 dev "${ifname}"
  ip link set mtu 1360 txqueuelen 2000 dev "${ifname}"
  wg setconf "${ifname}" "${conf_file}"
  rm -f "${conf_file}"
  ip link set up dev "${ifname}"
  tc qdisc replace dev "${ifname}" root fq_codel flows 1024 quantum 1514 target 5ms interval 100ms || true
  for peer_cidr in "$@"; do
    ip route replace "${peer_cidr}" dev "${ifname}"
  done
}

# wg0 on native UDP :51821 -> iPhone (10.100.1.2/32) + Windows Slot 1 (10.100.1.3/32)
TMP_WG0="/tmp/wg0-runtime.conf"
cat > "${TMP_WG0}" <<EOF
[Interface]
ListenPort = ${WG_PORT}
PrivateKey = ${SRV_PRIV}

[Peer]
PublicKey = ${CLI_PUB}
PresharedKey = ${PSK}
AllowedIPs = 10.100.1.2/32
EOF

WG0_ROUTES=("10.100.1.2/32")
if [[ -f "${STATE_DIR}/win.pub" && -f "${STATE_DIR}/win.psk" ]]; then
cat >> "${TMP_WG0}" <<EOF

[Peer]
PublicKey = $(cat "${STATE_DIR}/win.pub")
PresharedKey = $(cat "${STATE_DIR}/win.psk")
AllowedIPs = 10.100.1.3/32
EOF
  WG0_ROUTES+=("10.100.1.3/32")
fi
setup_wg_unit "wg0" "${WG_PORT}" "${TMP_WG0}" "${WG0_ROUTES[@]}"

# wg1..wg5 on native UDP :51822..:51826 (eliminates conntrack redirect source-port mismatches on rekeys!)
for idx in 2 3 4 5 6; do
  if [[ -f "${STATE_DIR}/win${idx}.pub" && -f "${STATE_DIR}/win${idx}.psk" ]]; then
    unit=$((idx - 1))
    port=$((WG_PORT + unit))
    vip="10.100.1.$((idx + 2))/32"
    tmp_cfg="/tmp/wg${unit}-runtime.conf"
    cat > "${tmp_cfg}" <<EOF
[Interface]
ListenPort = ${port}
PrivateKey = ${SRV_PRIV}

[Peer]
PublicKey = $(cat "${STATE_DIR}/win${idx}.pub")
PresharedKey = $(cat "${STATE_DIR}/win${idx}.psk")
AllowedIPs = ${vip}
EOF
    setup_wg_unit "wg${unit}" "${port}" "${tmp_cfg}" "${vip}"
  fi
done

REDIRECT_START=$((WG_PORT + 6))
nft -f - <<EOF
table ip ios_bridge
delete table ip ios_bridge
table ip ios_bridge {
  chain prerouting {
    type nat hook prerouting priority dstnat; policy accept;
    udp dport ${REDIRECT_START}-${WG_PORT_RANGE_END} redirect to :${WG_PORT}
  }
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    ip saddr 10.100.1.0/24 oifname "eth0" masquerade
    ip saddr 10.100.1.0/24 oifname "tun-gw0" masquerade
  }
  chain forward {
    type filter hook forward priority filter; policy accept;
    ip saddr 10.100.1.2 tcp flags syn tcp option maxseg size set 1220
    ip daddr 10.100.1.2 tcp flags syn tcp option maxseg size set 1220
    ip saddr != 10.100.1.2 iifname "wg*" tcp flags syn tcp option maxseg size set 1320
    ip daddr != 10.100.1.2 oifname "wg*" tcp flags syn tcp option maxseg size set 1320
    iifname "wg*" accept
    oifname "wg*" accept
  }
}
EOF

echo "[ios-gateway] Ready! Native kernel wg0..wg5 bound on UDP 51821..51826 (fq_codel, MTU 1360, MSS clamped)"
wait "${VPN_CLI_PID}"
