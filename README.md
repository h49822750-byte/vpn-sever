# Custom User-Space Layer 3 VPN Server (Linux)

A pure-Go, zero-CGO user-space Layer 3 VPN server, companion client, and control CLI implementing [spec.md](./spec.md).

## Architecture Highlights

- **Layer 3 Virtual Interface (`/dev/net/tun`):** Provisioned directly via `golang.org/x/sys/unix` (`IFF_TUN | IFF_NO_PI` and `IFF_MULTI_QUEUE` for multi-core scaling), with IPv4 CIDR (`10.100.0.1/24`), MTU (`1400`), and routes configured programmatically via `github.com/vishvananda/netlink`.
- **14-Byte Binary Wire Framing:**
  - `Version` (`1B`: `0x01`)
  - `Packet Type` (`1B`: `0x01` Handshake Init, `0x02` Handshake Resp, `0x03` Data, `0x04` Keepalive)
  - `Session ID` (`4B`: `uint32` for $O(1)$ session lookup)
  - `Counter / Nonce` (`8B`: monotonic `uint64` AEAD nonce & replay sequence number)
  - `Payload + Tag` (`Variable` + `16B` AEAD authentication tag, authenticating the 14-byte header as AAD)
- **Audited Cryptography:**
  - Ephemeral **X25519** Diffie-Hellman key agreement (`crypto/ecdh`)
  - Mutual **Ed25519** static key authentication (`crypto/ed25519`) + optional 32-byte **PSK** HMAC
  - Directional symmetric session keys derived via **HKDF-SHA256** (`golang.org/x/crypto/hkdf`)
  - Data plane AEAD supporting **ChaCha20-Poly1305** (default) and **AES-256-GCM**
  - **128-bit sliding window** anti-replay bitmap (two-phase pre-check + post-AEAD commit)
  - Automatic **key rotation** after `1h` or $2^{32}$ packets
- **Routing, Anti-Spoofing & Roaming:**
  - Thread-safe `SessionByID` (`uint32 -> *Session`) and `SessionByVirtualIP` (`[4]byte -> *Session`) maps
  - Inner IPv4 source address anti-spoofing enforcement (`pkt[12:16] == Session.VirtualIP`)
  - Seamless client IP/port roaming (`Session.RemoteAddr` updated atomically on authenticated packets)
  - Zero-copy in-place encryption/decryption with `sync.Pool` packet buffers and `recvmmsg` batch UDP reads (`golang.org/x/net/ipv4`)
- **Linux NAT, Control Plane, SQLite & Observability:**
  - Programmatic `nftables` SNAT masquerade & forward chain rules via `github.com/google/nftables`
  - Zero-downtime peer addition/revocation over `/run/vpn.sock` (`vpnctl`) backed by `modernc.org/sqlite`
  - Structured JSON logs (`log/slog`) and Prometheus metrics (`/metrics`)

## Build & Test

```bash
make build
make test-race
```

Binaries are emitted into `./bin/`:
- `bin/vpn-server` — VPN server daemon
- `bin/vpn-client` — VPN client daemon
- `bin/vpnctl` — Key generator & runtime control CLI

## Quick Start

1. Generate static Ed25519 keypairs for the server and a peer:
   ```bash
   ./bin/vpnctl keygen   # server keypair
   ./bin/vpnctl keygen   # client keypair
   ./bin/vpnctl psk      # optional 32-byte pre-shared key
   ```
2. Copy `configs/server.example.yaml` to `/etc/vpn/server.yaml`, populate `private_key`, and start the daemon:
   ```bash
   sudo ./bin/vpn-server -config /etc/vpn/server.yaml
   ```
3. Manage peers at runtime with zero downtime:
   ```bash
   sudo ./bin/vpnctl status --socket /run/vpn.sock
   sudo ./bin/vpnctl peer add --socket /run/vpn.sock --name alice --pubkey "<CLIENT_PUBKEY>" --vip 10.100.0.2
   sudo ./bin/vpnctl sessions --socket /run/vpn.sock
   sudo ./bin/vpnctl peer revoke --socket /run/vpn.sock --pubkey "<CLIENT_PUBKEY>"
   ```
