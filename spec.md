# **Technical Specification: Custom User-Space VPN Server (Linux)**

Building a VPN from scratch replaces WireGuard's kernel module with a user-space daemon that bridges a Linux virtual network interface (`/dev/net/tun`) and a public network socket (UDP or TCP).

# **1\. System Architecture & Data Flow**

The server operates as a Layer 3 packet router in user space. The Linux kernel handles IP routing and NAT, while the daemon handles encapsulation, encryption, and peer multiplexing.

* **Virtual Interface (`tun0`):** Created via `/dev/net/tun` with `IFF_TUN | IFF_NO_PI` flags. Reading from this file descriptor yields raw Layer 3 IP packets; writing to it injects decrypted IP packets into the Linux kernel's network stack.  
* **Transport Socket:** A single UDP socket bound to `0.0.0.0:51820` (UDP avoids TCP-over-TCP meltdown; TCP/TLS can be substituted if traversing restrictive firewalls).  
* **Recommended Implementation Stack:** Go (native concurrency via goroutines, [golang.org/x/crypto](https://golang.org/x/crypto) for audited primitives, and minimal GC overhead with `sync.Pool` packet buffers) or Rust (`tokio` \+ `tun` \+ `ring`).

# **2\. Wire Protocol & Packet Framing**

Every datagram sent over the public socket must follow a fixed binary header so the server can route and decrypt packets without ambiguity.

| Field | Size (Bytes) | Description |
| :---- | :---- | :---- |
| Version | 1 | Protocol version (e.g., `0x01`). |
| Packet Type | 1 | `0x01` \= Handshake Init, `0x02` \= Handshake Resp, `0x03` \= Data, `0x04` \= Keepalive. |
| Session ID | 4 | Unique 32-bit identifier assigned during handshake for \$O(1)\$ session lookup. |
| Counter / Nonce | 8 | Monotonically increasing 64-bit packet sequence number (used as AEAD nonce and for replay protection). |
| Payload \+ Tag | Variable | Ciphertext of the raw IP packet \+ 16-byte AEAD authentication tag. |

* **MTU Calculation:** Set `tun0` MTU to 1400 bytes to leave headroom for outer IP (20B), UDP (8B), custom header (14B), and AEAD tag (16B) without causing fragmentation.

# **3\. Cryptography & Security Model**

Do not invent custom cryptographic primitives. Use standard, audited AEAD and key-exchange algorithms:

* **Key Exchange (Handshake):**  
  * Use X25519 (Elliptic Curve Diffie-Hellman) for ephemeral key agreement.  
  * Authenticate peers using Ed25519 static public keys (or a pre-shared key) so unauthenticated handshakes are dropped immediately.  
  * Derive bidirectional symmetric session keys (`TxKey`, `RxKey`) via HKDF-SHA256.  
* **Data Plane Encryption:**  
  * Use ChaCha20-Poly1305 or AES-256-GCM (AEAD).  
  * Pass the 14-byte custom header as Additional Authenticated Data (AAD) so header tampering (e.g., altering Session ID or Type) invalidates the tag.  
* **Replay Protection:**  
  * Maintain a 64-bit or 128-bit sliding window bitmap per session on the Counter field. Reject packets with counters older than the window or already marked as seen.  
* **Key Rotation:** Trigger a re-handshake after 1 hour or \$2^{32}\$ packets to enforce forward secrecy.

# **4\. Session State & Routing Table**

Because a single `tun0` interface serves multiple clients, the server must maintain two thread-safe, in-memory lookup maps (protected by `RWMutex` or sharded locks):

* **`SessionByID` (`uint32` \$\\rightarrow\$ `*Session`):** Used on the inbound UDP path to find the decryption key and replay window.  
* **`SessionByVirtualIP` (`[4]byte` \$\\rightarrow\$ `*Session`):** Used on the outbound TUN path to map the destination IPv4 address of a returning packet to the client's current public `UDPAddr` and encryption key.

Each `Session` struct stores:

* `SessionID` (`uint32`)  
* `VirtualIP` (`netip.Addr`, e.g., `10.100.0.2`)  
* `RemoteAddr` (`*net.UDPAddr` — dynamically updated whenever a valid authenticated packet arrives from a new IP/port, supporting client roaming)  
* `RxKey`, `TxKey` (`cipher.AEAD`)  
* `TxCounter` (`atomic.Uint64`) and `ReplayWindow`  
* `LastSeen` (`time.Time` — for idle session expiration)

# **5\. Core Server Event Loops**

The server runs two primary concurrent loops using pre-allocated byte buffers (`sync.Pool`) to minimize memory allocations per packet:

## **Loop A: Inbound (UDP Socket \$\\rightarrow\$ TUN)**

1. Read raw datagram from UDP socket `(n, remoteAddr)`.  
2. Parse the 14-byte header; drop if malformed.  
3. If `Type == Data`:  
   * Look up Session via `SessionByID`.  
   * Verify Counter against `ReplayWindow`.  
   * Decrypt payload using `RxKey` with header as AAD; drop silently on auth failure.  
   * **Anti-Spoofing Check:** Inspect bytes 12..15 (IPv4 Source IP) of the decrypted inner packet. Drop if it does not match `Session.VirtualIP`.  
   * Update `Session.RemoteAddr = remoteAddr` and `Session.LastSeen`.  
   * Write decrypted IP packet to `tun0`.

## **Loop B: Outbound (TUN \$\\rightarrow\$ UDP Socket)**

1. Read raw IP packet from `tun0`.  
2. Inspect IP version (`pkt[0] >> 4`). If IPv4, extract Destination IP from bytes 16..19.  
3. Look up Session via `SessionByVirtualIP`; drop if no active client owns that IP.  
4. Increment `Session.TxCounter` atomically.  
5. Construct the 14-byte header and encrypt the IP packet with `TxKey`.  
6. Write the framed datagram to the UDP socket addressed to `Session.RemoteAddr`.

# **6\. Linux OS Integration Requirements**

The server binary requires `CAP_NET_ADMIN` (or root) at startup to configure the interface, after which it can drop privileges.

* **Interface Provisioning:** Open `/dev/net/tun`, issue `ioctl(fd, TUNSETIFF, &ifr)`, assign `10.100.0.1/24`, set MTU 1400, and bring the link UP (via Netlink or `ip` commands).  
* **Kernel Forwarding:** Enable `net.ipv4.ip_forward = 1`.  
* **NAT / Masquerading:** Configure `nftables` to masquerade traffic from `10.100.0.0/24` exiting the VM's public interface (`eth0`).

# **7\. Recommended Technical Stack**

For building a production-ready custom user-space VPN server on Linux, **Go (1.22+)** is the primary recommended stack. It compiles to a single static binary with low memory overhead, offers first-class concurrency via goroutines, provides direct access to Linux syscalls and Netlink, and ships with audited, constant-time cryptography in its standard and extended libraries.

| Layer | Recommended Technology / Package | Purpose & Rationale |
| :---- | :---- | :---- |
| Core Language & Runtime | Go 1.22+ | Fast development, native concurrency, static single-binary deployment, and predictable performance with buffer pooling. |
| TUN Interface Control | `golang.org/x/sys/unix` | Low-level open and ioctl calls for `/dev/net/tun` (`IFF_TUN`, `IFF_NO_PI`, and `IFF_MULTI_QUEUE` for multi-core scaling). |
| Linux Routing & Interfaces | `github.com/vishvananda/netlink` | Programmatically assigns tunnel IPs, sets MTU, brings `tun0` up, and configures routes without shelling out to `ip` commands. |
| NAT & Firewall Automation | `github.com/google/nftables` | Programmatically manages nftables masquerade and forwarding rules via Netlink. |
| Cryptography & Handshake | `crypto/ecdh`, `crypto/ed25519`, `golang.org/x/crypto/chacha20poly1305`, `golang.org/x/crypto/hkdf` | Audited standard implementations for X25519 key agreement, Ed25519 peer authentication, ChaCha20-Poly1305 AEAD, and HKDF-SHA256. |
| High-Throughput Socket I/O | `golang.org/x/net/ipv4` \+ `sync.Pool` | Enables recvmmsg/sendmmsg batch UDP reads and writes while eliminating per-packet heap allocations. |
| Configuration & Control Plane | `gopkg.in/yaml.v3` \+ Unix domain socket API (`net/http` or gRPC) | Declarative config loading paired with a local control socket (`/run/vpn.sock`) for zero-downtime peer additions and revocations. |
| Persistence (Optional) | SQLite (`modernc.org/sqlite`) or MySQL | Stores peer public keys, static virtual IP leases, and revocation status when scaling beyond static config files. |
| Observability & Logging | `log/slog` \+ `github.com/prometheus/client_golang` | Structured JSON lifecycle logs and Prometheus metrics for active sessions, RX/TX throughput, handshake counts, and dropped/replayed packets. |
| Deployment & Privilege Isolation | systemd (with `CAP_NET_ADMIN`) or Docker | Runs the daemon as a non-root service using `AmbientCapabilities=CAP_NET_ADMIN`, or containerized with `--cap-add=NET_ADMIN` and `/dev/net/tun` passthrough. |

## **Performance & OS Tuning Companion Stack**

* **Congestion Control & Queuing:** Enable Linux BBR (`net.ipv4.tcp_congestion_control=bbr`) and Fair Queuing (`net.core.default_qdisc=fq`).  
* **UDP Socket Buffers:** Increase `net.core.rmem_max` and `net.core.wmem_max` (e.g., to 16 MB or 26 MB) to prevent packet drops during high-throughput bursts.  
* **Multi-Core Scaling:** Enable `IFF_MULTI_QUEUE` on `/dev/net/tun` and `SO_REUSEPORT` on UDP sockets to parallelize packet processing across CPU cores.

## **Alternative Stack (Ultra-High Throughput / Zero-GC)**

* **Rust (`tokio` \+ `tun` \+ `ring` or `chacha20poly1305` \+ `rtnetlink`):** Consider Rust instead of Go if the server must saturate 10 Gbps+ links with strictly deterministic tail latency and zero garbage-collection pauses, accepting slower iteration speed and higher implementation complexity.