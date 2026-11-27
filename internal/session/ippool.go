package session

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sync"
)

var (
	ErrSubnetExhausted    = errors.New("session: virtual IPv4 subnet exhausted")
	ErrIPOutOfRange       = errors.New("session: virtual IP outside server tunnel subnet")
	ErrIPReserved         = errors.New("session: virtual IP is reserved (network, broadcast, or server IP)")
	ErrIPAlreadyAllocated = errors.New("session: virtual IP already leased to another peer")
)

// IPPool manages static and dynamic IPv4 tunnel leases within a subnet (e.g. 10.100.0.1/24).
type IPPool struct {
	mu          sync.Mutex
	prefix      netip.Prefix // masked network prefix, e.g. 10.100.0.0/24
	serverIP    netip.Addr   // server tunnel IP, e.g. 10.100.0.1
	networkU32  uint32
	bcastU32    uint32
	serverU32   uint32
	nextHintU32 uint32
	byPeer      map[string]netip.Addr
	byAddr      map[[4]byte]string
}

// NewIPPool initializes a tunnel IPv4 pool from an interface CIDR such as "10.100.0.1/24".
func NewIPPool(interfaceCIDR string) (*IPPool, error) {
	p, err := netip.ParsePrefix(interfaceCIDR)
	if err != nil {
		return nil, fmt.Errorf("invalid tunnel CIDR %q: %w", interfaceCIDR, err)
	}
	if !p.Addr().Is4() {
		return nil, errors.New("tunnel CIDR must be IPv4")
	}
	if p.Bits() > 30 || p.Bits() < 8 {
		return nil, fmt.Errorf("unsupported IPv4 prefix length /%d (must be between /8 and /30)", p.Bits())
	}

	serverIP := p.Addr()
	masked := p.Masked()
	net4 := masked.Addr().As4()
	srv4 := serverIP.As4()

	netU32 := binary.BigEndian.Uint32(net4[:])
	hostMask := uint32((uint64(1) << (32 - p.Bits())) - 1)
	bcastU32 := netU32 | hostMask
	srvU32 := binary.BigEndian.Uint32(srv4[:])

	if srvU32 == netU32 || srvU32 == bcastU32 {
		return nil, fmt.Errorf("server tunnel IP %s cannot be network or broadcast address", serverIP)
	}

	return &IPPool{
		prefix:      masked,
		serverIP:    serverIP,
		networkU32:  netU32,
		bcastU32:    bcastU32,
		serverU32:   srvU32,
		nextHintU32: netU32 + 1,
		byPeer:      make(map[string]netip.Addr),
		byAddr:      make(map[[4]byte]string),
	}, nil
}

// ServerIP returns the VPN server's own virtual IP (e.g. 10.100.0.1).
func (p *IPPool) ServerIP() netip.Addr { return p.serverIP }

// Prefix returns the masked tunnel subnet (e.g. 10.100.0.0/24).
func (p *IPPool) Prefix() netip.Prefix { return p.prefix }

// PrefixBits returns the subnet mask length (e.g. 24).
func (p *IPPool) PrefixBits() uint8 { return uint8(p.prefix.Bits()) }

// ReserveStatic assigns a specific IPv4 address to peerKey, or verifies it if already leased to peerKey.
func (p *IPPool) ReserveStatic(peerKey string, ip netip.Addr) error {
	if !ip.Is4() || !p.prefix.Contains(ip) {
		return fmt.Errorf("%w: %s not in %s", ErrIPOutOfRange, ip, p.prefix)
	}
	ip4 := ip.As4()
	ipU32 := binary.BigEndian.Uint32(ip4[:])
	if ipU32 == p.networkU32 || ipU32 == p.bcastU32 || ipU32 == p.serverU32 {
		return fmt.Errorf("%w: %s", ErrIPReserved, ip)
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if owner, taken := p.byAddr[ip4]; taken && owner != peerKey {
		return fmt.Errorf("%w: %s", ErrIPAlreadyAllocated, ip)
	}
	if prev, hadPrev := p.byPeer[peerKey]; hadPrev && prev != ip {
		delete(p.byAddr, prev.As4())
	}
	p.byPeer[peerKey] = ip
	p.byAddr[ip4] = peerKey
	return nil
}

// Allocate returns peerKey's existing lease if present, or allocates the next free IPv4 in the pool.
func (p *IPPool) Allocate(peerKey string) (netip.Addr, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if existing, ok := p.byPeer[peerKey]; ok {
		return existing, nil
	}

	totalUsable := p.bcastU32 - p.networkU32 - 1
	cur := p.nextHintU32
	for i := uint32(0); i < totalUsable; i++ {
		if cur <= p.networkU32 || cur >= p.bcastU32 {
			cur = p.networkU32 + 1
		}
		if cur != p.serverU32 {
			var b [4]byte
			binary.BigEndian.PutUint32(b[:], cur)
			if _, taken := p.byAddr[b]; !taken {
				addr := netip.AddrFrom4(b)
				p.byPeer[peerKey] = addr
				p.byAddr[b] = peerKey
				p.nextHintU32 = cur + 1
				return addr, nil
			}
		}
		cur++
	}
	return netip.Addr{}, ErrSubnetExhausted
}

// Lookup returns the leased VirtualIP for peerKey, if any.
func (p *IPPool) Lookup(peerKey string) (netip.Addr, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	ip, ok := p.byPeer[peerKey]
	return ip, ok
}

// Release frees any IPv4 lease held by peerKey.
func (p *IPPool) Release(peerKey string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if ip, ok := p.byPeer[peerKey]; ok {
		delete(p.byPeer, peerKey)
		delete(p.byAddr, ip.As4())
	}
}
