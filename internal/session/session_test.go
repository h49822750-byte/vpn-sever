package session

import (
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"vpn-server/internal/protocol"
)

func TestIPPoolAllocationAndReservation(t *testing.T) {
	pool, err := NewIPPool("10.100.0.1/29") // .0 net, .1 server, .2..6 usable (5 hosts), .7 bcast
	if err != nil {
		t.Fatalf("NewIPPool: %v", err)
	}

	// Reserving server IP or network/broadcast must fail.
	for _, bad := range []string{"10.100.0.0", "10.100.0.1", "10.100.0.7"} {
		if err := pool.ReserveStatic("peerA", netip.MustParseAddr(bad)); !errors.Is(err, ErrIPReserved) {
			t.Fatalf("expected ErrIPReserved for %s, got %v", bad, err)
		}
	}

	// Reserve static .4 for peerStatic.
	if err := pool.ReserveStatic("peerStatic", netip.MustParseAddr("10.100.0.4")); err != nil {
		t.Fatalf("ReserveStatic: %v", err)
	}
	if err := pool.ReserveStatic("otherPeer", netip.MustParseAddr("10.100.0.4")); !errors.Is(err, ErrIPAlreadyAllocated) {
		t.Fatalf("expected ErrIPAlreadyAllocated, got %v", err)
	}

	// Allocate remaining 4 usable addresses dynamically.
	peers := []string{"p1", "p2", "p3", "p4"}
	for _, p := range peers {
		ip, err := pool.Allocate(p)
		if err != nil {
			t.Fatalf("Allocate(%s): %v", p, err)
		}
		// Idempotent re-allocation returns same IP.
		ip2, err := pool.Allocate(p)
		if err != nil || ip != ip2 {
			t.Fatalf("expected stable lease for %s: %v vs %v", p, ip, ip2)
		}
	}

	// Pool should now be full.
	if _, err := pool.Allocate("p5"); !errors.Is(err, ErrSubnetExhausted) {
		t.Fatalf("expected ErrSubnetExhausted, got %v", err)
	}

	// Releasing p2 allows p5 to acquire its address.
	pool.Release("p2")
	if _, err := pool.Allocate("p5"); err != nil {
		t.Fatalf("expected allocation after release to succeed, got %v", err)
	}
}

func TestSessionRoamingRotationAndExpiration(t *testing.T) {
	pub, _, _ := protocol.GenerateStaticKeyPair()
	var key [32]byte
	aead, _ := protocol.NewAEAD(protocol.CipherChaCha20Poly1305, key[:])

	now := time.Now()
	vip := netip.MustParseAddr("10.100.0.2")
	addr1 := &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 40000}
	addr2 := &net.UDPAddr{IP: net.ParseIP("198.51.100.99"), Port: 51234}

	tbl := NewTable()
	sid1, err := tbl.AllocateSessionID()
	if err != nil {
		t.Fatal(err)
	}
	s1 := NewSession(sid1, vip, pub, addr1, protocol.CipherChaCha20Poly1305, aead, aead, now)
	if rotated := tbl.Install(s1, now); rotated {
		t.Fatal("first install should not report rotation")
	}

	// Roaming update.
	s1.SetRemoteAddr(addr2)
	if got := s1.RemoteAddr(); !got.IP.Equal(addr2.IP) || got.Port != addr2.Port {
		t.Fatalf("roaming failed: got %v, want %v", got, addr2)
	}

	// Key rotation installs sid2 for the same VirtualIP while keeping sid1 during grace window.
	sid2, _ := tbl.AllocateSessionID()
	s2 := NewSession(sid2, vip, pub, addr2, protocol.CipherChaCha20Poly1305, aead, aead, now.Add(55*time.Minute))
	if rotated := tbl.Install(s2, now.Add(55*time.Minute)); !rotated {
		t.Fatal("expected rotation=true when replacing existing VirtualIP session")
	}
	if tbl.GetByVirtualIP(vip.As4()) != s2 {
		t.Fatal("outbound routing should immediately point to rotated session s2")
	}
	if tbl.GetByID(sid1) != s1 {
		t.Fatal("superseded session s1 should remain in SessionByID during grace period")
	}

	// Advance past grace period -> Reap removes s1, keeps s2.
	s2.Touch(now.Add(56 * time.Minute))
	reaped := tbl.Reap(now.Add(56*time.Minute), time.Hour, 3*time.Minute, DefaultMaxPackets, 30*time.Second)
	if reaped != 1 || tbl.GetByID(sid1) != nil || tbl.GetByID(sid2) != s2 {
		t.Fatalf("unexpected reap state: reaped=%d", reaped)
	}

	// Peer revocation immediately removes remaining sessions.
	if removed := tbl.RemoveByPeer(pub); removed != 1 || tbl.ActiveCount() != 0 {
		t.Fatalf("expected peer revocation to remove active session, removed=%d", removed)
	}
}
