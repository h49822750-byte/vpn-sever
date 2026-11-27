package store

import (
	"errors"
	"net/netip"
	"path/filepath"
	"testing"

	"vpn-server/internal/protocol"
	"vpn-server/internal/session"
)

func TestSQLitePeerRegistryPersistenceAndRevocation(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "peers.sqlite")

	pool1, err := session.NewIPPool("10.100.0.1/24")
	if err != nil {
		t.Fatal(err)
	}
	reg1, err := OpenRegistry(pool1, dbPath)
	if err != nil {
		t.Fatalf("OpenRegistry: %v", err)
	}

	pubA, _, _ := protocol.GenerateStaticKeyPair()
	pubB, _, _ := protocol.GenerateStaticKeyPair()
	pskA, _ := protocol.GeneratePSK()

	peerA, err := reg1.UpsertPeer(pubA, "laptop", pskA, netip.MustParseAddr("10.100.0.10"))
	if err != nil {
		t.Fatalf("UpsertPeer A: %v", err)
	}
	peerB, err := reg1.UpsertPeer(pubB, "phone", [32]byte{}, netip.Addr{})
	if err != nil {
		t.Fatalf("UpsertPeer B: %v", err)
	}
	if err := reg1.RevokePeer(pubB); err != nil {
		t.Fatalf("RevokePeer B: %v", err)
	}
	if err := reg1.Close(); err != nil {
		t.Fatal(err)
	}

	// Re-open from SQLite and verify leases, PSK, and revocation status survived restart.
	pool2, _ := session.NewIPPool("10.100.0.1/24")
	reg2, err := OpenRegistry(pool2, dbPath)
	if err != nil {
		t.Fatalf("reopen OpenRegistry: %v", err)
	}
	defer reg2.Close()

	var pubA32, pubB32 [32]byte
	copy(pubA32[:], pubA)
	copy(pubB32[:], pubB)

	gotA, err := reg2.VerifyAndAcceptHandshake(pubA32, 1000, func(p *Peer) error {
		if p.PSK != pskA || p.VirtualIP != peerA.VirtualIP {
			t.Fatalf("persisted peerA mismatch: %+v", p)
		}
		return nil
	})
	if err != nil || gotA.Name != "laptop" {
		t.Fatalf("VerifyAndAcceptHandshake A failed: %v", err)
	}

	_, err = reg2.VerifyAndAcceptHandshake(pubB32, 1000, func(p *Peer) error { return nil })
	if !errors.Is(err, ErrPeerRevoked) {
		t.Fatalf("expected ErrPeerRevoked for peerB (%s), got %v", peerB.VirtualIP, err)
	}
}
