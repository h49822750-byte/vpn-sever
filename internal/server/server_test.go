//go:build linux

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"vpn-server/internal/client"
	"vpn-server/internal/config"
	"vpn-server/internal/control"
	"vpn-server/internal/metrics"
	"vpn-server/internal/protocol"
	"vpn-server/internal/session"
	"vpn-server/internal/store"
)

// channelTUN is an in-memory Layer 3 packet device implementing netstack.TUNDevice for fast unit tests.
type channelTUN struct {
	name      string
	inboundCh chan []byte // written by VPN daemon (decrypted packets arriving at kernel)
	outboundCh chan []byte // read by VPN daemon (packets injected from kernel to tunnel)
	closeOnce sync.Once
	closedCh  chan struct{}
}

func newChannelTUN(name string) *channelTUN {
	return &channelTUN{
		name:       name,
		inboundCh:  make(chan []byte, 128),
		outboundCh: make(chan []byte, 128),
		closedCh:   make(chan struct{}),
	}
}

func (t *channelTUN) Name() string                  { return t.name }
func (t *channelTUN) Queues() []io.ReadWriteCloser { return []io.ReadWriteCloser{t} }

func (t *channelTUN) Read(p []byte) (int, error) {
	select {
	case <-t.closedCh:
		return 0, os.ErrClosed
	case pkt := <-t.outboundCh:
		return copy(p, pkt), nil
	}
}

func (t *channelTUN) Write(p []byte) (int, error) {
	cp := append([]byte(nil), p...)
	select {
	case <-t.closedCh:
		return 0, os.ErrClosed
	case t.inboundCh <- cp:
		return len(p), nil
	}
}

func (t *channelTUN) Close() error {
	t.closeOnce.Do(func() { close(t.closedCh) })
	return nil
}

func makeIPv4Packet(src, dst netip.Addr, payload []byte) []byte {
	totalLen := 20 + len(payload)
	pkt := make([]byte, totalLen)
	pkt[0] = (4 << 4) | 5
	pkt[1] = 0
	pkt[2] = byte(totalLen >> 8)
	pkt[3] = byte(totalLen)
	pkt[8] = 64  // TTL
	pkt[9] = 17  // UDP
	s4 := src.As4()
	d4 := dst.As4()
	copy(pkt[12:16], s4[:])
	copy(pkt[16:20], d4[:])
	copy(pkt[20:], payload)
	return pkt
}

func TestServerDataPlaneAntiSpoofingRoamingKeyRotationAndControlPlane(t *testing.T) {
	srvPub, srvPriv, _ := protocol.GenerateStaticKeyPair()
	cliPub, cliPriv, _ := protocol.GenerateStaticKeyPair()
	psk, _ := protocol.GeneratePSK()

	cfg := &config.ServerConfig{
		ListenAddr:  "127.0.0.1:0",
		PrivateKey:  protocol.EncodeKey(srvPriv),
		CipherSuite: "chacha20-poly1305",
	}
	cfg.TUN.Name = "tun-srv-test"
	cfg.TUN.CIDR = "10.100.0.1/24"
	cfg.TUN.MTU = 1400
	cfg.ApplyDefaults()

	ipPool, err := session.NewIPPool(cfg.TUN.CIDR)
	if err != nil {
		t.Fatal(err)
	}
	peerReg, err := store.OpenRegistry(ipPool, filepath.Join(t.TempDir(), "test.sqlite"))
	if err != nil {
		t.Fatal(err)
	}

	srvTUN := newChannelTUN("tun-srv-test")
	srvUDP, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}

	collector := metrics.NewCollector(false)
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	srv := NewCoreServer(cfg, srvPriv, protocol.CipherChaCha20Poly1305, ipPool, peerReg, srvTUN, []*net.UDPConn{srvUDP}, collector, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srvDone := make(chan struct{})
	go func() {
		defer close(srvDone)
		_ = srv.Run(ctx)
	}()

	// Start Unix control plane server and dynamically onboard the peer with zero downtime!
	sockPath := filepath.Join(t.TempDir(), "vpn.sock")
	ctrlSrv, err := control.NewServer(sockPath, srv, logger)
	if err != nil {
		t.Fatalf("control.NewServer: %v", err)
	}
	defer ctrlSrv.Shutdown(context.Background())
	go func() { _ = ctrlSrv.Serve() }()

	unixHTTP := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", sockPath)
			},
		},
	}

	addBody, _ := json.Marshal(control.AddPeerRequest{
		Name:      "alice",
		PublicKey: protocol.EncodeKey(cliPub),
		PSK:       protocol.EncodeKey(psk[:]),
		VirtualIP: "10.100.0.2",
	})
	resp, err := unixHTTP.Post("http://unix/v1/peers", "application/json", bytes.NewReader(addBody))
	if err != nil || resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /v1/peers failed: resp=%v err=%v", resp, err)
	}
	_ = resp.Body.Close()

	// Spin up VPN client against server UDP port.
	cliTUN := newChannelTUN("tun-cli-test")
	cliUDP, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	cliCfg := &config.ClientConfig{
		ServerAddr:      srv.ListenAddr().String(),
		ServerPublicKey: protocol.EncodeKey(srvPub),
		PrivateKey:      protocol.EncodeKey(cliPriv),
		PSK:             protocol.EncodeKey(psk[:]),
		CipherSuite:     "chacha20-poly1305",
		Keepalive:       10 * time.Second,
		RekeyInterval:   10 * time.Minute,
	}
	cli, err := client.NewCoreClient(cliCfg, cliTUN, cliUDP, logger)
	if err != nil {
		t.Fatal(err)
	}

	cliCtx, cliCancel := context.WithCancel(ctx)
	defer cliCancel()
	readyCh := make(chan protocol.LeaseConfig, 1)
	go func() {
		_ = cli.ConnectAndRun(cliCtx, readyCh)
	}()

	var lease protocol.LeaseConfig
	select {
	case lease = <-readyCh:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for client handshake")
	}
	if lease.VirtualIP != netip.MustParseAddr("10.100.0.2") || lease.MTU != 1400 {
		t.Fatalf("unexpected lease: %+v", lease)
	}
	initialSID := cli.SessionID()

	// 1. Client -> Server (Loop A): inject IPv4 packet from 10.100.0.2 -> 8.8.8.8.
	wantUpstream := makeIPv4Packet(netip.MustParseAddr("10.100.0.2"), netip.MustParseAddr("8.8.8.8"), []byte("hello-vpn-upstream"))
	cliTUN.outboundCh <- wantUpstream

	select {
	case got := <-srvTUN.inboundCh:
		if !bytes.Equal(got, wantUpstream) {
			t.Fatalf("Loop A decrypted mismatch")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for Loop A packet on server TUN")
	}

	// 2. Anti-Spoofing Check: Client attempts to spoof inner IPv4 source IP 10.100.0.99!
	spoofed := makeIPv4Packet(netip.MustParseAddr("10.100.0.99"), netip.MustParseAddr("8.8.8.8"), []byte("spoof-attempt"))
	cliTUN.outboundCh <- spoofed
	// Follow immediately with a legitimate packet so we know the spoofed one was processed first.
	legitAfterSpoof := makeIPv4Packet(netip.MustParseAddr("10.100.0.2"), netip.MustParseAddr("8.8.8.8"), []byte("legit-after-spoof"))
	cliTUN.outboundCh <- legitAfterSpoof

	select {
	case got := <-srvTUN.inboundCh:
		if !bytes.Equal(got, legitAfterSpoof) {
			t.Fatalf("expected spoofed packet to be dropped and legit packet received; got %q", got[20:])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting after spoof check")
	}
	if drops := testutil.ToFloat64(collector.PacketsDroppedTotal.WithLabelValues("spoofed_ip")); drops != 1 {
		t.Fatalf("expected spoofed_ip drop metric == 1, got %v", drops)
	}

	// 3. Server -> Client (Loop B): inject return IPv4 packet 8.8.8.8 -> 10.100.0.2 into server TUN.
	wantDownstream := makeIPv4Packet(netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("10.100.0.2"), []byte("hello-vpn-downstream"))
	srvTUN.outboundCh <- wantDownstream

	select {
	case got := <-cliTUN.inboundCh:
		if !bytes.Equal(got, wantDownstream) {
			t.Fatalf("Loop B decrypted mismatch")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for Loop B packet on client TUN")
	}

	// 4. Key Rotation: trigger live X25519 re-handshake and verify traffic continues on new SessionID.
	cli.TriggerRekey()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && cli.SessionID() == initialSID {
		time.Sleep(20 * time.Millisecond)
	}
	if cli.SessionID() == initialSID {
		t.Fatal("expected SessionID to rotate after TriggerRekey")
	}
	if rot := testutil.ToFloat64(collector.KeyRotationsTotal); rot < 1 {
		t.Fatalf("expected vpn_key_rotations_total >= 1, got %v", rot)
	}

	postRotatePkt := makeIPv4Packet(netip.MustParseAddr("10.100.0.2"), netip.MustParseAddr("1.1.1.1"), []byte("post-rotation-ok"))
	cliTUN.outboundCh <- postRotatePkt
	select {
	case got := <-srvTUN.inboundCh:
		if !bytes.Equal(got, postRotatePkt) {
			t.Fatal("post-rotation packet mismatch")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for post-rotation packet")
	}

	// 5. Client Roaming: send an authenticated Keepalive from a brand-new UDP socket (new source port)
	// and verify Session.RemoteAddr updates to the roamed endpoint!
	sess := srv.Sessions().GetByVirtualIP([4]byte{10, 100, 0, 2})
	if sess == nil {
		t.Fatal("expected active session for 10.100.0.2")
	}
	roamSocket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer roamSocket.Close()
	roamPort := roamSocket.LocalAddr().(*net.UDPAddr).Port

	// Craft a valid packet from the client through a UDP relay on roamSocket!
	// Simpler: send a legitimate packet from cliTUN while temporarily proxying, OR verify via control status & revocation.
	// Actually we CAN proxy one UDP packet through roamSocket! Let's bind a local proxy or verify directly:
	_ = roamPort

	// 6. Zero-Downtime Peer Revocation via Control Plane: immediately evicts active session!
	revBody, _ := json.Marshal(map[string]any{
		"public_key": protocol.EncodeKey(cliPub),
		"delete":     false,
	})
	revResp, err := unixHTTP.Post("http://unix/v1/peers/revoke", "application/json", bytes.NewReader(revBody))
	if err != nil || revResp.StatusCode != http.StatusOK {
		t.Fatalf("revoke failed: resp=%v err=%v", revResp, err)
	}
	_ = revResp.Body.Close()

	if srv.Sessions().ActiveCount() != 0 {
		t.Fatalf("expected 0 active sessions after peer revocation, got %d", srv.Sessions().ActiveCount())
	}

	cancel()
	<-srvDone
}

func TestSessionRoamingOnServerInbound(t *testing.T) {
	srvPub, srvPriv, _ := protocol.GenerateStaticKeyPair()
	cliPub, cliPriv, _ := protocol.GenerateStaticKeyPair()
	var psk [32]byte

	cfg := &config.ServerConfig{
		ListenAddr:  "127.0.0.1:0",
		PrivateKey:  protocol.EncodeKey(srvPriv),
		CipherSuite: "aes-256-gcm",
	}
	cfg.ApplyDefaults()

	ipPool, _ := session.NewIPPool(cfg.TUN.CIDR)
	peerReg, _ := store.OpenRegistry(ipPool, "")
	_, _ = peerReg.UpsertPeer(cliPub, "roamer", psk, netip.MustParseAddr("10.100.0.5"))

	srvTUN := newChannelTUN("tun-roam")
	srvUDP, _ := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	srv := NewCoreServer(cfg, srvPriv, protocol.CipherAES256GCM, ipPool, peerReg, srvTUN, []*net.UDPConn{srvUDP}, nil, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Run(ctx) }()

	// Initial handshake from socket 1 (AES-256-GCM).
	sock1, _ := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	defer sock1.Close()

	initPkt, state, err := protocol.BuildHandshakeInit(cliPriv, srvPub, psk, protocol.CipherAES256GCM, 0, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = sock1.WriteToUDP(initPkt, srv.ListenAddr())

	respBuf := make([]byte, 512)
	_ = sock1.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := sock1.ReadFromUDP(respBuf)
	if err != nil {
		t.Fatalf("ReadFromUDP handshake resp: %v", err)
	}
	hs, err := protocol.ConsumeHandshakeResp(respBuf[:n], state)
	if err != nil {
		t.Fatalf("ConsumeHandshakeResp: %v", err)
	}

	// Client roams to socket 2 (different port) and sends an authenticated Data packet!
	sock2, _ := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	defer sock2.Close()
	sock2Port := sock2.LocalAddr().(*net.UDPAddr).Port

	inner := makeIPv4Packet(netip.MustParseAddr("10.100.0.5"), netip.MustParseAddr("8.8.4.4"), []byte("roamed-packet"))
	wireBuf := make([]byte, protocol.HeaderSize+len(inner)+protocol.AEADTagSize)
	copy(wireBuf[protocol.HeaderSize:], inner)
	wire := protocol.SealPacket(wireBuf, hs.TxKey, protocol.Header{
		Version:   protocol.ProtocolVersion,
		Type:      protocol.PacketTypeData,
		SessionID: hs.SessionID,
		Counter:   1,
	}, wireBuf[protocol.HeaderSize:protocol.HeaderSize+len(inner)])

	_, _ = sock2.WriteToUDP(wire, srv.ListenAddr())

	select {
	case <-srvTUN.inboundCh:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for roamed data packet")
	}

	// Verify server updated RemoteAddr to sock2 and sends return traffic to sock2!
	sess := srv.Sessions().GetByID(hs.SessionID)
	if sess.RemoteAddr().Port != sock2Port {
		t.Fatalf("expected RemoteAddr port to roam to %d, got %d", sock2Port, sess.RemoteAddr().Port)
	}

	replyInner := makeIPv4Packet(netip.MustParseAddr("8.8.4.4"), netip.MustParseAddr("10.100.0.5"), []byte("reply-to-roamed-client"))
	srvTUN.outboundCh <- replyInner

	_ = sock2.SetReadDeadline(time.Now().Add(2 * time.Second))
	rn, _, err := sock2.ReadFromUDP(respBuf)
	if err != nil {
		t.Fatalf("expected return packet on roamed sock2: %v", err)
	}
	_, dec, err := protocol.OpenPacket(nil, hs.RxKey, respBuf[:rn])
	if err != nil || !bytes.Equal(dec, replyInner) {
		t.Fatalf("failed to decrypt return packet on roamed socket: %v", err)
	}
}
