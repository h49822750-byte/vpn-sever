//go:build linux

package server

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"

	"vpn-server/internal/config"
	"vpn-server/internal/control"
	"vpn-server/internal/metrics"
	"vpn-server/internal/netstack"
	"vpn-server/internal/protocol"
	"vpn-server/internal/session"
	"vpn-server/internal/store"
)

const (
	udpBatchSize           = 32
	handshakeQueueCapacity = 256
	keepalivePingByte      = 0x00
)

type handshakeJob struct {
	raw        [protocol.HandshakeInitSize]byte
	remoteAddr *net.UDPAddr
	udpConn    *net.UDPConn
}

// Server implements the custom user-space Layer 3 VPN router specified in spec.md.
type Server struct {
	cfg        *config.ServerConfig
	serverPriv ed25519.PrivateKey
	serverPub  ed25519.PublicKey
	suite      protocol.CipherSuite

	ipPool   *session.IPPool
	peers    *store.Registry
	sessions *session.Table
	metrics  *metrics.Collector
	logger   *slog.Logger

	tun        netstack.TUNDevice
	udpConns   []*net.UDPConn
	natCleanup func() error

	handshakeCh chan handshakeJob
	startedAt   time.Time
}

// NewLinuxServer provisions the Linux TUN interface, Netlink addressing, kernel IPv4 forwarding,
// nftables masquerading, SQLite peer registry, and UDP socket(s).
func NewLinuxServer(cfg *config.ServerConfig, collector *metrics.Collector, logger *slog.Logger) (*Server, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if collector == nil {
		collector = metrics.NewCollector(false)
	}

	priv, err := protocol.DecodePrivateKey(cfg.PrivateKey)
	if err != nil {
		return nil, err
	}
	suite, err := protocol.ParseCipherSuite(cfg.CipherSuite)
	if err != nil {
		return nil, err
	}
	ipPool, err := session.NewIPPool(cfg.TUN.CIDR)
	if err != nil {
		return nil, err
	}
	peerReg, err := store.OpenRegistry(ipPool, cfg.Storage.SQLitePath)
	if err != nil {
		return nil, err
	}

	for _, p := range cfg.Peers {
		pub, err := protocol.DecodePublicKey(p.PublicKey)
		if err != nil {
			_ = peerReg.Close()
			return nil, err
		}
		psk, err := protocol.DecodePSK(p.PSK)
		if err != nil {
			_ = peerReg.Close()
			return nil, err
		}
		var staticVIP netip.Addr
		if p.VirtualIP != "" {
			staticVIP = netip.MustParseAddr(p.VirtualIP)
		}
		if _, err := peerReg.UpsertPeer(pub, p.Name, psk, staticVIP); err != nil {
			_ = peerReg.Close()
			return nil, fmt.Errorf("load static peer %q: %w", p.Name, err)
		}
	}

	tunDev, err := netstack.OpenTUN(cfg.TUN.Name, cfg.Workers)
	if err != nil {
		_ = peerReg.Close()
		return nil, err
	}
	if err := netstack.ConfigureInterface(tunDev.Name(), cfg.TUN.CIDR, cfg.TUN.MTU); err != nil {
		_ = tunDev.Close()
		_ = peerReg.Close()
		return nil, err
	}
	netstack.DisableRPFilterOnInterface("all")
	netstack.DisableRPFilterOnInterface(tunDev.Name())

	if err := netstack.EnableIPv4Forwarding(); err != nil {
		_ = tunDev.Close()
		_ = peerReg.Close()
		return nil, fmt.Errorf("enable net.ipv4.ip_forward: %w", err)
	}
	if cfg.Tuning.Enable {
		netstack.ApplyPerformanceTuning(logger, cfg.SocketBuffer)
	}

	var natCleanup func() error
	if cfg.NAT.Enable != nil && *cfg.NAT.Enable {
		egressIf := cfg.NAT.EgressInterface
		if egressIf == "" || egressIf == "auto" {
			detected, err := netstack.DetectDefaultEgressInterface()
			if err != nil {
				logger.Warn("could not auto-detect default egress interface; skipping nftables NAT", "err", err)
				egressIf = ""
			} else {
				egressIf = detected
			}
		}
		if egressIf != "" {
			cleanup, err := netstack.SetupNATMasquerade(cfg.NAT.TableName, ipPool.Prefix(), tunDev.Name(), egressIf)
			if err != nil {
				_ = tunDev.Close()
				_ = peerReg.Close()
				return nil, fmt.Errorf("configure nftables NAT on %q: %w", egressIf, err)
			}
			natCleanup = cleanup
			logger.Info("configured nftables masquerade and forwarding",
				"table", cfg.NAT.TableName,
				"subnet", ipPool.Prefix().String(),
				"tun", tunDev.Name(),
				"egress", egressIf,
			)
		}
	}

	reusePort := cfg.Workers > 1
	udpConns := make([]*net.UDPConn, 0, cfg.Workers)
	listenAddr := cfg.ListenAddr
	for i := 0; i < cfg.Workers; i++ {
		conn, err := netstack.ListenUDP(listenAddr, reusePort, cfg.SocketBuffer, cfg.SocketBuffer)
		if err != nil {
			for _, c := range udpConns {
				_ = c.Close()
			}
			if natCleanup != nil {
				_ = natCleanup()
			}
			_ = tunDev.Close()
			_ = peerReg.Close()
			return nil, fmt.Errorf("bind UDP socket %q (worker %d): %w", listenAddr, i, err)
		}
		udpConns = append(udpConns, conn)
	}

	srv := NewCoreServer(cfg, priv, suite, ipPool, peerReg, tunDev, udpConns, collector, logger)
	srv.natCleanup = natCleanup
	return srv, nil
}

// NewCoreServer constructs a Server from pre-created TUN and UDP transports (used directly in unit tests).
func NewCoreServer(
	cfg *config.ServerConfig,
	serverPriv ed25519.PrivateKey,
	suite protocol.CipherSuite,
	ipPool *session.IPPool,
	peers *store.Registry,
	tun netstack.TUNDevice,
	udpConns []*net.UDPConn,
	collector *metrics.Collector,
	logger *slog.Logger,
) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	if collector == nil {
		collector = metrics.NewCollector(false)
	}
	return &Server{
		cfg:         cfg,
		serverPriv:  serverPriv,
		serverPub:   serverPriv.Public().(ed25519.PublicKey),
		suite:       suite,
		ipPool:      ipPool,
		peers:       peers,
		sessions:    session.NewTable(),
		metrics:     collector,
		logger:      logger,
		tun:         tun,
		udpConns:    udpConns,
		handshakeCh: make(chan handshakeJob, handshakeQueueCapacity),
		startedAt:   time.Now(),
	}
}

func (s *Server) PublicKey() ed25519.PublicKey { return s.serverPub }

func (s *Server) ListenAddr() *net.UDPAddr {
	if len(s.udpConns) == 0 {
		return nil
	}
	addr, _ := s.udpConns[0].LocalAddr().(*net.UDPAddr)
	return addr
}

func (s *Server) Metrics() *metrics.Collector { return s.metrics }
func (s *Server) Sessions() *session.Table    { return s.sessions }

// Run starts the handshake workers, session expiration reaper, Loop A (UDP -> TUN),
// and Loop B (TUN -> UDP), blocking until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	var wg sync.WaitGroup

	stopDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			for _, c := range s.udpConns {
				_ = c.Close()
			}
			_ = s.tun.Close()
		case <-stopDone:
		}
	}()

	handshakeWorkers := max(2, len(s.udpConns))
	for i := 0; i < handshakeWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.runHandshakeWorker(ctx)
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		s.runSessionReaper(ctx)
	}()

	tunQueues := s.tun.Queues()

	// Loop A: Inbound (UDP Socket -> TUN).
	for i, udpConn := range s.udpConns {
		tunWriter := tunQueues[i%len(tunQueues)]
		wg.Add(1)
		go func(conn *net.UDPConn, tw io.Writer) {
			defer wg.Done()
			s.runInboundLoop(ctx, conn, tw)
		}(udpConn, tunWriter)
	}

	// Loop B: Outbound (TUN -> UDP Socket) with opportunistic batch draining + sendmmsg.
	for i, tunQueue := range tunQueues {
		udpConn := s.udpConns[i%len(s.udpConns)]
		wg.Add(1)
		go func(tr io.Reader, conn *net.UDPConn) {
			defer wg.Done()
			s.runOutboundLoop(ctx, tr, conn)
		}(tunQueue, udpConn)
	}

	s.logger.Info("vpn-server running",
		"listen_addr", s.ListenAddr().String(),
		"tun", s.tun.Name(),
		"cidr", s.cfg.TUN.CIDR,
		"mtu", s.cfg.TUN.MTU,
		"workers", len(s.udpConns),
		"public_key", protocol.EncodeKey(s.serverPub),
	)

	<-ctx.Done()
	close(stopDone)
	wg.Wait()

	if s.natCleanup != nil {
		if err := s.natCleanup(); err != nil {
			s.logger.Warn("nftables cleanup returned error", "err", err)
		}
	}
	_ = s.peers.Close()
	return nil
}

// runInboundLoop implements Section 5 Loop A (UDP -> TUN) using recvmmsg batch I/O via x/net/ipv4.
func (s *Server) runInboundLoop(ctx context.Context, udpConn *net.UDPConn, tunWriter io.Writer) {
	pconn := ipv4.NewPacketConn(udpConn)
	msgs := make([]ipv4.Message, udpBatchSize)
	bufs := make([]*[protocol.MaxPacketSize]byte, udpBatchSize)
	for i := range msgs {
		bufs[i] = protocol.GetPacketBuffer()
		msgs[i].Buffers = [][]byte{bufs[i][:]}
	}
	defer func() {
		for _, b := range bufs {
			protocol.PutPacketBuffer(b)
		}
	}()

	for {
		nMsgs, err := pconn.ReadBatch(msgs, 0)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			buf := bufs[0]
			n, raddr, rerr := udpConn.ReadFromUDP(buf[:])
			if rerr != nil {
				if ctx.Err() != nil || errors.Is(rerr, net.ErrClosed) {
					return
				}
				continue
			}
			s.handleInboundDatagram(buf[:n], raddr, udpConn, tunWriter)
			continue
		}

		for i := 0; i < nMsgs; i++ {
			n := msgs[i].N
			raddr, ok := msgs[i].Addr.(*net.UDPAddr)
			if !ok || raddr == nil {
				continue
			}
			s.handleInboundDatagram(bufs[i][:n], raddr, udpConn, tunWriter)
		}
	}
}

func (s *Server) handleInboundDatagram(raw []byte, remoteAddr *net.UDPAddr, udpConn *net.UDPConn, tunWriter io.Writer) {
	hdr, err := protocol.ParseHeader(raw)
	if err != nil {
		s.metrics.PacketsDroppedTotal.WithLabelValues("malformed").Inc()
		return
	}

	switch hdr.Type {
	case protocol.PacketTypeData:
		if len(raw) < protocol.HeaderSize+protocol.AEADTagSize+protocol.MinIPv4HdrSize {
			s.metrics.PacketsDroppedTotal.WithLabelValues("malformed").Inc()
			return
		}
		sess := s.sessions.GetByID(hdr.SessionID)
		if sess == nil {
			s.metrics.PacketsDroppedTotal.WithLabelValues("unknown_session").Inc()
			return
		}
		now := time.Now()
		if sess.HardExpired(now, s.cfg.Security.KeyRotationInterval, s.cfg.Security.MaxPackets, session.DefaultOldSessionGrace) {
			s.metrics.PacketsDroppedTotal.WithLabelValues("expired_key").Inc()
			return
		}
		if !sess.ReplayWindow.Check(hdr.Counter) {
			s.metrics.PacketsDroppedTotal.WithLabelValues("replay").Inc()
			return
		}
		_, plain, err := protocol.OpenPacket(raw[protocol.HeaderSize:], sess.RxKey, raw)
		if err != nil {
			s.metrics.PacketsDroppedTotal.WithLabelValues("auth_failed").Inc()
			return
		}
		if !sess.ReplayWindow.Accept(hdr.Counter) {
			s.metrics.PacketsDroppedTotal.WithLabelValues("replay").Inc()
			return
		}
		srcIP, ok := protocol.ExtractIPv4Src(plain)
		if !ok || srcIP != sess.VirtualIP4 {
			s.metrics.PacketsDroppedTotal.WithLabelValues("spoofed_ip").Inc()
			return
		}

		sess.SetRemoteAddr(remoteAddr)
		sess.Touch(now)

		if _, err := tunWriter.Write(plain); err != nil {
			if !errors.Is(err, os.ErrClosed) {
				s.logger.Debug("tun write failed", "err", err)
			}
			return
		}
		s.metrics.RxPacketsTotal.Inc()
		s.metrics.RxBytesTotal.Add(float64(len(plain)))

		if sess.ShouldRequestRekey(now, s.cfg.Security.KeyRotationInterval, s.cfg.Security.MaxPackets) {
			s.sendKeepalive(udpConn, sess, remoteAddr, []byte{protocol.KeepaliveFlagRekey})
		}

	case protocol.PacketTypeKeepalive:
		sess := s.sessions.GetByID(hdr.SessionID)
		if sess == nil {
			s.metrics.PacketsDroppedTotal.WithLabelValues("unknown_session").Inc()
			return
		}
		now := time.Now()
		if sess.HardExpired(now, s.cfg.Security.KeyRotationInterval, s.cfg.Security.MaxPackets, session.DefaultOldSessionGrace) {
			s.metrics.PacketsDroppedTotal.WithLabelValues("expired_key").Inc()
			return
		}
		if !sess.ReplayWindow.Check(hdr.Counter) {
			s.metrics.PacketsDroppedTotal.WithLabelValues("replay").Inc()
			return
		}
		_, plain, err := protocol.OpenPacket(raw[protocol.HeaderSize:], sess.RxKey, raw)
		if err != nil {
			s.metrics.PacketsDroppedTotal.WithLabelValues("auth_failed").Inc()
			return
		}
		if !sess.ReplayWindow.Accept(hdr.Counter) {
			s.metrics.PacketsDroppedTotal.WithLabelValues("replay").Inc()
			return
		}
		sess.SetRemoteAddr(remoteAddr)
		sess.Touch(now)

		if len(plain) == 1 && plain[0] == keepalivePingByte {
			s.sendKeepalive(udpConn, sess, remoteAddr, nil)
		}

	case protocol.PacketTypeHandshakeInit:
		if len(raw) != protocol.HandshakeInitSize {
			s.metrics.HandshakesTotal.WithLabelValues("malformed").Inc()
			s.metrics.PacketsDroppedTotal.WithLabelValues("malformed").Inc()
			return
		}
		var job handshakeJob
		copy(job.raw[:], raw)
		job.remoteAddr = &net.UDPAddr{
			IP:   append(net.IP(nil), remoteAddr.IP...),
			Port: remoteAddr.Port,
			Zone: remoteAddr.Zone,
		}
		job.udpConn = udpConn
		select {
		case s.handshakeCh <- job:
		default:
			s.metrics.HandshakesTotal.WithLabelValues("rate_limited").Inc()
		}

	default:
		s.metrics.PacketsDroppedTotal.WithLabelValues("malformed").Inc()
	}
}

// runOutboundLoop implements Section 5 Loop B (TUN -> UDP Socket) with zero-latency
// opportunistic TUN ring draining and batch sendmmsg (ipv4.PacketConn.WriteBatch) flushing.
func (s *Server) runOutboundLoop(ctx context.Context, tunReader io.Reader, udpConn *net.UDPConn) {
	pconn := ipv4.NewPacketConn(udpConn)
	bufs := make([]*[protocol.MaxPacketSize]byte, udpBatchSize)
	plainLens := make([]int, udpBatchSize)
	msgs := make([]ipv4.Message, udpBatchSize)
	for i := range bufs {
		bufs[i] = protocol.GetPacketBuffer()
		msgs[i].Buffers = make([][]byte, 1)
	}
	defer func() {
		for _, b := range bufs {
			protocol.PutPacketBuffer(b)
		}
	}()

	var rawTUNConn syscall.RawConn
	if osFile, ok := tunReader.(*os.File); ok {
		rawTUNConn, _ = osFile.SyscallConn()
	}

	maxPlain := protocol.MaxPacketSize - protocol.HeaderSize - protocol.AEADTagSize

	for {
		// 1. Block cleanly on the Go runtime netpoller for the first packet (zero added latency).
		n0, err := tunReader.Read(bufs[0][protocol.HeaderSize : protocol.HeaderSize+maxPlain])
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, os.ErrClosed) || errors.Is(err, io.EOF) {
				return
			}
			continue
		}
		plainLens[0] = n0
		readCount := 1

		// 2. Opportunistically drain up to 31 more immediately-ready packets from the kernel TUN queue
		// via non-blocking unix.Read (returns EAGAIN immediately when the burst ends).
		if rawTUNConn != nil {
			_ = rawTUNConn.Control(func(fd uintptr) {
				for readCount < udpBatchSize {
					nr, rerr := unix.Read(int(fd), bufs[readCount][protocol.HeaderSize:protocol.HeaderSize+maxPlain])
					if rerr != nil || nr <= 0 {
						break
					}
					plainLens[readCount] = nr
					readCount++
				}
			})
		}

		now := time.Now()
		sendCount := 0
		totalPlainBytes := 0

		for i := 0; i < readCount; i++ {
			n := plainLens[i]
			buf := bufs[i]
			plain := buf[protocol.HeaderSize : protocol.HeaderSize+n]

			dstIP, ok := protocol.ExtractIPv4Dst(plain)
			if !ok {
				s.metrics.PacketsDroppedTotal.WithLabelValues("malformed").Inc()
				continue
			}

			sess := s.sessions.GetByVirtualIP(dstIP)
			if sess == nil {
				s.metrics.PacketsDroppedTotal.WithLabelValues("no_route").Inc()
				continue
			}
			remote := sess.RemoteAddr()
			if remote == nil {
				s.metrics.PacketsDroppedTotal.WithLabelValues("no_route").Inc()
				continue
			}

			if sess.HardExpired(now, s.cfg.Security.KeyRotationInterval, s.cfg.Security.MaxPackets, session.DefaultOldSessionGrace) {
				s.metrics.PacketsDroppedTotal.WithLabelValues("expired_key").Inc()
				continue
			}

			counter, ok := sess.NextTxCounter(s.cfg.Security.MaxPackets)
			if !ok {
				s.metrics.PacketsDroppedTotal.WithLabelValues("expired_key").Inc()
				continue
			}

			hdr := protocol.Header{
				Version:   protocol.ProtocolVersion,
				Type:      protocol.PacketTypeData,
				SessionID: sess.SessionID,
				Counter:   counter,
			}
			framed := protocol.SealPacket(buf[:], sess.TxKey, hdr, plain)

			msgs[sendCount].Buffers[0] = framed
			msgs[sendCount].Addr = remote
			sendCount++
			totalPlainBytes += n

			if sess.ShouldRequestRekey(now, s.cfg.Security.KeyRotationInterval, s.cfg.Security.MaxPackets) {
				s.sendKeepalive(udpConn, sess, remote, []byte{protocol.KeepaliveFlagRekey})
			}
		}

		if sendCount == 0 {
			continue
		}

		// 3. Flush all encrypted datagrams in a single sendmmsg syscall (with WriteToUDP fallback).
		sent := 0
		for sent < sendCount {
			wn, werr := pconn.WriteBatch(msgs[sent:sendCount], 0)
			if werr != nil {
				if ctx.Err() != nil || errors.Is(werr, net.ErrClosed) {
					return
				}
				// Fallback to per-packet WriteToUDP for any unsent messages in the batch.
				for j := sent; j < sendCount; j++ {
					if raddr, ok := msgs[j].Addr.(*net.UDPAddr); ok {
						_, _ = udpConn.WriteToUDP(msgs[j].Buffers[0], raddr)
					}
				}
				break
			}
			if wn <= 0 {
				break
			}
			sent += wn
		}

		s.metrics.TxPacketsTotal.Add(float64(sendCount))
		s.metrics.TxBytesTotal.Add(float64(totalPlainBytes))
	}
}

func (s *Server) sendKeepalive(udpConn *net.UDPConn, sess *session.Session, remote *net.UDPAddr, payload []byte) {
	counter, ok := sess.NextTxCounter(s.cfg.Security.MaxPackets)
	if !ok {
		return
	}
	buf := protocol.GetPacketBuffer()
	defer protocol.PutPacketBuffer(buf)

	copy(buf[protocol.HeaderSize:], payload)
	hdr := protocol.Header{
		Version:   protocol.ProtocolVersion,
		Type:      protocol.PacketTypeKeepalive,
		SessionID: sess.SessionID,
		Counter:   counter,
	}
	framed := protocol.SealPacket(buf[:], sess.TxKey, hdr, buf[protocol.HeaderSize:protocol.HeaderSize+len(payload)])
	_, _ = udpConn.WriteToUDP(framed, remote)
}

func (s *Server) runHandshakeWorker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case job := <-s.handshakeCh:
			s.processHandshake(job)
		}
	}
}

func (s *Server) processHandshake(job handshakeJob) {
	parsed, err := protocol.ParseHandshakeInit(job.raw[:])
	if err != nil {
		s.metrics.HandshakesTotal.WithLabelValues("malformed").Inc()
		return
	}

	now := time.Now()
	peer, err := s.peers.VerifyAndAcceptHandshake(parsed.ClientStaticPub, parsed.Header.Counter, func(p *store.Peer) error {
		return protocol.VerifyHandshakeInit(
			parsed,
			s.serverPub,
			p.PSK,
			p.LastHandshakeNano,
			now,
			s.cfg.Security.MaxHandshakeSkew,
		)
	})
	if err != nil {
		switch {
		case errors.Is(err, protocol.ErrHandshakeReplay):
			s.metrics.HandshakesTotal.WithLabelValues("replayed").Inc()
		default:
			s.metrics.HandshakesTotal.WithLabelValues("unauthenticated").Inc()
		}
		s.logger.Debug("dropped handshake init", "remote", job.remoteAddr.String(), "err", err)
		return
	}

	sessionID, err := s.sessions.AllocateSessionID()
	if err != nil {
		s.logger.Error("failed to allocate session ID", "err", err)
		return
	}

	lease := protocol.LeaseConfig{
		VirtualIP: peer.VirtualIP,
		ServerVIP: s.ipPool.ServerIP(),
		PrefixLen: s.ipPool.PrefixBits(),
		MTU:       uint16(s.cfg.TUN.MTU),
	}
	respBytes, hsRes, err := protocol.RespondHandshake(parsed, s.serverPriv, peer.PSK, sessionID, lease)
	if err != nil {
		s.metrics.HandshakesTotal.WithLabelValues("malformed").Inc()
		return
	}

	newSess := session.NewSession(
		sessionID,
		peer.VirtualIP,
		peer.PublicKey,
		job.remoteAddr,
		hsRes.Suite,
		hsRes.RxKey,
		hsRes.TxKey,
		now,
	)
	rotated := s.sessions.Install(newSess, now)
	s.metrics.ActiveSessions.Set(float64(s.sessions.ActiveCount()))
	s.metrics.HandshakesTotal.WithLabelValues("success").Inc()
	if rotated {
		s.metrics.KeyRotationsTotal.Inc()
	}

	if _, err := job.udpConn.WriteToUDP(respBytes, job.remoteAddr); err != nil {
		s.logger.Warn("failed to send handshake response", "remote", job.remoteAddr.String(), "err", err)
		return
	}

	s.logger.Info("established client session",
		"session_id", sessionID,
		"peer_name", peer.Name,
		"virtual_ip", peer.VirtualIP.String(),
		"remote_addr", job.remoteAddr.String(),
		"suite", hsRes.Suite.String(),
		"rotated", rotated,
	)
}

func (s *Server) runSessionReaper(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			reaped := s.sessions.Reap(
				now,
				s.cfg.Security.KeyRotationInterval,
				s.cfg.Security.IdleTimeout,
				s.cfg.Security.MaxPackets,
				session.DefaultOldSessionGrace,
			)
			if reaped > 0 {
				s.metrics.ActiveSessions.Set(float64(s.sessions.ActiveCount()))
				s.logger.Info("reaped expired sessions", "count", reaped)
			}
		}
	}
}

func (s *Server) ServerStatus() control.StatusResponse {
	listenStr := s.cfg.ListenAddr
	if a := s.ListenAddr(); a != nil {
		listenStr = a.String()
	}
	return control.StatusResponse{
		Status:          "running",
		StartedAt:       s.startedAt,
		UptimeSeconds:   time.Since(s.startedAt).Seconds(),
		ListenAddr:      listenStr,
		TUNInterface:    s.tun.Name(),
		TUNCIDR:         s.cfg.TUN.CIDR,
		TUNMTU:          s.cfg.TUN.MTU,
		ServerPublicKey: protocol.EncodeKey(s.serverPub),
		CipherSuite:     s.suite.String(),
		AuthorizedPeers: s.peers.Count(),
		ActiveSessions:  s.sessions.ActiveCount(),
	}
}

func (s *Server) ListPeers() []store.PeerInfo        { return s.peers.List() }
func (s *Server) ListSessions() []session.SessionInfo { return s.sessions.Snapshot() }

func (s *Server) AddPeer(req control.AddPeerRequest) (*store.PeerInfo, error) {
	pub, psk, staticVIP, err := control.ValidateAddPeerRequest(req)
	if err != nil {
		return nil, err
	}
	peer, err := s.peers.UpsertPeer(pub, req.Name, psk, staticVIP)
	if err != nil {
		return nil, err
	}
	s.logger.Info("added/updated peer via control plane",
		"name", peer.Name,
		"virtual_ip", peer.VirtualIP.String(),
		"public_key", peer.PublicKeyB64,
	)
	return &store.PeerInfo{
		PublicKey:    peer.PublicKeyB64,
		PublicKeyHex: peer.PublicKeyHex,
		Name:         peer.Name,
		VirtualIP:    peer.VirtualIP.String(),
		HasPSK:       peer.HasPSK,
		Revoked:      peer.Revoked,
		CreatedAt:    peer.CreatedAt,
	}, nil
}

func (s *Server) RemovePeer(pubKeyEncoded string, deleteCompletely bool) error {
	pub, err := protocol.DecodePublicKey(pubKeyEncoded)
	if err != nil {
		return err
	}
	if deleteCompletely {
		if err := s.peers.DeletePeer(pub); err != nil {
			return err
		}
	} else {
		if err := s.peers.RevokePeer(pub); err != nil {
			return err
		}
	}
	evicted := s.sessions.RemoveByPeer(pub)
	s.metrics.ActiveSessions.Set(float64(s.sessions.ActiveCount()))
	s.logger.Info("revoked peer via control plane",
		"public_key", protocol.EncodeKey(pub),
		"deleted", deleteCompletely,
		"evicted_sessions", evicted,
	)
	return nil
}
