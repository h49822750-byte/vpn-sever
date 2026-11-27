//go:build linux

package client

import (
	"context"
	"crypto/cipher"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"

	"vpn-server/internal/config"
	"vpn-server/internal/netstack"
	"vpn-server/internal/protocol"
	"vpn-server/internal/session"
)

const clientBatchSize = 32

type activeKeySet struct {
	sessionID    uint32
	rxKey        cipher.AEAD
	txKey        cipher.AEAD
	txCounter    atomic.Uint64
	replayWindow protocol.ReplayWindow
	lease        protocol.LeaseConfig
	createdAt    time.Time
}

// Client implements a full user-space VPN client speaking the spec.md wire protocol,
// with 16 MiB UDP socket buffers and recvmmsg/sendmmsg batch I/O for high-bitrate streaming.
type Client struct {
	cfg        *config.ClientConfig
	clientPriv ed25519.PrivateKey
	serverPub  ed25519.PublicKey
	psk        [32]byte
	suite      protocol.CipherSuite
	serverAddr *net.UDPAddr
	logger     *slog.Logger

	tun           netstack.TUNDevice
	ownsTUNConfig bool
	udpConn       *net.UDPConn

	active      atomic.Pointer[activeKeySet]
	previous    atomic.Pointer[activeKeySet]
	rekeySignal chan struct{}

	handshakeMu sync.Mutex
	pendingHS   *protocol.HandshakeInitiatorState
	hsRespCh    chan []byte
}

// NewLinuxClient creates a VPN client backed by a real Linux /dev/net/tun interface.
func NewLinuxClient(cfg *config.ClientConfig, logger *slog.Logger) (*Client, error) {
	c, err := newBaseClient(cfg, logger)
	if err != nil {
		return nil, err
	}
	tunDev, err := netstack.OpenTUN(cfg.TUNName, 1)
	if err != nil {
		_ = c.udpConn.Close()
		return nil, err
	}
	c.tun = tunDev
	c.ownsTUNConfig = true
	return c, nil
}

// NewCoreClient creates a VPN client using a caller-supplied TUNDevice and UDPConn (for tests).
func NewCoreClient(cfg *config.ClientConfig, tun netstack.TUNDevice, udpConn *net.UDPConn, logger *slog.Logger) (*Client, error) {
	c, err := newBaseClientWithConn(cfg, udpConn, logger)
	if err != nil {
		return nil, err
	}
	c.tun = tun
	c.ownsTUNConfig = false
	return c, nil
}

func newBaseClient(cfg *config.ClientConfig, logger *slog.Logger) (*Client, error) {
	const bufSize = 16 * 1024 * 1024
	udpConn, err := netstack.ListenUDP("0.0.0.0:0", false, bufSize, bufSize)
	if err != nil {
		return nil, err
	}
	c, err := newBaseClientWithConn(cfg, udpConn, logger)
	if err != nil {
		_ = udpConn.Close()
		return nil, err
	}
	return c, nil
}

func newBaseClientWithConn(cfg *config.ClientConfig, udpConn *net.UDPConn, logger *slog.Logger) (*Client, error) {
	if logger == nil {
		logger = slog.Default()
	}
	priv, err := protocol.DecodePrivateKey(cfg.PrivateKey)
	if err != nil {
		return nil, err
	}
	srvPub, err := protocol.DecodePublicKey(cfg.ServerPublicKey)
	if err != nil {
		return nil, err
	}
	psk, err := protocol.DecodePSK(cfg.PSK)
	if err != nil {
		return nil, err
	}
	suite, err := protocol.ParseCipherSuite(cfg.CipherSuite)
	if err != nil {
		return nil, err
	}
	srvAddr, err := net.ResolveUDPAddr("udp4", cfg.ServerAddr)
	if err != nil {
		return nil, fmt.Errorf("resolve server_addr %q: %w", cfg.ServerAddr, err)
	}
	return &Client{
		cfg:         cfg,
		clientPriv:  priv,
		serverPub:   srvPub,
		psk:         psk,
		suite:       suite,
		serverAddr:  srvAddr,
		logger:      logger,
		udpConn:     udpConn,
		rekeySignal: make(chan struct{}, 1),
		hsRespCh:    make(chan []byte, 4),
	}, nil
}

func (c *Client) Lease() (protocol.LeaseConfig, bool) {
	cur := c.active.Load()
	if cur == nil {
		return protocol.LeaseConfig{}, false
	}
	return cur.lease, true
}

func (c *Client) SessionID() uint32 {
	if cur := c.active.Load(); cur != nil {
		return cur.sessionID
	}
	return 0
}

func (c *Client) TriggerRekey() {
	select {
	case c.rekeySignal <- struct{}{}:
	default:
	}
}

func (c *Client) ConnectAndRun(ctx context.Context, readyCh chan<- protocol.LeaseConfig) error {
	var wg sync.WaitGroup

	stopDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = c.udpConn.Close()
			_ = c.tun.Close()
		case <-stopDone:
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		c.runInboundLoop(ctx)
	}()

	if err := c.performHandshake(ctx); err != nil {
		close(stopDone)
		_ = c.udpConn.Close()
		_ = c.tun.Close()
		wg.Wait()
		return err
	}

	lease := c.active.Load().lease
	if c.ownsTUNConfig {
		cidr := fmt.Sprintf("%s/%d", lease.VirtualIP.String(), lease.PrefixLen)
		if err := netstack.ConfigureInterface(c.tun.Name(), cidr, int(lease.MTU)); err != nil {
			close(stopDone)
			_ = c.udpConn.Close()
			_ = c.tun.Close()
			wg.Wait()
			return err
		}
		for _, rt := range c.cfg.Routes {
			if err := netstack.AddRoute(c.tun.Name(), rt, lease.ServerVIP); err != nil {
				close(stopDone)
				_ = c.udpConn.Close()
				_ = c.tun.Close()
				wg.Wait()
				return err
			}
		}
	}

	if readyCh != nil {
		select {
		case readyCh <- lease:
		default:
		}
	}

	wg.Add(2)
	go func() {
		defer wg.Done()
		c.runOutboundLoop(ctx)
	}()
	go func() {
		defer wg.Done()
		c.runMaintenanceLoop(ctx)
	}()

	<-ctx.Done()
	close(stopDone)
	wg.Wait()
	return nil
}

func (c *Client) performHandshake(ctx context.Context) error {
	c.handshakeMu.Lock()
	defer c.handshakeMu.Unlock()

	var prevID uint32
	if cur := c.active.Load(); cur != nil {
		prevID = cur.sessionID
	}

	for attempt := 1; attempt <= 5; attempt++ {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		initPkt, state, err := protocol.BuildHandshakeInit(
			c.clientPriv,
			c.serverPub,
			c.psk,
			c.suite,
			prevID,
			time.Now(),
		)
		if err != nil {
			return err
		}
		c.pendingHS = state

		if _, err := c.udpConn.WriteToUDP(initPkt, c.serverAddr); err != nil {
			return fmt.Errorf("send handshake init: %w", err)
		}

		timer := time.NewTimer(time.Duration(attempt) * 500 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case respBytes := <-c.hsRespCh:
			timer.Stop()
			res, err := protocol.ConsumeHandshakeResp(respBytes, state)
			if err != nil {
				c.logger.Warn("discarded invalid handshake response", "err", err)
				continue
			}
			ks := &activeKeySet{
				sessionID: res.SessionID,
				rxKey:     res.RxKey,
				txKey:     res.TxKey,
				lease:     res.Lease,
				createdAt: time.Now(),
			}
			ks.replayWindow.Accept(0)

			if old := c.active.Swap(ks); old != nil {
				c.previous.Store(old)
			}
			c.pendingHS = nil
			c.logger.Info("vpn client handshake complete",
				"session_id", res.SessionID,
				"virtual_ip", res.Lease.VirtualIP.String(),
				"server_vip", res.Lease.ServerVIP.String(),
				"mtu", res.Lease.MTU,
				"suite", res.Suite.String(),
			)
			return nil
		case <-timer.C:
		}
	}
	return errors.New("client: handshake timed out after 5 attempts")
}

func (c *Client) lookupKeySet(sessionID uint32) *activeKeySet {
	if cur := c.active.Load(); cur != nil && cur.sessionID == sessionID {
		return cur
	}
	if prev := c.previous.Load(); prev != nil && prev.sessionID == sessionID {
		return prev
	}
	return nil
}

// runInboundLoop uses recvmmsg (ReadBatch) to receive downstream video bursts with minimal syscalls.
func (c *Client) runInboundLoop(ctx context.Context) {
	pconn := ipv4.NewPacketConn(c.udpConn)
	msgs := make([]ipv4.Message, clientBatchSize)
	bufs := make([]*[protocol.MaxPacketSize]byte, clientBatchSize)
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
			n, _, rerr := c.udpConn.ReadFromUDP(bufs[0][:])
			if rerr != nil {
				if ctx.Err() != nil || errors.Is(rerr, net.ErrClosed) {
					return
				}
				continue
			}
			c.handleInboundDatagram(bufs[0][:n])
			continue
		}

		for i := 0; i < nMsgs; i++ {
			c.handleInboundDatagram(bufs[i][:msgs[i].N])
		}
	}
}

func (c *Client) handleInboundDatagram(raw []byte) {
	hdr, err := protocol.ParseHeader(raw)
	if err != nil {
		return
	}

	switch hdr.Type {
	case protocol.PacketTypeHandshakeResp:
		cp := append([]byte(nil), raw...)
		select {
		case c.hsRespCh <- cp:
		default:
		}

	case protocol.PacketTypeData:
		ks := c.lookupKeySet(hdr.SessionID)
		if ks == nil || !ks.replayWindow.Check(hdr.Counter) {
			return
		}
		_, plain, err := protocol.OpenPacket(raw[protocol.HeaderSize:], ks.rxKey, raw)
		if err != nil || !ks.replayWindow.Accept(hdr.Counter) {
			return
		}
		if _, ok := protocol.ExtractIPv4Dst(plain); !ok {
			return
		}
		_, _ = c.tun.Write(plain)

	case protocol.PacketTypeKeepalive:
		ks := c.lookupKeySet(hdr.SessionID)
		if ks == nil || !ks.replayWindow.Check(hdr.Counter) {
			return
		}
		_, plain, err := protocol.OpenPacket(raw[protocol.HeaderSize:], ks.rxKey, raw)
		if err != nil || !ks.replayWindow.Accept(hdr.Counter) {
			return
		}
		if len(plain) == 1 && plain[0] == protocol.KeepaliveFlagRekey {
			c.TriggerRekey()
		}
	}
}

// runOutboundLoop uses opportunistic TUN draining + sendmmsg (WriteBatch).
func (c *Client) runOutboundLoop(ctx context.Context) {
	pconn := ipv4.NewPacketConn(c.udpConn)
	bufs := make([]*[protocol.MaxPacketSize]byte, clientBatchSize)
	plainLens := make([]int, clientBatchSize)
	msgs := make([]ipv4.Message, clientBatchSize)
	for i := range bufs {
		bufs[i] = protocol.GetPacketBuffer()
		msgs[i].Buffers = make([][]byte, 1)
		msgs[i].Addr = c.serverAddr
	}
	defer func() {
		for _, b := range bufs {
			protocol.PutPacketBuffer(b)
		}
	}()

	var rawTUNConn syscall.RawConn
	if queries := c.tun.Queues(); len(queries) > 0 {
		if osFile, ok := queries[0].(*os.File); ok {
			rawTUNConn, _ = osFile.SyscallConn()
		}
	}

	maxPlain := protocol.MaxPacketSize - protocol.HeaderSize - protocol.AEADTagSize

	for {
		n0, err := c.tun.Read(bufs[0][protocol.HeaderSize : protocol.HeaderSize+maxPlain])
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, os.ErrClosed) || errors.Is(err, io.EOF) {
				return
			}
			continue
		}
		plainLens[0] = n0
		readCount := 1

		if rawTUNConn != nil {
			_ = rawTUNConn.Control(func(fd uintptr) {
				for readCount < clientBatchSize {
					nr, rerr := unix.Read(int(fd), bufs[readCount][protocol.HeaderSize:protocol.HeaderSize+maxPlain])
					if rerr != nil || nr <= 0 {
						break
					}
					plainLens[readCount] = nr
					readCount++
				}
			})
		}

		ks := c.active.Load()
		if ks == nil {
			continue
		}

		sendCount := 0
		for i := 0; i < readCount; i++ {
			n := plainLens[i]
			plain := bufs[i][protocol.HeaderSize : protocol.HeaderSize+n]
			if _, ok := protocol.ExtractIPv4Src(plain); !ok {
				continue
			}

			counter := ks.txCounter.Add(1)
			if counter >= session.DefaultMaxPackets-(1<<20) {
				c.TriggerRekey()
			}
			if counter >= session.DefaultMaxPackets {
				continue
			}

			hdr := protocol.Header{
				Version:   protocol.ProtocolVersion,
				Type:      protocol.PacketTypeData,
				SessionID: ks.sessionID,
				Counter:   counter,
			}
			framed := protocol.SealPacket(bufs[i][:], ks.txKey, hdr, plain)
			msgs[sendCount].Buffers[0] = framed
			msgs[sendCount].Addr = c.serverAddr
			sendCount++
		}

		sent := 0
		for sent < sendCount {
			wn, werr := pconn.WriteBatch(msgs[sent:sendCount], 0)
			if werr != nil {
				if ctx.Err() != nil || errors.Is(werr, net.ErrClosed) {
					return
				}
				for j := sent; j < sendCount; j++ {
					_, _ = c.udpConn.WriteToUDP(msgs[j].Buffers[0], c.serverAddr)
				}
				break
			}
			if wn <= 0 {
				break
			}
			sent += wn
		}
	}
}

func (c *Client) runMaintenanceLoop(ctx context.Context) {
	keepaliveTicker := time.NewTicker(c.cfg.Keepalive)
	rekeyTicker := time.NewTicker(c.cfg.RekeyInterval)
	defer keepaliveTicker.Stop()
	defer rekeyTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-keepaliveTicker.C:
			ks := c.active.Load()
			if ks == nil {
				continue
			}
			counter := ks.txCounter.Add(1)
			var pkt [protocol.HeaderSize + 1 + protocol.AEADTagSize]byte
			pkt[protocol.HeaderSize] = 0x00
			hdr := protocol.Header{
				Version:   protocol.ProtocolVersion,
				Type:      protocol.PacketTypeKeepalive,
				SessionID: ks.sessionID,
				Counter:   counter,
			}
			framed := protocol.SealPacket(pkt[:], ks.txKey, hdr, pkt[protocol.HeaderSize:protocol.HeaderSize+1])
			_, _ = c.udpConn.WriteToUDP(framed, c.serverAddr)

		case <-rekeyTicker.C:
			if err := c.performHandshake(ctx); err != nil && ctx.Err() == nil {
				c.logger.Warn("periodic key rotation handshake failed", "err", err)
			}

		case <-c.rekeySignal:
			if err := c.performHandshake(ctx); err != nil && ctx.Err() == nil {
				c.logger.Warn("server-requested key rotation handshake failed", "err", err)
			}
		}
	}
}

func (c *Client) LocalUDPAddr() *net.UDPAddr {
	addr, _ := c.udpConn.LocalAddr().(*net.UDPAddr)
	return addr
}
