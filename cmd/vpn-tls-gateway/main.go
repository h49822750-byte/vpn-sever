//go:build linux

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	socketBufSize = 24 * 1024 * 1024 // 24 MiB per TCP socket for high-BDP 1080p/4K streaming
	notsentLowat  = 128 * 1024       // 128 KiB unsent buffer cap to prevent kernel bufferbloat
	copyBufSize   = 256 * 1024       // 256 KiB pooled relay buffers (4x fewer syscalls on bursts)
	tfoQueueLen   = 256              // Server-side TCP Fast Open SYN-data backlog
	dnsCacheTTL   = 5 * time.Minute  // In-memory CDN IPv4 cache TTL
)

var relayBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, copyBufSize)
		return &b
	},
}

type dnsCacheEntry struct {
	ip        netip.Addr
	expiresAt time.Time
}

type dnsResolverCache struct {
	mu      sync.RWMutex
	entries map[string]dnsCacheEntry
}

func newDNSResolverCache() *dnsResolverCache {
	return &dnsResolverCache{
		entries: make(map[string]dnsCacheEntry, 256),
	}
}

func (c *dnsResolverCache) resolvePublicIPv4(ctx context.Context, host string) (netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		if isPublicRoutableIPv4(ip) {
			return ip, nil
		}
		return netip.Addr{}, errors.New("non-public IP literal")
	}

	key := strings.ToLower(host)
	now := time.Now()

	c.mu.RLock()
	cached, ok := c.entries[key]
	c.mu.RUnlock()
	if ok && now.Before(cached.expiresAt) {
		return cached.ip, nil
	}

	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", key)
	if err != nil || len(ips) == 0 {
		if ok {
			// Serve stale cached entry if transient upstream DNS hiccups occur.
			return cached.ip, nil
		}
		return netip.Addr{}, errors.New("dns lookup failed")
	}

	for _, ip := range ips {
		if isPublicRoutableIPv4(ip) {
			c.mu.Lock()
			if len(c.entries) > 4096 {
				clear(c.entries)
			}
			c.entries[key] = dnsCacheEntry{
				ip:        ip,
				expiresAt: now.Add(dnsCacheTTL),
			}
			c.mu.Unlock()
			return ip, nil
		}
	}
	return netip.Addr{}, errors.New("resolved to non-public IPv4")
}

func main() {
	listenAddr := flag.String("listen", "0.0.0.0:443", "TLS TCP listen address")
	certPath := flag.String("cert", "/etc/vpn-tls/cert.pem", "Path to TLS certificate PEM")
	keyPath := flag.String("key", "/etc/vpn-tls/key.pem", "Path to TLS private key PEM")
	publicIP := flag.String("san-ip", "203.0.113.10", "Public IPv4 for auto-generated X.509 SAN")
	authUser := flag.String("user", os.Getenv("TLS_PROXY_USER"), "Required Basic auth username")
	authPass := flag.String("pass", os.Getenv("TLS_PROXY_PASS"), "Required Basic auth password")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	if *authUser == "" || *authPass == "" {
		logger.Error("TLS_PROXY_USER and TLS_PROXY_PASS are required")
		os.Exit(1)
	}

	tlsCert, fingerprintHex, err := loadOrGenerateCert(*certPath, *keyPath, *publicIP)
	if err != nil {
		logger.Error("failed to initialize TLS certificate", "err", err)
		os.Exit(1)
	}
	_ = os.WriteFile(filepath.Join(filepath.Dir(*certPath), "fingerprint.sha256"), []byte(fingerprintHex+"\n"), 0o600)

	expectedAuthHeader := "Basic " + base64.StdEncoding.EncodeToString([]byte(*authUser+":"+*authPass))

	lc := net.ListenConfig{
		KeepAlive: 30 * time.Second,
		Control:   tuneListenerSocket,
	}
	rawLn, err := lc.Listen(context.Background(), "tcp4", *listenAddr)
	if err != nil {
		logger.Error("failed to bind TCP listener", "addr", *listenAddr, "err", err)
		os.Exit(1)
	}

	tlsCfg := &tls.Config{
		Certificates:           []tls.Certificate{tlsCert},
		MinVersion:             tls.VersionTLS13,
		CurvePreferences:       []tls.CurveID{tls.X25519, tls.CurveP256}, // Compact 32B X25519 avoids 1.2KB MLKEM fragmentation
		SessionTicketsDisabled: false,
		NextProtos:             []string{"http/1.1"},
	}
	tlsLn := tls.NewListener(tcpTuneListener{rawLn}, tlsCfg)

	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
		Control:   tuneUpstreamSocket,
	}
	dnsCache := newDNSResolverCache()

	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handleRequest(w, r, expectedAuthHeader, dialer, dnsCache, logger)
		}),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       180 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()

	logger.Info("vpn-tls-gateway running (Split-TCP BBR + TFO + X25519 + DNS-Cache)",
		"listen", *listenAddr,
		"cert_sha256", fingerprintHex,
	)

	if err := srv.Serve(tlsLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("vpn-tls-gateway exited", "err", err)
		os.Exit(1)
	}
}

type tcpTuneListener struct {
	net.Listener
}

func (l tcpTuneListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		_ = tc.SetReadBuffer(socketBufSize)
		_ = tc.SetWriteBuffer(socketBufSize)
	}
	return c, nil
}

func tuneListenerSocket(_, _ string, c syscall.RawConn) error {
	_ = c.Control(func(fd uintptr) {
		_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
		_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, socketBufSize)
		_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF, socketBufSize)
		_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_NODELAY, 1)
		_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_FASTOPEN, tfoQueueLen)
		_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_NOTSENT_LOWAT, notsentLowat)
		_ = unix.SetsockoptString(int(fd), unix.IPPROTO_TCP, unix.TCP_CONGESTION, "bbr")
	})
	return nil
}

func tuneUpstreamSocket(_, _ string, c syscall.RawConn) error {
	_ = c.Control(func(fd uintptr) {
		_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, socketBufSize)
		_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF, socketBufSize)
		_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_NODELAY, 1)
		_ = unix.SetsockoptString(int(fd), unix.IPPROTO_TCP, unix.TCP_CONGESTION, "bbr")
	})
	return nil
}

func handleRequest(
	w http.ResponseWriter,
	r *http.Request,
	expectedAuth string,
	dialer *net.Dialer,
	dnsCache *dnsResolverCache,
	logger *slog.Logger,
) {
	auth := r.Header.Get("Proxy-Authorization")
	if subtle.ConstantTimeCompare([]byte(auth), []byte(expectedAuth)) != 1 {
		if r.Method == http.MethodConnect {
			w.Header().Set("Proxy-Authenticate", `Basic realm="vpn"`)
			http.Error(w, "Proxy Authentication Required", http.StatusProxyAuthRequired)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
		return
	}

	if r.Method != http.MethodConnect {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	host, port, err := net.SplitHostPort(r.Host)
	if err != nil || host == "" || port == "" {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()

	ip, err := dnsCache.resolvePublicIPv4(ctx, host)
	if err != nil {
		logger.Debug("rejected or failed CONNECT target resolution", "host", r.Host, "err", err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}

	upstream, err := dialer.DialContext(ctx, "tcp4", net.JoinHostPort(ip.String(), port))
	if err != nil {
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		_ = upstream.Close()
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	clientConn, clientBuf, err := hj.Hijack()
	if err != nil {
		_ = upstream.Close()
		return
	}

	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		_ = clientConn.Close()
		_ = upstream.Close()
		return
	}

	if buffered := clientBuf.Reader.Buffered(); buffered > 0 {
		if _, err := io.CopyN(upstream, clientBuf, int64(buffered)); err != nil {
			_ = clientConn.Close()
			_ = upstream.Close()
			return
		}
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		pipeStream(upstream, clientConn)
		if tc, ok := upstream.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		} else {
			_ = upstream.Close()
		}
	}()
	go func() {
		defer wg.Done()
		pipeStream(clientConn, upstream)
		_ = clientConn.Close()
	}()
	wg.Wait()
	_ = upstream.Close()
	_ = clientConn.Close()
}

func pipeStream(dst io.Writer, src io.Reader) {
	bufPtr := relayBufPool.Get().(*[]byte)
	defer relayBufPool.Put(bufPtr)
	_, _ = io.CopyBuffer(dst, src, *bufPtr)
}

func isPublicRoutableIPv4(ip netip.Addr) bool {
	if !ip.Is4() {
		return false
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}
	b := ip.As4()
	if b[0] == 100 && (b[1]&0xc0) == 64 {
		return false
	}
	return true
}

func loadOrGenerateCert(certPath, keyPath, sanIP string) (tls.Certificate, string, error) {
	if _, err := os.Stat(certPath); err == nil {
		cert, lerr := tls.LoadX509KeyPair(certPath, keyPath)
		if lerr == nil && len(cert.Certificate) > 0 {
			sum := sha256.Sum256(cert.Certificate[0])
			return cert, hex.EncodeToString(sum[:]), nil
		}
	}

	if err := os.MkdirAll(filepath.Dir(certPath), 0o700); err != nil {
		return tls.Certificate{}, "", err
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, "", err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, "", err
	}

	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: sanIP,
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if parsedIP := net.ParseIP(strings.TrimSpace(sanIP)); parsedIP != nil {
		tmpl.IPAddresses = []net.IP{parsedIP}
	} else {
		tmpl.DNSNames = []string{sanIP}
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, "", err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		return tls.Certificate{}, "", err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return tls.Certificate{}, "", err
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	sum := sha256.Sum256(derBytes)
	return cert, hex.EncodeToString(sum[:]), nil
}
