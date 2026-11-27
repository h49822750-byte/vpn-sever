package session

import (
	"bytes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"vpn-server/internal/protocol"
)

const (
	// DefaultKeyRotationInterval enforces forward secrecy by rotating session keys after 1 hour.
	DefaultKeyRotationInterval = 1 * time.Hour

	// DefaultMaxPackets enforces forward secrecy / AEAD safety after 2^32 packets.
	DefaultMaxPackets uint64 = 1 << 32

	// DefaultIdleTimeout expires inactive client sessions.
	DefaultIdleTimeout = 3 * time.Minute

	// DefaultOldSessionGrace keeps a superseded SessionID valid on inbound UDP briefly
	// during seamless key rotation so in-flight packets are not dropped.
	DefaultOldSessionGrace = 30 * time.Second
)

// Session holds per-client cryptographic, anti-replay, and routing state as specified in Section 4.
type Session struct {
	SessionID    uint32
	VirtualIP    netip.Addr
	VirtualIP4   [4]byte
	PeerPubKey   ed25519.PublicKey
	Suite        protocol.CipherSuite
	RxKey        cipher.AEAD
	TxKey        cipher.AEAD
	TxCounter    atomic.Uint64
	ReplayWindow protocol.ReplayWindow
	CreatedAt    time.Time

	remoteAddr       atomic.Pointer[net.UDPAddr]
	lastSeenNano     atomic.Int64
	supersededAtNano atomic.Int64
	rekeyNotifyNano  atomic.Int64
}

// NewSession constructs an initialized Session with LastSeen and RemoteAddr set.
func NewSession(
	sessionID uint32,
	virtualIP netip.Addr,
	peerPub ed25519.PublicKey,
	remote *net.UDPAddr,
	suite protocol.CipherSuite,
	rxKey, txKey cipher.AEAD,
	now time.Time,
) *Session {
	s := &Session{
		SessionID:  sessionID,
		VirtualIP:  virtualIP,
		VirtualIP4: virtualIP.As4(),
		PeerPubKey: append(ed25519.PublicKey(nil), peerPub...),
		Suite:      suite,
		RxKey:      rxKey,
		TxKey:      txKey,
		CreatedAt:  now,
	}
	s.lastSeenNano.Store(now.UnixNano())
	if remote != nil {
		s.SetRemoteAddr(remote)
	}
	return s
}

// RemoteAddr returns the client's current authenticated public UDP endpoint.
func (s *Session) RemoteAddr() *net.UDPAddr {
	return s.remoteAddr.Load()
}

// SetRemoteAddr updates the client's UDP endpoint (supporting seamless roaming across networks/NATs).
// Performs zero allocation when IP and Port match the current endpoint.
func (s *Session) SetRemoteAddr(addr *net.UDPAddr) {
	if addr == nil {
		return
	}
	cur := s.remoteAddr.Load()
	if cur != nil && cur.Port == addr.Port && cur.Zone == addr.Zone && cur.IP.Equal(addr.IP) {
		return
	}
	cloned := &net.UDPAddr{
		IP:   append(net.IP(nil), addr.IP...),
		Port: addr.Port,
		Zone: addr.Zone,
	}
	s.remoteAddr.Store(cloned)
}

// LastSeen returns the timestamp of the most recent authenticated packet from this client.
func (s *Session) LastSeen() time.Time {
	return time.Unix(0, s.lastSeenNano.Load())
}

// Touch updates LastSeen to now.
func (s *Session) Touch(now time.Time) {
	s.lastSeenNano.Store(now.UnixNano())
}

// NextTxCounter atomically increments TxCounter and returns (counter, true) if within maxPackets.
func (s *Session) NextTxCounter(maxPackets uint64) (uint64, bool) {
	if maxPackets == 0 {
		maxPackets = DefaultMaxPackets
	}
	next := s.TxCounter.Add(1)
	if next >= maxPackets {
		return next, false
	}
	return next, true
}

// ShouldRequestRekey reports whether the session has reached the soft key-rotation threshold.
func (s *Session) ShouldRequestRekey(now time.Time, maxAge time.Duration, maxPackets uint64) bool {
	if s.supersededAtNano.Load() != 0 {
		return false
	}
	if maxAge <= 0 {
		maxAge = DefaultKeyRotationInterval
	}
	if maxPackets == 0 {
		maxPackets = DefaultMaxPackets
	}
	softAge := maxAge - (maxAge / 10)
	var softPackets uint64
	if maxPackets > (1 << 20) {
		softPackets = maxPackets - (1 << 20)
	} else {
		softPackets = (maxPackets * 9) / 10
	}

	needs := now.Sub(s.CreatedAt) >= softAge || s.TxCounter.Load() >= softPackets || s.ReplayWindow.Highest() >= softPackets
	if !needs {
		return false
	}
	last := s.rekeyNotifyNano.Load()
	if now.UnixNano()-last < int64(5*time.Second) {
		return false
	}
	return s.rekeyNotifyNano.CompareAndSwap(last, now.UnixNano())
}

// HardExpired reports whether the session's cryptographic keys have exceeded their hard lifetime.
func (s *Session) HardExpired(now time.Time, maxAge time.Duration, maxPackets uint64, grace time.Duration) bool {
	if maxAge <= 0 {
		maxAge = DefaultKeyRotationInterval
	}
	if maxPackets == 0 {
		maxPackets = DefaultMaxPackets
	}
	if now.Sub(s.CreatedAt) > maxAge+grace {
		return true
	}
	if s.TxCounter.Load() >= maxPackets || s.ReplayWindow.Highest() >= maxPackets {
		return true
	}
	if sup := s.supersededAtNano.Load(); sup != 0 && now.Sub(time.Unix(0, sup)) > grace {
		return true
	}
	return false
}

// SessionInfo is a serializable snapshot of a session for observability and control APIs.
type SessionInfo struct {
	SessionID   uint32    `json:"session_id"`
	VirtualIP   string    `json:"virtual_ip"`
	PeerPubKey  string    `json:"peer_public_key"`
	RemoteAddr  string    `json:"remote_addr"`
	CipherSuite string    `json:"cipher_suite"`
	TxCounter   uint64    `json:"tx_counter"`
	RxHighest   uint64    `json:"rx_highest_counter"`
	CreatedAt   time.Time `json:"created_at"`
	LastSeen    time.Time `json:"last_seen"`
	Superseded  bool      `json:"superseded"`
}

// Table maintains the SessionByID and SessionByVirtualIP routing tables with lock-free
// data-plane read fast-paths (copy-on-write immutable snapshots + O(1) /24 direct array).
type Table struct {
	mu                 sync.RWMutex
	SessionByID        map[uint32]*Session
	SessionByVirtualIP map[[4]byte]*Session

	// Lock-free hot-path structures updated on control-plane mutations:
	idSnapshot  atomic.Pointer[map[uint32]*Session]
	vipSnapshot atomic.Pointer[map[[4]byte]*Session]

	fastPrefixSet bool
	fastPrefix    [3]byte // e.g. {10, 100, 0} for O(1) array indexing
	fastPrefixOK  atomic.Bool
	fastByOctet   [256]atomic.Pointer[Session]
}

// NewTable constructs an empty thread-safe session routing table.
func NewTable() *Table {
	t := &Table{
		SessionByID:        make(map[uint32]*Session),
		SessionByVirtualIP: make(map[[4]byte]*Session),
	}
	emptyID := make(map[uint32]*Session)
	emptyVIP := make(map[[4]byte]*Session)
	t.idSnapshot.Store(&emptyID)
	t.vipSnapshot.Store(&emptyVIP)
	return t
}

// rebuildSnapshotsLocked publishes fresh immutable maps and updates the O(1) /24 array.
// Must be called with t.mu held for writing.
func (t *Table) rebuildSnapshotsLocked() {
	idCopy := make(map[uint32]*Session, len(t.SessionByID))
	for k, v := range t.SessionByID {
		idCopy[k] = v
	}
	vipCopy := make(map[[4]byte]*Session, len(t.SessionByVirtualIP))
	allMatchPrefix := t.fastPrefixSet
	for k, v := range t.SessionByVirtualIP {
		vipCopy[k] = v
		if !t.fastPrefixSet {
			t.fastPrefix = [3]byte{k[0], k[1], k[2]}
			t.fastPrefixSet = true
			allMatchPrefix = true
		} else if k[0] != t.fastPrefix[0] || k[1] != t.fastPrefix[1] || k[2] != t.fastPrefix[2] {
			allMatchPrefix = false
		}
	}

	if allMatchPrefix && t.fastPrefixSet {
		for i := range t.fastByOctet {
			key := [4]byte{t.fastPrefix[0], t.fastPrefix[1], t.fastPrefix[2], byte(i)}
			t.fastByOctet[i].Store(t.SessionByVirtualIP[key])
		}
		t.fastPrefixOK.Store(true)
	} else {
		t.fastPrefixOK.Store(false)
	}

	t.idSnapshot.Store(&idCopy)
	t.vipSnapshot.Store(&vipCopy)
}

// AllocateSessionID generates a unique cryptographically random non-zero 32-bit SessionID.
func (t *Table) AllocateSessionID() (uint32, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	var b [4]byte
	for attempts := 0; attempts < 64; attempts++ {
		if _, err := rand.Read(b[:]); err != nil {
			return 0, err
		}
		id := binary.BigEndian.Uint32(b[:])
		if id == 0 {
			continue
		}
		if _, exists := t.SessionByID[id]; !exists {
			return id, nil
		}
	}
	return 0, ErrSubnetExhausted
}

// Install inserts a session into SessionByID and SessionByVirtualIP.
func (t *Table) Install(s *Session, now time.Time) (rotated bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if prev, ok := t.SessionByVirtualIP[s.VirtualIP4]; ok && prev.SessionID != s.SessionID {
		prev.supersededAtNano.Store(now.UnixNano())
		rotated = true
	}
	t.SessionByID[s.SessionID] = s
	t.SessionByVirtualIP[s.VirtualIP4] = s
	t.rebuildSnapshotsLocked()
	return rotated
}

// GetByID performs a lock-free O(1) lookup on the inbound UDP path.
func (t *Table) GetByID(sessionID uint32) *Session {
	snap := t.idSnapshot.Load()
	if snap == nil {
		return nil
	}
	return (*snap)[sessionID]
}

// GetByVirtualIP performs a lock-free O(1) lookup on the outbound TUN path, using direct
// 256-slot array indexing when all active tunnel IPs share a /24 prefix.
func (t *Table) GetByVirtualIP(dstIP [4]byte) *Session {
	if t.fastPrefixOK.Load() &&
		dstIP[0] == t.fastPrefix[0] &&
		dstIP[1] == t.fastPrefix[1] &&
		dstIP[2] == t.fastPrefix[2] {
		return t.fastByOctet[dstIP[3]].Load()
	}
	snap := t.vipSnapshot.Load()
	if snap == nil {
		return nil
	}
	return (*snap)[dstIP]
}

// RemoveByPeer immediately terminates all sessions belonging to pubKey.
func (t *Table) RemoveByPeer(pubKey ed25519.PublicKey) int {
	t.mu.Lock()
	defer t.mu.Unlock()

	removed := 0
	for id, s := range t.SessionByID {
		if bytes.Equal(s.PeerPubKey, pubKey) {
			delete(t.SessionByID, id)
			if cur := t.SessionByVirtualIP[s.VirtualIP4]; cur == s {
				delete(t.SessionByVirtualIP, s.VirtualIP4)
			}
			removed++
		}
	}
	if removed > 0 {
		t.rebuildSnapshotsLocked()
	}
	return removed
}

// Reap removes idle, hard-expired, and superseded sessions past their grace window.
func (t *Table) Reap(now time.Time, maxAge, idleTimeout time.Duration, maxPackets uint64, grace time.Duration) int {
	if idleTimeout <= 0 {
		idleTimeout = DefaultIdleTimeout
	}
	if maxAge <= 0 {
		maxAge = DefaultKeyRotationInterval
	}
	if grace <= 0 {
		grace = DefaultOldSessionGrace
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	reaped := 0
	for id, s := range t.SessionByID {
		idleExpired := now.Sub(s.LastSeen()) > idleTimeout
		hardExpired := s.HardExpired(now, maxAge, maxPackets, grace)
		if idleExpired || hardExpired {
			delete(t.SessionByID, id)
			if cur := t.SessionByVirtualIP[s.VirtualIP4]; cur == s {
				delete(t.SessionByVirtualIP, s.VirtualIP4)
			}
			reaped++
		}
	}
	if reaped > 0 {
		t.rebuildSnapshotsLocked()
	}
	return reaped
}

// ActiveCount returns the number of active sessions routed in SessionByVirtualIP.
func (t *Table) ActiveCount() int {
	snap := t.vipSnapshot.Load()
	if snap == nil {
		return 0
	}
	return len(*snap)
}

// Snapshot returns metadata for all sessions currently in SessionByID.
func (t *Table) Snapshot() []SessionInfo {
	t.mu.RLock()
	defer t.mu.RUnlock()

	out := make([]SessionInfo, 0, len(t.SessionByID))
	for _, s := range t.SessionByID {
		remoteStr := ""
		if r := s.RemoteAddr(); r != nil {
			remoteStr = r.String()
		}
		out = append(out, SessionInfo{
			SessionID:   s.SessionID,
			VirtualIP:   s.VirtualIP.String(),
			PeerPubKey:  protocol.EncodeKey(s.PeerPubKey),
			RemoteAddr:  remoteStr,
			CipherSuite: s.Suite.String(),
			TxCounter:   s.TxCounter.Load(),
			RxHighest:   s.ReplayWindow.Highest(),
			CreatedAt:   s.CreatedAt,
			LastSeen:    s.LastSeen(),
			Superseded:  s.supersededAtNano.Load() != 0,
		})
	}
	return out
}
