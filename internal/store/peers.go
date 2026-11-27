package store

import (
	"crypto/ed25519"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	_ "modernc.org/sqlite"

	"vpn-server/internal/protocol"
	"vpn-server/internal/session"
)

var (
	ErrPeerNotFound = errors.New("store: peer not found")
	ErrPeerRevoked  = errors.New("store: peer is revoked")
)

// Peer represents an authorized VPN client and its static/leased parameters.
type Peer struct {
	PublicKey         ed25519.PublicKey
	PublicKeyHex      string
	PublicKeyB64      string
	Name              string
	PSK               [32]byte
	HasPSK            bool
	VirtualIP         netip.Addr
	Revoked           bool
	CreatedAt         time.Time
	LastHandshakeNano uint64
}

// PeerInfo is a safe, secret-redacted representation of a peer for control-plane responses.
type PeerInfo struct {
	PublicKey    string    `json:"public_key"`
	PublicKeyHex string    `json:"public_key_hex"`
	Name         string    `json:"name,omitempty"`
	VirtualIP    string    `json:"virtual_ip"`
	HasPSK       bool      `json:"has_psk"`
	Revoked      bool      `json:"revoked"`
	CreatedAt    time.Time `json:"created_at"`
}

// Registry manages authorized peers in memory with optional SQLite persistence.
type Registry struct {
	mu     sync.RWMutex
	peers  map[string]*Peer // keyed by hex(ed25519.PublicKey)
	ipPool *session.IPPool
	db     *sql.DB
}

// OpenRegistry creates a peer registry backed by ipPool and optional sqlitePath
// (pass "" for purely in-memory storage).
func OpenRegistry(ipPool *session.IPPool, sqlitePath string) (*Registry, error) {
	r := &Registry{
		peers:  make(map[string]*Peer),
		ipPool: ipPool,
	}
	if sqlitePath != "" {
		db, err := sql.Open("sqlite", sqlitePath)
		if err != nil {
			return nil, fmt.Errorf("open sqlite %q: %w", sqlitePath, err)
		}
		db.SetMaxOpenConns(1) // serialize SQLite writes cleanly
		if err := initSchema(db); err != nil {
			_ = db.Close()
			return nil, err
		}
		r.db = db
		if err := r.loadFromDB(); err != nil {
			_ = db.Close()
			return nil, err
		}
	}
	return r, nil
}

func initSchema(db *sql.DB) error {
	const ddl = `
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
CREATE TABLE IF NOT EXISTS peers (
	public_key_hex      TEXT PRIMARY KEY,
	name                TEXT NOT NULL DEFAULT '',
	psk                 BLOB,
	virtual_ip          TEXT NOT NULL,
	revoked             INTEGER NOT NULL DEFAULT 0,
	created_at_unix     INTEGER NOT NULL,
	last_handshake_nano INTEGER NOT NULL DEFAULT 0
);`
	_, err := db.Exec(ddl)
	return err
}

func (r *Registry) loadFromDB() error {
	rows, err := r.db.Query(`SELECT public_key_hex, name, psk, virtual_ip, revoked, created_at_unix, last_handshake_nano FROM peers`)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var (
			pubHex  string
			name    string
			pskBlob []byte
			vipStr  string
			revoked int
			created int64
			lastHS  int64
		)
		if err := rows.Scan(&pubHex, &name, &pskBlob, &vipStr, &revoked, &created, &lastHS); err != nil {
			return err
		}
		pubBytes, err := hex.DecodeString(pubHex)
		if err != nil || len(pubBytes) != ed25519.PublicKeySize {
			return fmt.Errorf("corrupt public_key_hex in sqlite: %q", pubHex)
		}
		vip, err := netip.ParseAddr(vipStr)
		if err != nil {
			return fmt.Errorf("corrupt virtual_ip in sqlite: %q: %w", vipStr, err)
		}
		if err := r.ipPool.ReserveStatic(pubHex, vip); err != nil {
			return fmt.Errorf("reserve persisted peer IP %s: %w", vip, err)
		}
		p := &Peer{
			PublicKey:         ed25519.PublicKey(pubBytes),
			PublicKeyHex:      pubHex,
			PublicKeyB64:      protocol.EncodeKey(pubBytes),
			Name:              name,
			VirtualIP:         vip,
			Revoked:           revoked != 0,
			CreatedAt:         time.Unix(created, 0),
			LastHandshakeNano: uint64(lastHS),
		}
		if len(pskBlob) == 32 {
			copy(p.PSK[:], pskBlob)
			p.HasPSK = !isZeroPSK(p.PSK)
		}
		r.peers[pubHex] = p
	}
	return rows.Err()
}

// Close closes the underlying SQLite database if enabled.
func (r *Registry) Close() error {
	if r.db != nil {
		return r.db.Close()
	}
	return nil
}

// UpsertPeer adds or updates an authorized peer, reserving staticIP (if valid) or dynamically
// allocating an IPv4 address from the tunnel pool, and persists to SQLite if configured.
func (r *Registry) UpsertPeer(pub ed25519.PublicKey, name string, psk [32]byte, staticIP netip.Addr) (*Peer, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, protocol.ErrInvalidKeyEncoding
	}
	pubHex := hex.EncodeToString(pub)

	r.mu.Lock()
	defer r.mu.Unlock()

	var vip netip.Addr
	var err error
	if staticIP.IsValid() {
		if err := r.ipPool.ReserveStatic(pubHex, staticIP); err != nil {
			return nil, err
		}
		vip = staticIP
	} else {
		vip, err = r.ipPool.Allocate(pubHex)
		if err != nil {
			return nil, err
		}
	}

	now := time.Now()
	existing, exists := r.peers[pubHex]
	createdAt := now
	var lastHS uint64
	if exists {
		createdAt = existing.CreatedAt
		lastHS = existing.LastHandshakeNano
	}

	peer := &Peer{
		PublicKey:         append(ed25519.PublicKey(nil), pub...),
		PublicKeyHex:      pubHex,
		PublicKeyB64:      protocol.EncodeKey(pub),
		Name:              name,
		PSK:               psk,
		HasPSK:            !isZeroPSK(psk),
		VirtualIP:         vip,
		Revoked:           false,
		CreatedAt:         createdAt,
		LastHandshakeNano: lastHS,
	}

	if r.db != nil {
		var pskSlice []byte
		if peer.HasPSK {
			pskSlice = peer.PSK[:]
		}
		_, err := r.db.Exec(`
INSERT INTO peers (public_key_hex, name, psk, virtual_ip, revoked, created_at_unix, last_handshake_nano)
VALUES (?, ?, ?, ?, 0, ?, ?)
ON CONFLICT(public_key_hex) DO UPDATE SET
	name = excluded.name,
	psk = excluded.psk,
	virtual_ip = excluded.virtual_ip,
	revoked = 0`,
			pubHex, name, pskSlice, vip.String(), createdAt.Unix(), int64(lastHS),
		)
		if err != nil {
			if !exists {
				r.ipPool.Release(pubHex)
			}
			return nil, err
		}
	}

	r.peers[pubHex] = peer
	clone := *peer
	return &clone, nil
}

// RevokePeer marks a peer as revoked so future handshakes are immediately rejected.
func (r *Registry) RevokePeer(pub ed25519.PublicKey) error {
	pubHex := hex.EncodeToString(pub)

	r.mu.Lock()
	defer r.mu.Unlock()

	p, ok := r.peers[pubHex]
	if !ok {
		return ErrPeerNotFound
	}
	if r.db != nil {
		if _, err := r.db.Exec(`UPDATE peers SET revoked = 1 WHERE public_key_hex = ?`, pubHex); err != nil {
			return err
		}
	}
	p.Revoked = true
	return nil
}

// DeletePeer completely removes a peer and frees its virtual IP lease.
func (r *Registry) DeletePeer(pub ed25519.PublicKey) error {
	pubHex := hex.EncodeToString(pub)

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, ok := r.peers[pubHex]; !ok {
		return ErrPeerNotFound
	}
	if r.db != nil {
		if _, err := r.db.Exec(`DELETE FROM peers WHERE public_key_hex = ?`, pubHex); err != nil {
			return err
		}
	}
	delete(r.peers, pubHex)
	r.ipPool.Release(pubHex)
	return nil
}

// VerifyAndAcceptHandshake looks up the peer by its 32-byte Ed25519 public key, ensures it is
// not revoked, invokes verifyFn while holding the lock, and atomically records newTimestampNano
// to prevent concurrent handshake replay attacks.
func (r *Registry) VerifyAndAcceptHandshake(
	clientPub [32]byte,
	newTimestampNano uint64,
	verifyFn func(p *Peer) error,
) (*Peer, error) {
	pubHex := hex.EncodeToString(clientPub[:])

	r.mu.Lock()
	defer r.mu.Unlock()

	p, ok := r.peers[pubHex]
	if !ok {
		return nil, ErrPeerNotFound
	}
	if p.Revoked {
		return nil, ErrPeerRevoked
	}
	if err := verifyFn(p); err != nil {
		return nil, err
	}
	p.LastHandshakeNano = newTimestampNano
	if r.db != nil {
		_, _ = r.db.Exec(`UPDATE peers SET last_handshake_nano = ? WHERE public_key_hex = ?`, int64(newTimestampNano), pubHex)
	}
	clone := *p
	return &clone, nil
}

// List returns non-sensitive metadata for all configured peers.
func (r *Registry) List() []PeerInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make([]PeerInfo, 0, len(r.peers))
	for _, p := range r.peers {
		out = append(out, PeerInfo{
			PublicKey:    p.PublicKeyB64,
			PublicKeyHex: p.PublicKeyHex,
			Name:         p.Name,
			VirtualIP:    p.VirtualIP.String(),
			HasPSK:       p.HasPSK,
			Revoked:      p.Revoked,
			CreatedAt:    p.CreatedAt,
		})
	}
	return out
}

// Count returns the total number of non-revoked peers.
func (r *Registry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	n := 0
	for _, p := range r.peers {
		if !p.Revoked {
			n++
		}
	}
	return n
}

func isZeroPSK(psk [32]byte) bool {
	var zero [32]byte
	return psk == zero
}
