package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"vpn-server/internal/protocol"
	"vpn-server/internal/session"
	"vpn-server/internal/store"
)

// PeerManager defines the runtime control surface exposed by the VPN server.
type PeerManager interface {
	ServerStatus() StatusResponse
	ListPeers() []store.PeerInfo
	AddPeer(req AddPeerRequest) (*store.PeerInfo, error)
	RemovePeer(pubKeyEncoded string, deleteCompletely bool) error
	ListSessions() []session.SessionInfo
}

// StatusResponse summarizes live VPN daemon state.
type StatusResponse struct {
	Status          string    `json:"status"`
	StartedAt       time.Time `json:"started_at"`
	UptimeSeconds   float64   `json:"uptime_seconds"`
	ListenAddr      string    `json:"listen_addr"`
	TUNInterface    string    `json:"tun_interface"`
	TUNCIDR         string    `json:"tun_cidr"`
	TUNMTU          int       `json:"tun_mtu"`
	ServerPublicKey string    `json:"server_public_key"`
	CipherSuite     string    `json:"cipher_suite"`
	AuthorizedPeers int       `json:"authorized_peers"`
	ActiveSessions  int       `json:"active_sessions"`
}

// AddPeerRequest is the JSON payload for POST /v1/peers.
type AddPeerRequest struct {
	Name      string `json:"name"`
	PublicKey string `json:"public_key"`
	PSK       string `json:"psk,omitempty"`
	VirtualIP string `json:"virtual_ip,omitempty"`
}

// Server serves the local Unix domain socket control plane API (/run/vpn.sock).
type Server struct {
	socketPath string
	listener   net.Listener
	httpServer *http.Server
	logger     *slog.Logger
}

// NewServer binds the Unix domain control socket (chmod 0600) and prepares HTTP routes.
func NewServer(socketPath string, mgr PeerManager, logger *slog.Logger) (*Server, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if err := os.MkdirAll(filepath.Dir(socketPath), 0o755); err != nil {
		return nil, fmt.Errorf("mkdir control socket dir: %w", err)
	}
	// Remove stale socket file if left behind by an unclean crash.
	if st, err := os.Lstat(socketPath); err == nil && (st.Mode()&os.ModeSocket) != 0 {
		_ = os.Remove(socketPath)
	}

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("listen unix control socket %q: %w", socketPath, err)
	}
	if err := os.Chmod(socketPath, 0o600); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("chmod control socket: %w", err)
	}

	mux := http.NewServeMux()
	s := &Server{
		socketPath: socketPath,
		listener:   ln,
		logger:     logger,
		httpServer: &http.Server{
			Handler:           mux,
			ReadHeaderTimeout: 5 * time.Second,
		},
	}
	registerRoutes(mux, mgr)
	return s, nil
}

func registerRoutes(mux *http.ServeMux, mgr PeerManager) {
	mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, mgr.ServerStatus())
	})

	mux.HandleFunc("GET /v1/sessions", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, mgr.ListSessions())
	})

	mux.HandleFunc("GET /v1/peers", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, mgr.ListPeers())
	})

	mux.HandleFunc("POST /v1/peers", func(w http.ResponseWriter, r *http.Request) {
		var req AddPeerRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("invalid JSON body: %w", err))
			return
		}
		info, err := mgr.AddPeer(req)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusCreated, info)
	})

	mux.HandleFunc("POST /v1/peers/revoke", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			PublicKey string `json:"public_key"`
			Delete    bool   `json:"delete"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("invalid JSON body: %w", err))
			return
		}
		if err := mgr.RemovePeer(body.PublicKey, body.Delete); err != nil {
			status := http.StatusBadRequest
			if errors.Is(err, store.ErrPeerNotFound) {
				status = http.StatusNotFound
			}
			writeError(w, status, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"revoked": true, "deleted": body.Delete})
	})

	mux.HandleFunc("DELETE /v1/peers/", func(w http.ResponseWriter, r *http.Request) {
		key := strings.TrimPrefix(r.URL.Path, "/v1/peers/")
		if key == "" {
			writeError(w, http.StatusBadRequest, errors.New("missing peer public key"))
			return
		}
		if err := mgr.RemovePeer(key, true); err != nil {
			status := http.StatusBadRequest
			if errors.Is(err, store.ErrPeerNotFound) {
				status = http.StatusNotFound
			}
			writeError(w, status, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"deleted": true})
	})
}

// ValidateAddPeerRequest parses and validates key material in an AddPeerRequest.
func ValidateAddPeerRequest(req AddPeerRequest) (pub []byte, psk [32]byte, vip netip.Addr, err error) {
	pubKey, err := protocol.DecodePublicKey(req.PublicKey)
	if err != nil {
		return nil, [32]byte{}, netip.Addr{}, fmt.Errorf("invalid public_key: %w", err)
	}
	pskVal, err := protocol.DecodePSK(req.PSK)
	if err != nil {
		return nil, [32]byte{}, netip.Addr{}, fmt.Errorf("invalid psk: %w", err)
	}
	var staticIP netip.Addr
	if strings.TrimSpace(req.VirtualIP) != "" {
		staticIP, err = netip.ParseAddr(strings.TrimSpace(req.VirtualIP))
		if err != nil || !staticIP.Is4() {
			return nil, [32]byte{}, netip.Addr{}, fmt.Errorf("invalid IPv4 virtual_ip %q", req.VirtualIP)
		}
	}
	return pubKey, pskVal, staticIP, nil
}

// Serve runs the HTTP server until Shutdown or listener close.
func (s *Server) Serve() error {
	err := s.httpServer.Serve(s.listener)
	if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

// Shutdown gracefully stops the Unix control server and removes the socket file.
func (s *Server) Shutdown(ctx context.Context) error {
	err := s.httpServer.Shutdown(ctx)
	_ = os.Remove(s.socketPath)
	return err
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}
