package config

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	"vpn-server/internal/protocol"
	"vpn-server/internal/session"
)

// ServerConfig defines the declarative YAML schema for vpn-server.
type ServerConfig struct {
	ListenAddr   string `yaml:"listen_addr"`
	PrivateKey   string `yaml:"private_key"`
	CipherSuite  string `yaml:"cipher_suite"`
	Workers      int    `yaml:"workers"`
	SocketBuffer int    `yaml:"socket_buffer_bytes"`
	DropUser     string `yaml:"drop_user"`

	TUN struct {
		Name string `yaml:"name"`
		CIDR string `yaml:"cidr"`
		MTU  int    `yaml:"mtu"`
	} `yaml:"tun"`

	NAT struct {
		Enable          *bool  `yaml:"enable"`
		EgressInterface string `yaml:"egress_interface"`
		TableName       string `yaml:"table_name"`
	} `yaml:"nat"`

	Security struct {
		KeyRotationInterval time.Duration `yaml:"key_rotation_interval"`
		MaxPackets          uint64        `yaml:"max_packets"`
		IdleTimeout         time.Duration `yaml:"idle_timeout"`
		MaxHandshakeSkew    time.Duration `yaml:"max_handshake_skew"`
	} `yaml:"security"`

	Control struct {
		SocketPath string `yaml:"socket_path"`
	} `yaml:"control"`

	Storage struct {
		SQLitePath string `yaml:"sqlite_path"`
	} `yaml:"storage"`

	Observability struct {
		LogLevel    string `yaml:"log_level"`
		MetricsAddr string `yaml:"metrics_addr"`
	} `yaml:"observability"`

	Tuning struct {
		Enable bool `yaml:"enable"`
	} `yaml:"tuning"`

	Peers []PeerConfig `yaml:"peers"`
}

// PeerConfig declares a static peer in the server YAML configuration.
type PeerConfig struct {
	Name      string `yaml:"name"`
	PublicKey string `yaml:"public_key"`
	PSK       string `yaml:"psk"`
	VirtualIP string `yaml:"virtual_ip"`
}

// ClientConfig defines the declarative YAML schema for vpn-client.
type ClientConfig struct {
	ServerAddr      string        `yaml:"server_addr"`
	ServerPublicKey string        `yaml:"server_public_key"`
	PrivateKey      string        `yaml:"private_key"`
	PSK             string        `yaml:"psk"`
	CipherSuite     string        `yaml:"cipher_suite"`
	TUNName         string        `yaml:"tun_name"`
	Routes          []string      `yaml:"routes"`
	Keepalive       time.Duration `yaml:"keepalive_interval"`
	RekeyInterval   time.Duration `yaml:"rekey_interval"`
	LogLevel        string        `yaml:"log_level"`
}

// LoadServerConfig reads, defaults, and validates a ServerConfig from a YAML file.
func LoadServerConfig(path string) (*ServerConfig, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseServerConfig(raw)
}

// ParseServerConfig unmarshals YAML bytes and applies defaults + validation.
func ParseServerConfig(raw []byte) (*ServerConfig, error) {
	cfg := &ServerConfig{}
	if err := yaml.Unmarshal(raw, cfg); err != nil {
		return nil, fmt.Errorf("parse server yaml: %w", err)
	}
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// ApplyDefaults populates spec-compliant defaults on unset fields.
func (c *ServerConfig) ApplyDefaults() {
	if c.ListenAddr == "" {
		c.ListenAddr = "0.0.0.0:51820"
	}
	if c.CipherSuite == "" {
		c.CipherSuite = "chacha20-poly1305"
	}
	if c.Workers <= 0 {
		c.Workers = 1
	}
	if c.SocketBuffer <= 0 {
		c.SocketBuffer = 16 * 1024 * 1024 // 16 MiB
	}
	if c.TUN.Name == "" {
		c.TUN.Name = "tun0"
	}
	if c.TUN.CIDR == "" {
		c.TUN.CIDR = "10.100.0.1/24"
	}
	if c.TUN.MTU <= 0 {
		c.TUN.MTU = protocol.DefaultTUNMTU
	}
	if c.NAT.Enable == nil {
		tr := true
		c.NAT.Enable = &tr
	}
	if c.NAT.EgressInterface == "" {
		c.NAT.EgressInterface = "auto"
	}
	if c.NAT.TableName == "" {
		c.NAT.TableName = "vpn_nat"
	}
	if c.Security.KeyRotationInterval <= 0 {
		c.Security.KeyRotationInterval = session.DefaultKeyRotationInterval
	}
	if c.Security.MaxPackets == 0 {
		c.Security.MaxPackets = session.DefaultMaxPackets
	}
	if c.Security.IdleTimeout <= 0 {
		c.Security.IdleTimeout = session.DefaultIdleTimeout
	}
	if c.Security.MaxHandshakeSkew <= 0 {
		c.Security.MaxHandshakeSkew = protocol.DefaultMaxHandshakeSkew
	}
	if c.Control.SocketPath == "" {
		c.Control.SocketPath = "/run/vpn.sock"
	}
	if c.Observability.LogLevel == "" {
		c.Observability.LogLevel = "info"
	}
}

// Validate checks cryptographic keys, tunnel CIDR, MTU, and static peer entries.
func (c *ServerConfig) Validate() error {
	if c.PrivateKey == "" {
		return errors.New("config: private_key is required")
	}
	if _, err := protocol.DecodePrivateKey(c.PrivateKey); err != nil {
		return fmt.Errorf("config: invalid server private_key: %w", err)
	}
	if _, err := protocol.ParseCipherSuite(c.CipherSuite); err != nil {
		return fmt.Errorf("config: %w", err)
	}
	if _, err := session.NewIPPool(c.TUN.CIDR); err != nil {
		return fmt.Errorf("config: %w", err)
	}
	if c.TUN.MTU < 576 || c.TUN.MTU > protocol.MaxPacketSize-protocol.HeaderSize-protocol.AEADTagSize {
		return fmt.Errorf("config: invalid tun.mtu %d", c.TUN.MTU)
	}
	for i, p := range c.Peers {
		if _, err := protocol.DecodePublicKey(p.PublicKey); err != nil {
			return fmt.Errorf("config: peer[%d] invalid public_key: %w", i, err)
		}
		if _, err := protocol.DecodePSK(p.PSK); err != nil {
			return fmt.Errorf("config: peer[%d] invalid psk: %w", i, err)
		}
		if p.VirtualIP != "" {
			if addr, err := netip.ParseAddr(p.VirtualIP); err != nil || !addr.Is4() {
				return fmt.Errorf("config: peer[%d] invalid virtual_ip %q", i, p.VirtualIP)
			}
		}
	}
	return nil
}

// LoadClientConfig reads, defaults, and validates a ClientConfig from a YAML file.
func LoadClientConfig(path string) (*ClientConfig, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg := &ClientConfig{}
	if err := yaml.Unmarshal(raw, cfg); err != nil {
		return nil, fmt.Errorf("parse client yaml: %w", err)
	}
	if cfg.CipherSuite == "" {
		cfg.CipherSuite = "chacha20-poly1305"
	}
	if cfg.TUNName == "" {
		cfg.TUNName = "tun0"
	}
	if cfg.Keepalive <= 0 {
		cfg.Keepalive = 25 * time.Second
	}
	if cfg.RekeyInterval <= 0 {
		cfg.RekeyInterval = 50 * time.Minute
	}
	if cfg.ServerAddr == "" {
		return nil, errors.New("client config: server_addr is required")
	}
	if _, err := protocol.DecodePublicKey(cfg.ServerPublicKey); err != nil {
		return nil, fmt.Errorf("client config: invalid server_public_key: %w", err)
	}
	if _, err := protocol.DecodePrivateKey(cfg.PrivateKey); err != nil {
		return nil, fmt.Errorf("client config: invalid private_key: %w", err)
	}
	if _, err := protocol.DecodePSK(cfg.PSK); err != nil {
		return nil, fmt.Errorf("client config: invalid psk: %w", err)
	}
	if _, err := protocol.ParseCipherSuite(cfg.CipherSuite); err != nil {
		return nil, err
	}
	return cfg, nil
}
