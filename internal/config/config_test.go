package config

import (
	"testing"
	"time"

	"vpn-server/internal/protocol"
)

func TestParseServerConfigDefaultsAndValidation(t *testing.T) {
	_, srvPriv, _ := protocol.GenerateStaticKeyPair()
	peerPub, _, _ := protocol.GenerateStaticKeyPair()

	yamlText := `
private_key: "` + protocol.EncodeKey(srvPriv) + `"
peers:
  - name: "alice"
    public_key: "` + protocol.EncodeKey(peerPub) + `"
    virtual_ip: "10.100.0.2"
`
	cfg, err := ParseServerConfig([]byte(yamlText))
	if err != nil {
		t.Fatalf("ParseServerConfig: %v", err)
	}
	if cfg.ListenAddr != "0.0.0.0:51820" {
		t.Fatalf("unexpected default ListenAddr: %s", cfg.ListenAddr)
	}
	if cfg.TUN.MTU != 1400 || cfg.TUN.CIDR != "10.100.0.1/24" || cfg.TUN.Name != "tun0" {
		t.Fatalf("unexpected TUN defaults: %+v", cfg.TUN)
	}
	if cfg.Security.KeyRotationInterval != time.Hour || cfg.Security.MaxPackets != (1<<32) {
		t.Fatalf("unexpected security defaults: %+v", cfg.Security)
	}
}
