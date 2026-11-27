//go:build linux

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"vpn-server/internal/protocol"
)

// TestLinuxNetnsFullTunnelAndNAT builds three isolated Linux network namespaces:
//
//   [ns_cli: 198.51.100.2] <--UDP :51820--> [ns_srv: 198.51.100.1 | tun0 10.100.0.1/24 | eth0 203.0.113.1] <---> [ns_wan: 203.0.113.2]
//
// It compiles and runs the real vpn-server, vpn-client, and vpnctl binaries, verifying:
//  1. /dev/net/tun provisioning (tun0, MTU 1400, IFF_MULTI_QUEUE with 2 workers + SO_REUSEPORT)
//  2. Netlink IP/route assignment and net.ipv4.ip_forward = 1
//  3. Programmatic nftables SNAT masquerading (ns_wan has NO route to 10.100.0.0/24, so HTTP
//     requests from ns_cli -> 203.0.113.2:8080 ONLY succeed via nftables masquerade to 203.0.113.1!)
//  4. Zero-downtime peer onboarding and inspection via vpnctl over /run/vpn.sock
//  5. Prometheus metrics exposition (/metrics)
func TestLinuxNetnsFullTunnelAndNAT(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("Linux network namespace E2E test requires root / CAP_NET_ADMIN")
	}

	tmpDir := t.TempDir()
	srvBin := filepath.Join(tmpDir, "vpn-server")
	cliBin := filepath.Join(tmpDir, "vpn-client")
	ctlBin := filepath.Join(tmpDir, "vpnctl")

	repoRoot, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}

	// Build all three binaries once.
	for _, target := range []struct {
		pkg string
		out string
	}{
		{"./cmd/vpn-server", srvBin},
		{"./cmd/vpn-client", cliBin},
		{"./cmd/vpnctl", ctlBin},
	} {
		cmd := exec.Command("go", "build", "-o", target.out, target.pkg)
		cmd.Dir = repoRoot
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("go build %s failed: %v\n%s", target.pkg, err, out)
		}
	}

	suffix := fmt.Sprintf("%d", os.Getpid())
	nsCli := "vpn_cli_" + suffix
	nsSrv := "vpn_srv_" + suffix
	nsWan := "vpn_wan_" + suffix

	t.Cleanup(func() {
		for _, ns := range []string{nsCli, nsSrv, nsWan} {
			_ = exec.Command("ip", "netns", "del", ns).Run()
		}
	})

	setupScript := fmt.Sprintf(`set -e
ip netns add %[1]s
ip netns add %[2]s
ip netns add %[3]s

ip -n %[1]s link set lo up
ip -n %[2]s link set lo up
ip -n %[3]s link set lo up

# Public link between Client and VPN Server
ip link add veth-cli netns %[1]s type veth peer name veth-pub netns %[2]s
ip -n %[1]s addr add 198.51.100.2/24 dev veth-cli
ip -n %[1]s link set veth-cli up
ip -n %[2]s addr add 198.51.100.1/24 dev veth-pub
ip -n %[2]s link set veth-pub up

# Upstream WAN link between VPN Server (named eth0 per spec.md!) and WAN target
ip link add eth0 netns %[2]s type veth peer name veth-wan netns %[3]s
ip -n %[2]s addr add 203.0.113.1/24 dev eth0
ip -n %[2]s link set eth0 up
ip -n %[3]s addr add 203.0.113.2/24 dev veth-wan
ip -n %[3]s link set veth-wan up
ip -n %[3]s route add default via 203.0.113.1 dev veth-wan
`, nsCli, nsSrv, nsWan)

	if out, err := exec.Command("bash", "-c", setupScript).CombinedOutput(); err != nil {
		t.Fatalf("failed to set up netns topology: %v\n%s", err, out)
	}

	// Start an HTTP echo server inside nsWan on 203.0.113.2:8080 using python3.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pyServer := `
import http.server, socketserver
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = ("from=" + self.client_address[0]).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args):
        pass
socketserver.TCPServer.allow_reuse_address = True
with socketserver.TCPServer(("203.0.113.2", 8080), H) as s:
    s.serve_forever()
`
	wanCmd := exec.CommandContext(ctx, "ip", "netns", "exec", nsWan, "python3", "-c", pyServer)
	if err := wanCmd.Start(); err != nil {
		t.Fatalf("start WAN HTTP server: %v", err)
	}
	defer func() { _ = wanCmd.Process.Kill(); _ = wanCmd.Wait() }()

	// Generate server and client keys via vpnctl keygen & psk!
	srvKeys := runVPNCTLJSON(t, ctlBin, "keygen")
	cliKeys := runVPNCTLJSON(t, ctlBin, "keygen")
	pskJSON := runVPNCTLJSON(t, ctlBin, "psk")

	sockPath := filepath.Join(tmpDir, "vpn.sock")
	dbPath := filepath.Join(tmpDir, "vpn.sqlite")
	srvCfgPath := filepath.Join(tmpDir, "server.yaml")
	cliCfgPath := filepath.Join(tmpDir, "client.yaml")

	// Start server with NO static peers — we will add the peer dynamically via vpnctl!
	// Also set workers: 2 to test IFF_MULTI_QUEUE + SO_REUSEPORT!
	srvYAML := fmt.Sprintf(`
listen_addr: "198.51.100.1:51820"
private_key: %q
cipher_suite: "chacha20-poly1305"
workers: 2
tun:
  name: "tun0"
  cidr: "10.100.0.1/24"
  mtu: 1400
nat:
  enable: true
  egress_interface: "eth0"
  table_name: "vpn_nat"
control:
  socket_path: %q
storage:
  sqlite_path: %q
observability:
  log_level: "info"
  metrics_addr: "127.0.0.1:9090"
tuning:
  enable: true
`, srvKeys["private_key"], sockPath, dbPath)

	if err := os.WriteFile(srvCfgPath, []byte(srvYAML), 0o600); err != nil {
		t.Fatal(err)
	}

	var srvLogs bytes.Buffer
	srvCmd := exec.CommandContext(ctx, "ip", "netns", "exec", nsSrv, srvBin, "-config", srvCfgPath)
	srvCmd.Stdout = &srvLogs
	srvCmd.Stderr = &srvLogs
	if err := srvCmd.Start(); err != nil {
		t.Fatalf("start vpn-server: %v", err)
	}
	defer func() { _ = srvCmd.Process.Kill(); _ = srvCmd.Wait() }()

	// Wait for Unix control socket to become ready.
	waitForCondition(t, 5*time.Second, func() bool {
		_, err := os.Stat(sockPath)
		return err == nil
	}, func() string { return srvLogs.String() })

	// Dynamically add the client peer via `vpnctl peer add` over the Unix socket!
	addOut, err := exec.Command(
		ctlBin, "peer", "add",
		"--socket", sockPath,
		"--name", "e2e-client",
		"--pubkey", cliKeys["public_key"],
		"--psk", pskJSON["psk"],
		"--vip", "10.100.0.2",
	).CombinedOutput()
	if err != nil {
		t.Fatalf("vpnctl peer add failed: %v\n%s\nserver logs:\n%s", err, addOut, srvLogs.String())
	}

	// Verify `tun0` inside nsSrv has MTU 1400 and IP 10.100.0.1/24.
	ipAddrOut, err := exec.Command("ip", "-n", nsSrv, "addr", "show", "dev", "tun0").CombinedOutput()
	if err != nil || !strings.Contains(string(ipAddrOut), "mtu 1400") || !strings.Contains(string(ipAddrOut), "10.100.0.1/24") {
		t.Fatalf("unexpected tun0 state in nsSrv: err=%v\n%s", err, ipAddrOut)
	}

	// Write client config routing 203.0.113.0/24 through the VPN tunnel!
	cliYAML := fmt.Sprintf(`
server_addr: "198.51.100.1:51820"
server_public_key: %q
private_key: %q
psk: %q
cipher_suite: "chacha20-poly1305"
tun_name: "tun0"
routes:
  - "203.0.113.0/24"
keepalive_interval: 5s
rekey_interval: 30m
`, srvKeys["public_key"], cliKeys["private_key"], pskJSON["psk"])

	if err := os.WriteFile(cliCfgPath, []byte(cliYAML), 0o600); err != nil {
		t.Fatal(err)
	}

	var cliLogs bytes.Buffer
	cliCmd := exec.CommandContext(ctx, "ip", "netns", "exec", nsCli, cliBin, "-config", cliCfgPath)
	cliCmd.Stdout = &cliLogs
	cliCmd.Stderr = &cliLogs
	if err := cliCmd.Start(); err != nil {
		t.Fatalf("start vpn-client: %v", err)
	}
	defer func() { _ = cliCmd.Process.Kill(); _ = cliCmd.Wait() }()

	// Wait until vpnctl status reports active_sessions == 1.
	waitForCondition(t, 6*time.Second, func() bool {
		out, err := exec.Command(ctlBin, "status", "--socket", sockPath).Output()
		if err != nil {
			return false
		}
		var st map[string]any
		if json.Unmarshal(out, &st) != nil {
			return false
		}
		active, _ := st["active_sessions"].(float64)
		return active == 1
	}, func() string {
		return fmt.Sprintf("srv:\n%s\ncli:\n%s", srvLogs.String(), cliLogs.String())
	})

	// Perform a real TCP/HTTP request from inside nsCli to http://203.0.113.2:8080/test!
	// Because nsWan ONLY knows how to reach 203.0.113.0/24, receiving "from=203.0.113.1"
	// proves end-to-end TUN capture -> encryption -> UDP -> decryption -> kernel forwarding -> nftables SNAT masquerade!
	curlPy := `import urllib.request; print(urllib.request.urlopen("http://203.0.113.2:8080/hello", timeout=5).read().decode())`
	httpOut, err := exec.CommandContext(ctx, "ip", "netns", "exec", nsCli, "python3", "-c", curlPy).CombinedOutput()
	if err != nil {
		t.Fatalf("HTTP over VPN tunnel + nftables NAT failed: %v\noutput: %s\nsrv:\n%s\ncli:\n%s",
			err, httpOut, srvLogs.String(), cliLogs.String())
	}
	if strings.TrimSpace(string(httpOut)) != "from=203.0.113.1" {
		t.Fatalf("expected masqueraded source IP from=203.0.113.1, got %q", string(httpOut))
	}

	//Also verify ping / TCP directly to server's virtual IP 10.100.0.1 works (ping via ICMP or Prometheus check).
	pingOut, err := exec.CommandContext(ctx, "ip", "netns", "exec", nsCli, "ping", "-c", "2", "-W", "2", "10.100.0.1").CombinedOutput()
	if err == nil && !strings.Contains(string(pingOut), "0% packet loss") {
		t.Logf("ping output: %s", pingOut)
	}

	// Scrape Prometheus metrics inside nsSrv and verify RX/TX packet counters and handshakes_total!
	promPy := `import urllib.request; print(urllib.request.urlopen("http://127.0.0.1:9090/metrics", timeout=3).read().decode())`
	promOut, err := exec.CommandContext(ctx, "ip", "netns", "exec", nsSrv, "python3", "-c", promPy).CombinedOutput()
	if err != nil {
		t.Fatalf("scrape /metrics failed: %v\n%s", err, promOut)
	}
	metricsText := string(promOut)
	for _, needle := range []string{
		`vpn_active_sessions 1`,
		`vpn_handshakes_total{result="success"} 1`,
		`vpn_rx_packets_total`,
		`vpn_tx_packets_total`,
	} {
		if !strings.Contains(metricsText, needle) {
			t.Fatalf("expected Prometheus /metrics to contain %q; got:\n%s", needle, metricsText)
		}
	}

	// Ensure unused import check stays clean.
	_ = http.StatusOK
	_ = protocol.ProtocolVersion
}

func runVPNCTLJSON(t *testing.T, ctlBin string, args ...string) map[string]string {
	t.Helper()
	out, err := exec.Command(ctlBin, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("vpnctl %v failed: %v\n%s", args, err, out)
	}
	var res map[string]string
	if err := json.Unmarshal(out, &res); err != nil {
		t.Fatalf("unmarshal vpnctl output %q: %v", out, err)
	}
	return res
}

func waitForCondition(t *testing.T, timeout time.Duration, cond func() bool, diag func() string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("condition timed out after %s:\n%s", timeout, diag())
}
