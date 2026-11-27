package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	"vpn-server/internal/control"
	"vpn-server/internal/protocol"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "keygen":
		pub, priv, err := protocol.GenerateStaticKeyPair()
		if err != nil {
			fatal(err)
		}
		out := map[string]string{
			"public_key":  protocol.EncodeKey(pub),
			"private_key": protocol.EncodeKey(priv),
		}
		printPrettyJSON(out)

	case "psk":
		psk, err := protocol.GeneratePSK()
		if err != nil {
			fatal(err)
		}
		printPrettyJSON(map[string]string{"psk": protocol.EncodeKey(psk[:])})

	case "status":
		fs := flag.NewFlagSet("status", flag.ExitOnError)
		sock := fs.String("socket", "/run/vpn.sock", "Path to vpn-server Unix control socket")
		_ = fs.Parse(os.Args[2:])
		doUnixRequest(*sock, http.MethodGet, "/v1/status", nil)

	case "sessions":
		fs := flag.NewFlagSet("sessions", flag.ExitOnError)
		sock := fs.String("socket", "/run/vpn.sock", "Path to vpn-server Unix control socket")
		_ = fs.Parse(os.Args[2:])
		doUnixRequest(*sock, http.MethodGet, "/v1/sessions", nil)

	case "peer":
		if len(os.Args) < 3 {
			printUsage()
			os.Exit(1)
		}
		handlePeerSubcommand(os.Args[2], os.Args[3:])

	default:
		printUsage()
		os.Exit(1)
	}
}

func handlePeerSubcommand(sub string, args []string) {
	switch sub {
	case "list":
		fs := flag.NewFlagSet("peer list", flag.ExitOnError)
		sock := fs.String("socket", "/run/vpn.sock", "Path to vpn-server Unix control socket")
		_ = fs.Parse(args)
		doUnixRequest(*sock, http.MethodGet, "/v1/peers", nil)

	case "add":
		fs := flag.NewFlagSet("peer add", flag.ExitOnError)
		sock := fs.String("socket", "/run/vpn.sock", "Path to vpn-server Unix control socket")
		name := fs.String("name", "", "Human-readable peer name")
		pub := fs.String("pubkey", "", "Peer Ed25519 static public key (Base64 or Hex)")
		psk := fs.String("psk", "", "Optional 32-byte pre-shared key (Base64 or Hex)")
		vip := fs.String("vip", "", "Optional static virtual IPv4 address (e.g. 10.100.0.10)")
		_ = fs.Parse(args)
		if *pub == "" {
			fatal(fmt.Errorf("--pubkey is required"))
		}
		req := control.AddPeerRequest{
			Name:      *name,
			PublicKey: *pub,
			PSK:       *psk,
			VirtualIP: *vip,
		}
		doUnixRequest(*sock, http.MethodPost, "/v1/peers", req)

	case "revoke":
		fs := flag.NewFlagSet("peer revoke", flag.ExitOnError)
		sock := fs.String("socket", "/run/vpn.sock", "Path to vpn-server Unix control socket")
		pub := fs.String("pubkey", "", "Peer Ed25519 static public key (Base64 or Hex)")
		del := fs.Bool("delete", false, "Delete peer record and release IP lease completely")
		_ = fs.Parse(args)
		if *pub == "" {
			fatal(fmt.Errorf("--pubkey is required"))
		}
		body := map[string]any{
			"public_key": *pub,
			"delete":     *del,
		}
		doUnixRequest(*sock, http.MethodPost, "/v1/peers/revoke", body)

	default:
		printUsage()
		os.Exit(1)
	}
}

func doUnixRequest(socketPath, method, path string, body any) {
	var bodyReader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			fatal(err)
		}
		bodyReader = bytes.NewReader(raw)
	}

	hc := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", socketPath)
			},
		},
	}

	req, err := http.NewRequest(method, "http://unix"+path, bodyReader)
	if err != nil {
		fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := hc.Do(req)
	if err != nil {
		fatal(fmt.Errorf("control request failed (%s): %w", socketPath, err))
	}
	defer resp.Body.Close()

	respBytes, _ := io.ReadAll(resp.Body)
	var pretty bytes.Buffer
	if json.Indent(&pretty, respBytes, "", "  ") == nil {
		fmt.Println(pretty.String())
	} else {
		fmt.Println(string(respBytes))
	}
	if resp.StatusCode >= 400 {
		os.Exit(1)
	}
}

func printPrettyJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `Usage: vpnctl <command> [flags]

Commands:
  keygen                         Generate a new Ed25519 static keypair
  psk                            Generate a random 32-byte pre-shared key
  status   [--socket PATH]       Query vpn-server daemon status
  sessions [--socket PATH]       List active encrypted client sessions
  peer list   [--socket PATH]    List authorized peers
  peer add    --pubkey KEY [--name NAME] [--vip IP] [--psk PSK] [--socket PATH]
  peer revoke --pubkey KEY [--delete] [--socket PATH]
`)
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	os.Exit(1)
}
