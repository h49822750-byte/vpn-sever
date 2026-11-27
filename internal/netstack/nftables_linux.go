//go:build linux

package netstack

import (
	"encoding/binary"
	"fmt"
	"net/netip"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// SetupNATMasquerade programmatically configures an IPv4 nftables table via Netlink to:
//  1. Masquerade traffic from tunnelSubnet (e.g. 10.100.0.0/24) exiting egressIf (e.g. eth0).
//  2. Accept forwarded traffic entering or leaving tunIf (e.g. tun0).
//
// Returns a cleanup function that deletes the dedicated nftables table on daemon shutdown.
func SetupNATMasquerade(tableName string, tunnelSubnet netip.Prefix, tunIf string, egressIf string) (func() error, error) {
	if !tunnelSubnet.Addr().Is4() {
		return nil, fmt.Errorf("nftables NAT requires IPv4 subnet, got %s", tunnelSubnet)
	}
	if tableName == "" {
		tableName = "vpn_nat"
	}

	masked := tunnelSubnet.Masked()
	netAddr4 := masked.Addr().As4()
	var mask4 [4]byte
	if masked.Bits() > 0 {
		maskU32 := ^uint32(0) << (32 - masked.Bits())
		binary.BigEndian.PutUint32(mask4[:], maskU32)
	}

	conn, err := nftables.New()
	if err != nil {
		return nil, fmt.Errorf("open nftables netlink conn: %w", err)
	}

	// Best-effort cleanup of any stale table with the same name from a prior crash.
	existingTables, err := conn.ListTablesOfFamily(nftables.TableFamilyIPv4)
	if err == nil {
		for _, t := range existingTables {
			if t.Name == tableName {
				conn.DelTable(t)
				_ = conn.Flush()
				break
			}
		}
	}

	tbl := conn.AddTable(&nftables.Table{
		Name:   tableName,
		Family: nftables.TableFamilyIPv4,
	})

	acceptPolicy := nftables.ChainPolicyAccept

	postrouting := conn.AddChain(&nftables.Chain{
		Name:     "postrouting",
		Table:    tbl,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPostrouting,
		Priority: nftables.ChainPriorityNATSource,
		Policy:   &acceptPolicy,
	})

	// Rule: ip saddr == tunnelSubnet && oifname == egressIf -> masquerade
	conn.AddRule(&nftables.Rule{
		Table: tbl,
		Chain: postrouting,
		Exprs: []expr.Any{
			// Load IPv4 Source IP (offset 12, len 4) into reg 1.
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       12,
				Len:          4,
			},
			// Mask reg 1 with subnet mask.
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            4,
				Mask:           mask4[:],
				Xor:            []byte{0, 0, 0, 0},
			},
			// Compare masked IPv4 saddr == network address.
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     netAddr4[:],
			},
			// Match outgoing public interface name.
			&expr.Meta{
				Key:      expr.MetaKeyOIFNAME,
				Register: 1,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     ifnameBytes(egressIf),
			},
			// SNAT Masquerade.
			&expr.Masq{},
		},
	})

	forward := conn.AddChain(&nftables.Chain{
		Name:     "forward",
		Table:    tbl,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookForward,
		Priority: nftables.ChainPriorityFilter,
		Policy:   &acceptPolicy,
	})

	if tunIf != "" {
		// Clamp TCP SYN MSS dynamically to route MTU (prevents PMTU blackholes & IP fragmentation).
		conn.AddRule(&nftables.Rule{
			Table: tbl,
			Chain: forward,
			Exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_TCP}},
				&expr.Payload{
					DestRegister: 1,
					Base:         expr.PayloadBaseTransportHeader,
					Offset:       13,
					Len:          1,
				},
				&expr.Bitwise{
					SourceRegister: 1,
					DestRegister:   1,
					Len:            1,
					Mask:           []byte{0x02}, // TCP SYN flag
					Xor:            []byte{0x00},
				},
				&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{0x00}},
				&expr.Rt{Register: 1, Key: expr.RtTCPMSS},
				&expr.Exthdr{
					SourceRegister: 1,
					Type:           2, // TCPOPT_MAXSEG
					Offset:         2,
					Len:            2,
					Op:             expr.ExthdrOpTcpopt,
				},
			},
		})

		// Accept traffic originating from tun0.
		conn.AddRule(&nftables.Rule{
			Table: tbl,
			Chain: forward,
			Exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifnameBytes(tunIf)},
				&expr.Verdict{Kind: expr.VerdictAccept},
			},
		})
		// Accept return traffic routed back to tun0.
		conn.AddRule(&nftables.Rule{
			Table: tbl,
			Chain: forward,
			Exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifnameBytes(tunIf)},
				&expr.Verdict{Kind: expr.VerdictAccept},
			},
		})
	}

	if err := conn.Flush(); err != nil {
		return nil, fmt.Errorf("flush nftables rules: %w", err)
	}

	cleanup := func() error {
		cleanConn, err := nftables.New()
		if err != nil {
			return err
		}
		cleanConn.DelTable(&nftables.Table{
			Name:   tableName,
			Family: nftables.TableFamilyIPv4,
		})
		return cleanConn.Flush()
	}
	return cleanup, nil
}

// ifnameBytes encodes an interface name into the 16-byte IFNAMSIZ buffer expected by nftables MetaKeyIIFNAME/OIFNAME.
func ifnameBytes(name string) []byte {
	b := make([]byte, 16)
	copy(b, name+"\x00")
	return b
}
