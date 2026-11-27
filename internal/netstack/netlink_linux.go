//go:build linux

package netstack

import (
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/vishvananda/netlink"
)

// ConfigureInterface assigns an IPv4 CIDR (e.g. "10.100.0.1/24"), sets the MTU (e.g. 1400),
// and brings the interface link UP via Linux Netlink without shelling out to ip(8).
func ConfigureInterface(ifName string, cidr string, mtu int) error {
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return fmt.Errorf("netlink lookup %q: %w", ifName, err)
	}
	if mtu > 0 {
		if err := netlink.LinkSetMTU(link, mtu); err != nil {
			return fmt.Errorf("netlink set MTU %d on %q: %w", mtu, ifName, err)
		}
	}
	if cidr != "" {
		nlAddr, err := netlink.ParseAddr(cidr)
		if err != nil {
			return fmt.Errorf("parse interface CIDR %q: %w", cidr, err)
		}
		if err := netlink.AddrReplace(link, nlAddr); err != nil {
			return fmt.Errorf("netlink assign %s to %q: %w", cidr, ifName, err)
		}
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("netlink bring link %q UP: %w", ifName, err)
	}
	return nil
}

// AddRoute installs or replaces an IPv4 route exiting via ifName (and optional gateway).
func AddRoute(ifName string, dstCIDR string, gateway netip.Addr) error {
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return fmt.Errorf("netlink lookup %q: %w", ifName, err)
	}
	_, ipNet, err := net.ParseCIDR(dstCIDR)
	if err != nil {
		return fmt.Errorf("parse route CIDR %q: %w", dstCIDR, err)
	}
	route := &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       ipNet,
	}
	if gateway.IsValid() && gateway.Is4() {
		gw4 := gateway.As4()
		route.Gw = net.IP(gw4[:])
	} else {
		route.Scope = netlink.SCOPE_LINK
	}
	if err := netlink.RouteReplace(route); err != nil {
		return fmt.Errorf("netlink route replace %s via %s: %w", dstCIDR, ifName, err)
	}
	return nil
}

// DetectDefaultEgressInterface inspects the kernel IPv4 routing table via Netlink
// to find the network interface carrying the default route.
func DetectDefaultEgressInterface() (string, error) {
	routes, err := netlink.RouteList(nil, netlink.FAMILY_V4)
	if err != nil {
		return "", fmt.Errorf("netlink list routes: %w", err)
	}
	for _, r := range routes {
		isDefault := r.Dst == nil
		if !isDefault {
			ones, _ := r.Dst.Mask.Size()
			isDefault = ones == 0 && r.Dst.IP.Equal(net.IPv4zero)
		}
		if isDefault && r.LinkIndex > 0 {
			link, err := netlink.LinkByIndex(r.LinkIndex)
			if err == nil {
				return link.Attrs().Name, nil
			}
		}
	}
	return "", errors.New("no default IPv4 egress interface found")
}
