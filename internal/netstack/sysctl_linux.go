//go:build linux

package netstack

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// EnableIPv4Forwarding ensures net.ipv4.ip_forward = 1 via procfs.
// If ip_forward is already enabled (e.g., via Docker --sysctl with a read-only /proc/sys mount),
// it returns nil without attempting a redundant write.
func EnableIPv4Forwarding() error {
	if cur, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward"); err == nil {
		if strings.TrimSpace(string(cur)) == "1" {
			return nil
		}
	}
	return writeSysctl("net/ipv4/ip_forward", "1")
}

// DisableRPFilterOnInterface relaxes strict reverse-path filtering on an interface
// so asymmetric or hairpinned tunnel packets are not dropped by the kernel.
func DisableRPFilterOnInterface(ifName string) {
	_ = writeSysctl(filepath.Join("net/ipv4/conf", ifName, "rp_filter"), "0")
}

// ApplyPerformanceTuning applies recommended OS sysctls from Section 7 of spec.md
// (BBR congestion control, fq qdisc, and expanded UDP socket buffers). Because some
// sysctls are global-only (unavailable inside non-init network namespaces or containers),
// failures are logged at warn/debug level rather than aborting startup.
func ApplyPerformanceTuning(logger *slog.Logger, socketBufBytes int) {
	if logger == nil {
		logger = slog.Default()
	}
	if err := writeSysctl("net/core/default_qdisc", "fq"); err != nil {
		logger.Debug("skipping net.core.default_qdisc=fq tuning", "err", err)
	}
	if err := writeSysctl("net/ipv4/tcp_congestion_control", "bbr"); err != nil {
		logger.Debug("skipping net.ipv4.tcp_congestion_control=bbr tuning", "err", err)
	}
	if socketBufBytes > 0 {
		val := strconv.Itoa(socketBufBytes)
		if err := writeSysctl("net/core/rmem_max", val); err != nil {
			logger.Debug("skipping net.core.rmem_max tuning", "err", err)
		}
		if err := writeSysctl("net/core/wmem_max", val); err != nil {
			logger.Debug("skipping net.core.wmem_max tuning", "err", err)
		}
	}
}

func writeSysctl(relPath, value string) error {
	full := filepath.Join("/proc/sys", relPath)
	return os.WriteFile(full, []byte(value+"\n"), 0o644)
}

// ListenUDP binds a UDP socket with optional SO_REUSEPORT (for multi-core scaling)
// and configured kernel receive/send buffer sizes.
func ListenUDP(listenAddr string, reusePort bool, rcvBuf, sndBuf int) (*net.UDPConn, error) {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var sockErr error
			err := c.Control(func(fd uintptr) {
				_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
				if reusePort {
					if e := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); e != nil {
						sockErr = fmt.Errorf("setsockopt SO_REUSEPORT: %w", e)
						return
					}
				}
				if rcvBuf > 0 {
					_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, rcvBuf)
				}
				if sndBuf > 0 {
					_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF, sndBuf)
				}
			})
			if err != nil {
				return err
			}
			return sockErr
		},
	}

	pc, err := lc.ListenPacket(context.Background(), "udp4", listenAddr)
	if err != nil {
		return nil, err
	}
	udpConn, ok := pc.(*net.UDPConn)
	if !ok {
		_ = pc.Close()
		return nil, fmt.Errorf("unexpected PacketConn type %T", pc)
	}
	return udpConn, nil
}

// DropPrivileges drops root privileges to the specified username or numeric UID
// after privileged interface/netlink/nftables initialization has completed.
func DropPrivileges(targetUser string) error {
	targetUser = strings.TrimSpace(targetUser)
	if targetUser == "" {
		return nil
	}

	var uid, gid int
	if u, err := user.Lookup(targetUser); err == nil {
		uid, err = strconv.Atoi(u.Uid)
		if err != nil {
			return fmt.Errorf("parse uid for %q: %w", targetUser, err)
		}
		gid, err = strconv.Atoi(u.Gid)
		if err != nil {
			return fmt.Errorf("parse gid for %q: %w", targetUser, err)
		}
	} else if parsedUID, parseErr := strconv.Atoi(targetUser); parseErr == nil {
		uid = parsedUID
		gid = parsedUID
	} else {
		return fmt.Errorf("lookup drop_user %q: %w", targetUser, err)
	}

	if uid == 0 {
		return nil
	}
	if err := syscall.Setgroups([]int{}); err != nil {
		return fmt.Errorf("clear supplementary groups: %w", err)
	}
	if err := syscall.Setgid(gid); err != nil {
		return fmt.Errorf("setgid(%d): %w", gid, err)
	}
	if err := syscall.Setuid(uid); err != nil {
		return fmt.Errorf("setuid(%d): %w", uid, err)
	}
	return nil
}
