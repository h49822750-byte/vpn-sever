//go:build linux

package netstack

import (
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// TUNDevice abstracts a single-queue or multi-queue Layer 3 virtual interface.
type TUNDevice interface {
	Name() string
	Queues() []io.ReadWriteCloser
	io.ReadWriteCloser
}

// LinuxTUN wraps one or more /dev/net/tun file descriptors created via TUNSETIFF.
type LinuxTUN struct {
	name   string
	queues []*os.File
}

// OpenTUN opens /dev/net/tun and creates/attaches a Layer 3 TUN interface with
// IFF_TUN | IFF_NO_PI (and IFF_MULTI_QUEUE when numQueues > 1).
func OpenTUN(requestedName string, numQueues int) (*LinuxTUN, error) {
	if numQueues <= 0 {
		numQueues = 1
	}
	flags := uint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if numQueues > 1 {
		flags |= unix.IFF_MULTI_QUEUE
	}

	files := make([]*os.File, 0, numQueues)
	actualName := requestedName

	for i := 0; i < numQueues; i++ {
		fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
		if err != nil {
			closeAllFiles(files)
			return nil, fmt.Errorf("open /dev/net/tun (queue %d): %w", i, err)
		}

		ifr, err := unix.NewIfreq(actualName)
		if err != nil {
			_ = unix.Close(fd)
			closeAllFiles(files)
			return nil, fmt.Errorf("invalid tun interface name %q: %w", actualName, err)
		}
		ifr.SetUint16(flags)

		if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
			_ = unix.Close(fd)
			closeAllFiles(files)
			return nil, fmt.Errorf("ioctl TUNSETIFF on %q (queue %d): %w", actualName, i, err)
		}
		if i == 0 {
			actualName = ifr.Name()
		}

		if err := unix.SetNonblock(fd, true); err != nil {
			_ = unix.Close(fd)
			closeAllFiles(files)
			return nil, fmt.Errorf("set nonblock on tun fd: %w", err)
		}

		files = append(files, os.NewFile(uintptr(fd), "/dev/net/tun"))
	}

	return &LinuxTUN{
		name:   actualName,
		queues: files,
	}, nil
}

func (t *LinuxTUN) Name() string {
	return t.name
}

func (t *LinuxTUN) Queues() []io.ReadWriteCloser {
	out := make([]io.ReadWriteCloser, len(t.queues))
	for i, f := range t.queues {
		out[i] = f
	}
	return out
}

func (t *LinuxTUN) Read(p []byte) (int, error) {
	if len(t.queues) == 0 {
		return 0, os.ErrClosed
	}
	return t.queues[0].Read(p)
}

func (t *LinuxTUN) Write(p []byte) (int, error) {
	if len(t.queues) == 0 {
		return 0, os.ErrClosed
	}
	return t.queues[0].Write(p)
}

func (t *LinuxTUN) Close() error {
	var firstErr error
	for _, f := range t.queues {
		if err := f.Close(); err != nil && firstErr == nil && !errors.Is(err, os.ErrClosed) {
			firstErr = err
		}
	}
	return firstErr
}

func closeAllFiles(files []*os.File) {
	for _, f := range files {
		_ = f.Close()
	}
}
