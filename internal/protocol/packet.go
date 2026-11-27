package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
)

const (
	// ProtocolVersion is the wire protocol version byte.
	ProtocolVersion uint8 = 0x01

	// Packet types defined in Section 2 of spec.md.
	PacketTypeHandshakeInit uint8 = 0x01
	PacketTypeHandshakeResp uint8 = 0x02
	PacketTypeData          uint8 = 0x03
	PacketTypeKeepalive     uint8 = 0x04

	// Framing sizes in bytes.
	HeaderSize     = 14
	AEADTagSize    = 16
	AEADNonceSize  = 12
	MinIPv4HdrSize = 20

	// DefaultTUNMTU leaves headroom for outer IPv4 (20B), UDP (8B),
	// custom VPN header (14B), and AEAD tag (16B) without fragmentation.
	DefaultTUNMTU = 1400

	// MaxPacketSize accommodates maximum Ethernet/TUN frames plus header and AEAD tag.
	MaxPacketSize = 2048

	// KeepaliveFlagRekey is an optional 1-byte authenticated payload inside a
	// Keepalive packet instructing the peer to initiate a fresh handshake.
	KeepaliveFlagRekey uint8 = 0x01
)

var (
	ErrPacketTooShort     = errors.New("protocol: packet shorter than 14-byte header")
	ErrUnsupportedVersion = errors.New("protocol: unsupported protocol version")
	ErrUnknownPacketType  = errors.New("protocol: unknown packet type")
	ErrCiphertextTooShort = errors.New("protocol: payload shorter than AEAD tag")
	ErrInvalidIPv4Packet  = errors.New("protocol: invalid or non-IPv4 inner packet")
)

// Header represents the fixed 14-byte binary wire header prepended to every UDP datagram.
//
// Layout:
//   - Byte 0:     Version (0x01)
//   - Byte 1:     Packet Type (0x01..0x04)
//   - Bytes 2..5: Session ID (big-endian uint32)
//   - Bytes 6..13: Counter / Nonce (big-endian uint64)
type Header struct {
	Version   uint8
	Type      uint8
	SessionID uint32
	Counter   uint64
}

// ParseHeader decodes and validates a 14-byte wire header.
func ParseHeader(b []byte) (Header, error) {
	if len(b) < HeaderSize {
		return Header{}, ErrPacketTooShort
	}
	ver := b[0]
	if ver != ProtocolVersion {
		return Header{}, fmt.Errorf("%w: 0x%02x", ErrUnsupportedVersion, ver)
	}
	pktType := b[1]
	switch pktType {
	case PacketTypeHandshakeInit, PacketTypeHandshakeResp, PacketTypeData, PacketTypeKeepalive:
	default:
		return Header{}, fmt.Errorf("%w: 0x%02x", ErrUnknownPacketType, pktType)
	}
	return Header{
		Version:   ver,
		Type:      pktType,
		SessionID: binary.BigEndian.Uint32(b[2:6]),
		Counter:   binary.BigEndian.Uint64(b[6:14]),
	}, nil
}

// Put serializes the 14-byte wire header into dst[0:14].
// Panics if len(dst) < HeaderSize.
func (h Header) Put(dst []byte) {
	_ = dst[HeaderSize-1]
	dst[0] = h.Version
	dst[1] = h.Type
	binary.BigEndian.PutUint32(dst[2:6], h.SessionID)
	binary.BigEndian.PutUint64(dst[6:14], h.Counter)
}

var packetBufferPool = sync.Pool{
	New: func() any {
		return new([MaxPacketSize]byte)
	},
}

// GetPacketBuffer retrieves a pre-allocated [MaxPacketSize]byte buffer from the pool.
func GetPacketBuffer() *[MaxPacketSize]byte {
	return packetBufferPool.Get().(*[MaxPacketSize]byte)
}

// PutPacketBuffer returns a packet buffer to the pool.
func PutPacketBuffer(buf *[MaxPacketSize]byte) {
	if buf != nil {
		packetBufferPool.Put(buf)
	}
}

// ExtractIPv4Src validates that pkt is an IPv4 packet and extracts its Source IP (bytes 12..15).
func ExtractIPv4Src(pkt []byte) ([4]byte, bool) {
	if len(pkt) < MinIPv4HdrSize {
		return [4]byte{}, false
	}
	if (pkt[0]>>4) != 4 || (pkt[0]&0x0f) < 5 {
		return [4]byte{}, false
	}
	var src [4]byte
	copy(src[:], pkt[12:16])
	return src, true
}

// ExtractIPv4Dst validates that pkt is an IPv4 packet and extracts its Destination IP (bytes 16..19).
func ExtractIPv4Dst(pkt []byte) ([4]byte, bool) {
	if len(pkt) < MinIPv4HdrSize {
		return [4]byte{}, false
	}
	if (pkt[0]>>4) != 4 || (pkt[0]&0x0f) < 5 {
		return [4]byte{}, false
	}
	var dst [4]byte
	copy(dst[:], pkt[16:20])
	return dst, true
}
