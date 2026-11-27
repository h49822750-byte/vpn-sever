package protocol

import (
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"time"
)

const (
	// HandshakeInitSize is the fixed wire length of a Handshake Init datagram:
	// 14B Header + 1B Suite + 32B EphemX25519 + 32B ClientEd25519 + 16B Nonce + 32B PSKTag + 64B Ed25519Sig = 191 bytes.
	HandshakeInitSize = HeaderSize + 1 + 32 + 32 + 16 + 32 + 64

	// HandshakeLeasePlainSize is the encrypted lease configuration length inside Handshake Resp:
	// 4B VirtualIP + 4B ServerVIP + 1B PrefixLen + 2B MTU = 11 bytes.
	HandshakeLeasePlainSize = 11

	// HandshakeRespSize is the fixed wire length of a Handshake Resp datagram:
	// 14B Header + 32B EphemX25519 + 16B Nonce + 64B Ed25519Sig + 11B EncryptedLease + 16B Tag = 153 bytes.
	// Note: 153B < 191B eliminates UDP amplification vectors.
	HandshakeRespSize = HeaderSize + 32 + 16 + 64 + HandshakeLeasePlainSize + AEADTagSize

	// DefaultMaxHandshakeSkew bounds acceptable clock skew on Handshake Init timestamps.
	DefaultMaxHandshakeSkew = 2 * time.Minute
)

var (
	ErrMalformedHandshake     = errors.New("protocol: malformed handshake packet")
	ErrHandshakeSkewExceeded  = errors.New("protocol: handshake timestamp outside allowed skew")
	ErrHandshakeReplay        = errors.New("protocol: replayed handshake timestamp")
	ErrInvalidPSKTag          = errors.New("protocol: invalid handshake pre-shared key MAC")
	ErrInvalidHandshakeSig    = errors.New("protocol: invalid Ed25519 handshake signature")
	ErrHandshakeDecryptFailed = errors.New("protocol: failed to authenticate handshake lease")
)

// HandshakeInitiatorState holds ephemeral state retained by a client awaiting Handshake Resp.
type HandshakeInitiatorState struct {
	EphemeralPriv   *ecdh.PrivateKey
	EphemeralPub    [32]byte
	ClientNonce     [16]byte
	ClientStaticPub ed25519.PublicKey
	ServerStaticPub ed25519.PublicKey
	PSK             [32]byte
	Suite           CipherSuite
	CreatedAt       time.Time
}

// ParsedHandshakeInit holds fields extracted from an incoming Handshake Init prior to ECDH.
type ParsedHandshakeInit struct {
	Header           Header
	Suite            CipherSuite
	ClientEphemPub   [32]byte
	ClientStaticPub  [32]byte
	ClientNonce      [16]byte
	PSKTag           [32]byte
	Signature        [64]byte
	RawAuthenticated []byte // raw[0:127] signed by Ed25519
	RawPSKTranscript []byte // raw[0:95] authenticated by PSK HMAC
}

// LeaseConfig carries tunnel addressing assigned to a client during handshake.
type LeaseConfig struct {
	VirtualIP netip.Addr
	ServerVIP netip.Addr
	PrefixLen uint8
	MTU       uint16
}

// HandshakeResult contains directional AEAD ciphers and negotiated parameters.
type HandshakeResult struct {
	SessionID uint32
	Suite     CipherSuite
	RxKey     cipher.AEAD
	TxKey     cipher.AEAD
	Lease     LeaseConfig
}

// BuildHandshakeInit constructs and signs a 191-byte Handshake Init packet.
func BuildHandshakeInit(
	clientPriv ed25519.PrivateKey,
	serverPub ed25519.PublicKey,
	psk [32]byte,
	suite CipherSuite,
	prevSessionID uint32,
	now time.Time,
) ([]byte, *HandshakeInitiatorState, error) {
	if len(clientPriv) != ed25519.PrivateKeySize || len(serverPub) != ed25519.PublicKeySize {
		return nil, nil, ErrInvalidKeyEncoding
	}
	if !suite.Valid() {
		return nil, nil, fmt.Errorf("%w: 0x%02x", ErrUnsupportedCipherSuite, uint8(suite))
	}

	ephemPriv, err := GenerateEphemeralKeyPair()
	if err != nil {
		return nil, nil, err
	}
	var ephemPub [32]byte
	copy(ephemPub[:], ephemPriv.PublicKey().Bytes())

	var clientNonce [16]byte
	if _, err := io.ReadFull(rand.Reader, clientNonce[:]); err != nil {
		return nil, nil, err
	}

	clientPub := clientPriv.Public().(ed25519.PublicKey)

	pkt := make([]byte, HandshakeInitSize)
	hdr := Header{
		Version:   ProtocolVersion,
		Type:      PacketTypeHandshakeInit,
		SessionID: prevSessionID,
		Counter:   uint64(now.UnixNano()),
	}
	hdr.Put(pkt[0:HeaderSize])
	pkt[14] = byte(suite)
	copy(pkt[15:47], ephemPub[:])
	copy(pkt[47:79], clientPub)
	copy(pkt[79:95], clientNonce[:])

	pskTag := computePSKTag(psk, pkt[0:95], serverPub)
	copy(pkt[95:127], pskTag[:])

	sigMsg := buildInitSignTranscript(pkt[0:127], serverPub)
	sig := ed25519.Sign(clientPriv, sigMsg)
	copy(pkt[127:191], sig)

	state := &HandshakeInitiatorState{
		EphemeralPriv:   ephemPriv,
		EphemeralPub:    ephemPub,
		ClientNonce:     clientNonce,
		ClientStaticPub: clientPub,
		ServerStaticPub: serverPub,
		PSK:             psk,
		Suite:           suite,
		CreatedAt:       now,
	}
	return pkt, state, nil
}

// ParseHandshakeInit decodes a raw Handshake Init packet so the caller can look up
// ClientStaticPub in the authorized peer registry before running cryptographic verification.
func ParseHandshakeInit(raw []byte) (*ParsedHandshakeInit, error) {
	if len(raw) != HandshakeInitSize {
		return nil, ErrMalformedHandshake
	}
	hdr, err := ParseHeader(raw)
	if err != nil || hdr.Type != PacketTypeHandshakeInit {
		return nil, ErrMalformedHandshake
	}
	suite := CipherSuite(raw[14])
	if !suite.Valid() {
		return nil, fmt.Errorf("%w: 0x%02x", ErrUnsupportedCipherSuite, raw[14])
	}
	parsed := &ParsedHandshakeInit{
		Header:           hdr,
		Suite:            suite,
		RawPSKTranscript: raw[0:95],
		RawAuthenticated: raw[0:127],
	}
	copy(parsed.ClientEphemPub[:], raw[15:47])
	copy(parsed.ClientStaticPub[:], raw[47:79])
	copy(parsed.ClientNonce[:], raw[79:95])
	copy(parsed.PSKTag[:], raw[95:127])
	copy(parsed.Signature[:], raw[127:191])
	return parsed, nil
}

// VerifyHandshakeInit authenticates a parsed Handshake Init against clock skew, monotonic
// peer timestamp replay protection, PSK HMAC, and Ed25519 static key signature.
func VerifyHandshakeInit(
	initPkt *ParsedHandshakeInit,
	serverPub ed25519.PublicKey,
	peerPSK [32]byte,
	lastTimestampNano uint64,
	now time.Time,
	maxSkew time.Duration,
) error {
	if maxSkew <= 0 {
		maxSkew = DefaultMaxHandshakeSkew
	}
	pktTime := time.Unix(0, int64(initPkt.Header.Counter))
	skew := now.Sub(pktTime)
	if skew < 0 {
		skew = -skew
	}
	if skew > maxSkew {
		return ErrHandshakeSkewExceeded
	}
	if initPkt.Header.Counter <= lastTimestampNano {
		return ErrHandshakeReplay
	}

	expectedPSKTag := computePSKTag(peerPSK, initPkt.RawPSKTranscript, serverPub)
	if !hmac.Equal(expectedPSKTag[:], initPkt.PSKTag[:]) {
		return ErrInvalidPSKTag
	}

	sigMsg := buildInitSignTranscript(initPkt.RawAuthenticated, serverPub)
	if !ed25519.Verify(ed25519.PublicKey(initPkt.ClientStaticPub[:]), sigMsg, initPkt.Signature[:]) {
		return ErrInvalidHandshakeSig
	}
	return nil
}

// RespondHandshake completes X25519 ECDH, derives directional session keys via HKDF-SHA256,
// and builds a signed + AEAD-sealed 153-byte Handshake Resp packet.
// Note: Counter 0 on serverToClient AEAD is consumed by sealing the lease payload, so
// callers MUST start data-plane TxCounter from >= 1 (e.g., TxCounter.Add(1) starting from 0).
func RespondHandshake(
	initPkt *ParsedHandshakeInit,
	serverPriv ed25519.PrivateKey,
	peerPSK [32]byte,
	sessionID uint32,
	lease LeaseConfig,
) (respBytes []byte, result *HandshakeResult, err error) {
	if sessionID == 0 {
		return nil, nil, errors.New("protocol: session ID must be non-zero")
	}
	if !lease.VirtualIP.Is4() || !lease.ServerVIP.Is4() {
		return nil, nil, errors.New("protocol: lease addresses must be IPv4")
	}

	clientEphemKey, err := ecdh.X25519().NewPublicKey(initPkt.ClientEphemPub[:])
	if err != nil {
		return nil, nil, fmt.Errorf("%w: invalid client X25519 key", ErrMalformedHandshake)
	}
	serverEphemPriv, err := GenerateEphemeralKeyPair()
	if err != nil {
		return nil, nil, err
	}
	sharedSecret, err := serverEphemPriv.ECDH(clientEphemKey)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: X25519 ECDH rejected", ErrMalformedHandshake)
	}
	defer clear(sharedSecret)

	var serverNonce [16]byte
	if _, err := io.ReadFull(rand.Reader, serverNonce[:]); err != nil {
		return nil, nil, err
	}

	serverPub := serverPriv.Public().(ed25519.PublicKey)
	serverEphemPub := serverEphemPriv.PublicKey().Bytes()

	c2sAEAD, s2cAEAD, err := DeriveSessionKeys(
		sharedSecret,
		initPkt.ClientNonce,
		serverNonce,
		peerPSK,
		sessionID,
		ed25519.PublicKey(initPkt.ClientStaticPub[:]),
		serverPub,
		initPkt.ClientEphemPub[:],
		serverEphemPub,
		initPkt.Suite,
	)
	if err != nil {
		return nil, nil, err
	}

	resp := make([]byte, HandshakeRespSize)
	hdr := Header{
		Version:   ProtocolVersion,
		Type:      PacketTypeHandshakeResp,
		SessionID: sessionID,
		Counter:   0,
	}
	hdr.Put(resp[0:HeaderSize])
	copy(resp[14:46], serverEphemPub)
	copy(resp[46:62], serverNonce[:])

	sigMsg := buildRespSignTranscript(resp[0:62], initPkt.ClientEphemPub[:], initPkt.ClientNonce[:], initPkt.Suite)
	sig := ed25519.Sign(serverPriv, sigMsg)
	copy(resp[62:126], sig)

	vip4 := lease.VirtualIP.As4()
	svip4 := lease.ServerVIP.As4()
	var leasePlain [HandshakeLeasePlainSize]byte
	copy(leasePlain[0:4], vip4[:])
	copy(leasePlain[4:8], svip4[:])
	leasePlain[8] = lease.PrefixLen
	binary.BigEndian.PutUint16(leasePlain[9:11], lease.MTU)

	nonce0 := MakeNonce(0)
	s2cAEAD.Seal(resp[126:126], nonce0[:], leasePlain[:], resp[0:HeaderSize])

	return resp, &HandshakeResult{
		SessionID: sessionID,
		Suite:     initPkt.Suite,
		RxKey:     c2sAEAD, // Server receives with client->server key
		TxKey:     s2cAEAD, // Server transmits with server->client key
		Lease:     lease,
	}, nil
}

// ConsumeHandshakeResp verifies a 153-byte Handshake Resp on the client, authenticates
// the server's Ed25519 signature BEFORE running ECDH, derives directional session keys,
// and decrypts the assigned tunnel lease.
func ConsumeHandshakeResp(raw []byte, state *HandshakeInitiatorState) (*HandshakeResult, error) {
	if len(raw) != HandshakeRespSize {
		return nil, ErrMalformedHandshake
	}
	hdr, err := ParseHeader(raw)
	if err != nil || hdr.Type != PacketTypeHandshakeResp || hdr.Counter != 0 || hdr.SessionID == 0 {
		return nil, ErrMalformedHandshake
	}

	serverEphemBytes := raw[14:46]
	var serverNonce [16]byte
	copy(serverNonce[:], raw[46:62])
	serverSig := raw[62:126]
	encryptedLease := raw[126:153]

	sigMsg := buildRespSignTranscript(raw[0:62], state.EphemeralPub[:], state.ClientNonce[:], state.Suite)
	if !ed25519.Verify(state.ServerStaticPub, sigMsg, serverSig) {
		return nil, ErrInvalidHandshakeSig
	}

	serverEphemKey, err := ecdh.X25519().NewPublicKey(serverEphemBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid server X25519 key", ErrMalformedHandshake)
	}
	sharedSecret, err := state.EphemeralPriv.ECDH(serverEphemKey)
	if err != nil {
		return nil, fmt.Errorf("%w: X25519 ECDH failed", ErrMalformedHandshake)
	}
	defer clear(sharedSecret)

	c2sAEAD, s2cAEAD, err := DeriveSessionKeys(
		sharedSecret,
		state.ClientNonce,
		serverNonce,
		state.PSK,
		hdr.SessionID,
		state.ClientStaticPub,
		state.ServerStaticPub,
		state.EphemeralPub[:],
		serverEphemBytes,
		state.Suite,
	)
	if err != nil {
		return nil, err
	}

	nonce0 := MakeNonce(0)
	leasePlain, err := s2cAEAD.Open(nil, nonce0[:], encryptedLease, raw[0:HeaderSize])
	if err != nil || len(leasePlain) != HandshakeLeasePlainSize {
		return nil, ErrHandshakeDecryptFailed
	}

	var vip4, svip4 [4]byte
	copy(vip4[:], leasePlain[0:4])
	copy(svip4[:], leasePlain[4:8])

	return &HandshakeResult{
		SessionID: hdr.SessionID,
		Suite:     state.Suite,
		RxKey:     s2cAEAD, // Client receives with server->client key
		TxKey:     c2sAEAD, // Client transmits with client->server key
		Lease: LeaseConfig{
			VirtualIP: netip.AddrFrom4(vip4),
			ServerVIP: netip.AddrFrom4(svip4),
			PrefixLen: leasePlain[8],
			MTU:       binary.BigEndian.Uint16(leasePlain[9:11]),
		},
	}, nil
}

func computePSKTag(psk [32]byte, initPrefix []byte, serverPub ed25519.PublicKey) [32]byte {
	mac := hmac.New(sha256.New, psk[:])
	mac.Write([]byte("vpn-v1-psk-mac"))
	mac.Write(initPrefix)
	mac.Write(serverPub)
	var out [32]byte
	copy(out[:], mac.Sum(nil))
	return out
}

func buildInitSignTranscript(initPrefix []byte, serverPub ed25519.PublicKey) []byte {
	out := make([]byte, 0, 14+len(initPrefix)+len(serverPub))
	out = append(out, "vpn-v1-hs-init"...)
	out = append(out, initPrefix...)
	out = append(out, serverPub...)
	return out
}

func buildRespSignTranscript(respPrefix, clientEphemPub, clientNonce []byte, suite CipherSuite) []byte {
	out := make([]byte, 0, 14+len(respPrefix)+len(clientEphemPub)+len(clientNonce)+1)
	out = append(out, "vpn-v1-hs-resp"...)
	out = append(out, respPrefix...)
	out = append(out, clientEphemPub...)
	out = append(out, clientNonce...)
	out = append(out, byte(suite))
	return out
}
