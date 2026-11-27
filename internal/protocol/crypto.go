package protocol

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// CipherSuite identifies the AEAD algorithm negotiated for the data plane.
type CipherSuite uint8

const (
	CipherChaCha20Poly1305 CipherSuite = 0x01
	CipherAES256GCM        CipherSuite = 0x02
)

var (
	ErrUnsupportedCipherSuite = errors.New("protocol: unsupported cipher suite")
	ErrInvalidKeyEncoding     = errors.New("protocol: invalid key encoding or length")
	ErrAuthenticationFailed   = errors.New("protocol: AEAD authentication failed")
)

// ParseCipherSuite parses a human-readable cipher suite name.
func ParseCipherSuite(s string) (CipherSuite, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "chacha20-poly1305", "chacha20poly1305":
		return CipherChaCha20Poly1305, nil
	case "aes-256-gcm", "aes256gcm":
		return CipherAES256GCM, nil
	default:
		return 0, fmt.Errorf("%w: %q", ErrUnsupportedCipherSuite, s)
	}
}

func (c CipherSuite) String() string {
	switch c {
	case CipherChaCha20Poly1305:
		return "chacha20-poly1305"
	case CipherAES256GCM:
		return "aes-256-gcm"
	default:
		return fmt.Sprintf("unknown(0x%02x)", uint8(c))
	}
}

// Valid reports whether c is a supported AEAD cipher suite.
func (c CipherSuite) Valid() bool {
	return c == CipherChaCha20Poly1305 || c == CipherAES256GCM
}

// NewAEAD constructs a cipher.AEAD from a 32-byte symmetric key for the given suite.
func NewAEAD(suite CipherSuite, key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("protocol: symmetric key must be 32 bytes, got %d", len(key))
	}
	switch suite {
	case CipherChaCha20Poly1305:
		return chacha20poly1305.New(key)
	case CipherAES256GCM:
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(block)
	default:
		return nil, fmt.Errorf("%w: 0x%02x", ErrUnsupportedCipherSuite, uint8(suite))
	}
}

// MakeNonce converts a 64-bit packet sequence counter into a 96-bit (12-byte) AEAD nonce
// per RFC 8439 / TLS 1.3 convention (4 zero bytes followed by big-endian uint64).
func MakeNonce(counter uint64) [AEADNonceSize]byte {
	var nonce [AEADNonceSize]byte
	binary.BigEndian.PutUint64(nonce[4:12], counter)
	return nonce
}

// SealPacket writes the 14-byte header into dst[0:14] and encrypts plaintext into dst[14:],
// authenticating dst[0:14] as Additional Authenticated Data (AAD).
// Supports zero-copy in-place encryption when plaintext aliases dst[14 : 14+len(plaintext)].
func SealPacket(dst []byte, aead cipher.AEAD, hdr Header, plaintext []byte) []byte {
	hdr.Put(dst[0:HeaderSize])
	nonce := MakeNonce(hdr.Counter)
	cipherAndTag := aead.Seal(dst[HeaderSize:HeaderSize], nonce[:], plaintext, dst[0:HeaderSize])
	return dst[:HeaderSize+len(cipherAndTag)]
}

// OpenPacket parses the 14-byte header and authenticates/decrypts rawPacket[14:] into dst[:0],
// passing rawPacket[0:14] as Additional Authenticated Data (AAD).
// Supports zero-copy in-place decryption when dst aliases rawPacket[14:].
func OpenPacket(dst []byte, aead cipher.AEAD, rawPacket []byte) (Header, []byte, error) {
	hdr, err := ParseHeader(rawPacket)
	if err != nil {
		return Header{}, nil, err
	}
	if len(rawPacket) < HeaderSize+AEADTagSize {
		return Header{}, nil, ErrCiphertextTooShort
	}
	nonce := MakeNonce(hdr.Counter)
	plaintext, err := aead.Open(dst[:0], nonce[:], rawPacket[HeaderSize:], rawPacket[0:HeaderSize])
	if err != nil {
		return Header{}, nil, ErrAuthenticationFailed
	}
	return hdr, plaintext, nil
}

// DeriveSessionKeys uses HKDF-SHA256 to derive distinct directional 32-byte AEAD keys
// (client->server and server->client) bound to the full handshake transcript.
func DeriveSessionKeys(
	sharedSecret []byte,
	clientNonce [16]byte,
	serverNonce [16]byte,
	psk [32]byte,
	sessionID uint32,
	clientStaticPub ed25519.PublicKey,
	serverStaticPub ed25519.PublicKey,
	clientEphemPub []byte,
	serverEphemPub []byte,
	suite CipherSuite,
) (clientToServer cipher.AEAD, serverToClient cipher.AEAD, err error) {
	if len(sharedSecret) != 32 {
		return nil, nil, errors.New("protocol: invalid X25519 shared secret length")
	}

	saltHash := sha256.New()
	saltHash.Write([]byte("vpn-v1-hkdf-salt"))
	saltHash.Write(clientNonce[:])
	saltHash.Write(serverNonce[:])
	saltHash.Write(psk[:])
	salt := saltHash.Sum(nil)

	// Bind session parameters into HKDF info to prevent cross-session/cross-role key confusion.
	var sidBytes [4]byte
	binary.BigEndian.PutUint32(sidBytes[:], sessionID)

	info := make([]byte, 0, 20+4+32+32+32+32+1)
	info = append(info, "vpn-v1-session-keys"...)
	info = append(info, sidBytes[:]...)
	info = append(info, clientStaticPub...)
	info = append(info, serverStaticPub...)
	info = append(info, clientEphemPub...)
	info = append(info, serverEphemPub...)
	info = append(info, byte(suite))

	hkdfReader := hkdf.New(sha256.New, sharedSecret, salt, info)
	keyMaterial := make([]byte, 64)
	if _, err := io.ReadFull(hkdfReader, keyMaterial); err != nil {
		return nil, nil, fmt.Errorf("protocol: hkdf expansion failed: %w", err)
	}
	defer clear(keyMaterial)

	c2s, err := NewAEAD(suite, keyMaterial[0:32])
	if err != nil {
		return nil, nil, err
	}
	s2c, err := NewAEAD(suite, keyMaterial[32:64])
	if err != nil {
		return nil, nil, err
	}
	return c2s, s2c, nil
}

// GenerateStaticKeyPair creates a new Ed25519 identity keypair for a server or peer.
func GenerateStaticKeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// GenerateEphemeralKeyPair creates a fresh X25519 ephemeral keypair for a handshake.
func GenerateEphemeralKeyPair() (*ecdh.PrivateKey, error) {
	return ecdh.X25519().GenerateKey(rand.Reader)
}

// GeneratePSK generates a cryptographically random 32-byte pre-shared key.
func GeneratePSK() ([32]byte, error) {
	var psk [32]byte
	_, err := io.ReadFull(rand.Reader, psk[:])
	return psk, err
}

// EncodeKey formats raw key bytes as standard Base64.
func EncodeKey(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

// DecodeFixedKey decodes either Base64 (standard or URL) or Hex into an exact byte length.
func DecodeFixedKey(encoded string, expectedLen int) ([]byte, error) {
	s := strings.TrimSpace(encoded)
	if s == "" {
		return nil, ErrInvalidKeyEncoding
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil && len(b) == expectedLen {
		return b, nil
	}
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil && len(b) == expectedLen {
		return b, nil
	}
	if b, err := hex.DecodeString(s); err == nil && len(b) == expectedLen {
		return b, nil
	}
	return nil, fmt.Errorf("%w: expected %d decoded bytes", ErrInvalidKeyEncoding, expectedLen)
}

// DecodePublicKey parses a 32-byte Ed25519 public key from Base64 or Hex.
func DecodePublicKey(s string) (ed25519.PublicKey, error) {
	b, err := DecodeFixedKey(s, ed25519.PublicKeySize)
	if err != nil {
		return nil, err
	}
	return ed25519.PublicKey(b), nil
}

// DecodePrivateKey parses an Ed25519 private key from either a 64-byte full key or 32-byte seed.
func DecodePrivateKey(s string) (ed25519.PrivateKey, error) {
	if b, err := DecodeFixedKey(s, ed25519.PrivateKeySize); err == nil {
		return ed25519.PrivateKey(b), nil
	}
	seed, err := DecodeFixedKey(s, ed25519.SeedSize)
	if err != nil {
		return nil, err
	}
	defer clear(seed)
	return ed25519.NewKeyFromSeed(seed), nil
}

// DecodePSK parses an optional 32-byte PSK; an empty string returns an all-zero PSK.
func DecodePSK(s string) ([32]byte, error) {
	var psk [32]byte
	if strings.TrimSpace(s) == "" {
		return psk, nil
	}
	b, err := DecodeFixedKey(s, 32)
	if err != nil {
		return psk, err
	}
	copy(psk[:], b)
	return psk, nil
}
