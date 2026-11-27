package protocol

import (
	"bytes"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func TestHeaderRoundTripAndValidation(t *testing.T) {
	orig := Header{
		Version:   ProtocolVersion,
		Type:      PacketTypeData,
		SessionID: 0xdeadbeef,
		Counter:   0x0102030405060708,
	}
	var buf [HeaderSize]byte
	orig.Put(buf[:])

	got, err := ParseHeader(buf[:])
	if err != nil {
		t.Fatalf("ParseHeader failed: %v", err)
	}
	if got != orig {
		t.Fatalf("header mismatch: got %+v, want %+v", got, orig)
	}

	if _, err := ParseHeader(buf[:13]); !errors.Is(err, ErrPacketTooShort) {
		t.Fatalf("expected ErrPacketTooShort, got %v", err)
	}

	badVer := buf
	badVer[0] = 0x02
	if _, err := ParseHeader(badVer[:]); !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("expected ErrUnsupportedVersion, got %v", err)
	}

	badType := buf
	badType[1] = 0x99
	if _, err := ParseHeader(badType[:]); !errors.Is(err, ErrUnknownPacketType) {
		t.Fatalf("expected ErrUnknownPacketType, got %v", err)
	}
}

func TestReplayWindow128BitBoundaries(t *testing.T) {
	var rw ReplayWindow

	// First packet at sequence 5 (allows 0..4 out-of-order).
	if !rw.Check(5) || !rw.Accept(5) {
		t.Fatal("expected initial packet 5 to be accepted")
	}
	if rw.Check(5) || rw.Accept(5) {
		t.Fatal("expected duplicate packet 5 to be rejected")
	}

	// Out-of-order packets 0..4 should all be accepted once.
	for c := uint64(0); c < 5; c++ {
		if !rw.Check(c) || !rw.Accept(c) {
			t.Fatalf("expected out-of-order counter %d to be accepted", c)
		}
		if rw.Check(c) || rw.Accept(c) {
			t.Fatalf("expected duplicate counter %d to be rejected", c)
		}
	}

	// Jump by 64 (crosses lo -> hi boundary): highest becomes 69.
	if !rw.Accept(69) {
		t.Fatal("expected counter 69 to be accepted")
	}
	// Counters 0..5 are at diff 69..64 (in hi word) and already seen!
	for c := uint64(0); c <= 5; c++ {
		if rw.Check(c) || rw.Accept(c) {
			t.Fatalf("expected previously seen counter %d in hi bitmap to be rejected", c)
		}
	}
	// Counter 6 (diff 63) and counter 68 (diff 1) were not seen yet -> should be accepted.
	for _, c := range []uint64{6, 37, 68} {
		if !rw.Check(c) || !rw.Accept(c) {
			t.Fatalf("expected unseen counter %d to be accepted", c)
		}
	}

	// Advance highest to 200: window covers [73..200]. Counter 72 is outside 128-bit window.
	if !rw.Accept(200) {
		t.Fatal("expected counter 200 to be accepted")
	}
	if rw.Check(72) || rw.Accept(72) {
		t.Fatal("expected counter 72 (diff 128) to be rejected as outside window")
	}
	if !rw.Check(73) || !rw.Accept(73) {
		t.Fatal("expected counter 73 (diff 127) to be accepted at window edge")
	}
	if rw.Check(73) || rw.Accept(73) {
		t.Fatal("expected duplicate counter 73 to be rejected")
	}
}

func TestReplayWindowConcurrentSafety(t *testing.T) {
	var rw ReplayWindow
	const total = 512
	var accepted sync.Map
	var wg sync.WaitGroup

	// Have 8 goroutines race to accept every counter 1..total twice.
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(offset int) {
			defer wg.Done()
			for i := 1; i <= total; i++ {
				c := uint64(((i + offset) % total) + 1)
				if rw.Accept(c) {
					if _, loaded := accepted.LoadOrStore(c, true); loaded {
						t.Errorf("counter %d accepted more than once!", c)
					}
				}
			}
		}(g * 17)
	}
	wg.Wait()
}

func TestHandshakeAndDataPlaneBothSuites(t *testing.T) {
	for _, suite := range []CipherSuite{CipherChaCha20Poly1305, CipherAES256GCM} {
		t.Run(suite.String(), func(t *testing.T) {
			serverPub, serverPriv, err := GenerateStaticKeyPair()
			if err != nil {
				t.Fatal(err)
			}
			clientPub, clientPriv, err := GenerateStaticKeyPair()
			if err != nil {
				t.Fatal(err)
			}
			psk, err := GeneratePSK()
			if err != nil {
				t.Fatal(err)
			}

			now := time.Now()
			initBytes, clientState, err := BuildHandshakeInit(clientPriv, serverPub, psk, suite, 0, now)
			if err != nil {
				t.Fatalf("BuildHandshakeInit: %v", err)
			}
			if len(initBytes) != HandshakeInitSize {
				t.Fatalf("unexpected init size: %d", len(initBytes))
			}

			parsedInit, err := ParseHandshakeInit(initBytes)
			if err != nil {
				t.Fatalf("ParseHandshakeInit: %v", err)
			}
			if !bytes.Equal(parsedInit.ClientStaticPub[:], clientPub) {
				t.Fatal("parsed client static pubkey mismatch")
			}

			if err := VerifyHandshakeInit(parsedInit, serverPub, psk, 0, now, DefaultMaxHandshakeSkew); err != nil {
				t.Fatalf("VerifyHandshakeInit: %v", err)
			}
			// Replay with same timestamp must fail.
			if err := VerifyHandshakeInit(parsedInit, serverPub, psk, parsedInit.Header.Counter, now, DefaultMaxHandshakeSkew); !errors.Is(err, ErrHandshakeReplay) {
				t.Fatalf("expected ErrHandshakeReplay, got %v", err)
			}
			// Wrong PSK must fail.
			var wrongPSK [32]byte
			if err := VerifyHandshakeInit(parsedInit, serverPub, wrongPSK, 0, now, DefaultMaxHandshakeSkew); !errors.Is(err, ErrInvalidPSKTag) {
				t.Fatalf("expected ErrInvalidPSKTag, got %v", err)
			}

			lease := LeaseConfig{
				VirtualIP: netip.MustParseAddr("10.100.0.2"),
				ServerVIP: netip.MustParseAddr("10.100.0.1"),
				PrefixLen: 24,
				MTU:       DefaultTUNMTU,
			}
			respBytes, serverRes, err := RespondHandshake(parsedInit, serverPriv, psk, 42, lease)
			if err != nil {
				t.Fatalf("RespondHandshake: %v", err)
			}
			if len(respBytes) >= len(initBytes) {
				t.Fatalf("handshake resp (%d) must be smaller than init (%d)", len(respBytes), len(initBytes))
			}

			clientRes, err := ConsumeHandshakeResp(respBytes, clientState)
			if err != nil {
				t.Fatalf("ConsumeHandshakeResp: %v", err)
			}
			if clientRes.SessionID != 42 || clientRes.Lease != lease {
				t.Fatalf("lease mismatch: got %+v, want %+v", clientRes.Lease, lease)
			}

			// Test in-place SealPacket & OpenPacket + AAD tampering rejection!
			payload := []byte("0123456789abcdef-simulated-ipv4-packet")
			buf := GetPacketBuffer()
			defer PutPacketBuffer(buf)
			copy(buf[HeaderSize:], payload)

			hdr := Header{
				Version:   ProtocolVersion,
				Type:      PacketTypeData,
				SessionID: clientRes.SessionID,
				Counter:   1,
			}
			wire := SealPacket(buf[:], clientRes.TxKey, hdr, buf[HeaderSize:HeaderSize+len(payload)])

			// Tampering with SessionID in header AAD must invalidate AEAD tag.
			tampered := append([]byte(nil), wire...)
			tampered[5] ^= 0x01
			if _, _, err := OpenPacket(nil, serverRes.RxKey, tampered); !errors.Is(err, ErrAuthenticationFailed) {
				t.Fatalf("expected AAD header tampering to fail authentication, got %v", err)
			}

			// Valid in-place decryption on server.
			gotHdr, plain, err := OpenPacket(wire[HeaderSize:], serverRes.RxKey, wire)
			if err != nil {
				t.Fatalf("OpenPacket failed: %v", err)
			}
			if gotHdr != hdr || !bytes.Equal(plain, payload) {
				t.Fatalf("decrypted packet mismatch")
			}
		})
	}
}

func TestIPv4AddressExtraction(t *testing.T) {
	pkt := make([]byte, 20)
	pkt[0] = (4 << 4) | 5 // IPv4, IHL=5 (20 bytes)
	copy(pkt[12:16], []byte{10, 100, 0, 2})
	copy(pkt[16:20], []byte{8, 8, 8, 8})

	src, ok := ExtractIPv4Src(pkt)
	if !ok || src != [4]byte{10, 100, 0, 2} {
		t.Fatalf("unexpected src: %v, %v", src, ok)
	}
	dst, ok := ExtractIPv4Dst(pkt)
	if !ok || dst != [4]byte{8, 8, 8, 8} {
		t.Fatalf("unexpected dst: %v, %v", dst, ok)
	}

	// IPv6 packet should return false for IPv4 extractor.
	pkt[0] = 6 << 4
	if _, ok := ExtractIPv4Src(pkt); ok {
		t.Fatal("expected false for IPv6 packet")
	}
}
