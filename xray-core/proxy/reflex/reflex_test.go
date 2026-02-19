package reflex

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"testing"
	"time"
)

// ------------------------------------------------------------------ helpers

func mustGenerateKey(t *testing.T) ([32]byte, [32]byte) {
	t.Helper()
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	return priv, pub
}

// ------------------------------------------------------------------ key exchange

func TestGenerateKeyPair(t *testing.T) {
	priv1, pub1 := mustGenerateKey(t)
	priv2, pub2 := mustGenerateKey(t)

	// Shared secret must be equal from both sides (DH property).
	shared1, err := DeriveSharedKey(priv1, pub2)
	if err != nil {
		t.Fatalf("DeriveSharedKey (side 1): %v", err)
	}
	shared2, err := DeriveSharedKey(priv2, pub1)
	if err != nil {
		t.Fatalf("DeriveSharedKey (side 2): %v", err)
	}
	if shared1 != shared2 {
		t.Fatal("shared keys do not match — DH broken")
	}
}

func TestDeriveSessionKey(t *testing.T) {
	priv1, pub1 := mustGenerateKey(t)
	priv2, pub2 := mustGenerateKey(t)

	shared1, _ := DeriveSharedKey(priv1, pub2)
	shared2, _ := DeriveSharedKey(priv2, pub1)

	var nonce [16]byte
	io.ReadFull(rand.Reader, nonce[:])

	key1, err := DeriveSessionKey(shared1, nonce)
	if err != nil {
		t.Fatalf("DeriveSessionKey (side 1): %v", err)
	}
	key2, err := DeriveSessionKey(shared2, nonce)
	if err != nil {
		t.Fatalf("DeriveSessionKey (side 2): %v", err)
	}
	if !bytes.Equal(key1, key2) {
		t.Fatal("session keys do not match — KDF broken")
	}
	if len(key1) != 32 {
		t.Fatalf("expected 32-byte session key, got %d", len(key1))
	}
}

func TestDifferentNoncesDifferentKeys(t *testing.T) {
	priv1, pub1 := mustGenerateKey(t)
	priv2, pub2 := mustGenerateKey(t)
	shared1, _ := DeriveSharedKey(priv1, pub2)
	shared2, _ := DeriveSharedKey(priv2, pub1)
	_ = shared2 // both equal

	var nonce1, nonce2 [16]byte
	io.ReadFull(rand.Reader, nonce1[:])
	io.ReadFull(rand.Reader, nonce2[:])

	key1, _ := DeriveSessionKey(shared1, nonce1)
	key2, _ := DeriveSessionKey(shared1, nonce2)
	if bytes.Equal(key1, key2) {
		t.Fatal("different nonces produced same session key")
	}
}

// ------------------------------------------------------------------ session: encrypt/decrypt

func TestSessionEncryptDecrypt(t *testing.T) {
	key := make([]byte, 32)
	io.ReadFull(rand.Reader, key)

	sender, _ := NewSession(key)
	receiver, _ := NewSession(key)

	original := []byte("hello reflex protocol")

	var buf bytes.Buffer
	if err := sender.WriteFrame(&buf, FrameTypeData, original); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}

	frame, err := receiver.ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if frame.Type != FrameTypeData {
		t.Fatalf("expected FrameTypeData, got 0x%02x", frame.Type)
	}
	if !bytes.Equal(frame.Payload, original) {
		t.Fatalf("payload mismatch: got %q, want %q", frame.Payload, original)
	}
}

func TestSessionMultipleFrames(t *testing.T) {
	key := make([]byte, 32)
	io.ReadFull(rand.Reader, key)
	sender, _ := NewSession(key)
	receiver, _ := NewSession(key)

	messages := [][]byte{
		[]byte("first frame"),
		[]byte("second frame"),
		[]byte("third frame — slightly longer data to test buffering"),
	}

	var buf bytes.Buffer
	for _, msg := range messages {
		if err := sender.WriteFrame(&buf, FrameTypeData, msg); err != nil {
			t.Fatalf("WriteFrame: %v", err)
		}
	}

	for i, want := range messages {
		frame, err := receiver.ReadFrame(&buf)
		if err != nil {
			t.Fatalf("ReadFrame[%d]: %v", i, err)
		}
		if !bytes.Equal(frame.Payload, want) {
			t.Fatalf("frame[%d] mismatch: got %q, want %q", i, frame.Payload, want)
		}
	}
}

func TestSessionWrongKeyFails(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	io.ReadFull(rand.Reader, key1)
	io.ReadFull(rand.Reader, key2)

	sender, _ := NewSession(key1)
	receiver, _ := NewSession(key2) // different key

	var buf bytes.Buffer
	sender.WriteFrame(&buf, FrameTypeData, []byte("secret"))

	_, err := receiver.ReadFrame(&buf)
	if err == nil {
		t.Fatal("decryption with wrong key should fail, but succeeded")
	}
}

func TestSessionNonceIncrement(t *testing.T) {
	// Sending the same plaintext twice must produce different ciphertext
	// (because nonce increments).
	key := make([]byte, 32)
	io.ReadFull(rand.Reader, key)
	sender1, _ := NewSession(key)
	sender2, _ := NewSession(key)

	data := []byte("identical plaintext")

	var buf1, buf2 bytes.Buffer
	sender1.WriteFrame(&buf1, FrameTypeData, data)
	sender2.WriteFrame(&buf2, FrameTypeData, data) // same session state → same output
	if !bytes.Equal(buf1.Bytes(), buf2.Bytes()) {
		t.Fatal("identical sessions should produce identical ciphertext")
	}

	// Now advance sender1 by one frame and check ciphertext differs.
	sender1.WriteFrame(&buf1, FrameTypeData, data) // nonce=1
	sender2.WriteFrame(io.Discard, FrameTypeData, []byte("advance"))
	sender2.WriteFrame(&buf2, FrameTypeData, data) // nonce=1 too, but buf2 now has both frames

	// Just confirm the first frame's ciphertext differs from the second.
	first := buf1.Bytes()[:len(buf1.Bytes())/2]
	second := buf1.Bytes()[len(buf1.Bytes())/2:]
	if bytes.Equal(first, second) {
		t.Fatal("consecutive frames with same plaintext should differ (nonce increment)")
	}
}

func TestAllFrameTypes(t *testing.T) {
	key := make([]byte, 32)
	io.ReadFull(rand.Reader, key)
	sender, _ := NewSession(key)
	receiver, _ := NewSession(key)

	types := []uint8{FrameTypeData, FrameTypePadding, FrameTypeTiming, FrameTypeClose}
	var buf bytes.Buffer
	for _, ft := range types {
		if err := sender.WriteFrame(&buf, ft, []byte{byte(ft)}); err != nil {
			t.Fatalf("WriteFrame type=0x%02x: %v", ft, err)
		}
	}
	for _, ft := range types {
		frame, err := receiver.ReadFrame(&buf)
		if err != nil {
			t.Fatalf("ReadFrame type=0x%02x: %v", ft, err)
		}
		if frame.Type != ft {
			t.Fatalf("type mismatch: got 0x%02x want 0x%02x", frame.Type, ft)
		}
	}
}

// ------------------------------------------------------------------ session: edge cases

func TestEmptyPayload(t *testing.T) {
	key := make([]byte, 32)
	io.ReadFull(rand.Reader, key)
	sender, _ := NewSession(key)
	receiver, _ := NewSession(key)

	var buf bytes.Buffer
	if err := sender.WriteFrame(&buf, FrameTypeData, []byte{}); err != nil {
		t.Fatalf("WriteFrame empty: %v", err)
	}
	frame, err := receiver.ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame empty: %v", err)
	}
	// Payload may be nil or empty slice — both are acceptable.
	if len(frame.Payload) != 0 {
		t.Fatalf("expected empty payload, got %d bytes", len(frame.Payload))
	}
}

func TestLargePayload(t *testing.T) {
	key := make([]byte, 32)
	io.ReadFull(rand.Reader, key)
	sender, _ := NewSession(key)
	receiver, _ := NewSession(key)

	// 32 KB — well within uint16 range after AEAD tag overhead.
	large := make([]byte, 32*1024)
	io.ReadFull(rand.Reader, large)

	var buf bytes.Buffer
	if err := sender.WriteFrame(&buf, FrameTypeData, large); err != nil {
		t.Fatalf("WriteFrame large: %v", err)
	}
	frame, err := receiver.ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame large: %v", err)
	}
	if !bytes.Equal(frame.Payload, large) {
		t.Fatal("large payload mismatch")
	}
}

func TestClosedWriterError(t *testing.T) {
	key := make([]byte, 32)
	io.ReadFull(rand.Reader, key)
	sender, _ := NewSession(key)

	// net.Pipe gives us a real connection we can close.
	c1, c2 := net.Pipe()
	c2.Close() // close the read side immediately

	err := sender.WriteFrame(c1, FrameTypeData, []byte("test"))
	if err == nil {
		t.Fatal("writing to closed connection should return error")
	}
	c1.Close()
}

func TestTruncatedFrame(t *testing.T) {
	key := make([]byte, 32)
	io.ReadFull(rand.Reader, key)
	sender, _ := NewSession(key)
	receiver, _ := NewSession(key)

	var buf bytes.Buffer
	sender.WriteFrame(&buf, FrameTypeData, []byte("hello"))

	// Truncate: keep header but cut payload in half.
	data := buf.Bytes()
	truncated := bytes.NewReader(data[:len(data)/2])

	_, err := receiver.ReadFrame(truncated)
	if err == nil {
		t.Fatal("reading truncated frame should return error")
	}
}

// ------------------------------------------------------------------ handshake payloads

func TestClientPayloadRoundtrip(t *testing.T) {
	original := &ClientPayload{
		Timestamp: time.Now().Unix(),
	}
	io.ReadFull(rand.Reader, original.PublicKey[:])
	io.ReadFull(rand.Reader, original.UserID[:])
	io.ReadFull(rand.Reader, original.Nonce[:])

	encoded := EncodeClientPayload(original)
	decoded, err := DecodeClientPayload(encoded)
	if err != nil {
		t.Fatalf("DecodeClientPayload: %v", err)
	}

	if decoded.PublicKey != original.PublicKey {
		t.Error("PublicKey mismatch")
	}
	if decoded.UserID != original.UserID {
		t.Error("UserID mismatch")
	}
	if decoded.Timestamp != original.Timestamp {
		t.Error("Timestamp mismatch")
	}
	if decoded.Nonce != original.Nonce {
		t.Error("Nonce mismatch")
	}
}

func TestServerPayloadRoundtrip(t *testing.T) {
	original := &ServerPayload{}
	io.ReadFull(rand.Reader, original.PublicKey[:])

	encoded := EncodeServerPayload(original)
	decoded, err := DecodeServerPayload(encoded)
	if err != nil {
		t.Fatalf("DecodeServerPayload: %v", err)
	}
	if decoded.PublicKey != original.PublicKey {
		t.Error("ServerPayload PublicKey mismatch")
	}
}

func TestDecodeClientPayloadTooShort(t *testing.T) {
	_, err := DecodeClientPayload([]byte{1, 2, 3})
	if err == nil {
		t.Fatal("should error on too-short payload")
	}
}

// ------------------------------------------------------------------ destination encoding

func TestDestinationIPv4Roundtrip(t *testing.T) {
	ip := []byte{1, 2, 3, 4}
	port := uint16(8080)
	data := []byte("hello")

	encoded := EncodeDestination(AddrTypeIPv4, ip, port)
	encoded = append(encoded, data...)

	addrType, addr, gotPort, gotData, err := DecodeDestination(encoded)
	if err != nil {
		t.Fatalf("DecodeDestination IPv4: %v", err)
	}
	if addrType != AddrTypeIPv4 {
		t.Errorf("addrType: got %d want %d", addrType, AddrTypeIPv4)
	}
	if !bytes.Equal(addr, ip) {
		t.Errorf("addr mismatch: got %v want %v", addr, ip)
	}
	if gotPort != port {
		t.Errorf("port: got %d want %d", gotPort, port)
	}
	if !bytes.Equal(gotData, data) {
		t.Errorf("data mismatch: got %q want %q", gotData, data)
	}
}

func TestDestinationDomainRoundtrip(t *testing.T) {
	domain := []byte("example.com")
	port := uint16(443)
	data := []byte("payload bytes")

	encoded := EncodeDestination(AddrTypeDomain, domain, port)
	encoded = append(encoded, data...)

	addrType, addr, gotPort, gotData, err := DecodeDestination(encoded)
	if err != nil {
		t.Fatalf("DecodeDestination domain: %v", err)
	}
	if addrType != AddrTypeDomain {
		t.Errorf("addrType: got %d want %d", addrType, AddrTypeDomain)
	}
	if string(addr) != string(domain) {
		t.Errorf("domain mismatch: got %q want %q", addr, domain)
	}
	if gotPort != port {
		t.Errorf("port: got %d want %d", gotPort, port)
	}
	if !bytes.Equal(gotData, data) {
		t.Errorf("data mismatch")
	}
}

func TestDestinationIPv6Roundtrip(t *testing.T) {
	ip := []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	port := uint16(80)

	encoded := EncodeDestination(AddrTypeIPv6, ip, port)

	addrType, addr, gotPort, _, err := DecodeDestination(encoded)
	if err != nil {
		t.Fatalf("DecodeDestination IPv6: %v", err)
	}
	if addrType != AddrTypeIPv6 {
		t.Errorf("addrType mismatch")
	}
	if !bytes.Equal(addr, ip) {
		t.Errorf("IPv6 addr mismatch")
	}
	if gotPort != port {
		t.Errorf("port mismatch")
	}
}

func TestDestinationUnknownType(t *testing.T) {
	bad := []byte{0xFF, 1, 2, 3, 4, 5, 6}
	_, _, _, _, err := DecodeDestination(bad)
	if err == nil {
		t.Fatal("unknown address type should return error")
	}
}

// ------------------------------------------------------------------ HTTP framing

func TestHTTPClientWrapUnwrap(t *testing.T) {
	payload := &ClientPayload{Timestamp: time.Now().Unix()}
	io.ReadFull(rand.Reader, payload.PublicKey[:])
	io.ReadFull(rand.Reader, payload.UserID[:])
	io.ReadFull(rand.Reader, payload.Nonce[:])

	wrapped, err := WrapClientHTTP(payload, "example.com")
	if err != nil {
		t.Fatalf("WrapClientHTTP: %v", err)
	}
	// Must start with the HTTP request line.
	if !bytes.HasPrefix(wrapped, []byte("POST /api/v1/data HTTP/1.1\r\n")) {
		t.Fatalf("wrapped HTTP request has wrong prefix: %q", wrapped[:min(len(wrapped), 40)])
	}
}

func TestHTTPServerWrapUnwrap(t *testing.T) {
	payload := &ServerPayload{}
	io.ReadFull(rand.Reader, payload.PublicKey[:])

	wrapped, err := WrapServerHTTP(payload)
	if err != nil {
		t.Fatalf("WrapServerHTTP: %v", err)
	}
	if !bytes.HasPrefix(wrapped, []byte("HTTP/1.1 200 OK\r\n")) {
		t.Fatalf("wrapped HTTP response has wrong prefix: %q", wrapped[:min(len(wrapped), 40)])
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
