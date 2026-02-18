package reflex

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// ---- Wire types (what goes over the network) ----

// HTTPHandshakeBody is the JSON body of the POST request/response.
type HTTPHandshakeBody struct {
	Data string `json:"data"` // base64-encoded HandshakePayload
}

// ClientPayload is the binary structure encoded inside Data.
// Total: 32 + 16 + 8 + 16 = 72 bytes (before any encryption).
type ClientPayload struct {
	PublicKey [32]byte // ephemeral X25519 public key
	UserID    [16]byte // UUID as raw bytes
	Timestamp int64    // Unix timestamp (8 bytes, big-endian)
	Nonce     [16]byte // random nonce
}

// ServerPayload is what the server sends back inside the HTTP 200 body.
type ServerPayload struct {
	PublicKey [32]byte // ephemeral X25519 public key
}

// ---- HTTP framing constants ----

const (
	ClientRequestTemplate = "POST /api/v1/data HTTP/1.1\r\n" +
		"Host: %s\r\n" +
		"Content-Type: application/json\r\n" +
		"Content-Length: %d\r\n" +
		"\r\n"

	ServerResponseTemplate = "HTTP/1.1 200 OK\r\n" +
		"Content-Type: application/json\r\n" +
		"Content-Length: %d\r\n" +
		"\r\n"

	FallbackResponse = "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"
)

// ---- Key generation ----

// GenerateKeyPair creates a random X25519 key pair.
func GenerateKeyPair() (privateKey [32]byte, publicKey [32]byte, err error) {
	if _, err = io.ReadFull(rand.Reader, privateKey[:]); err != nil {
		return
	}
	// Clamp private key per RFC 7748
	privateKey[0] &= 248
	privateKey[31] &= 127
	privateKey[31] |= 64
	curve25519.ScalarBaseMult(&publicKey, &privateKey)
	return
}

// DeriveSharedKey performs X25519 DH.
func DeriveSharedKey(privateKey, peerPublicKey [32]byte) ([32]byte, error) {
	sharedSlice, err := curve25519.X25519(privateKey[:], peerPublicKey[:])
	if err != nil {
		return [32]byte{}, err
	}
	var shared [32]byte
	copy(shared[:], sharedSlice)
	return shared, nil
}

// DeriveSessionKey runs HKDF-SHA256 over the shared secret.
func DeriveSessionKey(sharedKey [32]byte, nonce [16]byte) ([]byte, error) {
	r := hkdf.New(sha256.New, sharedKey[:], nonce[:], []byte("reflex-session-v1"))
	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, err
	}
	return key, nil
}

// ---- Serialization helpers ----

// EncodeClientPayload serializes a ClientPayload to bytes (72 bytes, binary).
func EncodeClientPayload(p *ClientPayload) []byte {
	buf := make([]byte, 0, 72)
	buf = append(buf, p.PublicKey[:]...)
	buf = append(buf, p.UserID[:]...)
	// Timestamp: 8 bytes big-endian
	buf = append(buf,
		byte(p.Timestamp>>56),
		byte(p.Timestamp>>48),
		byte(p.Timestamp>>40),
		byte(p.Timestamp>>32),
		byte(p.Timestamp>>24),
		byte(p.Timestamp>>16),
		byte(p.Timestamp>>8),
		byte(p.Timestamp),
	)
	buf = append(buf, p.Nonce[:]...)
	return buf
}

// DecodeClientPayload parses bytes back into a ClientPayload.
func DecodeClientPayload(b []byte) (*ClientPayload, error) {
	if len(b) < 72 {
		return nil, fmt.Errorf("reflex: client payload too short: %d bytes", len(b))
	}
	p := &ClientPayload{}
	copy(p.PublicKey[:], b[0:32])
	copy(p.UserID[:], b[32:48])
	p.Timestamp = int64(b[48])<<56 | int64(b[49])<<48 | int64(b[50])<<40 |
		int64(b[51])<<32 | int64(b[52])<<24 | int64(b[53])<<16 |
		int64(b[54])<<8 | int64(b[55])
	copy(p.Nonce[:], b[56:72])
	return p, nil
}

// EncodeServerPayload serializes a ServerPayload to 32 bytes.
func EncodeServerPayload(p *ServerPayload) []byte {
	return p.PublicKey[:]
}

// DecodeServerPayload parses 32 bytes into a ServerPayload.
func DecodeServerPayload(b []byte) (*ServerPayload, error) {
	if len(b) < 32 {
		return nil, fmt.Errorf("reflex: server payload too short: %d bytes", len(b))
	}
	p := &ServerPayload{}
	copy(p.PublicKey[:], b[0:32])
	return p, nil
}

// ---- HTTP framing ----

// WrapClientHTTP wraps a ClientPayload into an HTTP POST request (bytes).
func WrapClientHTTP(payload *ClientPayload, host string) ([]byte, error) {
	raw := EncodeClientPayload(payload)
	body := HTTPHandshakeBody{Data: base64.StdEncoding.EncodeToString(raw)}
	bodyJSON, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	header := fmt.Sprintf(ClientRequestTemplate, host, len(bodyJSON))
	return append([]byte(header), bodyJSON...), nil
}

// WrapServerHTTP wraps a ServerPayload into an HTTP 200 response (bytes).
func WrapServerHTTP(payload *ServerPayload) ([]byte, error) {
	raw := EncodeServerPayload(payload)
	body := HTTPHandshakeBody{Data: base64.StdEncoding.EncodeToString(raw)}
	bodyJSON, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	header := fmt.Sprintf(ServerResponseTemplate, len(bodyJSON))
	return append([]byte(header), bodyJSON...), nil
}

// UnwrapHTTPBody extracts the base64 Data field from an HTTP body JSON.
func UnwrapHTTPBody(jsonBytes []byte) ([]byte, error) {
	var body HTTPHandshakeBody
	if err := json.Unmarshal(jsonBytes, &body); err != nil {
		return nil, fmt.Errorf("reflex: failed to parse handshake body: %w", err)
	}
	raw, err := base64.StdEncoding.DecodeString(body.Data)
	if err != nil {
		return nil, fmt.Errorf("reflex: failed to decode base64: %w", err)
	}
	return raw, nil
}
