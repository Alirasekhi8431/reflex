package reflex

import (
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"io"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
)

// ---- Frame type constants ----

const (
	FrameTypeData    uint8 = 0x01
	FrameTypePadding uint8 = 0x02
	FrameTypeTiming  uint8 = 0x03
	FrameTypeClose   uint8 = 0x04
)

// ---- Address type constants (inside FrameTypeData payload) ----
// First FrameTypeData from client carries destination before the actual data.
// Format: [1 byte addrType][addr bytes][2 bytes port][data bytes]

const (
	AddrTypeIPv4   uint8 = 0x01 // 4 bytes
	AddrTypeDomain uint8 = 0x03 // 1 byte length + N bytes
	AddrTypeIPv6   uint8 = 0x04 // 16 bytes
)

// ---- Frame ----

type Frame struct {
	Type    uint8
	Payload []byte // decrypted
}

// ---- Session ----

type Session struct {
	aead       cipher.AEAD
	readNonce  uint64
	writeNonce uint64
	writeMu    sync.Mutex
}

func NewSession(sessionKey []byte) (*Session, error) {
	if len(sessionKey) != 32 {
		return nil, fmt.Errorf("reflex: session key must be 32 bytes, got %d", len(sessionKey))
	}
	aead, err := chacha20poly1305.New(sessionKey)
	if err != nil {
		return nil, fmt.Errorf("reflex: failed to create AEAD: %w", err)
	}
	return &Session{aead: aead}, nil
}

// buildNonce encodes a uint64 counter into the 12-byte nonce.
// Bytes 0-3 are zeroed, bytes 4-11 carry the counter big-endian.
func buildNonce(counter uint64) []byte {
	nonce := make([]byte, 12)
	binary.BigEndian.PutUint64(nonce[4:], counter)
	return nonce
}

// ReadFrame reads one complete frame from r, decrypts its payload, and returns it.
func (s *Session) ReadFrame(r io.Reader) (*Frame, error) {
	// 3-byte header: [length uint16][type uint8]
	header := make([]byte, 3)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, fmt.Errorf("reflex: failed to read frame header: %w", err)
	}
	encLen := binary.BigEndian.Uint16(header[0:2])
	frameType := header[2]

	// Read encrypted payload.
	encrypted := make([]byte, encLen)
	if _, err := io.ReadFull(r, encrypted); err != nil {
		return nil, fmt.Errorf("reflex: failed to read frame payload: %w", err)
	}

	// Decrypt.
	nonce := buildNonce(s.readNonce)
	s.readNonce++

	plaintext, err := s.aead.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return nil, fmt.Errorf("reflex: frame decryption failed (nonce=%d): %w", s.readNonce-1, err)
	}

	return &Frame{Type: frameType, Payload: plaintext}, nil
}

// WriteFrame encrypts data and writes a complete frame to w.
func (s *Session) WriteFrame(w io.Writer, frameType uint8, data []byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	nonce := buildNonce(s.writeNonce)
	s.writeNonce++

	encrypted := s.aead.Seal(nil, nonce, data, nil)

	// 3-byte header.
	header := make([]byte, 3)
	binary.BigEndian.PutUint16(header[0:2], uint16(len(encrypted)))
	header[2] = frameType

	if _, err := w.Write(header); err != nil {
		return fmt.Errorf("reflex: failed to write frame header: %w", err)
	}
	if _, err := w.Write(encrypted); err != nil {
		return fmt.Errorf("reflex: failed to write frame payload: %w", err)
	}
	return nil
}

// ---- Destination encoding helpers (used in first FrameTypeData) ----

// EncodeDestination serializes [addrType][addr][port] into bytes.
// Used by the outbound to prefix the first data frame.
func EncodeDestination(addrType uint8, addr []byte, port uint16) []byte {
	var out []byte
	out = append(out, addrType)
	if addrType == AddrTypeDomain {
		out = append(out, byte(len(addr)))
	}
	out = append(out, addr...)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, port)
	out = append(out, portBytes...)
	return out
}

// DecodeDestination parses the destination prefix from a data frame payload.
// Returns addrType, addr bytes, port, and the remaining data after the destination.
func DecodeDestination(payload []byte) (addrType uint8, addr []byte, port uint16, data []byte, err error) {
	if len(payload) < 4 {
		err = fmt.Errorf("reflex: destination payload too short: %d bytes", len(payload))
		return
	}
	addrType = payload[0]
	offset := 1

	switch addrType {
	case AddrTypeIPv4:
		if len(payload) < offset+4+2 {
			err = fmt.Errorf("reflex: truncated IPv4 destination")
			return
		}
		addr = payload[offset : offset+4]
		offset += 4
	case AddrTypeIPv6:
		if len(payload) < offset+16+2 {
			err = fmt.Errorf("reflex: truncated IPv6 destination")
			return
		}
		addr = payload[offset : offset+16]
		offset += 16
	case AddrTypeDomain:
		if len(payload) < offset+1 {
			err = fmt.Errorf("reflex: truncated domain length")
			return
		}
		domainLen := int(payload[offset])
		offset++
		if len(payload) < offset+domainLen+2 {
			err = fmt.Errorf("reflex: truncated domain name")
			return
		}
		addr = payload[offset : offset+domainLen]
		offset += domainLen
	default:
		err = fmt.Errorf("reflex: unknown address type: 0x%02x", addrType)
		return
	}

	port = binary.BigEndian.Uint16(payload[offset : offset+2])
	offset += 2
	data = payload[offset:]
	return
}
