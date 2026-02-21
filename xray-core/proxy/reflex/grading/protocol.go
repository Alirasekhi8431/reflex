// Package grading contains integration tests that verify the Reflex protocol
// as specified in the step docs. These tests run against the student's
// proxy/reflex implementation and ensure handshake, encryption, fallback,
// and morphing behave correctly.
//
// Protocol constants and wire format follow docs/protocol.md and step docs.
package grading

import (
	"encoding/binary"
	"io"
)

// Reflex wire format constants (from docs).
const (
	ReflexMagicU32 = 0x5246584C // "REFX" big-endian
	ReflexMagicLen = 4

	FrameTypeData    = 0x01
	FrameTypePadding = 0x02
	FrameTypeTiming  = 0x03
	FrameTypeClose   = 0x04

	HandshakeMinSize = 64 // for Peek
)

// WriteMagic writes the 4-byte Reflex magic number (big-endian) to w.
func WriteMagic(w io.Writer) error {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], ReflexMagicU32)
	_, err := w.Write(b[:])
	return err
}

// WriteU16BigEndian writes a uint16 in big-endian.
func WriteU16BigEndian(w io.Writer, v uint16) error {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	_, err := w.Write(b[:])
	return err
}

// ReadU16BigEndian reads a uint16 in big-endian.
func ReadU16BigEndian(r io.Reader) (uint16, error) {
	var b [2]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(b[:]), nil
}
