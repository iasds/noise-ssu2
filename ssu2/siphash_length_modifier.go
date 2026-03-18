package ssu2

import (
	"github.com/go-i2p/go-noise/handshake"
	"github.com/go-i2p/go-noise/ntcp2"
)

// SipHashLengthModifier is an SSU2-specific wrapper around NTCP2's SipHash-2-4
// length obfuscation modifier. The SipHash algorithm and length obfuscation logic
// are identical between NTCP2 and SSU2 protocols, so we reuse the NTCP2
// implementation to avoid code duplication.
//
// This modifier obfuscates 2-byte frame lengths in the data phase using
// SipHash-2-4 with provided keys and IV. It prevents identification of frame
// lengths in the encrypted data stream.
//
// Usage:
//
//	sipKeys := [2]uint64{0x0123456789ABCDEF, 0xFEDCBA9876543210}
//	initialIV := uint64(0x1122334455667788)
//	modifier := NewSSU2LengthModifier("ssu2-siphash", sipKeys, initialIV)
//
// Thread Safety: This modifier maintains separate counters for inbound and
// outbound operations, making it safe for concurrent use from separate
// goroutines (one reader, one writer). However, concurrent calls to the same
// direction (multiple ModifyOutbound or multiple ModifyInbound) are not safe.
type SipHashLengthModifier struct {
	*ntcp2.SipHashLengthModifier
}

// NewSSU2LengthModifier creates a new SipHash length obfuscation modifier
// for SSU2 connections. This is a convenience wrapper around the NTCP2
// implementation with SSU2-appropriate naming.
//
// Parameters:
//   - name: Identifier for logging and debugging (e.g., "ssu2-length-obf")
//   - sipKeys: Array of 2 uint64 values for SipHash-2-4 (k1, k2)
//   - initialIV: 8-byte IV from the data phase KDF
//
// Returns a HandshakeModifier that obfuscates 2-byte lengths in the data phase.
//
// Example:
//
//	// Derive SipHash keys from Noise handshake
//	k1 := binary.LittleEndian.Uint64(derivedKey[0:8])
//	k2 := binary.LittleEndian.Uint64(derivedKey[8:16])
//	iv := binary.LittleEndian.Uint64(derivedKey[16:24])
//
//	modifier := NewSSU2LengthModifier("ssu2-siphash", [2]uint64{k1, k2}, iv)
func NewSSU2LengthModifier(name string, sipKeys [2]uint64, initialIV uint64) handshake.HandshakeModifier {
	return &SipHashLengthModifier{
		SipHashLengthModifier: ntcp2.NewSipHashLengthModifier(name, sipKeys, initialIV),
	}
}

// ModifyOutbound obfuscates 2-byte frame lengths using SipHash.
// Only applies to data phase (PhaseFinal), handshake messages pass through unchanged.
//
// The length is XORed with a SipHash-derived mask that changes for each frame,
// preventing length fingerprinting attacks.
func (slm *SipHashLengthModifier) ModifyOutbound(phase handshake.HandshakePhase, data []byte) ([]byte, error) {
	return slm.SipHashLengthModifier.ModifyOutbound(phase, data)
}

// ModifyInbound removes SipHash obfuscation from frame lengths.
// Only applies to data phase (PhaseFinal), handshake messages pass through unchanged.
//
// Uses the same SipHash calculation to derive the mask and XOR it with the
// obfuscated length to recover the original value.
func (slm *SipHashLengthModifier) ModifyInbound(phase handshake.HandshakePhase, data []byte) ([]byte, error) {
	return slm.SipHashLengthModifier.ModifyInbound(phase, data)
}

// Name returns the modifier name for logging and debugging.
func (slm *SipHashLengthModifier) Name() string {
	return slm.SipHashLengthModifier.Name()
}
