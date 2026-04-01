package ssu2

import (
	"github.com/go-i2p/go-noise/internal"
)

// SipHashIVSize is the byte size of a SipHash IV (uint64 = 8 bytes).
const SipHashIVSize = 8

// DataLengthFieldSize is the 2-byte data-phase length field that is
// obfuscated with SipHash-2-4 per SSU2 §Data Phase Length Obfuscation.
const DataLengthFieldSize = 2

// SipHashLengthModifier implements SSU2's SipHash-2-4 length obfuscation
// for data-phase packet lengths. This type delegates to the shared implementation
// in the internal package.
type SipHashLengthModifier = internal.SipHashLengthModifier

// NewSipHashLengthModifier creates a new SipHash length modifier with shared
// keys for both directions.
func NewSipHashLengthModifier(name string, sipKeys [2]uint64, initialIV uint64) *SipHashLengthModifier {
	return internal.NewSipHashLengthModifier(name, sipKeys, initialIV)
}

// NewSipHashLengthModifierDirectional creates a SipHash length modifier with
// per-direction keys as required by the SSU2 specification.
func NewSipHashLengthModifierDirectional(name string, outKeys, inKeys [2]uint64, outIV, inIV uint64) *SipHashLengthModifier {
	return internal.NewSipHashLengthModifierDirectional(name, outKeys, inKeys, outIV, inIV)
}
