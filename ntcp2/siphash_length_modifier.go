package ntcp2

import (
	"github.com/go-i2p/go-noise/internal"
)

// SipHashLengthModifier implements NTCP2's SipHash-2-4 length obfuscation
// for data phase frame lengths. This type delegates to the shared implementation
// in the internal package.
type SipHashLengthModifier = internal.SipHashLengthModifier

// NewSipHashLengthModifier creates a new SipHash length obfuscation modifier
// with shared keys for both directions.
func NewSipHashLengthModifier(name string, sipKeys [2]uint64, initialIV uint64) *SipHashLengthModifier {
	return internal.NewSipHashLengthModifier(name, sipKeys, initialIV)
}

// NewSipHashLengthModifierDirectional creates a SipHash length obfuscation
// modifier with per-direction keys as required by the NTCP2 spec.
func NewSipHashLengthModifierDirectional(name string, outKeys, inKeys [2]uint64, outIV, inIV uint64) *SipHashLengthModifier {
	return internal.NewSipHashLengthModifierDirectional(name, outKeys, inKeys, outIV, inIV)
}
