package ntcp2

import (
	pkgsiphash "github.com/go-i2p/go-noise/handshake/siphash"
)

// SipHashLengthModifier implements NTCP2's SipHash-2-4 length obfuscation
// for data phase frame lengths. The canonical implementation lives in
// handshake/siphash; this alias makes the type directly accessible from
// the ntcp2 package without an extra import.
type SipHashLengthModifier = pkgsiphash.LengthModifier

// NewSipHashLengthModifier creates a new SipHash length obfuscation modifier
// with shared keys for both directions.
func NewSipHashLengthModifier(name string, sipKeys [2]uint64, initialIV uint64) *SipHashLengthModifier {
	return pkgsiphash.NewLengthModifier(name, sipKeys, initialIV)
}

// NewSipHashLengthModifierDirectional creates a SipHash length obfuscation
// modifier with per-direction keys as required by the NTCP2 spec.
func NewSipHashLengthModifierDirectional(name string, outKeys, inKeys [2]uint64, outIV, inIV uint64) *SipHashLengthModifier {
	return pkgsiphash.NewLengthModifierDirectional(name, outKeys, inKeys, outIV, inIV)
}
