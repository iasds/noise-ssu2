package internal

import (
	pkgsiphash "github.com/go-i2p/go-noise/handshake/siphash"
)

// LengthFieldSize is the 2-byte length field used in both NTCP2 and SSU2.
// The canonical definition lives in handshake/siphash; this alias keeps
// internal callers working without a source change.
const LengthFieldSize = pkgsiphash.LengthFieldSize

// SipHashLengthModifier is a type alias for the canonical implementation in
// handshake/siphash. Both ntcp2 and ssu2 re-export this type directly.
type SipHashLengthModifier = pkgsiphash.LengthModifier

// NewSipHashLengthModifier creates a new SipHash length modifier with shared
// keys for both directions.
func NewSipHashLengthModifier(name string, sipKeys [2]uint64, initialIV uint64) *SipHashLengthModifier {
	return pkgsiphash.NewLengthModifier(name, sipKeys, initialIV)
}

// NewSipHashLengthModifierDirectional creates a SipHash length modifier with
// per-direction keys as required by the NTCP2 and SSU2 specifications.
func NewSipHashLengthModifierDirectional(name string, outKeys, inKeys [2]uint64, outIV, inIV uint64) *SipHashLengthModifier {
	return pkgsiphash.NewLengthModifierDirectional(name, outKeys, inKeys, outIV, inIV)
}
