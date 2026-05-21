package internal

import (
	pkgsiphash "github.com/go-i2p/go-noise/handshake/siphash"
)

// SipHashNextMask computes the next SipHash-2-4 mask value.
// Delegates to handshake/siphash.NextMask; kept here for backward compatibility.
func SipHashNextMask(keys [2]uint64, iv *uint64) uint16 {
	return pkgsiphash.NextMask(keys, iv)
}
