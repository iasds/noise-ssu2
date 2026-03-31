package internal

import (
	"encoding/binary"

	"github.com/go-i2p/crypto/siphash"
)

// SipHashNextMask computes the next SipHash-2-4 mask value. It updates the IV
// in place and returns the low 16 bits of the hash as the mask.
//
// This implements the shared core of the SipHash length obfuscation chain used
// by both NTCP2 and SSU2:
//
//	IV[n] = SipHash-2-4(k1, k2, IV[n-1])
//	mask  = uint16(IV[n] & 0xFFFF)
func SipHashNextMask(keys [2]uint64, iv *uint64) uint16 {
	var input [8]byte
	binary.LittleEndian.PutUint64(input[:], *iv)
	hash := siphash.Hash(keys[0], keys[1], input[:])
	*iv = hash
	return uint16(hash & 0xFFFF)
}
