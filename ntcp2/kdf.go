package ntcp2

import (
	"encoding/binary"

	"github.com/go-i2p/crypto/hmac"
	"github.com/go-i2p/go-noise/internal"
	"github.com/samber/oops"
)

// DeriveSipHashKeys derives per-direction SipHash-2-4 keys and initial IVs
// from the Noise handshake hash and ask_master secret per the I2P NTCP2 spec.
//
// The derivation follows the spec's 5-step HMAC-SHA256 chain:
//
//	Step 1: temp_key   = HMAC-SHA256(key=ask_master, data=h || "siphash")
//	Step 2: sip_master = HMAC-SHA256(key=temp_key,   data=byte(0x01))
//	Step 3: temp_key   = HMAC-SHA256(key=sip_master, data=zerolen)
//	Step 4: sipkeys_ab = HMAC-SHA256(key=temp_key,   data=byte(0x01))[0:24]
//	Step 5: sipkeys_ba = HMAC-SHA256(key=temp_key,   data=sipkeys_ab || byte(0x02))[0:24]
//
// Each 24-byte output is split into (sipk1, sipk2, sipiv) as little-endian uint64s.
//
// Parameters:
//   - askMaster: the ask_master secret from the Noise handshake (32 bytes)
//   - handshakeHash: the handshake hash (h) from the completed Noise session (32 bytes)
//
// Returns:
//   - sipKeysAB: [2]uint64{sipk1, sipk2} for direction A→B (initiator→responder)
//   - sipIVAB: initial IV for A→B SipHash length obfuscation chain
//   - sipKeysBA: [2]uint64{sipk1, sipk2} for direction B→A (responder→initiator)
//   - sipIVBA: initial IV for B→A SipHash length obfuscation chain
//   - err: non-nil if derivation fails
func DeriveSipHashKeys(askMaster, handshakeHash []byte) (
	sipKeysAB [2]uint64, sipIVAB uint64,
	sipKeysBA [2]uint64, sipIVBA uint64,
	err error,
) {
	if len(askMaster) != StaticKeySize {
		return sipKeysAB, 0, sipKeysBA, 0, oops.
			Code("INVALID_ASK_MASTER").
			In("ntcp2").
			With("length", len(askMaster)).
			Errorf("ask_master must be exactly %d bytes", StaticKeySize)
	}

	if len(handshakeHash) != StaticKeySize {
		return sipKeysAB, 0, sipKeysBA, 0, oops.
			Code("INVALID_HANDSHAKE_HASH").
			In("ntcp2").
			With("length", len(handshakeHash)).
			Errorf("handshake hash must be exactly %d bytes", StaticKeySize)
	}

	// Step 1: temp_key = HMAC-SHA256(key=ask_master, data=h || "siphash")
	hData := make([]byte, len(handshakeHash)+len("siphash"))
	copy(hData, handshakeHash)
	copy(hData[len(handshakeHash):], "siphash")
	tempKey := hmac.HMACSHA256(askMaster, hData)

	// Step 2: sip_master = HMAC-SHA256(key=temp_key, data=byte(0x01))
	sipMaster := hmac.HMACSHA256(tempKey[:], []byte{0x01})

	// Step 3: temp_key = HMAC-SHA256(key=sip_master, data=zerolen)
	tempKey = hmac.HMACSHA256(sipMaster[:], []byte{})

	// Step 4: sipkeys_ab = HMAC-SHA256(key=temp_key, data=byte(0x01))[0:24]
	fullAB := hmac.HMACSHA256(tempKey[:], []byte{0x01})
	sipKeysAB[0] = binary.LittleEndian.Uint64(fullAB[0:8])
	sipKeysAB[1] = binary.LittleEndian.Uint64(fullAB[8:16])
	sipIVAB = binary.LittleEndian.Uint64(fullAB[16:24])

	// Step 5: sipkeys_ba = HMAC-SHA256(key=temp_key, data=sipkeys_ab[0:24] || byte(0x02))[0:24]
	// Per spec, the input is the truncated 24-byte sipkeys_ab, not the full 32-byte HMAC output.
	const sipKeysLen = 24
	step5Data := make([]byte, sipKeysLen+1)
	copy(step5Data, fullAB[:sipKeysLen])
	step5Data[sipKeysLen] = 0x02
	fullBA := hmac.HMACSHA256(tempKey[:], step5Data)
	sipKeysBA[0] = binary.LittleEndian.Uint64(fullBA[0:8])
	sipKeysBA[1] = binary.LittleEndian.Uint64(fullBA[8:16])
	sipIVBA = binary.LittleEndian.Uint64(fullBA[16:24])

	// Per NTCP2 spec: zero all intermediate key material after use.
	// "overwrite ask_master in memory, no longer needed"
	// "overwrite sip_master in memory, no longer needed"
	// "overwrite the temp_key in memory, no longer needed"
	internal.SecureZero(hData)
	internal.SecureZero(tempKey[:])
	internal.SecureZero(sipMaster[:])
	internal.SecureZero(fullAB[:])
	internal.SecureZero(step5Data)
	internal.SecureZero(fullBA[:])

	return sipKeysAB, sipIVAB, sipKeysBA, sipIVBA, nil
}
