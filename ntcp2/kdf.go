package ntcp2

import (
	"crypto/sha256"
	"encoding/binary"

	"github.com/samber/oops"
	"golang.org/x/crypto/hkdf"
)

// DeriveSipHashKeys derives the SipHash-2-4 keys (sipk1, sipk2) and initial IV
// from the Noise handshake hash and ask_master secret per the I2P NTCP2 spec.
//
// The derivation is:
//
//	temp_key = HMAC-SHA256(ask_master, handshakeHash)
//	output   = HKDF-Expand(temp_key, info="siphash", L=24)
//	sipk1    = output[0:8]   as little-endian uint64
//	sipk2    = output[8:16]  as little-endian uint64
//	sipiv    = output[16:24] as little-endian uint64
//
// Parameters:
//   - askMaster: the ask_master secret from the Noise handshake (32 bytes)
//   - handshakeHash: the handshake hash (h) from the completed Noise session (32 bytes)
//
// Returns:
//   - sipKeys: [2]uint64{sipk1, sipk2} for SipHash-2-4
//   - sipIV: initial IV for the SipHash length obfuscation chain
//   - err: non-nil if derivation fails
func DeriveSipHashKeys(askMaster, handshakeHash []byte) (sipKeys [2]uint64, sipIV uint64, err error) {
	if len(askMaster) != 32 {
		return sipKeys, 0, oops.
			Code("INVALID_ASK_MASTER").
			In("ntcp2").
			With("length", len(askMaster)).
			Errorf("ask_master must be exactly 32 bytes")
	}

	if len(handshakeHash) != 32 {
		return sipKeys, 0, oops.
			Code("INVALID_HANDSHAKE_HASH").
			In("ntcp2").
			With("length", len(handshakeHash)).
			Errorf("handshake hash must be exactly 32 bytes")
	}

	// HKDF-SHA256 with ask_master as the secret, handshake hash as salt,
	// and "siphash" as the info string. Extract 24 bytes: sipk1(8) + sipk2(8) + sipiv(8).
	reader := hkdf.New(sha256.New, askMaster, handshakeHash, []byte("siphash"))

	output := make([]byte, 24)
	if _, err := reader.Read(output); err != nil {
		return sipKeys, 0, oops.
			Code("HKDF_DERIVATION_FAILED").
			In("ntcp2").
			Wrapf(err, "failed to derive SipHash keys via HKDF")
	}

	sipKeys[0] = binary.LittleEndian.Uint64(output[0:8])
	sipKeys[1] = binary.LittleEndian.Uint64(output[8:16])
	sipIV = binary.LittleEndian.Uint64(output[16:24])

	return sipKeys, sipIV, nil
}
