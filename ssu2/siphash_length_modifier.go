package ssu2

import (
	"encoding/binary"
	"sync"

	"github.com/go-i2p/crypto/siphash"
	"github.com/go-i2p/go-noise/handshake"
)

// SipHashIVSize is the byte size of a SipHash IV (uint64 = 8 bytes).
const SipHashIVSize = 8

// DataLengthFieldSize is the 2-byte data-phase length field that is
// obfuscated with SipHash-2-4 per SSU2 §Data Phase Length Obfuscation.
const DataLengthFieldSize = 2

// SipHashLengthModifier implements SSU2's SipHash-2-4 length obfuscation
// for data-phase packet lengths. Per the SSU2 specification, the 2-byte
// length field is XOR'd with the low 16 bits of a SipHash chain:
//
//	IV[n] = SipHash-2-4(k1, k2, IV[n-1])
//	mask  = uint16(IV[n] & 0xFFFF)
//
// Per-direction keys are used: the initiator→responder direction (AB) and
// responder→initiator direction (BA) derive separate SipHash key pairs and
// initial IVs from the handshake KDF.
type SipHashLengthModifier struct {
	mu           sync.Mutex
	name         string
	outboundKeys [2]uint64
	inboundKeys  [2]uint64
	outboundIV   uint64
	inboundIV    uint64
}

// NewSipHashLengthModifier creates a new SipHash length modifier with shared
// keys for both directions. Suitable for testing or when key derivation is
// handled externally.
func NewSipHashLengthModifier(name string, sipKeys [2]uint64, initialIV uint64) *SipHashLengthModifier {
	return &SipHashLengthModifier{
		name:         name,
		outboundKeys: sipKeys,
		inboundKeys:  sipKeys,
		outboundIV:   initialIV,
		inboundIV:    initialIV,
	}
}

// NewSipHashLengthModifierDirectional creates a SipHash length modifier with
// per-direction keys as required by the SSU2 specification.
func NewSipHashLengthModifierDirectional(name string, outKeys, inKeys [2]uint64, outIV, inIV uint64) *SipHashLengthModifier {
	return &SipHashLengthModifier{
		name:         name,
		outboundKeys: outKeys,
		inboundKeys:  inKeys,
		outboundIV:   outIV,
		inboundIV:    inIV,
	}
}

// ModifyOutbound obfuscates a 2-byte data-phase length field with SipHash.
func (slm *SipHashLengthModifier) ModifyOutbound(phase handshake.HandshakePhase, data []byte) ([]byte, error) {
	return slm.applyMask(phase, data, slm.getNextOutboundMask)
}

// ModifyInbound deobfuscates a 2-byte data-phase length field with SipHash.
func (slm *SipHashLengthModifier) ModifyInbound(phase handshake.HandshakePhase, data []byte) ([]byte, error) {
	return slm.applyMask(phase, data, slm.getNextInboundMask)
}

func (slm *SipHashLengthModifier) applyMask(phase handshake.HandshakePhase, data []byte, maskFunc func() uint16) ([]byte, error) {
	if phase < handshake.PhaseFinal || len(data) != DataLengthFieldSize {
		return data, nil
	}

	slm.mu.Lock()
	mask := maskFunc()
	slm.mu.Unlock()

	length := binary.BigEndian.Uint16(data)
	maskedLength := length ^ mask

	result := make([]byte, 2)
	binary.BigEndian.PutUint16(result, maskedLength)
	return result, nil
}

func (slm *SipHashLengthModifier) computeNextMask(keys [2]uint64, iv *uint64) uint16 {
	var input [SipHashIVSize]byte
	binary.LittleEndian.PutUint64(input[:], *iv)
	hash := siphash.Hash(keys[0], keys[1], input[:])
	*iv = hash
	return uint16(hash & 0xFFFF)
}

func (slm *SipHashLengthModifier) getNextOutboundMask() uint16 {
	return slm.computeNextMask(slm.outboundKeys, &slm.outboundIV)
}

func (slm *SipHashLengthModifier) getNextInboundMask() uint16 {
	return slm.computeNextMask(slm.inboundKeys, &slm.inboundIV)
}

// NextInboundMask returns the next SipHash mask for the inbound direction.
func (slm *SipHashLengthModifier) NextInboundMask() uint16 {
	slm.mu.Lock()
	mask := slm.getNextInboundMask()
	slm.mu.Unlock()
	return mask
}

// NextOutboundMask returns the next SipHash mask for the outbound direction.
func (slm *SipHashLengthModifier) NextOutboundMask() uint16 {
	slm.mu.Lock()
	mask := slm.getNextOutboundMask()
	slm.mu.Unlock()
	return mask
}

// ZeroKeys zeroes all SipHash key material and IVs.
func (slm *SipHashLengthModifier) ZeroKeys() {
	slm.mu.Lock()
	slm.outboundKeys[0] = 0
	slm.outboundKeys[1] = 0
	slm.inboundKeys[0] = 0
	slm.inboundKeys[1] = 0
	slm.outboundIV = 0
	slm.inboundIV = 0
	slm.mu.Unlock()
}

// Name returns the modifier name.
func (slm *SipHashLengthModifier) Name() string {
	return slm.name
}

// Close zeroes key material.
func (slm *SipHashLengthModifier) Close() error {
	slm.ZeroKeys()
	return nil
}
