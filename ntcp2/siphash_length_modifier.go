package ntcp2

import (
	"encoding/binary"
	"sync"

	"github.com/dchest/siphash"
	"github.com/go-i2p/go-noise/handshake"
)

// SipHashLengthModifier implements NTCP2's SipHash-2-4 length obfuscation
// for data phase frame lengths. This prevents identification of frame
// lengths in the data stream.
//
// Per the NTCP2 spec: IV[n] = SipHash-2-4(sipk1, sipk2, IV[n-1]).
// The input to SipHash is the 8-byte little-endian encoding of the previous IV.
//
// NTCP2 uses per-direction keys: the initiator→responder direction (AB) uses
// different SipHash keys and IV than the responder→initiator direction (BA).
// Use NewSipHashLengthModifierDirectional with keys from DeriveSipHashKeys().
type SipHashLengthModifier struct {
	mu           sync.Mutex
	name         string
	outboundKeys [2]uint64 // SipHash k1, k2 keys for outbound direction
	inboundKeys  [2]uint64 // SipHash k1, k2 keys for inbound direction
	outboundIV   uint64    // Current IV value for outbound
	inboundIV    uint64    // Current IV value for inbound
}

// NewSipHashLengthModifier creates a new SipHash length obfuscation modifier
// with shared keys for both directions. This is suitable for testing or when
// per-direction key derivation is handled externally.
// sipKeys must contain exactly 2 uint64 values (k1, k2).
// initialIV is the 8-byte IV from the data phase KDF.
func NewSipHashLengthModifier(name string, sipKeys [2]uint64, initialIV uint64) *SipHashLengthModifier {
	return &SipHashLengthModifier{
		name:         name,
		outboundKeys: sipKeys,
		inboundKeys:  sipKeys,
		outboundIV:   initialIV,
		inboundIV:    initialIV,
	}
}

// NewSipHashLengthModifierDirectional creates a SipHash length obfuscation
// modifier with per-direction keys as required by the NTCP2 spec.
//
// For the initiator (Alice):
//
//	outKeys, outIV = sipKeysAB, sipIVAB   (Alice→Bob)
//	inKeys,  inIV  = sipKeysBA, sipIVBA   (Bob→Alice)
//
// For the responder (Bob):
//
//	outKeys, outIV = sipKeysBA, sipIVBA   (Bob→Alice)
//	inKeys,  inIV  = sipKeysAB, sipIVAB   (Alice→Bob)
func NewSipHashLengthModifierDirectional(name string, outKeys, inKeys [2]uint64, outIV, inIV uint64) *SipHashLengthModifier {
	return &SipHashLengthModifier{
		name:         name,
		outboundKeys: outKeys,
		inboundKeys:  inKeys,
		outboundIV:   outIV,
		inboundIV:    inIV,
	}
}

// ModifyOutbound obfuscates 2-byte frame lengths using SipHash.
func (slm *SipHashLengthModifier) ModifyOutbound(phase handshake.HandshakePhase, data []byte) ([]byte, error) {
	// Only apply to data phase (not handshake messages 1, 2, or 3 part 1)
	if phase != handshake.PhaseFinal || len(data) != FrameLengthFieldSize {
		return data, nil
	}

	slm.mu.Lock()
	mask := slm.getNextOutboundMask()
	slm.mu.Unlock()

	// XOR the 2-byte length with the mask
	length := binary.BigEndian.Uint16(data)
	obfuscatedLength := length ^ mask

	result := make([]byte, 2)
	binary.BigEndian.PutUint16(result, obfuscatedLength)

	return result, nil
}

// ModifyInbound removes SipHash obfuscation from frame lengths.
func (slm *SipHashLengthModifier) ModifyInbound(phase handshake.HandshakePhase, data []byte) ([]byte, error) {
	// Only apply to data phase (not handshake messages 1, 2, or 3 part 1)
	if phase != handshake.PhaseFinal || len(data) != FrameLengthFieldSize {
		return data, nil
	}

	slm.mu.Lock()
	mask := slm.getNextInboundMask()
	slm.mu.Unlock()

	// XOR the 2-byte length with the mask (XOR is symmetric)
	length := binary.BigEndian.Uint16(data)
	deobfuscatedLength := length ^ mask

	result := make([]byte, 2)
	binary.BigEndian.PutUint16(result, deobfuscatedLength)

	return result, nil
}

// getNextOutboundMask generates the next SipHash mask for outbound data.
// Per NTCP2 spec: IV[n] = SipHash-2-4(sipk1, sipk2, IV[n-1]).
func (slm *SipHashLengthModifier) getNextOutboundMask() uint16 {
	// Use the previous IV as SipHash input (8-byte little-endian)
	input := make([]byte, SipHashIVSize)
	binary.LittleEndian.PutUint64(input, slm.outboundIV)

	// Calculate SipHash with outbound k1, k2 keys
	hash := siphash.Hash(slm.outboundKeys[0], slm.outboundKeys[1], input)

	// Update IV with the hash result for next iteration
	slm.outboundIV = hash

	// Return first 2 bytes as mask
	return uint16(hash & 0xFFFF)
}

// getNextInboundMask generates the next SipHash mask for inbound data.
// Per NTCP2 spec: IV[n] = SipHash-2-4(sipk1, sipk2, IV[n-1]).
func (slm *SipHashLengthModifier) getNextInboundMask() uint16 {
	// Use the previous IV as SipHash input (8-byte little-endian)
	input := make([]byte, SipHashIVSize)
	binary.LittleEndian.PutUint64(input, slm.inboundIV)

	// Calculate SipHash with inbound k1, k2 keys
	hash := siphash.Hash(slm.inboundKeys[0], slm.inboundKeys[1], input)

	// Update IV with the hash result for next iteration
	slm.inboundIV = hash

	// Return first 2 bytes as mask
	return uint16(hash & 0xFFFF)
}

// NextInboundMask generates the next SipHash mask for inbound (read) direction.
// This method is safe for concurrent use.
func (slm *SipHashLengthModifier) NextInboundMask() uint16 {
	slm.mu.Lock()
	mask := slm.getNextInboundMask()
	slm.mu.Unlock()
	return mask
}

// NextOutboundMask generates the next SipHash mask for outbound (write) direction.
// This method is safe for concurrent use.
func (slm *SipHashLengthModifier) NextOutboundMask() uint16 {
	slm.mu.Lock()
	mask := slm.getNextOutboundMask()
	slm.mu.Unlock()
	return mask
}

// ZeroKeys zeroes all SipHash key material and IVs. This should be called
// during connection close to prevent sensitive data from lingering in memory.
// This method is safe for concurrent use.
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

// Name returns the modifier name for logging and debugging.
func (slm *SipHashLengthModifier) Name() string {
	return slm.name
}
