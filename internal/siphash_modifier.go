package internal

import (
	"encoding/binary"
	"sync"

	"github.com/go-i2p/go-noise/handshake"
	"github.com/go-i2p/logger"
)

// LengthFieldSize is the 2-byte length field used in both NTCP2 and SSU2.
const LengthFieldSize = 2

// SipHashLengthModifier implements SipHash-2-4 length obfuscation for
// data-phase packet/frame lengths. Both NTCP2 and SSU2 use this identical
// algorithm with per-direction keys derived from their respective KDFs.
type SipHashLengthModifier struct {
	mu           sync.Mutex
	name         string
	outboundKeys [2]uint64
	inboundKeys  [2]uint64
	outboundIV   uint64
	inboundIV    uint64
}

// NewSipHashLengthModifier creates a new SipHash length modifier with shared
// keys for both directions.
func NewSipHashLengthModifier(name string, sipKeys [2]uint64, initialIV uint64) *SipHashLengthModifier {
	log.WithFields(logger.Fields{"pkg": "internal", "func": "NewSipHashLengthModifier", "name": name}).Debug("Creating SipHash length modifier")
	return &SipHashLengthModifier{
		name:         name,
		outboundKeys: sipKeys,
		inboundKeys:  sipKeys,
		outboundIV:   initialIV,
		inboundIV:    initialIV,
	}
}

// NewSipHashLengthModifierDirectional creates a SipHash length modifier with
// per-direction keys as required by the NTCP2 and SSU2 specifications.
func NewSipHashLengthModifierDirectional(name string, outKeys, inKeys [2]uint64, outIV, inIV uint64) *SipHashLengthModifier {
	log.WithFields(logger.Fields{"pkg": "internal", "func": "NewSipHashLengthModifierDirectional", "name": name}).Debug("Creating directional SipHash length modifier")
	return &SipHashLengthModifier{
		name:         name,
		outboundKeys: outKeys,
		inboundKeys:  inKeys,
		outboundIV:   outIV,
		inboundIV:    inIV,
	}
}

// ModifyOutbound obfuscates a 2-byte length field using SipHash.
func (slm *SipHashLengthModifier) ModifyOutbound(phase handshake.HandshakePhase, data []byte) ([]byte, error) {
	log.WithFields(logger.Fields{"pkg": "internal", "func": "SipHashLengthModifier.ModifyOutbound", "name": slm.name, "phase": phase, "data_len": len(data)}).Debug("SipHash ModifyOutbound")
	return slm.applyMask(phase, data, slm.getNextOutboundMask)
}

// ModifyInbound deobfuscates a 2-byte length field using SipHash.
func (slm *SipHashLengthModifier) ModifyInbound(phase handshake.HandshakePhase, data []byte) ([]byte, error) {
	log.WithFields(logger.Fields{"pkg": "internal", "func": "SipHashLengthModifier.ModifyInbound", "name": slm.name, "phase": phase, "data_len": len(data)}).Debug("SipHash ModifyInbound")
	return slm.applyMask(phase, data, slm.getNextInboundMask)
}

func (slm *SipHashLengthModifier) applyMask(phase handshake.HandshakePhase, data []byte, maskFunc func() uint16) ([]byte, error) {
	if phase < handshake.PhaseData || len(data) != LengthFieldSize {
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
	return SipHashNextMask(keys, iv)
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
	log.WithField("name", slm.name).Debug("Zeroing SipHash key material")
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

// Close zeroes all SipHash key material and IVs.
func (slm *SipHashLengthModifier) Close() error {
	log.WithField("name", slm.name).Debug("Closing SipHash length modifier")
	slm.ZeroKeys()
	return nil
}
