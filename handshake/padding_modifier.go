package handshake

import (
	"crypto/rand"
	"encoding/binary"
	"math"
	"math/big"

	"github.com/samber/oops"
)

// PaddingModifier implements padding-based obfuscation by adding random
// padding to handshake messages and removing it during processing.
// Moved from: handshake/modifiers.go
type PaddingModifier struct {
	name       string
	minPadding int
	maxPadding int
}

// NewPaddingModifier creates a new padding modifier with the specified
// minimum and maximum padding sizes.
func NewPaddingModifier(name string, minPadding, maxPadding int) (*PaddingModifier, error) {
	if minPadding < 0 {
		return nil, oops.
			Code("INVALID_PADDING").
			In("handshake").
			With("min_padding", minPadding).
			Errorf("minimum padding cannot be negative")
	}

	if maxPadding < minPadding {
		return nil, oops.
			Code("INVALID_PADDING").
			In("handshake").
			With("min_padding", minPadding).
			With("max_padding", maxPadding).
			Errorf("maximum padding cannot be less than minimum padding")
	}

	return &PaddingModifier{
		name:       name,
		minPadding: minPadding,
		maxPadding: maxPadding,
	}, nil
}

// ModifyOutbound adds padding to outbound handshake data.
// Padding format: [original_length:4][original_data][padding_data]
// Returns an error if data exceeds the 4-byte length prefix capacity (math.MaxUint32).
func (pm *PaddingModifier) ModifyOutbound(phase HandshakePhase, data []byte) ([]byte, error) {
	if pm.minPadding == 0 && pm.maxPadding == 0 {
		return data, nil // No padding configured
	}

	if len(data) > math.MaxUint32 {
		return nil, oops.
			Code("DATA_TOO_LARGE").
			In("handshake").
			With("data_length", len(data)).
			With("max_length", math.MaxUint32).
			With("modifier_name", pm.name).
			Errorf("data exceeds 4-byte length prefix capacity")
	}

	// Calculate padding size using crypto/rand for traffic analysis resistance
	paddingSize := pm.minPadding
	if pm.maxPadding > pm.minPadding {
		paddingRange := pm.maxPadding - pm.minPadding + 1
		n, err := rand.Int(rand.Reader, big.NewInt(int64(paddingRange)))
		if err != nil {
			return nil, oops.
				Code("PADDING_RANDOM_ERROR").
				In("handshake").
				With("modifier_name", pm.name).
				Wrapf(err, "failed to generate random padding size")
		}
		paddingSize = pm.minPadding + int(n.Int64())
	}

	// Create result with length prefix, original data, and padding
	result := make([]byte, 4+len(data)+paddingSize)

	// Write original length as 4-byte big-endian
	binary.BigEndian.PutUint32(result[:4], uint32(len(data)))

	// Copy original data
	copy(result[4:4+len(data)], data)

	// Fill padding with cryptographically random bytes
	if paddingSize > 0 {
		if _, err := rand.Read(result[4+len(data):]); err != nil {
			return nil, oops.
				Code("PADDING_RANDOM_ERROR").
				In("handshake").
				With("modifier_name", pm.name).
				Wrapf(err, "failed to generate random padding content")
		}
	}

	return result, nil
}

// ModifyInbound removes padding from inbound handshake data.
func (pm *PaddingModifier) ModifyInbound(phase HandshakePhase, data []byte) ([]byte, error) {
	if pm.minPadding == 0 && pm.maxPadding == 0 {
		return data, nil // No padding configured, return data unchanged
	}

	if len(data) < 4 {
		return nil, oops.
			Code("INVALID_PADDED_DATA").
			In("handshake").
			With("data_length", len(data)).
			With("modifier_name", pm.name).
			Errorf("padded data too short, missing length prefix")
	}

	// Read original length from 4-byte big-endian prefix.
	// Use binary.BigEndian.Uint32 to match the outbound encoder and avoid
	// manual bit-shifts that overflow on 32-bit platforms.
	originalLen := int(binary.BigEndian.Uint32(data[:4]))

	if 4+originalLen > len(data) {
		return nil, oops.
			Code("INVALID_PADDED_DATA").
			In("handshake").
			With("original_length", originalLen).
			With("data_length", len(data)).
			With("modifier_name", pm.name).
			Errorf("invalid original length in padded data")
	}

	// Extract original data
	result := make([]byte, originalLen)
	copy(result, data[4:4+originalLen])

	return result, nil
}

// Name returns the name of the padding modifier for logging and debugging.
func (pm *PaddingModifier) Name() string {
	return pm.name
}

// Close is a no-op for PaddingModifier because it holds no sensitive key material.
// It satisfies the HandshakeModifier lifecycle contract.
func (pm *PaddingModifier) Close() error {
	return nil
}
