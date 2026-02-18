package ntcp2

import (
	"crypto/rand"
	"encoding/binary"
	"math"
	"sync"

	"github.com/go-i2p/go-noise/handshake"
	"github.com/samber/oops"
)

// NTCP2PaddingModifier implements production-grade NTCP2-specific padding strategies.
// Supports I2P NTCP2 specification requirements including:
// - Cleartext padding for messages 1 and 2 (outside AEAD frames)
// - AEAD padding for message 3 and data phase (inside AEAD frames with type 254)
// - Cryptographically secure random padding distribution
// - Configurable padding ratios for traffic analysis resistance
//
// All exported methods are safe for concurrent use.
type NTCP2PaddingModifier struct {
	mu             sync.Mutex
	name           string
	minPadding     int
	maxPadding     int
	useAEADPadding bool    // true for message 3+ (AEAD), false for messages 1-2 (cleartext)
	paddingRatio   float64 // padding to data ratio (0.0 to 15.9375 as per I2P spec)
	testMode       bool    // if true, use deterministic padding for testing
}

// NewNTCP2PaddingModifier creates a new production-grade NTCP2 padding modifier.
//
// Parameters:
//   - name: identifier for logging and debugging
//   - minPadding: minimum padding bytes (0-65516)
//   - maxPadding: maximum padding bytes (>= minPadding, 0-65516)
//   - useAEADPadding: false for messages 1-2 (cleartext), true for message 3+ (AEAD)
//
// The modifier uses cryptographically secure random padding by default.
// Padding sizes follow I2P NTCP2 specification guidelines.
func NewNTCP2PaddingModifier(name string, minPadding, maxPadding int, useAEADPadding bool) (*NTCP2PaddingModifier, error) {
	return NewNTCP2PaddingModifierWithRatio(name, minPadding, maxPadding, useAEADPadding, 0.0)
}

// NewNTCP2PaddingModifierWithRatio creates a new NTCP2 padding modifier with a specific padding ratio.
//
// Parameters:
//   - name: identifier for logging and debugging
//   - minPadding: minimum padding bytes (0-65516)
//   - maxPadding: maximum padding bytes (>= minPadding, 0-65516)
//   - useAEADPadding: false for messages 1-2 (cleartext), true for message 3+ (AEAD)
//   - paddingRatio: ratio of padding to data (0.0 to 15.9375 as per I2P NTCP2 spec)
//
// A paddingRatio of 0.0 means no ratio-based padding (uses min/max only).
// A paddingRatio of 1.0 means 100% padding (double the message size).
func NewNTCP2PaddingModifierWithRatio(name string, minPadding, maxPadding int, useAEADPadding bool, paddingRatio float64) (*NTCP2PaddingModifier, error) {
	if minPadding < 0 {
		return nil, oops.
			Code("INVALID_PADDING").
			In("ntcp2").
			With("min_padding", minPadding).
			Errorf("minimum padding cannot be negative")
	}

	if maxPadding < minPadding {
		return nil, oops.
			Code("INVALID_PADDING").
			In("ntcp2").
			With("min_padding", minPadding).
			With("max_padding", maxPadding).
			Errorf("maximum padding cannot be less than minimum padding")
	}

	// I2P NTCP2 spec: maximum single block data size is 65516 bytes
	if maxPadding > MaxBlockDataSize {
		return nil, oops.
			Code("INVALID_PADDING").
			In("ntcp2").
			With("max_padding", maxPadding).
			Errorf("maximum padding cannot exceed %d bytes (I2P NTCP2 spec limit)", MaxBlockDataSize)
	}

	// I2P NTCP2 spec: padding ratio range is 0.0 to 15.9375
	if paddingRatio < 0.0 || paddingRatio > MaxPaddingRatio {
		return nil, oops.
			Code("INVALID_PADDING_RATIO").
			In("ntcp2").
			With("padding_ratio", paddingRatio).
			Errorf("padding ratio must be between 0.0 and %.4f (I2P NTCP2 spec)", MaxPaddingRatio)
	}

	return &NTCP2PaddingModifier{
		name:           name,
		minPadding:     minPadding,
		maxPadding:     maxPadding,
		useAEADPadding: useAEADPadding,
		paddingRatio:   paddingRatio,
		testMode:       false,
	}, nil
}

// NewNTCP2PaddingModifierForTesting creates a modifier with deterministic padding for testing.
// This should NEVER be used in production as it compromises security.
func NewNTCP2PaddingModifierForTesting(name string, minPadding, maxPadding int, useAEADPadding bool) (*NTCP2PaddingModifier, error) {
	modifier, err := NewNTCP2PaddingModifier(name, minPadding, maxPadding, useAEADPadding)
	if err != nil {
		return nil, err
	}
	modifier.testMode = true
	return modifier, nil
}

// ModifyOutbound adds NTCP2-specific padding based on message phase.
func (npm *NTCP2PaddingModifier) ModifyOutbound(phase handshake.HandshakePhase, data []byte) ([]byte, error) {
	npm.mu.Lock()
	defer npm.mu.Unlock()

	paddingSize := npm.calculatePaddingSize(len(data))
	if paddingSize == 0 {
		return data, nil
	}

	if npm.useAEADPadding && phase >= handshake.PhaseFinal {
		// AEAD padding: block format with type 254
		return npm.addAEADPadding(data, paddingSize)
	} else if !npm.useAEADPadding && phase < handshake.PhaseFinal {
		// Cleartext padding: simple append
		return npm.addCleartextPadding(data, paddingSize)
	}

	return data, nil
}

// ModifyInbound removes NTCP2-specific padding.
func (npm *NTCP2PaddingModifier) ModifyInbound(phase handshake.HandshakePhase, data []byte) ([]byte, error) {
	npm.mu.Lock()
	defer npm.mu.Unlock()

	if npm.useAEADPadding && phase >= handshake.PhaseFinal {
		// Remove AEAD padding (block format)
		return npm.removeAEADPadding(data)
	} else if !npm.useAEADPadding && phase < handshake.PhaseFinal {
		// Cleartext padding was included in KDF, cannot be removed here
		// This is handled by the protocol itself
		return data, nil
	}

	return data, nil
}

// calculatePaddingSize determines padding size using production-grade strategies.
// Uses cryptographically secure random padding distribution aligned with I2P NTCP2 spec.
func (npm *NTCP2PaddingModifier) calculatePaddingSize(dataLen int) int {
	if npm.shouldSkipPadding() {
		return 0
	}

	paddingSize := npm.calculateRatioPadding(dataLen)
	paddingSize = npm.enforceMinimumPadding(paddingSize)
	paddingSize = npm.applyRandomVariation(paddingSize, dataLen)
	return npm.enforceMaximumPadding(paddingSize)
}

// shouldSkipPadding checks if padding should be skipped based on configuration.
func (npm *NTCP2PaddingModifier) shouldSkipPadding() bool {
	return npm.minPadding == 0 && npm.maxPadding == 0 && npm.paddingRatio == 0.0
}

// calculateRatioPadding computes padding size based on the configured ratio.
func (npm *NTCP2PaddingModifier) calculateRatioPadding(dataLen int) int {
	if npm.paddingRatio > 0.0 {
		return int(float64(dataLen) * npm.paddingRatio)
	}
	return 0
}

// enforceMinimumPadding ensures the padding size meets the minimum requirement.
func (npm *NTCP2PaddingModifier) enforceMinimumPadding(paddingSize int) int {
	if paddingSize < npm.minPadding {
		return npm.minPadding
	}
	return paddingSize
}

// applyRandomVariation adds cryptographically secure random variation to padding size.
func (npm *NTCP2PaddingModifier) applyRandomVariation(paddingSize, dataLen int) int {
	paddingRange := npm.maxPadding - npm.minPadding
	if paddingRange <= 0 {
		return paddingSize
	}

	if npm.testMode {
		return npm.calculateDeterministicPadding(dataLen, paddingRange)
	}
	return npm.calculateSecureRandomPadding(paddingSize, paddingRange)
}

// calculateDeterministicPadding generates deterministic padding for testing only.
func (npm *NTCP2PaddingModifier) calculateDeterministicPadding(dataLen, paddingRange int) int {
	return npm.minPadding + (dataLen%paddingRange+paddingRange)%paddingRange
}

// calculateSecureRandomPadding generates cryptographically secure random padding.
func (npm *NTCP2PaddingModifier) calculateSecureRandomPadding(paddingSize, paddingRange int) int {
	randomBytes := make([]byte, 4)
	if _, err := rand.Read(randomBytes); err != nil {
		return paddingSize
	}

	randomValue := binary.BigEndian.Uint32(randomBytes)
	// Use unsigned modulus before converting to int to avoid negative values on 32-bit platforms.
	randomPadding := int(randomValue % uint32(paddingRange+1))

	if npm.paddingRatio > 0.0 {
		if randomPadding > paddingSize-npm.minPadding {
			return npm.minPadding + randomPadding
		}
		return paddingSize
	}
	return npm.minPadding + randomPadding
}

// enforceMaximumPadding ensures the padding size does not exceed the maximum limit.
func (npm *NTCP2PaddingModifier) enforceMaximumPadding(paddingSize int) int {
	if paddingSize > npm.maxPadding {
		return npm.maxPadding
	}
	return paddingSize
}

// addCleartextPadding adds production-grade cleartext padding for messages 1 and 2.
// Uses cryptographically secure random padding data as required by I2P NTCP2 spec.
func (npm *NTCP2PaddingModifier) addCleartextPadding(data []byte, paddingSize int) ([]byte, error) {
	result := make([]byte, len(data)+paddingSize)
	copy(result, data)

	// Generate cryptographically secure random padding
	paddingData := result[len(data):]
	if npm.testMode {
		// Deterministic padding for testing (INSECURE - for testing only)
		for i := 0; i < paddingSize; i++ {
			paddingData[i] = byte((i + len(data)) % 256)
		}
	} else {
		// Production: use cryptographically secure random padding
		if _, err := rand.Read(paddingData); err != nil {
			return nil, oops.
				Code("PADDING_GENERATION_FAILED").
				In("ntcp2").
				With("padding_size", paddingSize).
				Wrapf(err, "failed to generate secure random padding")
		}
	}

	return result, nil
}

// addAEADPadding adds production-grade AEAD padding in I2P block format (type 254).
// Follows I2P NTCP2 spec: [type:1][size:2][padding_data] inside AEAD frames.
func (npm *NTCP2PaddingModifier) addAEADPadding(data []byte, paddingSize int) ([]byte, error) {
	// Block format: [type:1][size:2][padding_data]
	blockSize := 3 + paddingSize
	result := make([]byte, len(data)+blockSize)
	copy(result, data)

	offset := len(data)
	result[offset] = PaddingBlockType                                  // Padding block type (I2P NTCP2 spec)
	binary.BigEndian.PutUint16(result[offset+1:], uint16(paddingSize)) // Padding size (big-endian)

	// Generate cryptographically secure random padding data
	paddingData := result[offset+3:]
	if npm.testMode {
		// Deterministic padding for testing (INSECURE - for testing only)
		for i := 0; i < paddingSize; i++ {
			paddingData[i] = byte((i + len(data)) % 256)
		}
	} else {
		// Production: use cryptographically secure random padding
		if _, err := rand.Read(paddingData); err != nil {
			return nil, oops.
				Code("AEAD_PADDING_GENERATION_FAILED").
				In("ntcp2").
				With("padding_size", paddingSize).
				Wrapf(err, "failed to generate secure random AEAD padding")
		}
	}

	return result, nil
}

// removeAEADPadding removes AEAD padding blocks (type 254) using forward block parsing.
// Parses data as I2P block structure [type:1][size:2][data...] from the beginning,
// tracking the end of the last non-padding block. Falls back to trailing padding
// block detection when the data is not fully in I2P block format (e.g., raw payload
// followed by an appended padding block).
func (npm *NTCP2PaddingModifier) removeAEADPadding(data []byte) ([]byte, error) {
	if len(data) < BlockHeaderSize {
		return data, nil // No room for block header
	}

	// Try forward block parsing first (proper I2P block format)
	result := npm.parseBlockStructure(data)
	if result.foundValidBlocks && result.lastDataEnd > 0 && result.lastDataEnd <= len(data) {
		return data[:result.lastDataEnd], nil
	}

	// Fallback: check for a trailing padding block appended to raw data.
	// Scan for [254][size:2][padding:size] at the end of the data where the
	// declared size exactly matches the remaining bytes after the header.
	return npm.removeTrailingPaddingBlock(data)
}

// removeTrailingPaddingBlock looks for a valid padding block at the end of the data
// by iterating through possible padding sizes and verifying the block header matches.
// This is safe because it requires an exact match: data[start] == PaddingBlockType
// and the declared big-endian size equals the number of trailing bytes after the header.
func (npm *NTCP2PaddingModifier) removeTrailingPaddingBlock(data []byte) ([]byte, error) {
	maxPadding := len(data) - BlockHeaderSize
	if maxPadding < 0 {
		return data, nil
	}
	if maxPadding > MaxBlockDataSize {
		maxPadding = MaxBlockDataSize
	}

	for paddingSize := 0; paddingSize <= maxPadding; paddingSize++ {
		start := len(data) - BlockHeaderSize - paddingSize
		if start < 0 {
			break
		}
		if data[start] == PaddingBlockType {
			declaredSize := int(binary.BigEndian.Uint16(data[start+1 : start+3]))
			if declaredSize == paddingSize {
				return data[:start], nil
			}
		}
	}

	return data, nil
}

// removePaddingFromBlocks parses data as proper I2P block structure to locate padding blocks.
// Returns original data if no valid block structure or padding found.
func (npm *NTCP2PaddingModifier) removePaddingFromBlocks(data []byte) ([]byte, error) {
	result := npm.parseBlockStructure(data)
	if result.foundValidBlocks && result.lastDataEnd > 0 && result.lastDataEnd <= len(data) {
		return data[:result.lastDataEnd], nil
	}
	return data, nil
}

// parseBlockStructure analyzes data as I2P block format and tracks parsing state.
func (npm *NTCP2PaddingModifier) parseBlockStructure(data []byte) blockParseResult {
	result := blockParseResult{}
	offset := 0

	for offset < len(data) {
		if !npm.validateBlockBounds(data, offset) {
			break
		}

		blockType, blockSize := npm.extractBlockHeader(data, offset)
		if !npm.validateBlockSize(data, offset, blockSize) {
			break
		}

		result.foundValidBlocks = true
		if blockType == PaddingBlockType {
			return result // Found padding block
		}

		result.lastDataEnd = offset + 3 + blockSize
		offset = result.lastDataEnd
	}

	return result
}

// blockParseResult holds the state from parsing I2P block structure.
type blockParseResult struct {
	foundValidBlocks bool
	lastDataEnd      int
}

// validateBlockBounds checks if there's enough data for a block header at the given offset.
func (npm *NTCP2PaddingModifier) validateBlockBounds(data []byte, offset int) bool {
	return offset+3 <= len(data)
}

// extractBlockHeader reads the block type and size from the data at the given offset.
func (npm *NTCP2PaddingModifier) extractBlockHeader(data []byte, offset int) (byte, int) {
	blockType := data[offset]
	blockSize := int(binary.BigEndian.Uint16(data[offset+1 : offset+3]))
	return blockType, blockSize
}

// validateBlockSize ensures the block size doesn't exceed the available data.
func (npm *NTCP2PaddingModifier) validateBlockSize(data []byte, offset, blockSize int) bool {
	return offset+3+blockSize <= len(data)
}

// SetPaddingRatio updates the padding ratio for dynamic adjustment during connection.
// This supports I2P NTCP2 options negotiation where padding parameters can be updated.
func (npm *NTCP2PaddingModifier) SetPaddingRatio(ratio float64) error {
	if ratio < 0.0 || ratio > MaxPaddingRatio {
		return oops.
			Code("INVALID_PADDING_RATIO").
			In("ntcp2").
			With("padding_ratio", ratio).
			Errorf("padding ratio must be between 0.0 and %.4f (I2P NTCP2 spec)", MaxPaddingRatio)
	}
	npm.mu.Lock()
	npm.paddingRatio = ratio
	npm.mu.Unlock()
	return nil
}

// GetPaddingRatio returns the current padding ratio.
func (npm *NTCP2PaddingModifier) GetPaddingRatio() float64 {
	npm.mu.Lock()
	defer npm.mu.Unlock()
	return npm.paddingRatio
}

// GetPaddingLimits returns the current min/max padding limits.
func (npm *NTCP2PaddingModifier) GetPaddingLimits() (int, int) {
	npm.mu.Lock()
	defer npm.mu.Unlock()
	return npm.minPadding, npm.maxPadding
}

// SetPaddingLimits updates the padding limits for dynamic adjustment.
// Supports I2P NTCP2 options negotiation during data phase.
func (npm *NTCP2PaddingModifier) SetPaddingLimits(minPadding, maxPadding int) error {
	if minPadding < 0 {
		return oops.
			Code("INVALID_PADDING").
			In("ntcp2").
			With("min_padding", minPadding).
			Errorf("minimum padding cannot be negative")
	}

	if maxPadding < minPadding {
		return oops.
			Code("INVALID_PADDING").
			In("ntcp2").
			With("min_padding", minPadding).
			With("max_padding", maxPadding).
			Errorf("maximum padding cannot be less than minimum padding")
	}

	if maxPadding > MaxBlockDataSize {
		return oops.
			Code("INVALID_PADDING").
			In("ntcp2").
			With("max_padding", maxPadding).
			Errorf("maximum padding cannot exceed %d bytes (I2P NTCP2 spec limit)", MaxBlockDataSize)
	}

	npm.mu.Lock()
	npm.minPadding = minPadding
	npm.maxPadding = maxPadding
	npm.mu.Unlock()
	return nil
}

// IsAEADMode returns true if this modifier is configured for AEAD padding (message 3+).
func (npm *NTCP2PaddingModifier) IsAEADMode() bool {
	return npm.useAEADPadding
}

// EstimatePaddingSize estimates the padding size for a given data length.
// Useful for pre-allocating buffers and bandwidth calculations.
func (npm *NTCP2PaddingModifier) EstimatePaddingSize(dataLen int) int {
	if npm.paddingRatio > 0.0 {
		ratioPadding := int(math.Ceil(float64(dataLen) * npm.paddingRatio))
		if ratioPadding < npm.minPadding {
			return npm.minPadding
		}
		if ratioPadding > npm.maxPadding {
			return npm.maxPadding
		}
		return ratioPadding
	}

	// Return average of min/max for estimation
	return (npm.minPadding + npm.maxPadding) / 2
}

// ValidateAEADFrame validates that a frame contains properly formatted AEAD blocks.
// Returns true if the frame structure is valid according to I2P NTCP2 spec.
func (npm *NTCP2PaddingModifier) ValidateAEADFrame(data []byte) bool {
	if len(data) == 0 {
		return true // Empty frame is valid
	}

	offset := 0
	hasPadding := false

	for offset < len(data) {
		if !npm.validateFrameBlockHeader(data, offset) {
			return false
		}

		blockType, blockSize := npm.parseFrameBlockHeader(data, offset)

		if !npm.validateBlockSize(data, offset, blockSize) {
			return false
		}

		if !npm.validateFramePaddingRules(blockType, blockSize, offset, len(data), &hasPadding) {
			return false
		}

		offset += 3 + blockSize
	}

	return true
}

// validateFrameBlockHeader checks if there's enough data for a complete block header
func (npm *NTCP2PaddingModifier) validateFrameBlockHeader(data []byte, offset int) bool {
	return offset+3 <= len(data)
}

// parseFrameBlockHeader extracts block type and size from the header
func (npm *NTCP2PaddingModifier) parseFrameBlockHeader(data []byte, offset int) (byte, int) {
	blockType := data[offset]
	blockSize := int(binary.BigEndian.Uint16(data[offset+1 : offset+3]))
	return blockType, blockSize
}

// validateFramePaddingRules enforces I2P NTCP2 padding block ordering rules
func (npm *NTCP2PaddingModifier) validateFramePaddingRules(blockType byte, blockSize, offset, dataLen int, hasPadding *bool) bool {
	if blockType == PaddingBlockType { // Padding block
		if *hasPadding {
			return false // Multiple padding blocks not allowed
		}
		*hasPadding = true
		// Padding must be last block
		if offset+3+blockSize != dataLen {
			return false
		}
	}
	return true
}

// Name returns the modifier name for logging and debugging.
func (npm *NTCP2PaddingModifier) Name() string {
	return npm.name
}
