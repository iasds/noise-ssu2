package ssu2

import (
	"crypto/rand"
	"encoding/binary"
	"math"
	"sync"

	"github.com/go-i2p/go-noise/handshake"
	"github.com/samber/oops"
)

// SSU2PaddingModifier implements MTU-aware padding for SSU2 transport.
// Key differences from NTCP2:
// - MTU awareness: padding must respect UDP packet size limits (1280-1500 bytes)
// - Different overhead calculations for UDP vs TCP
// - Dynamic MTU adjustment during connection
// - Uses same I2P block format (type 254) and padding ratios (0.0-15.9375)
type SSU2PaddingModifier struct {
	name         string
	minPadding   int
	maxPadding   int
	aeadMode     bool
	paddingRatio float64
	mtu          int
	testMode     bool
	mutex        sync.RWMutex // Protects dynamic parameter updates
}

const (
	// SSU2 MTU constants
	minMTU           = 1280 // IPv6 minimum MTU
	maxMTU           = 1500 // Typical Ethernet MTU
	defaultMTU       = 1280
	ssu2HeaderSize   = 80 // Approximate SSU2 header overhead
	aeadTagSize      = 16 // ChaCha20-Poly1305 AEAD tag
	maxPaddingBlocks = 65516
)

// NewSSU2PaddingModifier creates a new SSU2 padding modifier with default MTU.
//
// Parameters:
//   - name: identifier for logging and debugging
//   - minPad: minimum padding bytes (0-65516)
//   - maxPad: maximum padding bytes (>= minPad, 0-65516)
//   - aeadMode: true for AEAD-encrypted padding (message 3+)
func NewSSU2PaddingModifier(name string, minPad, maxPad int, aeadMode bool) (*SSU2PaddingModifier, error) {
	return NewSSU2PaddingModifierWithMTU(name, minPad, maxPad, defaultMTU, aeadMode, 0.0)
}

// NewSSU2PaddingModifierWithRatio creates a modifier with a specific padding ratio.
//
// Parameters:
//   - ratio: ratio of padding to data (0.0 to 15.9375 per I2P spec)
func NewSSU2PaddingModifierWithRatio(name string, minPad, maxPad int, aeadMode bool, ratio float64) (*SSU2PaddingModifier, error) {
	return NewSSU2PaddingModifierWithMTU(name, minPad, maxPad, defaultMTU, aeadMode, ratio)
}

// NewSSU2PaddingModifierWithMTU creates a modifier with custom MTU.
//
// Parameters:
//   - mtu: Maximum Transmission Unit (1280-1500 bytes)
//
// This is the primary constructor - all others delegate to it.
func NewSSU2PaddingModifierWithMTU(name string, minPad, maxPad, mtu int, aeadMode bool, ratio float64) (*SSU2PaddingModifier, error) {
	if err := validatePaddingParams(minPad, maxPad, ratio); err != nil {
		return nil, err
	}

	if err := validateMTU(mtu); err != nil {
		return nil, err
	}

	return &SSU2PaddingModifier{
		name:         name,
		minPadding:   minPad,
		maxPadding:   maxPad,
		aeadMode:     aeadMode,
		paddingRatio: ratio,
		mtu:          mtu,
		testMode:     false,
	}, nil
}

// NewSSU2PaddingModifierForTesting creates a modifier with deterministic padding.
// WARNING: This should NEVER be used in production as it compromises security.
func NewSSU2PaddingModifierForTesting(name string, minPad, maxPad int, aeadMode bool) (*SSU2PaddingModifier, error) {
	modifier, err := NewSSU2PaddingModifier(name, minPad, maxPad, aeadMode)
	if err != nil {
		return nil, err
	}
	modifier.testMode = true
	return modifier, nil
}

// ModifyOutbound adds MTU-aware padding based on message phase.
func (spm *SSU2PaddingModifier) ModifyOutbound(phase handshake.HandshakePhase, data []byte) ([]byte, error) {
	spm.mutex.RLock()
	defer spm.mutex.RUnlock()

	paddingSize := spm.calculateMTUAwarePadding(len(data))
	if paddingSize == 0 {
		return data, nil
	}

	if spm.aeadMode && phase >= handshake.PhaseFinal {
		return spm.addAEADPadding(data, paddingSize)
	} else if !spm.aeadMode && phase < handshake.PhaseFinal {
		return spm.addCleartextPadding(data, paddingSize)
	}

	return data, nil
}

// ModifyInbound removes SSU2-specific padding.
func (spm *SSU2PaddingModifier) ModifyInbound(phase handshake.HandshakePhase, data []byte) ([]byte, error) {
	spm.mutex.RLock()
	defer spm.mutex.RUnlock()

	if spm.aeadMode && phase >= handshake.PhaseFinal {
		return spm.removeAEADPadding(data)
	}
	// Cleartext padding included in KDF, cannot be removed
	return data, nil
}

// Name returns the modifier name for logging and debugging.
func (spm *SSU2PaddingModifier) Name() string {
	return spm.name
}

// UpdatePaddingParams dynamically updates padding parameters.
// Thread-safe for concurrent use during connection lifetime.
func (spm *SSU2PaddingModifier) UpdatePaddingParams(minPad, maxPad int, ratio float64) error {
	if err := validatePaddingParams(minPad, maxPad, ratio); err != nil {
		return err
	}

	spm.mutex.Lock()
	defer spm.mutex.Unlock()

	spm.minPadding = minPad
	spm.maxPadding = maxPad
	spm.paddingRatio = ratio
	return nil
}

// SetMTU updates the MTU value for dynamic MTU discovery.
// Thread-safe for concurrent use during connection lifetime.
func (spm *SSU2PaddingModifier) SetMTU(mtu int) error {
	if err := validateMTU(mtu); err != nil {
		return err
	}

	spm.mutex.Lock()
	defer spm.mutex.Unlock()

	spm.mtu = mtu
	return nil
}

// calculateMTUAwarePadding computes padding size respecting MTU limits.
// Key difference from NTCP2: enforces UDP packet size constraints.
func (spm *SSU2PaddingModifier) calculateMTUAwarePadding(dataLen int) int {
	if spm.shouldSkipPadding() {
		return 0
	}

	// Calculate available space in MTU
	overhead := ssu2HeaderSize + aeadTagSize
	if spm.aeadMode {
		overhead += 3 // Block header for AEAD padding
	}

	availableSpace := spm.mtu - dataLen - overhead
	if availableSpace <= 0 {
		return 0 // No room for padding
	}

	// Calculate desired padding based on ratio
	paddingSize := spm.calculateRatioPadding(dataLen)
	paddingSize = spm.enforceMinimumPadding(paddingSize)
	paddingSize = spm.applyRandomVariation(paddingSize, dataLen)
	paddingSize = spm.enforceMaximumPadding(paddingSize)

	// Enforce MTU constraint (key SSU2 difference)
	if paddingSize > availableSpace {
		paddingSize = availableSpace
	}

	return paddingSize
}

// shouldSkipPadding checks if padding should be skipped.
func (spm *SSU2PaddingModifier) shouldSkipPadding() bool {
	return spm.minPadding == 0 && spm.maxPadding == 0 && spm.paddingRatio == 0.0
}

// calculateRatioPadding computes padding based on configured ratio.
func (spm *SSU2PaddingModifier) calculateRatioPadding(dataLen int) int {
	if spm.paddingRatio > 0.0 {
		return int(float64(dataLen) * spm.paddingRatio)
	}
	return 0
}

// enforceMinimumPadding ensures minimum padding requirement.
func (spm *SSU2PaddingModifier) enforceMinimumPadding(paddingSize int) int {
	if paddingSize < spm.minPadding {
		return spm.minPadding
	}
	return paddingSize
}

// applyRandomVariation adds cryptographically secure random variation.
func (spm *SSU2PaddingModifier) applyRandomVariation(paddingSize, dataLen int) int {
	paddingRange := spm.maxPadding - spm.minPadding
	if paddingRange <= 0 {
		return paddingSize
	}

	if spm.testMode {
		return spm.calculateDeterministicPadding(dataLen, paddingRange)
	}
	return spm.calculateSecureRandomPadding(paddingSize, paddingRange)
}

// calculateDeterministicPadding generates deterministic padding for testing.
func (spm *SSU2PaddingModifier) calculateDeterministicPadding(dataLen, paddingRange int) int {
	return spm.minPadding + (dataLen%paddingRange+paddingRange)%paddingRange
}

// calculateSecureRandomPadding generates cryptographically secure random padding.
func (spm *SSU2PaddingModifier) calculateSecureRandomPadding(paddingSize, paddingRange int) int {
	randomBytes := make([]byte, 4)
	if _, err := rand.Read(randomBytes); err != nil {
		return paddingSize
	}

	randomValue := binary.BigEndian.Uint32(randomBytes)
	randomPadding := int(randomValue) % (paddingRange + 1)

	if spm.paddingRatio > 0.0 {
		if randomPadding > paddingSize-spm.minPadding {
			return spm.minPadding + randomPadding
		}
		return paddingSize
	}
	return spm.minPadding + randomPadding
}

// enforceMaximumPadding ensures padding doesn't exceed maximum.
func (spm *SSU2PaddingModifier) enforceMaximumPadding(paddingSize int) int {
	if paddingSize > spm.maxPadding {
		return spm.maxPadding
	}
	return paddingSize
}

// addCleartextPadding adds cleartext padding for early handshake messages.
func (spm *SSU2PaddingModifier) addCleartextPadding(data []byte, paddingSize int) ([]byte, error) {
	result := make([]byte, len(data)+paddingSize)
	copy(result, data)

	paddingData := result[len(data):]
	if spm.testMode {
		for i := 0; i < paddingSize; i++ {
			paddingData[i] = byte((i + len(data)) % 256)
		}
	} else {
		if _, err := rand.Read(paddingData); err != nil {
			return nil, oops.
				Code("PADDING_GENERATION_FAILED").
				In("ssu2").
				With("padding_size", paddingSize).
				Wrapf(err, "failed to generate secure random padding")
		}
	}

	return result, nil
}

// addAEADPadding adds AEAD padding in I2P block format (type 254).
// Block format: [type:1][size:2][padding_data]
func (spm *SSU2PaddingModifier) addAEADPadding(data []byte, paddingSize int) ([]byte, error) {
	blockSize := 3 + paddingSize
	result := make([]byte, len(data)+blockSize)
	copy(result, data)

	offset := len(data)
	result[offset] = 254                                               // Padding block type
	binary.BigEndian.PutUint16(result[offset+1:], uint16(paddingSize)) // Padding size

	paddingData := result[offset+3:]
	if spm.testMode {
		for i := 0; i < paddingSize; i++ {
			paddingData[i] = byte((i + len(data)) % 256)
		}
	} else {
		if _, err := rand.Read(paddingData); err != nil {
			return nil, oops.
				Code("AEAD_PADDING_GENERATION_FAILED").
				In("ssu2").
				With("padding_size", paddingSize).
				Wrapf(err, "failed to generate secure random AEAD padding")
		}
	}

	return result, nil
}

// removeAEADPadding removes AEAD padding blocks (type 254).
func (spm *SSU2PaddingModifier) removeAEADPadding(data []byte) ([]byte, error) {
	if len(data) < 3 {
		return data, nil
	}

	// Try reverse scan for trailing padding block
	if result := spm.removePaddingFromEnd(data); result != nil {
		return result, nil
	}

	// Fallback to structured block parsing
	return spm.removePaddingFromBlocks(data)
}

// removePaddingFromEnd scans for trailing padding block.
func (spm *SSU2PaddingModifier) removePaddingFromEnd(data []byte) []byte {
	for i := len(data) - 1; i >= 2; i-- {
		if data[i-2] == 254 {
			if i-1 < len(data) {
				paddingSize := binary.BigEndian.Uint16(data[i-1 : i+1])
				expectedEnd := i + 1 + int(paddingSize)
				if expectedEnd == len(data) && i-2 >= 0 {
					return data[:i-2]
				}
			}
		}
	}
	return nil
}

// removePaddingFromBlocks parses I2P block structure.
func (spm *SSU2PaddingModifier) removePaddingFromBlocks(data []byte) ([]byte, error) {
	result := spm.parseBlockStructure(data)
	if result.foundValidBlocks && result.lastDataEnd > 0 && result.lastDataEnd <= len(data) {
		return data[:result.lastDataEnd], nil
	}
	return data, nil
}

// parseBlockStructure analyzes data as I2P block format.
func (spm *SSU2PaddingModifier) parseBlockStructure(data []byte) blockParseResult {
	result := blockParseResult{}
	offset := 0

	for offset < len(data) {
		if offset+3 > len(data) {
			break
		}

		blockType := data[offset]
		blockSize := int(binary.BigEndian.Uint16(data[offset+1 : offset+3]))

		if offset+3+blockSize > len(data) {
			break
		}

		result.foundValidBlocks = true
		if blockType == 254 {
			return result
		}

		result.lastDataEnd = offset + 3 + blockSize
		offset = result.lastDataEnd
	}

	return result
}

// blockParseResult holds block structure parsing state.
type blockParseResult struct {
	foundValidBlocks bool
	lastDataEnd      int
}

// EstimatePaddingSize estimates padding for bandwidth calculations.
func (spm *SSU2PaddingModifier) EstimatePaddingSize(dataLen int) int {
	spm.mutex.RLock()
	defer spm.mutex.RUnlock()

	if spm.paddingRatio > 0.0 {
		ratioPadding := int(math.Ceil(float64(dataLen) * spm.paddingRatio))
		if ratioPadding < spm.minPadding {
			return spm.minPadding
		}
		if ratioPadding > spm.maxPadding {
			return spm.maxPadding
		}

		// Respect MTU constraint
		overhead := ssu2HeaderSize + aeadTagSize
		availableSpace := spm.mtu - dataLen - overhead
		if ratioPadding > availableSpace {
			return availableSpace
		}

		return ratioPadding
	}

	return (spm.minPadding + spm.maxPadding) / 2
}

// GetMTU returns the current MTU value.
func (spm *SSU2PaddingModifier) GetMTU() int {
	spm.mutex.RLock()
	defer spm.mutex.RUnlock()
	return spm.mtu
}

// GetPaddingParams returns current padding configuration.
func (spm *SSU2PaddingModifier) GetPaddingParams() (minPad, maxPad int, ratio float64) {
	spm.mutex.RLock()
	defer spm.mutex.RUnlock()
	return spm.minPadding, spm.maxPadding, spm.paddingRatio
}

// validatePaddingParams validates padding parameters.
func validatePaddingParams(minPad, maxPad int, ratio float64) error {
	if minPad < 0 {
		return oops.
			Code("INVALID_PADDING").
			In("ssu2").
			With("min_padding", minPad).
			Errorf("minimum padding cannot be negative")
	}

	if maxPad < minPad {
		return oops.
			Code("INVALID_PADDING").
			In("ssu2").
			With("min_padding", minPad).
			With("max_padding", maxPad).
			Errorf("maximum padding cannot be less than minimum padding")
	}

	if maxPad > maxPaddingBlocks {
		return oops.
			Code("INVALID_PADDING").
			In("ssu2").
			With("max_padding", maxPad).
			Errorf("maximum padding cannot exceed 65516 bytes (I2P spec limit)")
	}

	if ratio < 0.0 || ratio > 15.9375 {
		return oops.
			Code("INVALID_PADDING_RATIO").
			In("ssu2").
			With("padding_ratio", ratio).
			Errorf("padding ratio must be between 0.0 and 15.9375 (I2P spec)")
	}

	return nil
}

// validateMTU validates MTU value.
func validateMTU(mtu int) error {
	if mtu < minMTU || mtu > maxMTU {
		return oops.
			Code("INVALID_MTU").
			In("ssu2").
			With("mtu", mtu).
			Errorf("MTU must be between %d and %d bytes", minMTU, maxMTU)
	}
	return nil
}
