package mod

import (
	"time"

	"github.com/go-i2p/go-noise/mod/validation"
)

// ValidatePattern checks that a Noise protocol pattern is non-empty.
// Delegates to mod/validation.ValidatePattern.
func ValidatePattern(pattern, pkg string) error {
	return validation.ValidatePattern(pattern, pkg)
}

// ValidateHandshakeTimeout checks that the handshake timeout is positive.
// Delegates to mod/validation.ValidateHandshakeTimeout.
func ValidateHandshakeTimeout(timeout time.Duration, pkg string) error {
	return validation.ValidateHandshakeTimeout(timeout, pkg)
}

// ValidateKeySize validates that a key has the expected size.
// Delegates to mod/validation.ValidateKeySize.
func ValidateKeySize(key []byte, expectedSize int) bool {
	return validation.ValidateKeySize(key, expectedSize)
}

// ValidateKeyLength checks that a key is either empty or exactly 32 bytes.
// Delegates to mod/validation.ValidateKeyLength.
func ValidateKeyLength(key []byte, name, pkg string) error {
	return validation.ValidateKeyLength(key, name, pkg)
}

// RunValidators executes a sequence of validation functions, returning the
// first error encountered or nil if all pass.
// Delegates to mod/validation.RunValidators.
func RunValidators(validators ...func() error) error {
	return validation.RunValidators(validators...)
}

// ValidateRetryConfig checks that retry parameters are within valid ranges.
// Delegates to mod/validation.ValidateRetryConfig.
func ValidateRetryConfig(retries int, backoff time.Duration, pkg string) error {
	return validation.ValidateRetryConfig(retries, backoff, pkg)
}

// ValidateTransportConfig validates the combination of handshake timeout and
// retry configuration common to all transport configs.
// Equivalent to ValidateHandshakeTimeout + ValidateRetryConfig in sequence.
// Delegates to mod/validation.ValidateTransportConfig.
func ValidateTransportConfig(timeout time.Duration, retries int, backoff time.Duration, pkg string) error {
	return validation.ValidateTransportConfig(timeout, retries, backoff, pkg)
}
