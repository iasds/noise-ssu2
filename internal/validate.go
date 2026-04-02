package internal

import (
	"time"

	"github.com/samber/oops"
)

// ValidatePattern checks that a Noise protocol pattern is non-empty.
func ValidatePattern(pattern, pkg string) error {
	log.WithField("pattern", pattern).WithField("pkg", pkg).Debug("Validating pattern")
	if pattern == "" {
		return oops.
			Code("INVALID_PATTERN").
			In(pkg).
			Errorf("noise pattern is required")
	}
	return nil
}

// ValidateHandshakeTimeout checks that the handshake timeout is positive.
func ValidateHandshakeTimeout(timeout time.Duration, pkg string) error {
	if timeout <= 0 {
		return oops.
			Code("INVALID_TIMEOUT").
			In(pkg).
			With("timeout", timeout).
			Errorf("handshake timeout must be positive")
	}
	return nil
}

// ValidateKeyLength checks that a key is either empty or exactly 32 bytes.
func ValidateKeyLength(key []byte, name, pkg string) error {
	if len(key) > 0 && len(key) != 32 {
		return oops.
			Code("INVALID_KEY_LENGTH").
			In(pkg).
			With("key_length", len(key)).
			Errorf("%s must be 32 bytes for Curve25519", name)
	}
	return nil
}

// RunValidators executes a sequence of validation functions, returning the
// first error encountered or nil if all pass.
func RunValidators(validators ...func() error) error {
	log.WithField("validator_count", len(validators)).Debug("Running validators")
	for _, v := range validators {
		if err := v(); err != nil {
			return err
		}
	}
	return nil
}

// ValidateRetryConfig checks that retry parameters are within valid ranges.
func ValidateRetryConfig(retries int, backoff time.Duration, pkg string) error {
	if retries < -1 {
		return oops.
			Code("INVALID_RETRY_COUNT").
			In(pkg).
			With("retries", retries).
			Errorf("handshake retries must be >= -1 (-1 = infinite, 0 = no retries)")
	}
	if backoff < 0 {
		return oops.
			Code("INVALID_RETRY_BACKOFF").
			In(pkg).
			With("backoff", backoff).
			Errorf("retry backoff must be non-negative")
	}
	return nil
}
