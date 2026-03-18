package handshake

import "github.com/samber/oops"

// ValidatePaddingRange checks that min and max padding sizes form a valid range.
// It returns a contextual oops error scoped to the given subsystem name.
func ValidatePaddingRange(subsystem string, minPadding, maxPadding int) error {
	if minPadding < 0 {
		return oops.
			Code("INVALID_MIN_PADDING").
			In(subsystem).
			With("min_padding", minPadding).
			Errorf("min padding size must be non-negative")
	}

	if maxPadding < minPadding {
		return oops.
			Code("INVALID_PADDING_RANGE").
			In(subsystem).
			With("min_padding", minPadding).
			With("max_padding", maxPadding).
			Errorf("max padding size must be >= min padding size")
	}

	return nil
}
