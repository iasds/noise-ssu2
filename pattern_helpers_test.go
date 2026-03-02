package noise

// This file contains test-only helper functions that were formerly in conn.go.
// They are not called from any production code path — only from test cases.
// Moved here to avoid dead code in the production binary.

import (
	"strings"

	i2plogger "github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// getPatternMessageCount returns the expected number of handshake messages for each pattern.
// Returns an error for unknown patterns instead of defaulting, preventing configuration errors.
func (nc *NoiseConn) getPatternMessageCount() (int, error) {
	pattern := nc.config.Pattern

	switch pattern {
	case "N", "K", "X":
		nc.logPatternDetected(pattern, 1, "one-way", "short")
		return 1, nil
	case "NN", "NK", "NX", "KN", "KK", "KX", "IN", "IK", "IX":
		nc.logPatternDetected(pattern, 2, "two-message-interactive", "short")
		return 2, nil
	case "XN", "XK", "XX":
		nc.logPatternDetected(pattern, 3, "three-message", "short")
		return 3, nil
	default:
		return matchFullFormPattern(nc, pattern)
	}
}

// matchFullFormPattern detects full-form Noise protocol pattern names (e.g.
// "Noise_XX_25519_AESGCM_SHA256") and returns the expected message count.
func matchFullFormPattern(nc *NoiseConn, pattern string) (int, error) {
	oneWay := []string{"_N_", "_K_", "_X_"}
	twoMsg := []string{"_NN_", "_NK_", "_NX_", "_KN_", "_KK_", "_KX_", "_IN_", "_IK_", "_IX_"}
	threeMsg := []string{"_XN_", "_XK_", "_XX_"}

	if containsAny(pattern, oneWay) {
		nc.logPatternDetected(pattern, 1, "one-way", "full")
		return 1, nil
	}
	if containsAny(pattern, twoMsg) {
		nc.logPatternDetected(pattern, 2, "two-message-interactive", "full")
		return 2, nil
	}
	if containsAny(pattern, threeMsg) {
		nc.logPatternDetected(pattern, 3, "three-message", "full")
		return 3, nil
	}

	return 0, oops.
		Code("UNKNOWN_PATTERN").
		In("noise").
		With("pattern", pattern).
		Errorf("unknown handshake pattern: %s", pattern)
}

// logPatternDetected logs the detection of a handshake pattern with its expected message count.
func (nc *NoiseConn) logPatternDetected(pattern string, msgCount int, patternType, patternFormat string) {
	nc.logger.WithFields(i2plogger.Fields{
		"pattern":           pattern,
		"expected_messages": msgCount,
		"pattern_type":      patternType,
		"pattern_format":    patternFormat,
	}).Debug("detected handshake pattern")
}

// containsAny returns true if s contains any of the given substrings.
func containsAny(s string, substrings []string) bool {
	for _, sub := range substrings {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
