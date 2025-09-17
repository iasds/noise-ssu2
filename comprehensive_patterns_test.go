package noise

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAllHandshakePatterns tests that all Noise Protocol patterns are supported
func TestAllHandshakePatterns(t *testing.T) {
	// Test cases for all supported patterns
	testCases := []struct {
		name           string
		pattern        string
		messageCount   int
		requiresStatic bool
	}{
		// One-way patterns (1 message)
		{"N pattern", "N", 1, false},
		{"K pattern", "K", 1, true},
		{"X pattern", "X", 1, true},

		// Two-message interactive patterns
		{"NN pattern", "NN", 2, false},
		{"NK pattern", "NK", 2, false},
		{"NX pattern", "NX", 2, false},
		{"XN pattern", "XN", 2, true},
		{"XK pattern", "XK", 2, true},
		{"KN pattern", "KN", 2, true},
		{"KK pattern", "KK", 2, true},
		{"IN pattern", "IN", 2, true},
		{"IK pattern", "IK", 2, true},
		{"IX pattern", "IX", 2, true},

		// Three-message patterns
		{"XX pattern", "XX", 3, true},
		{"KX pattern", "KX", 3, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Test pattern recognition and message count
			config := NewConnConfig(tc.pattern, true)

			// Create a minimal mock connection to test pattern parsing
			localAddr := &mockNetAddr{network: "tcp", address: "127.0.0.1:8001"}
			remoteAddr := &mockNetAddr{network: "tcp", address: "127.0.0.1:8002"}
			mockConn := newMockNetConn(localAddr, remoteAddr)

			nc, err := NewNoiseConn(mockConn, config)
			require.NoError(t, err, "Failed to create NoiseConn for pattern %s", tc.pattern)

			// Test that pattern is correctly parsed and message count is correct
			actualMessageCount := nc.getPatternMessageCount()
			assert.Equal(t, tc.messageCount, actualMessageCount,
				"Pattern %s should have %d messages but got %d", tc.pattern, tc.messageCount, actualMessageCount)

			// Test that the pattern is supported (no panic when calling handshake methods)
			assert.NotPanics(t, func() {
				// This will fail due to mock connection, but should not panic due to unsupported pattern
				nc.performInitiatorHandshake(context.Background())
			}, "Pattern %s should be supported and not panic", tc.pattern)

			assert.NotPanics(t, func() {
				// This will fail due to mock connection, but should not panic due to unsupported pattern
				nc.performResponderHandshake(context.Background())
			}, "Pattern %s should be supported and not panic", tc.pattern)
		})
	}
}

// TestFullPatternNames tests that full Noise protocol specification names are supported
func TestFullPatternNames(t *testing.T) {
	fullPatternTests := []struct {
		name         string
		pattern      string
		messageCount int
	}{
		{"Full NN", "Noise_NN_25519_AESGCM_SHA256", 2},
		{"Full XX", "Noise_XX_25519_AESGCM_SHA256", 3},
		{"Full N", "Noise_N_25519_AESGCM_SHA256", 1},
		{"Full NK", "Noise_NK_25519_AESGCM_SHA256", 2},
		{"Full KX", "Noise_KX_25519_AESGCM_SHA256", 3},
	}

	for _, tc := range fullPatternTests {
		t.Run(tc.name, func(t *testing.T) {
			config := NewConnConfig(tc.pattern, true)

			localAddr := &mockNetAddr{network: "tcp", address: "127.0.0.1:8001"}
			remoteAddr := &mockNetAddr{network: "tcp", address: "127.0.0.1:8002"}
			mockConn := newMockNetConn(localAddr, remoteAddr)

			nc, err := NewNoiseConn(mockConn, config)
			require.NoError(t, err, "Failed to create NoiseConn for full pattern %s", tc.pattern)

			actualMessageCount := nc.getPatternMessageCount()
			assert.Equal(t, tc.messageCount, actualMessageCount,
				"Full pattern %s should have %d messages but got %d", tc.pattern, tc.messageCount, actualMessageCount)
		})
	}
}

// TestUnsupportedPattern tests that unsupported patterns return proper errors
func TestUnsupportedPattern(t *testing.T) {
	config := NewConnConfig("INVALID_PATTERN", true)

	localAddr := &mockNetAddr{network: "tcp", address: "127.0.0.1:8001"}
	remoteAddr := &mockNetAddr{network: "tcp", address: "127.0.0.1:8002"}
	mockConn := newMockNetConn(localAddr, remoteAddr)

	// Test that unsupported pattern is caught during NoiseConn creation
	_, err := NewNoiseConn(mockConn, config)
	assert.Error(t, err, "Unsupported pattern should return an error during creation")
	assert.Contains(t, err.Error(), "unsupported handshake pattern", "Error should mention unsupported pattern")
}
