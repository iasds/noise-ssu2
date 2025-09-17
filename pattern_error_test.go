package noise

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPatternMessageCountError tests that getPatternMessageCount returns an error for unknown patterns
func TestPatternMessageCountError(t *testing.T) {
	// Use a valid pattern for NoiseConn creation
	config := NewConnConfig("XX", true)

	localAddr := &mockNetAddr{network: "tcp", address: "127.0.0.1:8001"}
	remoteAddr := &mockNetAddr{network: "tcp", address: "127.0.0.1:8002"}
	mockConn := newMockNetConn(localAddr, remoteAddr)

	nc, err := NewNoiseConn(mockConn, config)
	require.NoError(t, err, "Failed to create NoiseConn")

	// Manually set an invalid pattern to test the error case
	nc.config.Pattern = "INVALID_PATTERN"

	count, err := nc.getPatternMessageCount()
	assert.Error(t, err, "Should return error for unknown pattern")
	assert.Equal(t, 0, count, "Should return 0 count on error")
	assert.Contains(t, err.Error(), "unknown handshake pattern: INVALID_PATTERN")
}
