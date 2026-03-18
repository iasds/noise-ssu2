package ssu2

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/go-i2p/go-noise/handshake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewChaChaObfuscationModifier tests the constructor validation
func TestNewChaChaObfuscationModifier(t *testing.T) {
	tests := []struct {
		name        string
		modName     string
		routerHash  []byte
		iv          []byte
		expectError bool
		errorCode   string
	}{
		{
			name:        "valid parameters",
			modName:     "test-chacha",
			routerHash:  make([]byte, 32),
			iv:          make([]byte, 8),
			expectError: false,
		},
		{
			name:        "invalid router hash - too short",
			modName:     "test-chacha",
			routerHash:  make([]byte, 31),
			iv:          make([]byte, 8),
			expectError: true,
			errorCode:   "INVALID_ROUTER_HASH",
		},
		{
			name:        "invalid router hash - too long",
			modName:     "test-chacha",
			routerHash:  make([]byte, 33),
			iv:          make([]byte, 8),
			expectError: true,
			errorCode:   "INVALID_ROUTER_HASH",
		},
		{
			name:        "invalid IV - too short",
			modName:     "test-chacha",
			routerHash:  make([]byte, 32),
			iv:          make([]byte, 7),
			expectError: true,
			errorCode:   "INVALID_IV",
		},
		{
			name:        "invalid IV - too long",
			modName:     "test-chacha",
			routerHash:  make([]byte, 32),
			iv:          make([]byte, 9),
			expectError: true,
			errorCode:   "INVALID_IV",
		},
		{
			name:        "empty router hash",
			modName:     "test-chacha",
			routerHash:  []byte{},
			iv:          make([]byte, 8),
			expectError: true,
			errorCode:   "INVALID_ROUTER_HASH",
		},
		{
			name:        "nil router hash",
			modName:     "test-chacha",
			routerHash:  nil,
			iv:          make([]byte, 8),
			expectError: true,
			errorCode:   "INVALID_ROUTER_HASH",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mod, err := NewChaChaObfuscationModifier(tt.modName, tt.routerHash, tt.iv)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, mod)
				// Error code checking would require oops error inspection
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, mod)
				assert.Equal(t, tt.modName, mod.Name())
			}
		})
	}
}

// TestChaChaObfuscationModifier_DefensiveCopy verifies defensive copying
func TestChaChaObfuscationModifier_DefensiveCopy(t *testing.T) {
	routerHash := make([]byte, 32)
	iv := make([]byte, 8)

	// Fill with test data
	for i := range routerHash {
		routerHash[i] = byte(i)
	}
	for i := range iv {
		iv[i] = byte(i + 100)
	}

	mod, err := NewChaChaObfuscationModifier("test", routerHash, iv)
	require.NoError(t, err)

	// Modify original slices
	routerHash[0] = 0xFF
	iv[0] = 0xFF

	// Verify modifier's internal copies are unchanged
	assert.NotEqual(t, byte(0xFF), mod.routerHash[0])
	assert.NotEqual(t, byte(0xFF), mod.iv[0])
	assert.Equal(t, byte(0), mod.routerHash[0])
	assert.Equal(t, byte(100), mod.iv[0])
}

// TestChaChaObfuscationModifier_Roundtrip tests encryption/decryption roundtrip
func TestChaChaObfuscationModifier_Roundtrip(t *testing.T) {
	// Create modifier with random key and IV
	routerHash := make([]byte, 32)
	iv := make([]byte, 8)
	_, err := rand.Read(routerHash)
	require.NoError(t, err)
	_, err = rand.Read(iv)
	require.NoError(t, err)

	mod, err := NewChaChaObfuscationModifier("test-roundtrip", routerHash, iv)
	require.NoError(t, err)

	// Test message 1 (PhaseInitial)
	original1 := make([]byte, 32)
	_, err = rand.Read(original1)
	require.NoError(t, err)

	encrypted1, err := mod.ModifyOutbound(handshake.PhaseInitial, original1)
	require.NoError(t, err)
	assert.NotNil(t, encrypted1)
	assert.Len(t, encrypted1, 32)

	// Verify encryption changed the data
	assert.False(t, bytes.Equal(original1, encrypted1), "encrypted data should differ from original")

	// Create new modifier for decryption (simulates receiver)
	modDecrypt, err := NewChaChaObfuscationModifier("test-decrypt", routerHash, iv)
	require.NoError(t, err)

	decrypted1, err := modDecrypt.ModifyInbound(handshake.PhaseInitial, encrypted1)
	require.NoError(t, err)
	assert.Equal(t, original1, decrypted1, "decrypted should match original")

	// Test message 2 (PhaseExchange) using same modifier instances
	original2 := make([]byte, 32)
	_, err = rand.Read(original2)
	require.NoError(t, err)

	encrypted2, err := mod.ModifyOutbound(handshake.PhaseExchange, original2)
	require.NoError(t, err)
	assert.NotNil(t, encrypted2)
	assert.Len(t, encrypted2, 32)

	assert.False(t, bytes.Equal(original2, encrypted2), "encrypted data should differ from original")

	decrypted2, err := modDecrypt.ModifyInbound(handshake.PhaseExchange, encrypted2)
	require.NoError(t, err)
	assert.Equal(t, original2, decrypted2, "decrypted should match original")
}

// TestChaChaObfuscationModifier_PhaseSpecific tests phase-specific behavior
func TestChaChaObfuscationModifier_PhaseSpecific(t *testing.T) {
	routerHash := make([]byte, 32)
	iv := make([]byte, 8)
	_, err := rand.Read(routerHash)
	require.NoError(t, err)
	_, err = rand.Read(iv)
	require.NoError(t, err)

	mod, err := NewChaChaObfuscationModifier("test-phase", routerHash, iv)
	require.NoError(t, err)

	data := make([]byte, 32)
	_, err = rand.Read(data)
	require.NoError(t, err)

	// Test PhaseInitial - should encrypt
	result, err := mod.ModifyOutbound(handshake.PhaseInitial, data)
	require.NoError(t, err)
	assert.False(t, bytes.Equal(data, result))

	// Test PhaseExchange - should encrypt (requires PhaseInitial first)
	result2, err := mod.ModifyOutbound(handshake.PhaseExchange, data)
	require.NoError(t, err)
	assert.False(t, bytes.Equal(data, result2))

	// Test PhaseFinal - should NOT encrypt (pass through)
	result3, err := mod.ModifyOutbound(handshake.PhaseFinal, data)
	require.NoError(t, err)
	assert.True(t, bytes.Equal(data, result3), "PhaseFinal should pass data through unchanged")
}

// TestChaChaObfuscationModifier_NonEphemeralKey tests handling of non-32-byte data
func TestChaChaObfuscationModifier_NonEphemeralKey(t *testing.T) {
	routerHash := make([]byte, 32)
	iv := make([]byte, 8)

	mod, err := NewChaChaObfuscationModifier("test-size", routerHash, iv)
	require.NoError(t, err)

	testCases := []int{0, 1, 16, 31, 33, 64, 128}

	for _, size := range testCases {
		t.Run(string(rune(size))+"_bytes", func(t *testing.T) {
			data := make([]byte, size)
			_, _ = rand.Read(data)

			// Should pass through unchanged for non-32-byte data
			result, err := mod.ModifyOutbound(handshake.PhaseInitial, data)
			require.NoError(t, err)
			assert.True(t, bytes.Equal(data, result), "non-32-byte data should pass through unchanged")
		})
	}
}

// TestChaChaObfuscationModifier_StateManagement tests state handling across messages
func TestChaChaObfuscationModifier_StateManagement(t *testing.T) {
	routerHash := make([]byte, 32)
	iv := make([]byte, 8)
	_, err := rand.Read(routerHash)
	require.NoError(t, err)
	_, err = rand.Read(iv)
	require.NoError(t, err)

	mod, err := NewChaChaObfuscationModifier("test-state", routerHash, iv)
	require.NoError(t, err)

	// Initially, ChaCha state should be nil
	assert.Nil(t, mod.chachaState)

	// After message 1, state should be set
	data := make([]byte, 32)
	_, err = rand.Read(data)
	require.NoError(t, err)

	_, err = mod.ModifyOutbound(handshake.PhaseInitial, data)
	require.NoError(t, err)
	assert.NotNil(t, mod.chachaState, "ChaCha state should be set after message 1")
	assert.Len(t, mod.chachaState, 8, "ChaCha state should be 8 bytes")

	// Message 2 should succeed with state available
	_, err = mod.ModifyOutbound(handshake.PhaseExchange, data)
	require.NoError(t, err)
}

// TestChaChaObfuscationModifier_MissingState tests error when state is missing
func TestChaChaObfuscationModifier_MissingState(t *testing.T) {
	routerHash := make([]byte, 32)
	iv := make([]byte, 8)

	mod, err := NewChaChaObfuscationModifier("test-missing-state", routerHash, iv)
	require.NoError(t, err)

	data := make([]byte, 32)

	// Try message 2 without calling message 1 first
	_, err = mod.ModifyOutbound(handshake.PhaseExchange, data)
	assert.Error(t, err, "should error when ChaCha state is missing")
}

// TestChaChaObfuscationModifier_DifferentKeys tests that different keys produce different output
func TestChaChaObfuscationModifier_DifferentKeys(t *testing.T) {
	iv := make([]byte, 8)
	_, err := rand.Read(iv)
	require.NoError(t, err)

	// Create two modifiers with different router hashes
	routerHash1 := make([]byte, 32)
	routerHash2 := make([]byte, 32)
	_, err = rand.Read(routerHash1)
	require.NoError(t, err)
	_, err = rand.Read(routerHash2)
	require.NoError(t, err)

	mod1, err := NewChaChaObfuscationModifier("mod1", routerHash1, iv)
	require.NoError(t, err)

	mod2, err := NewChaChaObfuscationModifier("mod2", routerHash2, iv)
	require.NoError(t, err)

	data := make([]byte, 32)
	_, err = rand.Read(data)
	require.NoError(t, err)

	// Encrypt with both modifiers
	encrypted1, err := mod1.ModifyOutbound(handshake.PhaseInitial, data)
	require.NoError(t, err)

	encrypted2, err := mod2.ModifyOutbound(handshake.PhaseInitial, data)
	require.NoError(t, err)

	// Different keys should produce different ciphertext
	assert.False(t, bytes.Equal(encrypted1, encrypted2), "different keys should produce different output")
}

// TestChaChaObfuscationModifier_DifferentIVs tests that different IVs produce different output
func TestChaChaObfuscationModifier_DifferentIVs(t *testing.T) {
	routerHash := make([]byte, 32)
	_, err := rand.Read(routerHash)
	require.NoError(t, err)

	// Create two modifiers with different IVs
	iv1 := make([]byte, 8)
	iv2 := make([]byte, 8)
	_, err = rand.Read(iv1)
	require.NoError(t, err)
	_, err = rand.Read(iv2)
	require.NoError(t, err)

	mod1, err := NewChaChaObfuscationModifier("mod1", routerHash, iv1)
	require.NoError(t, err)

	mod2, err := NewChaChaObfuscationModifier("mod2", routerHash, iv2)
	require.NoError(t, err)

	data := make([]byte, 32)
	_, err = rand.Read(data)
	require.NoError(t, err)

	// Encrypt with both modifiers
	encrypted1, err := mod1.ModifyOutbound(handshake.PhaseInitial, data)
	require.NoError(t, err)

	encrypted2, err := mod2.ModifyOutbound(handshake.PhaseInitial, data)
	require.NoError(t, err)

	// Different IVs should produce different ciphertext
	assert.False(t, bytes.Equal(encrypted1, encrypted2), "different IVs should produce different output")
}

// TestChaChaObfuscationModifier_SymmetricOperation tests that ChaCha20 encryption and decryption are identical
func TestChaChaObfuscationModifier_SymmetricOperation(t *testing.T) {
	routerHash := make([]byte, 32)
	iv := make([]byte, 8)
	_, err := rand.Read(routerHash)
	require.NoError(t, err)
	_, err = rand.Read(iv)
	require.NoError(t, err)

	mod, err := NewChaChaObfuscationModifier("test-symmetric", routerHash, iv)
	require.NoError(t, err)

	data := make([]byte, 32)
	_, err = rand.Read(data)
	require.NoError(t, err)

	// ModifyOutbound and ModifyInbound should produce same result (XOR property)
	encrypted, err := mod.ModifyOutbound(handshake.PhaseInitial, data)
	require.NoError(t, err)

	// Reset state for fair comparison
	mod2, err := NewChaChaObfuscationModifier("test-symmetric2", routerHash, iv)
	require.NoError(t, err)

	decrypted, err := mod2.ModifyInbound(handshake.PhaseInitial, data)
	require.NoError(t, err)

	assert.Equal(t, encrypted, decrypted, "ChaCha20 is symmetric - encrypt and decrypt should be identical")
}

// BenchmarkChaChaObfuscation benchmarks the ChaCha20 obfuscation performance
func BenchmarkChaChaObfuscation(b *testing.B) {
	routerHash := make([]byte, 32)
	iv := make([]byte, 8)
	_, _ = rand.Read(routerHash)
	_, _ = rand.Read(iv)

	mod, _ := NewChaChaObfuscationModifier("bench", routerHash, iv)
	data := make([]byte, 32)
	_, _ = rand.Read(data)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = mod.ModifyOutbound(handshake.PhaseInitial, data)
	}
}
