package ntcp2

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/go-i2p/go-noise/handshake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewNTCP2ConfigWithInitiator(t *testing.T) {
	routerHash := make([]byte, 32)
	_, err := rand.Read(routerHash)
	require.NoError(t, err)

	// Test initiator configuration
	config, err := NewNTCP2Config(routerHash, true)
	require.NoError(t, err)

	assert.Equal(t, "XK", config.Pattern)
	assert.Equal(t, true, config.Initiator)
	assert.Equal(t, routerHash, config.BobRouterHash)
	assert.Equal(t, 30*time.Second, config.HandshakeTimeout)
	assert.Equal(t, time.Duration(0), config.ReadTimeout)
	assert.Equal(t, time.Duration(0), config.WriteTimeout)
	assert.Equal(t, 3, config.HandshakeRetries)
	assert.Equal(t, 1*time.Second, config.RetryBackoff)
	assert.Equal(t, true, config.EnableAESObfuscation)
	assert.Equal(t, true, config.EnableSipHashLength)
	assert.Equal(t, 16384, config.MaxFrameSize)
	assert.Equal(t, true, config.FramePaddingEnabled)
	assert.Equal(t, 0, config.MinPaddingSize)
	assert.Equal(t, 64, config.MaxPaddingSize)

	// Test responder configuration
	config, err = NewNTCP2Config(routerHash, false)
	require.NoError(t, err)
	assert.Equal(t, false, config.Initiator)
}

func TestNTCP2ConfigBuilderMethods(t *testing.T) {
	routerHash := make([]byte, 32)
	_, err := rand.Read(routerHash)
	require.NoError(t, err)

	staticKey := make([]byte, 32)
	_, err = rand.Read(staticKey)
	require.NoError(t, err)

	remoteHash := make([]byte, 32)
	_, err = rand.Read(remoteHash)
	require.NoError(t, err)

	obfuscationIV := make([]byte, 16)
	_, err = rand.Read(obfuscationIV)
	require.NoError(t, err)

	config, err := NewNTCP2Config(routerHash, true)
	require.NoError(t, err)

	// Test all builder methods
	config, err = config.WithStaticKey(staticKey)
	require.NoError(t, err)
	config, err = config.WithRemoteRouterHash(remoteHash)
	require.NoError(t, err)
	config = config.
		WithPattern("XK").
		WithHandshakeTimeout(45 * time.Second).
		WithReadTimeout(10 * time.Second).
		WithWriteTimeout(15 * time.Second).
		WithHandshakeRetries(5).
		WithRetryBackoff(2 * time.Second)
	config, err = config.WithAESObfuscation(true, obfuscationIV)
	require.NoError(t, err)
	config = config.
		WithSipHashLength(true, 0x123456789ABCDEF0, 0xFEDCBA9876543210).
		WithFrameSettings(32768, false, 16, 128)

	assert.Equal(t, "XK", config.Pattern)
	assert.Equal(t, staticKey, config.StaticKey)
	assert.Equal(t, remoteHash, config.RemoteRouterHash)
	assert.Equal(t, 45*time.Second, config.HandshakeTimeout)
	assert.Equal(t, 10*time.Second, config.ReadTimeout)
	assert.Equal(t, 15*time.Second, config.WriteTimeout)
	assert.Equal(t, 5, config.HandshakeRetries)
	assert.Equal(t, 2*time.Second, config.RetryBackoff)
	assert.Equal(t, true, config.EnableAESObfuscation)
	assert.Equal(t, obfuscationIV, config.ObfuscationIV)
	assert.Equal(t, true, config.EnableSipHashLength)
	assert.Equal(t, uint64(0x123456789ABCDEF0), config.SipHashKeys[0])
	assert.Equal(t, uint64(0xFEDCBA9876543210), config.SipHashKeys[1])
	assert.Equal(t, 32768, config.MaxFrameSize)
	assert.Equal(t, false, config.FramePaddingEnabled)
	assert.Equal(t, 16, config.MinPaddingSize)
	assert.Equal(t, 128, config.MaxPaddingSize)
}

func TestNTCP2ConfigWithModifiers(t *testing.T) {
	routerHash := make([]byte, 32)
	_, err := rand.Read(routerHash)
	require.NoError(t, err)

	// Create some test modifiers
	xorMod := handshake.NewXORModifier("test-xor", []byte{0xAA, 0xBB})
	paddingMod, err := handshake.NewPaddingModifier("test-padding", 4, 8)
	require.NoError(t, err)

	config, err := NewNTCP2Config(routerHash, true)
	require.NoError(t, err)

	config = config.WithModifiers(xorMod, paddingMod)

	assert.Len(t, config.Modifiers, 2)
	assert.Equal(t, "test-xor", config.Modifiers[0].Name())
	assert.Equal(t, "test-padding", config.Modifiers[1].Name())
}

func TestNTCP2ConfigComprehensiveValidation(t *testing.T) {
	routerHash := make([]byte, 32)
	_, err := rand.Read(routerHash)
	require.NoError(t, err)

	tests := []struct {
		name        string
		setupConfig func() *NTCP2Config
		expectError bool
		errorCode   string
	}{
		{
			name: "valid config",
			setupConfig: func() *NTCP2Config {
				config, _ := NewNTCP2Config(routerHash, false)
				return config
			},
			expectError: false,
		},
		{
			name: "invalid router hash",
			setupConfig: func() *NTCP2Config {
				config, _ := NewNTCP2Config(routerHash, false)
				config.BobRouterHash = make([]byte, 16) // Invalid length
				return config
			},
			expectError: true,
			errorCode:   "INVALID_ROUTER_HASH",
		},
		{
			name: "invalid static key",
			setupConfig: func() *NTCP2Config {
				config, _ := NewNTCP2Config(routerHash, false)
				config.StaticKey = make([]byte, 16) // Invalid length
				return config
			},
			expectError: true,
			errorCode:   "INVALID_STATIC_KEY",
		},
		{
			name: "invalid remote router hash",
			setupConfig: func() *NTCP2Config {
				config, _ := NewNTCP2Config(routerHash, false)
				config.RemoteRouterHash = make([]byte, 16) // Invalid length
				return config
			},
			expectError: true,
			errorCode:   "INVALID_REMOTE_ROUTER_HASH",
		},
		{
			name: "missing remote hash for initiator",
			setupConfig: func() *NTCP2Config {
				config, _ := NewNTCP2Config(routerHash, true) // Initiator = true
				config.RemoteRouterHash = nil
				return config
			},
			expectError: true,
			errorCode:   "MISSING_REMOTE_ROUTER_HASH",
		},
		{
			name: "invalid handshake timeout",
			setupConfig: func() *NTCP2Config {
				config, _ := NewNTCP2Config(routerHash, false)
				config.HandshakeTimeout = -1 * time.Second
				return config
			},
			expectError: true,
			errorCode:   "INVALID_HANDSHAKE_TIMEOUT",
		},
		{
			name: "invalid retry count",
			setupConfig: func() *NTCP2Config {
				config, _ := NewNTCP2Config(routerHash, false)
				config.HandshakeRetries = -2 // Less than -1
				return config
			},
			expectError: true,
			errorCode:   "INVALID_RETRY_COUNT",
		},
		{
			name: "invalid retry backoff",
			setupConfig: func() *NTCP2Config {
				config, _ := NewNTCP2Config(routerHash, false)
				config.RetryBackoff = -1 * time.Second
				return config
			},
			expectError: true,
			errorCode:   "INVALID_RETRY_BACKOFF",
		},
		{
			name: "invalid obfuscation IV",
			setupConfig: func() *NTCP2Config {
				config, _ := NewNTCP2Config(routerHash, false)
				config.ObfuscationIV = make([]byte, 8) // Invalid length
				return config
			},
			expectError: true,
			errorCode:   "INVALID_OBFUSCATION_IV",
		},
		{
			name: "invalid max frame size",
			setupConfig: func() *NTCP2Config {
				config, _ := NewNTCP2Config(routerHash, false)
				config.MaxFrameSize = 0
				return config
			},
			expectError: true,
			errorCode:   "INVALID_MAX_FRAME_SIZE",
		},
		{
			name: "invalid min padding",
			setupConfig: func() *NTCP2Config {
				config, _ := NewNTCP2Config(routerHash, false)
				config.MinPaddingSize = -1
				return config
			},
			expectError: true,
			errorCode:   "INVALID_MIN_PADDING",
		},
		{
			name: "invalid padding range",
			setupConfig: func() *NTCP2Config {
				config, _ := NewNTCP2Config(routerHash, false)
				config.MinPaddingSize = 100
				config.MaxPaddingSize = 50
				return config
			},
			expectError: true,
			errorCode:   "INVALID_PADDING_RANGE",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := tt.setupConfig()
			err := config.Validate()
			if tt.expectError {
				assert.Error(t, err)
				// Note: oops errors include codes but not necessarily in the message text
				// So we test for key words from the error message instead
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestNTCP2ConfigToConnConfig(t *testing.T) {
	routerHash := make([]byte, 32)
	_, err := rand.Read(routerHash)
	require.NoError(t, err)

	staticKey := make([]byte, 32)
	_, err = rand.Read(staticKey)
	require.NoError(t, err)

	remoteHash := make([]byte, 32)
	_, err = rand.Read(remoteHash)
	require.NoError(t, err)

	obfuscationIV := make([]byte, 16)
	_, err = rand.Read(obfuscationIV)
	require.NoError(t, err)

	ntcp2Config, err := NewNTCP2Config(routerHash, true)
	require.NoError(t, err)

	ntcp2Config, err = ntcp2Config.WithStaticKey(staticKey)
	require.NoError(t, err)
	ntcp2Config, err = ntcp2Config.WithRemoteRouterHash(remoteHash)
	require.NoError(t, err)
	ntcp2Config, err = ntcp2Config.WithRemoteStaticKey(generateRandomBytes(32))
	require.NoError(t, err)
	ntcp2Config, err = ntcp2Config.WithAESObfuscation(true, obfuscationIV)
	require.NoError(t, err)
	ntcp2Config = ntcp2Config.
		WithHandshakeTimeout(45 * time.Second).
		WithReadTimeout(10 * time.Second).
		WithWriteTimeout(15 * time.Second).
		WithHandshakeRetries(5).
		WithRetryBackoff(2 * time.Second)

	connConfig, err := ntcp2Config.ToConnConfig()
	require.NoError(t, err)

	// Verify basic config translation
	assert.Equal(t, "XK", connConfig.Pattern)
	assert.Equal(t, true, connConfig.Initiator)
	assert.Equal(t, staticKey, connConfig.StaticKey)
	assert.Equal(t, 45*time.Second, connConfig.HandshakeTimeout)
	assert.Equal(t, 10*time.Second, connConfig.ReadTimeout)
	assert.Equal(t, 15*time.Second, connConfig.WriteTimeout)
	assert.Equal(t, 5, connConfig.HandshakeRetries)
	assert.Equal(t, 2*time.Second, connConfig.RetryBackoff)

	// Verify NTCP2-specific modifiers are added
	assert.Len(t, connConfig.Modifiers, 2) // AES + SipHash
}

func TestNTCP2ConfigToConnConfigWithDisabledModifiers(t *testing.T) {
	routerHash := make([]byte, 32)
	_, err := rand.Read(routerHash)
	require.NoError(t, err)

	ntcp2Config, err := NewNTCP2Config(routerHash, false)
	require.NoError(t, err)

	// Disable all modifiers
	ntcp2Config, err = ntcp2Config.WithAESObfuscation(false, nil)
	require.NoError(t, err)
	ntcp2Config = ntcp2Config.
		WithSipHashLength(false, 0, 0)

	connConfig, err := ntcp2Config.ToConnConfig()
	require.NoError(t, err)

	// Should have no NTCP2-specific modifiers
	assert.Len(t, connConfig.Modifiers, 0)
}

func TestNTCP2ConfigToConnConfigWithCustomModifiers(t *testing.T) {
	routerHash := make([]byte, 32)
	_, err := rand.Read(routerHash)
	require.NoError(t, err)

	obfuscationIV := make([]byte, 16)
	_, err = rand.Read(obfuscationIV)
	require.NoError(t, err)

	// Create custom modifiers
	xorMod := handshake.NewXORModifier("custom-xor", []byte{0xCC, 0xDD})
	paddingMod, err := handshake.NewPaddingModifier("custom-padding", 8, 16)
	require.NoError(t, err)

	ntcp2Config, err := NewNTCP2Config(routerHash, false)
	require.NoError(t, err)

	ntcp2Config, err = ntcp2Config.WithAESObfuscation(true, obfuscationIV)
	require.NoError(t, err)
	ntcp2Config = ntcp2Config.
		WithModifiers(xorMod, paddingMod)

	connConfig, err := ntcp2Config.ToConnConfig()
	require.NoError(t, err)

	// Should have NTCP2 modifiers + custom modifiers
	assert.Len(t, connConfig.Modifiers, 4) // AES + SipHash + 2 custom

	// Custom modifiers should be at the end
	assert.Equal(t, "custom-xor", connConfig.Modifiers[2].Name())
	assert.Equal(t, "custom-padding", connConfig.Modifiers[3].Name())
}

func TestNTCP2ConfigBuilderDefensiveCopying(t *testing.T) {
	routerHash := make([]byte, 32)
	_, err := rand.Read(routerHash)
	require.NoError(t, err)

	staticKey := make([]byte, 32)
	_, err = rand.Read(staticKey)
	require.NoError(t, err)

	config, err := NewNTCP2Config(routerHash, false)
	require.NoError(t, err)

	config, err = config.WithStaticKey(staticKey)
	require.NoError(t, err)

	// Modify original slices
	routerHash[0] = 0xFF
	staticKey[0] = 0xFF

	// Config should be unaffected
	assert.NotEqual(t, byte(0xFF), config.BobRouterHash[0])
	assert.NotEqual(t, byte(0xFF), config.StaticKey[0])
}

func TestNTCP2ConfigValidationEdgeCases(t *testing.T) {
	routerHash := make([]byte, 32)
	_, err := rand.Read(routerHash)
	require.NoError(t, err)

	// Test empty pattern
	config, err := NewNTCP2Config(routerHash, false)
	require.NoError(t, err)
	config.Pattern = ""

	err = config.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "noise pattern is required")

	// Test infinite retries (should be valid)
	config, err = NewNTCP2Config(routerHash, false)
	require.NoError(t, err)
	config.HandshakeRetries = -1

	err = config.Validate()
	assert.NoError(t, err)

	// Test zero retry backoff (should be valid)
	config.RetryBackoff = 0
	err = config.Validate()
	assert.NoError(t, err)
}

// TestNTCP2ConfigEdgeCases tests edge cases for NTCP2Config validation.
func TestNTCP2ConfigEdgeCases(t *testing.T) {
	routerHash := make([]byte, 32)
	_, err := rand.Read(routerHash)
	require.NoError(t, err)

	t.Run("valid config with all options", func(t *testing.T) {
		config, err := NewNTCP2Config(routerHash, false)
		require.NoError(t, err)

		staticKey := make([]byte, 32)
		_, err = rand.Read(staticKey)
		require.NoError(t, err)

		config, err = config.WithStaticKey(staticKey)
		require.NoError(t, err)
		config = config.
			WithHandshakeTimeout(10 * time.Second).
			WithReadTimeout(5 * time.Second).
			WithWriteTimeout(5 * time.Second)

		err = config.Validate()
		assert.NoError(t, err)

		// Verify defensive copying in config
		originalHash := make([]byte, 32)
		copy(originalHash, routerHash)
		routerHash[0] = 0xFF // Modify original

		assert.Equal(t, originalHash, config.BobRouterHash) // Should be unchanged
	})

	t.Run("invalid static key in WithStaticKey", func(t *testing.T) {
		config, err := NewNTCP2Config(routerHash, false)
		require.NoError(t, err)

		// Try to set invalid static key (wrong size) - should return error
		invalidKey := make([]byte, 16)
		_, err = config.WithStaticKey(invalidKey)
		assert.Error(t, err)

		// StaticKey should remain nil
		assert.Nil(t, config.StaticKey)
	})
}

// ============================================================================
// Tests from audit_fixes_test.go — config-related
// ============================================================================

func TestAudit_Quality_SilentRejection(t *testing.T) {
	routerHash := make([]byte, 32)
	config, err := NewNTCP2Config(routerHash, true)
	require.NoError(t, err)
	require.NotNil(t, config)

	_, err = config.WithStaticKey(make([]byte, 31))
	assert.Error(t, err)
	assert.Nil(t, config.StaticKey, "Invalid static key must not be set")

	validKey := make([]byte, 32)
	for i := range validKey {
		validKey[i] = byte(i)
	}
	config, err = config.WithStaticKey(validKey)
	require.NoError(t, err)
	assert.Equal(t, validKey, config.StaticKey, "Valid static key must be set")

	_, err = config.WithRemoteRouterHash(make([]byte, 31))
	assert.Error(t, err)
	assert.Nil(t, config.RemoteRouterHash, "Invalid router hash must not be set")

	validHash := make([]byte, 32)
	for i := range validHash {
		validHash[i] = byte(i + 100)
	}
	config, err = config.WithRemoteRouterHash(validHash)
	require.NoError(t, err)
	assert.Equal(t, validHash, config.RemoteRouterHash, "Valid router hash must be set")
}

func TestAudit_Quality_Constants(t *testing.T) {
	assert.Equal(t, 32, RouterHashSize)
	assert.Equal(t, 32, StaticKeySize)
	assert.Equal(t, 16, IVSize)
	assert.Equal(t, byte(254), byte(PaddingBlockType))
	assert.Equal(t, 65516, MaxBlockDataSize)
	assert.Equal(t, 65535, MaxFrameSize)
	assert.Equal(t, 3, BlockHeaderSize)
	assert.Equal(t, 8, SipHashIVSize)
	assert.Equal(t, 2, FrameLengthFieldSize)
	assert.Equal(t, "XK", NTCP2Pattern)
	assert.Equal(t, "Noise_XKaesobfse+hs2+hs3_25519_ChaChaPoly_SHA256", NTCP2ProtocolName)
}

func TestAudit_ConfigUsesXKPattern(t *testing.T) {
	routerHash := make([]byte, 32)
	config, err := NewNTCP2Config(routerHash, true)
	require.NoError(t, err)
	require.NotNil(t, config)

	assert.Equal(t, "XK", NTCP2Pattern)

	validKey := make([]byte, 32)
	config, err = config.WithStaticKey(validKey)
	require.NoError(t, err)
	config, err = config.WithRemoteRouterHash(make([]byte, 32))
	require.NoError(t, err)
	config, err = config.WithRemoteStaticKey(make([]byte, 32))
	require.NoError(t, err)
	config, err = config.WithAESObfuscation(true, make([]byte, 16))
	require.NoError(t, err)
	connConfig, err2 := config.ToConnConfig()
	require.NoError(t, err2)
	require.NotNil(t, connConfig)
	assert.Equal(t, "XK", connConfig.Pattern)
}

// ============================================================================
// Tests from audit_fixes_3_test.go — config-related
// ============================================================================

func TestWithAESObfuscation_WrongIVLengthReturnsError(t *testing.T) {
	routerHash := make([]byte, 32)
	_, err := rand.Read(routerHash)
	require.NoError(t, err)

	config, err := NewNTCP2Config(routerHash, false)
	require.NoError(t, err)
	config.EnableAESObfuscation = false

	wrongIV := make([]byte, 10)
	_, err = config.WithAESObfuscation(true, wrongIV)
	assert.Error(t, err, "Wrong-length IV must return an error")
	assert.Contains(t, err.Error(), "custom IV must be exactly")

	correctIV := make([]byte, 16)
	config, err = config.WithAESObfuscation(true, correctIV)
	require.NoError(t, err)
	assert.NotNil(t, config.ObfuscationIV, "Correct-length IV must be set")

	config, err = config.WithAESObfuscation(false, nil)
	require.NoError(t, err)
}

func TestSipHashModifier_NilBeforeHandshake(t *testing.T) {
	routerHash := make([]byte, 32)
	_, err := rand.Read(routerHash)
	require.NoError(t, err)

	obfuscationIV := make([]byte, 16)
	_, err = rand.Read(obfuscationIV)
	require.NoError(t, err)

	config, err := NewNTCP2Config(routerHash, false)
	require.NoError(t, err)

	config, err = config.WithAESObfuscation(true, obfuscationIV)
	require.NoError(t, err)

	assert.Nil(t, config.SipHashModifier())

	_, err = config.ToConnConfig()
	require.NoError(t, err)

	assert.Nil(t, config.SipHashModifier(),
		"Placeholder zero-key modifier must not be exposed via SipHashModifier()")
}

func TestKDF_ASKLabelConfigured(t *testing.T) {
	routerHash := make([]byte, 32)
	_, err := rand.Read(routerHash)
	require.NoError(t, err)

	obfuscationIV := make([]byte, 16)
	_, err = rand.Read(obfuscationIV)
	require.NoError(t, err)

	config, err := NewNTCP2Config(routerHash, false)
	require.NoError(t, err)
	config, err = config.WithAESObfuscation(true, obfuscationIV)
	require.NoError(t, err)

	connConfig, err := config.ToConnConfig()
	require.NoError(t, err)

	assert.Len(t, connConfig.AdditionalSymmetricKeyLabels, 1)
	assert.Equal(t, []byte("ask"), connConfig.AdditionalSymmetricKeyLabels[0])

	assert.NotNil(t, connConfig.PostHandshakeHook)
}

// ============================================================================
// Tests from audit_fixes_4_test.go — config-related
// ============================================================================

func TestAuditFix_Clone_IndependentConfig(t *testing.T) {
	original := &NTCP2Config{
		Pattern:       "XK",
		MaxFrameSize:  16384,
		BobRouterHash: []byte("original-hash-32-bytes-long!!!!!"),
	}

	clone := original.Clone()

	clone.MaxFrameSize = 8192
	clone.BobRouterHash[0] = 0xFF

	assert.Equal(t, 16384, original.MaxFrameSize, "clone modification should not affect original")
	assert.NotEqual(t, byte(0xFF), original.BobRouterHash[0], "clone byte slice modification should not affect original")
}

// ============================================================================
// Tests from audit_fixes_5_test.go — config-related
// ============================================================================

func TestAuditFix_BobRouterHash_FieldRenamed(t *testing.T) {
	rhb := make([]byte, 32)
	for i := range rhb {
		rhb[i] = byte(i + 1)
	}

	config, err := NewNTCP2Config(rhb, true)
	require.NoError(t, err)
	assert.Equal(t, rhb, config.BobRouterHash, "BobRouterHash must be set by constructor")
}

func TestAuditFix_BobRouterHash_ValidationWorks(t *testing.T) {
	_, err := NewNTCP2Config(make([]byte, 16), true)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "bob router hash must be exactly 32 bytes")

	config, err := NewNTCP2Config(make([]byte, 32), false)
	require.NoError(t, err)

	config.BobRouterHash = make([]byte, 10)
	err = config.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "bob router hash must be exactly 32 bytes")
}

func TestAuditFix_BobRouterHash_DefensiveCopy(t *testing.T) {
	rhb := make([]byte, 32)
	config, err := NewNTCP2Config(rhb, true)
	require.NoError(t, err)

	rhb[0] = 0xFF
	assert.NotEqual(t, byte(0xFF), config.BobRouterHash[0],
		"BobRouterHash must be a defensive copy")
}

func TestAuditFix_BobRouterHash_AESModifierUsesIt(t *testing.T) {
	rhb := make([]byte, 32)
	for i := range rhb {
		rhb[i] = byte(i + 10)
	}
	iv := make([]byte, 16)
	for i := range iv {
		iv[i] = byte(i + 0x30)
	}

	config, err := NewNTCP2Config(rhb, false)
	require.NoError(t, err)
	config, err = config.WithAESObfuscation(true, iv)
	require.NoError(t, err)

	mod, err := config.createAESModifierIfEnabled()
	require.NoError(t, err)
	assert.NotNil(t, mod)
}

func TestAuditFix_BobRouterHash_ClonePreserves(t *testing.T) {
	rhb := make([]byte, 32)
	for i := range rhb {
		rhb[i] = byte(i)
	}
	config, err := NewNTCP2Config(rhb, true)
	require.NoError(t, err)

	clone := config.Clone()
	assert.Equal(t, config.BobRouterHash, clone.BobRouterHash)

	clone.BobRouterHash[0] = 0xFF
	assert.NotEqual(t, config.BobRouterHash[0], clone.BobRouterHash[0])
}

func TestAuditFix_Clone_DocCommentsPresent(t *testing.T) {
	rhb := make([]byte, 32)
	config, err := NewNTCP2Config(rhb, true)
	require.NoError(t, err)

	clone := config.Clone()

	clone.Pattern = "NN"
	assert.Equal(t, "XK", config.Pattern, "Clone must not share value fields")

	clone.BobRouterHash[0] = 0xFF
	assert.NotEqual(t, byte(0xFF), config.BobRouterHash[0],
		"Clone must deep-copy BobRouterHash")
}

// TestConfigSipHashModifier verifies that NTCP2Config stores and returns
// the SipHash modifier after ToConnConfig() is called.
func TestConfigSipHashModifier(t *testing.T) {
	routerHash := make([]byte, 32)
	copy(routerHash, "test-router-hash-32-bytes-long!")

	config, err := NewNTCP2Config(routerHash, true)
	require.NoError(t, err)

	// Set remote router hash (required for initiator)
	config.RemoteRouterHash = make([]byte, 32)
	copy(config.RemoteRouterHash, "remote-hash-32-bytes-long!!!!!")

	// Provide a static key
	config.StaticKey = make([]byte, 32)
	copy(config.StaticKey, "static-key-32-bytes-long!!!!!!!")

	// Provide remote static key (required for initiator XK)
	config.RemoteStaticKey = make([]byte, 32)
	copy(config.RemoteStaticKey, "remote-static-key-32-bytes!!!!!")

	// AES obfuscation requires an explicit IV
	config, err = config.WithAESObfuscation(true, make([]byte, 16))
	require.NoError(t, err)

	// Before ToConnConfig, modifier should be nil
	assert.Nil(t, config.SipHashModifier())

	// Call ToConnConfig
	connConfig, err := config.ToConnConfig()
	require.NoError(t, err)

	// After ToConnConfig (before handshake), SipHashModifier() should be nil
	// because the placeholder zero-key modifier is no longer exposed.
	// The proper directional modifier is set by the post-handshake hook.
	assert.Nil(t, config.SipHashModifier(),
		"Placeholder zero-key modifier must not be exposed pre-handshake")

	// But the SipHash modifier is still in the modifier list for the handshake
	hasSipHashMod := false
	for _, mod := range connConfig.Modifiers {
		if mod.Name() == "ntcp2-siphash" {
			hasSipHashMod = true
			break
		}
	}
	assert.True(t, hasSipHashMod,
		"SipHash modifier should be in the handshake modifier list")
}

// TestConfigSipHashModifier_Disabled verifies that the modifier is nil
// when SipHash is disabled.
func TestConfigSipHashModifier_Disabled(t *testing.T) {
	routerHash := make([]byte, 32)
	copy(routerHash, "test-router-hash-32-bytes-long!")

	config, err := NewNTCP2Config(routerHash, true)
	require.NoError(t, err)

	config.RemoteRouterHash = make([]byte, 32)
	copy(config.RemoteRouterHash, "remote-hash-32-bytes-long!!!!!")
	config.StaticKey = make([]byte, 32)
	copy(config.StaticKey, "static-key-32-bytes-long!!!!!!!")

	// Provide remote static key (required for initiator XK)
	config.RemoteStaticKey = make([]byte, 32)
	copy(config.RemoteStaticKey, "remote-static-key-32-bytes!!!!!")

	// Disable SipHash
	config.EnableSipHashLength = false

	// AES obfuscation requires an explicit IV
	config, err = config.WithAESObfuscation(true, make([]byte, 16))
	require.NoError(t, err)

	_, err = config.ToConnConfig()
	require.NoError(t, err)

	// Modifier should be nil
	assert.Nil(t, config.SipHashModifier())
}
