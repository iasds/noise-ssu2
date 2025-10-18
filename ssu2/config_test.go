package ssu2

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewSSU2Config verifies the constructor creates a valid config with defaults.
func TestNewSSU2Config(t *testing.T) {
	t.Run("valid router hash creates config with defaults", func(t *testing.T) {
		routerHash := make([]byte, 32)
		for i := range routerHash {
			routerHash[i] = byte(i)
		}

		config, err := NewSSU2Config(routerHash, true)
		require.NoError(t, err)
		require.NotNil(t, config)

		// Verify defaults
		assert.Equal(t, "XK", config.Pattern)
		assert.True(t, config.Initiator)
		assert.Equal(t, 32, len(config.RouterHash))
		assert.Equal(t, 30*time.Second, config.HandshakeTimeout)
		assert.Equal(t, time.Duration(0), config.ReadTimeout)
		assert.Equal(t, time.Duration(0), config.WriteTimeout)
		assert.Equal(t, 3, config.HandshakeRetries)
		assert.Equal(t, 1*time.Second, config.RetryBackoff)
		assert.True(t, config.EnableChaChaObfuscation)
		assert.True(t, config.EnableSipHashLength)
		assert.Equal(t, 1280, config.MTU)
		assert.Equal(t, 1500, config.MaxPacketSize)
		assert.False(t, config.EnableFragmentation)
		assert.True(t, config.PaddingEnabled)
		assert.Equal(t, 0, config.MinPaddingSize)
		assert.Equal(t, 64, config.MaxPaddingSize)
		assert.Equal(t, 1.0, config.PaddingRatio)
		assert.Equal(t, uint64(0), config.ConnectionID)
		assert.Equal(t, 15*time.Second, config.KeepaliveInterval)
	})

	t.Run("router hash defensive copy", func(t *testing.T) {
		routerHash := make([]byte, 32)
		for i := range routerHash {
			routerHash[i] = byte(i)
		}

		config, err := NewSSU2Config(routerHash, false)
		require.NoError(t, err)

		// Modify original, verify config unchanged
		routerHash[0] = 255
		assert.Equal(t, byte(0), config.RouterHash[0])
	})

	t.Run("invalid router hash length returns error", func(t *testing.T) {
		testCases := []struct {
			name   string
			length int
		}{
			{"too short", 31},
			{"too long", 33},
			{"empty", 0},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				routerHash := make([]byte, tc.length)
				config, err := NewSSU2Config(routerHash, true)
				assert.Error(t, err)
				assert.Nil(t, config)
				assert.Contains(t, err.Error(), "router hash must be exactly 32 bytes")
			})
		}
	})
}

// TestSSU2Config_BuilderPattern verifies the fluent builder pattern.
func TestSSU2Config_BuilderPattern(t *testing.T) {
	routerHash := make([]byte, 32)
	staticKey := make([]byte, 32)
	remoteHash := make([]byte, 32)
	customIV := make([]byte, 8)

	config, err := NewSSU2Config(routerHash, true)
	require.NoError(t, err)

	// Chain multiple With* methods
	result := config.
		WithPattern("IK").
		WithStaticKey(staticKey).
		WithRemoteRouterHash(remoteHash).
		WithHandshakeTimeout(10*time.Second).
		WithReadTimeout(5*time.Second).
		WithWriteTimeout(5*time.Second).
		WithHandshakeRetries(5).
		WithRetryBackoff(2*time.Second).
		WithChaChaObfuscation(true, customIV).
		WithSipHashLength(true, 0x1234567890ABCDEF, 0xFEDCBA0987654321).
		WithMTU(1500).
		WithPacketSettings(1600, true).
		WithPaddingSettings(true, 10, 100, 2.5).
		WithConnectionID(12345).
		WithKeepalive(30 * time.Second)

	// Verify chaining returns same config
	assert.Equal(t, config, result)

	// Verify all values set correctly
	assert.Equal(t, "IK", config.Pattern)
	assert.Equal(t, 10*time.Second, config.HandshakeTimeout)
	assert.Equal(t, 5*time.Second, config.ReadTimeout)
	assert.Equal(t, 5*time.Second, config.WriteTimeout)
	assert.Equal(t, 5, config.HandshakeRetries)
	assert.Equal(t, 2*time.Second, config.RetryBackoff)
	assert.Equal(t, 1500, config.MTU)
	assert.Equal(t, 1600, config.MaxPacketSize)
	assert.True(t, config.EnableFragmentation)
	assert.Equal(t, 10, config.MinPaddingSize)
	assert.Equal(t, 100, config.MaxPaddingSize)
	assert.Equal(t, 2.5, config.PaddingRatio)
	assert.Equal(t, uint64(12345), config.ConnectionID)
	assert.Equal(t, 30*time.Second, config.KeepaliveInterval)
	assert.Equal(t, uint64(0x1234567890ABCDEF), config.SipHashKeys[0])
	assert.Equal(t, uint64(0xFEDCBA0987654321), config.SipHashKeys[1])
}

// TestSSU2Config_WithStaticKey verifies static key defensive copying.
func TestSSU2Config_WithStaticKey(t *testing.T) {
	routerHash := make([]byte, 32)
	config, _ := NewSSU2Config(routerHash, true)

	t.Run("valid key is copied", func(t *testing.T) {
		staticKey := make([]byte, 32)
		for i := range staticKey {
			staticKey[i] = byte(i)
		}

		config.WithStaticKey(staticKey)
		require.Equal(t, 32, len(config.StaticKey))

		// Modify original, verify config unchanged
		staticKey[0] = 255
		assert.Equal(t, byte(0), config.StaticKey[0])
	})

	t.Run("invalid key length is ignored", func(t *testing.T) {
		invalidKey := make([]byte, 31)
		config.WithStaticKey(invalidKey)
		assert.Equal(t, 32, len(config.StaticKey)) // Still has old value
	})
}

// TestSSU2Config_WithRemoteRouterHash verifies remote hash defensive copying.
func TestSSU2Config_WithRemoteRouterHash(t *testing.T) {
	routerHash := make([]byte, 32)
	config, _ := NewSSU2Config(routerHash, true)

	t.Run("valid hash is copied", func(t *testing.T) {
		remoteHash := make([]byte, 32)
		for i := range remoteHash {
			remoteHash[i] = byte(i + 100)
		}

		config.WithRemoteRouterHash(remoteHash)
		require.Equal(t, 32, len(config.RemoteRouterHash))

		// Modify original, verify config unchanged
		remoteHash[0] = 255
		assert.Equal(t, byte(100), config.RemoteRouterHash[0])
	})

	t.Run("invalid hash length is ignored", func(t *testing.T) {
		freshConfig, _ := NewSSU2Config(routerHash, true)
		invalidHash := make([]byte, 31)
		freshConfig.WithRemoteRouterHash(invalidHash)
		assert.Equal(t, 0, len(freshConfig.RemoteRouterHash)) // Not set
	})
}

// TestSSU2Config_WithChaChaObfuscation verifies IV handling.
func TestSSU2Config_WithChaChaObfuscation(t *testing.T) {
	routerHash := make([]byte, 32)

	t.Run("valid IV is copied", func(t *testing.T) {
		config, _ := NewSSU2Config(routerHash, true)
		customIV := []byte{1, 2, 3, 4, 5, 6, 7, 8}
		config.WithChaChaObfuscation(true, customIV)

		require.Equal(t, 8, len(config.ObfuscationIV))
		customIV[0] = 255
		assert.Equal(t, byte(1), config.ObfuscationIV[0])
	})

	t.Run("invalid IV length is ignored", func(t *testing.T) {
		config, _ := NewSSU2Config(routerHash, true)
		invalidIV := make([]byte, 16) // Wrong length for SSU2
		config.WithChaChaObfuscation(true, invalidIV)
		assert.Nil(t, config.ObfuscationIV)
	})

	t.Run("disabled obfuscation", func(t *testing.T) {
		config, _ := NewSSU2Config(routerHash, true)
		config.WithChaChaObfuscation(false, nil)
		assert.False(t, config.EnableChaChaObfuscation)
	})
}

// TestSSU2Config_WithMTU verifies MTU range validation.
func TestSSU2Config_WithMTU(t *testing.T) {
	routerHash := make([]byte, 32)

	testCases := []struct {
		name     string
		mtu      int
		expected int
	}{
		{"minimum valid", 1280, 1280},
		{"maximum valid", 1500, 1500},
		{"middle value", 1400, 1400},
		{"too small ignored", 1279, 1280}, // Keeps default
		{"too large ignored", 1501, 1280}, // Keeps default
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			freshConfig, _ := NewSSU2Config(routerHash, true)
			freshConfig.WithMTU(tc.mtu)
			assert.Equal(t, tc.expected, freshConfig.MTU)
		})
	}
}

// TestSSU2Config_WithPaddingSettings verifies padding parameter validation.
func TestSSU2Config_WithPaddingSettings(t *testing.T) {
	routerHash := make([]byte, 32)

	t.Run("valid padding settings", func(t *testing.T) {
		config, _ := NewSSU2Config(routerHash, true)
		config.WithPaddingSettings(true, 10, 100, 5.5)

		assert.True(t, config.PaddingEnabled)
		assert.Equal(t, 10, config.MinPaddingSize)
		assert.Equal(t, 100, config.MaxPaddingSize)
		assert.Equal(t, 5.5, config.PaddingRatio)
	})

	t.Run("invalid ratio ignored", func(t *testing.T) {
		config, _ := NewSSU2Config(routerHash, true)
		config.WithPaddingSettings(true, 0, 64, 20.0) // Exceeds 15.9375

		assert.Equal(t, 1.0, config.PaddingRatio) // Keeps default
	})

	t.Run("negative padding ignored", func(t *testing.T) {
		config, _ := NewSSU2Config(routerHash, true)
		config.WithPaddingSettings(true, -5, 64, 1.0)

		assert.Equal(t, 0, config.MinPaddingSize) // Keeps default
	})
}

// TestSSU2Config_Validate verifies comprehensive validation.
func TestSSU2Config_Validate(t *testing.T) {
	t.Run("valid config passes", func(t *testing.T) {
		routerHash := make([]byte, 32)
		config, _ := NewSSU2Config(routerHash, false)

		err := config.Validate()
		assert.NoError(t, err)
	})

	t.Run("missing pattern fails", func(t *testing.T) {
		routerHash := make([]byte, 32)
		config, _ := NewSSU2Config(routerHash, true)
		config.Pattern = ""

		err := config.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "noise pattern is required")
	})

	t.Run("invalid router hash fails", func(t *testing.T) {
		config := &SSU2Config{
			Pattern:    "XK",
			RouterHash: make([]byte, 31),
		}

		err := config.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "router hash must be exactly 32 bytes")
	})

	t.Run("invalid static key fails", func(t *testing.T) {
		routerHash := make([]byte, 32)
		config, _ := NewSSU2Config(routerHash, true)
		config.StaticKey = make([]byte, 31)

		err := config.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "static key must be 32 bytes")
	})

	t.Run("initiator without remote hash fails", func(t *testing.T) {
		routerHash := make([]byte, 32)
		config, _ := NewSSU2Config(routerHash, true)
		config.RemoteRouterHash = nil

		err := config.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "remote router hash is required for initiator")
	})

	t.Run("invalid obfuscation IV fails", func(t *testing.T) {
		routerHash := make([]byte, 32)
		config, _ := NewSSU2Config(routerHash, false)
		config.ObfuscationIV = make([]byte, 16) // Wrong length for SSU2

		err := config.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "obfuscation IV must be 8 bytes")
	})

	t.Run("invalid handshake timeout fails", func(t *testing.T) {
		routerHash := make([]byte, 32)
		config, _ := NewSSU2Config(routerHash, false)
		config.HandshakeTimeout = -1 * time.Second

		err := config.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "handshake timeout must be positive")
	})

	t.Run("invalid retry count fails", func(t *testing.T) {
		routerHash := make([]byte, 32)
		config, _ := NewSSU2Config(routerHash, false)
		config.HandshakeRetries = -2

		err := config.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "handshake retries must be >= -1")
	})

	t.Run("invalid keepalive interval fails", func(t *testing.T) {
		routerHash := make([]byte, 32)
		config, _ := NewSSU2Config(routerHash, false)
		config.KeepaliveInterval = 0

		err := config.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "keepalive interval must be positive")
	})

	t.Run("invalid MTU fails", func(t *testing.T) {
		routerHash := make([]byte, 32)
		config, _ := NewSSU2Config(routerHash, false)
		config.MTU = 1000 // Too small

		err := config.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "MTU must be between 1280 and 1500")
	})

	t.Run("packet size less than MTU fails", func(t *testing.T) {
		routerHash := make([]byte, 32)
		config, _ := NewSSU2Config(routerHash, false)
		config.MTU = 1400
		config.MaxPacketSize = 1300

		err := config.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "max packet size must be >= MTU")
	})

	t.Run("invalid padding range fails", func(t *testing.T) {
		routerHash := make([]byte, 32)
		config, _ := NewSSU2Config(routerHash, false)
		config.MaxPaddingSize = 10
		config.MinPaddingSize = 20

		err := config.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "max padding size must be >= min padding size")
	})

	t.Run("invalid padding ratio fails", func(t *testing.T) {
		routerHash := make([]byte, 32)
		config, _ := NewSSU2Config(routerHash, false)
		config.PaddingRatio = 20.0

		err := config.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "padding ratio must be between 0.0 and 15.9375")
	})
}

// TestSSU2Config_ToConnConfig verifies conversion to base ConnConfig.
func TestSSU2Config_ToConnConfig(t *testing.T) {
	t.Run("valid config converts successfully", func(t *testing.T) {
		routerHash := make([]byte, 32)
		for i := range routerHash {
			routerHash[i] = byte(i)
		}
		staticKey := make([]byte, 32)
		for i := range staticKey {
			staticKey[i] = byte(i + 100)
		}

		ssu2Config, err := NewSSU2Config(routerHash, false)
		require.NoError(t, err)

		ssu2Config.WithStaticKey(staticKey).
			WithHandshakeTimeout(20 * time.Second).
			WithReadTimeout(10 * time.Second)

		connConfig, err := ssu2Config.ToConnConfig()
		require.NoError(t, err)
		require.NotNil(t, connConfig)

		// Verify base config fields
		assert.Equal(t, "XK", connConfig.Pattern)
		assert.False(t, connConfig.Initiator)
		assert.Equal(t, 32, len(connConfig.StaticKey))
		assert.Equal(t, 20*time.Second, connConfig.HandshakeTimeout)
		assert.Equal(t, 10*time.Second, connConfig.ReadTimeout)

		// Verify modifiers are set up
		assert.NotEmpty(t, connConfig.Modifiers)
	})

	t.Run("invalid config fails conversion", func(t *testing.T) {
		routerHash := make([]byte, 32)
		config, _ := NewSSU2Config(routerHash, true)
		config.HandshakeTimeout = -1 * time.Second // Invalid

		connConfig, err := config.ToConnConfig()
		assert.Error(t, err)
		assert.Nil(t, connConfig)
	})

	t.Run("modifiers are created with correct settings", func(t *testing.T) {
		routerHash := make([]byte, 32)
		config, _ := NewSSU2Config(routerHash, false)

		config.EnableChaChaObfuscation = true
		config.PaddingEnabled = true
		config.EnableSipHashLength = true

		connConfig, err := config.ToConnConfig()
		require.NoError(t, err)

		// Should have ChaCha, Padding, and SipHash modifiers
		assert.GreaterOrEqual(t, len(connConfig.Modifiers), 3)
	})

	t.Run("disabled modifiers are not created", func(t *testing.T) {
		routerHash := make([]byte, 32)
		config, _ := NewSSU2Config(routerHash, false)

		config.EnableChaChaObfuscation = false
		config.PaddingEnabled = false
		config.EnableSipHashLength = false

		connConfig, err := config.ToConnConfig()
		require.NoError(t, err)

		// Should have no modifiers
		assert.Empty(t, connConfig.Modifiers)
	})

	t.Run("static key is defensively copied", func(t *testing.T) {
		routerHash := make([]byte, 32)
		staticKey := make([]byte, 32)
		for i := range staticKey {
			staticKey[i] = byte(i)
		}

		config, _ := NewSSU2Config(routerHash, false)
		config.WithStaticKey(staticKey)

		connConfig, err := config.ToConnConfig()
		require.NoError(t, err)

		// Modify ssu2Config's key
		config.StaticKey[0] = 255

		// Verify connConfig's key is unchanged
		assert.Equal(t, byte(0), connConfig.StaticKey[0])
	})
}

// TestSSU2Config_WithModifiers verifies custom modifier handling.
func TestSSU2Config_WithModifiers(t *testing.T) {
	routerHash := make([]byte, 32)
	config, _ := NewSSU2Config(routerHash, false)

	// Create a mock modifier (using existing ChaCha modifier for testing)
	customIV := make([]byte, 8)
	modifier1, _ := NewChaChaObfuscationModifier("custom1", routerHash, customIV)
	modifier2, _ := NewChaChaObfuscationModifier("custom2", routerHash, customIV)

	config.WithModifiers(modifier1, modifier2)

	assert.Equal(t, 2, len(config.Modifiers))
	assert.Equal(t, "custom1", config.Modifiers[0].Name())
	assert.Equal(t, "custom2", config.Modifiers[1].Name())
}

// TestSSU2Config_EdgeCases tests boundary conditions.
func TestSSU2Config_EdgeCases(t *testing.T) {
	t.Run("zero connection ID is valid", func(t *testing.T) {
		routerHash := make([]byte, 32)
		config, _ := NewSSU2Config(routerHash, false)
		config.WithConnectionID(0)

		err := config.Validate()
		assert.NoError(t, err)
	})

	t.Run("max padding ratio is valid", func(t *testing.T) {
		routerHash := make([]byte, 32)
		config, _ := NewSSU2Config(routerHash, false)
		config.WithPaddingSettings(true, 0, 64, 15.9375)

		err := config.Validate()
		assert.NoError(t, err)
	})

	t.Run("infinite retries (-1) is valid", func(t *testing.T) {
		routerHash := make([]byte, 32)
		config, _ := NewSSU2Config(routerHash, false)
		config.WithHandshakeRetries(-1)

		err := config.Validate()
		assert.NoError(t, err)
	})

	t.Run("zero timeouts for read/write are valid", func(t *testing.T) {
		routerHash := make([]byte, 32)
		config, _ := NewSSU2Config(routerHash, false)
		config.WithReadTimeout(0).WithWriteTimeout(0)

		err := config.Validate()
		assert.NoError(t, err)
	})
}

// Benchmark configuration creation and conversion.
func BenchmarkSSU2Config_Creation(b *testing.B) {
	routerHash := make([]byte, 32)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		config, _ := NewSSU2Config(routerHash, true)
		_ = config
	}
}

func BenchmarkSSU2Config_ToConnConfig(b *testing.B) {
	routerHash := make([]byte, 32)
	config, _ := NewSSU2Config(routerHash, false)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		connConfig, _ := config.ToConnConfig()
		_ = connConfig
	}
}
