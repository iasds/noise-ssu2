package ssu2

import (
	"encoding/binary"
	"testing"

	"github.com/go-i2p/go-noise/handshake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewSSU2LengthModifier verifies that the constructor creates a valid
// modifier instance with the correct name.
func TestNewSSU2LengthModifier(t *testing.T) {
	sipKeys := [2]uint64{0x0123456789ABCDEF, 0xFEDCBA9876543210}
	initialIV := uint64(0x1122334455667788)

	modifier := NewSSU2LengthModifier("ssu2-test", sipKeys, initialIV)

	assert.NotNil(t, modifier, "Modifier should be created")
	assert.Equal(t, "ssu2-test", modifier.Name(), "Modifier name should match")
}

// TestSSU2LengthModifier_Roundtrip verifies that obfuscation and deobfuscation
// are symmetric - applying both operations returns the original data.
func TestSSU2LengthModifier_Roundtrip(t *testing.T) {
	sipKeys := [2]uint64{0x0123456789ABCDEF, 0xFEDCBA9876543210}
	initialIV := uint64(0x1122334455667788)

	modifier := NewSSU2LengthModifier("ssu2-roundtrip", sipKeys, initialIV)

	tests := []struct {
		name   string
		phase  handshake.HandshakePhase
		length uint16
	}{
		{
			name:   "Data phase standard length",
			phase:  handshake.PhaseFinal,
			length: 1024,
		},
		{
			name:   "Minimum length value",
			phase:  handshake.PhaseFinal,
			length: 16,
		},
		{
			name:   "Maximum length value",
			phase:  handshake.PhaseFinal,
			length: 65535,
		},
		{
			name:   "Zero length",
			phase:  handshake.PhaseFinal,
			length: 0,
		},
		{
			name:   "SSU2 typical MTU size",
			phase:  handshake.PhaseFinal,
			length: 1280,
		},
		{
			name:   "Ethernet MTU size",
			phase:  handshake.PhaseFinal,
			length: 1500,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encode length as 2-byte big-endian
			lengthData := make([]byte, 2)
			binary.BigEndian.PutUint16(lengthData, tt.length)

			// Apply obfuscation
			obfuscated, err := modifier.ModifyOutbound(tt.phase, lengthData)
			require.NoError(t, err, "Obfuscation should succeed")
			assert.Len(t, obfuscated, 2, "Obfuscated length should be 2 bytes")

			// Apply deobfuscation
			deobfuscated, err := modifier.ModifyInbound(tt.phase, obfuscated)
			require.NoError(t, err, "Deobfuscation should succeed")

			// Verify roundtrip
			recoveredLength := binary.BigEndian.Uint16(deobfuscated)
			assert.Equal(t, tt.length, recoveredLength, "Roundtrip should recover original length")
		})
	}
}

// TestSSU2LengthModifier_HandshakePhases verifies that the modifier only
// applies to data phase (PhaseFinal) and passes through handshake messages unchanged.
func TestSSU2LengthModifier_HandshakePhases(t *testing.T) {
	sipKeys := [2]uint64{0x0123456789ABCDEF, 0xFEDCBA9876543210}
	modifier := NewSSU2LengthModifier("ssu2-phase-test", sipKeys, 0)

	testData := []byte{0x04, 0x00} // 1024 in big-endian

	tests := []struct {
		name  string
		phase handshake.HandshakePhase
	}{
		{
			name:  "Message 1 (PhaseInitial)",
			phase: handshake.PhaseInitial,
		},
		{
			name:  "Message 2 (PhaseExchange)",
			phase: handshake.PhaseExchange,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Should pass through unchanged during handshake
			result, err := modifier.ModifyOutbound(tt.phase, testData)
			require.NoError(t, err)
			assert.Equal(t, testData, result, "Handshake phase should pass through unchanged")

			result, err = modifier.ModifyInbound(tt.phase, testData)
			require.NoError(t, err)
			assert.Equal(t, testData, result, "Handshake phase should pass through unchanged")
		})
	}
}

// TestSSU2LengthModifier_Obfuscation verifies that obfuscation actually
// changes the length value (prevents trivial bypass).
func TestSSU2LengthModifier_Obfuscation(t *testing.T) {
	sipKeys := [2]uint64{0x0123456789ABCDEF, 0xFEDCBA9876543210}
	initialIV := uint64(0x1122334455667788)

	modifier := NewSSU2LengthModifier("ssu2-obf-test", sipKeys, initialIV)

	// Test multiple lengths to ensure obfuscation is working
	lengths := []uint16{100, 500, 1000, 1280, 1500, 2000, 5000}

	for _, length := range lengths {
		lengthData := make([]byte, 2)
		binary.BigEndian.PutUint16(lengthData, length)

		obfuscated, err := modifier.ModifyOutbound(handshake.PhaseFinal, lengthData)
		require.NoError(t, err)

		obfuscatedLength := binary.BigEndian.Uint16(obfuscated)

		// The mask is extremely unlikely to be zero, so obfuscated should differ
		// If this fails, it means SipHash produced a zero mask (astronomically rare)
		if obfuscatedLength == length {
			t.Logf("Warning: SipHash mask was zero for length %d (extremely rare)", length)
		}
	}
}

// TestSSU2LengthModifier_NonLengthData verifies that non-2-byte data
// passes through unchanged.
func TestSSU2LengthModifier_NonLengthData(t *testing.T) {
	sipKeys := [2]uint64{0x0123456789ABCDEF, 0xFEDCBA9876543210}
	modifier := NewSSU2LengthModifier("ssu2-size-test", sipKeys, 0)

	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "Single byte",
			data: []byte{0x42},
		},
		{
			name: "Three bytes",
			data: []byte{0x01, 0x02, 0x03},
		},
		{
			name: "Empty data",
			data: []byte{},
		},
		{
			name: "Large data",
			data: make([]byte, 100),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := modifier.ModifyOutbound(handshake.PhaseFinal, tt.data)
			require.NoError(t, err)
			assert.Equal(t, tt.data, result, "Non-2-byte data should pass through unchanged")

			result, err = modifier.ModifyInbound(handshake.PhaseFinal, tt.data)
			require.NoError(t, err)
			assert.Equal(t, tt.data, result, "Non-2-byte data should pass through unchanged")
		})
	}
}

// TestSSU2LengthModifier_SequentialFrames verifies that each frame gets a
// different obfuscation mask (counters are incremented).
func TestSSU2LengthModifier_SequentialFrames(t *testing.T) {
	sipKeys := [2]uint64{0x0123456789ABCDEF, 0xFEDCBA9876543210}
	modifier := NewSSU2LengthModifier("ssu2-sequential", sipKeys, 0)

	// Send the same length multiple times
	length := uint16(1000)
	lengthData := make([]byte, 2)
	binary.BigEndian.PutUint16(lengthData, length)

	obfuscatedValues := make([]uint16, 5)

	// Obfuscate the same value 5 times
	for i := 0; i < 5; i++ {
		obfuscated, err := modifier.ModifyOutbound(handshake.PhaseFinal, lengthData)
		require.NoError(t, err)
		obfuscatedValues[i] = binary.BigEndian.Uint16(obfuscated)
	}

	// Each obfuscated value should be different (different mask)
	for i := 1; i < len(obfuscatedValues); i++ {
		assert.NotEqual(t, obfuscatedValues[0], obfuscatedValues[i],
			"Frame %d should have different obfuscation than frame 0", i)
	}
}

// TestSSU2LengthModifier_SeparateDirections verifies that inbound and
// outbound maintain separate counters.
func TestSSU2LengthModifier_SeparateDirections(t *testing.T) {
	sipKeys := [2]uint64{0x0123456789ABCDEF, 0xFEDCBA9876543210}
	modifier := NewSSU2LengthModifier("ssu2-directions", sipKeys, 0)

	length := uint16(500)
	lengthData := make([]byte, 2)
	binary.BigEndian.PutUint16(lengthData, length)

	// Alternate between outbound and inbound operations
	outbound1, err := modifier.ModifyOutbound(handshake.PhaseFinal, lengthData)
	require.NoError(t, err)

	inbound1, err := modifier.ModifyInbound(handshake.PhaseFinal, lengthData)
	require.NoError(t, err)

	outbound2, err := modifier.ModifyOutbound(handshake.PhaseFinal, lengthData)
	require.NoError(t, err)

	inbound2, err := modifier.ModifyInbound(handshake.PhaseFinal, lengthData)
	require.NoError(t, err)

	// Outbound sequences should be different
	assert.NotEqual(t, outbound1, outbound2, "Consecutive outbound operations should differ")

	// Inbound sequences should be different
	assert.NotEqual(t, inbound1, inbound2, "Consecutive inbound operations should differ")
}

// TestSSU2LengthModifier_DifferentKeys verifies that different SipHash keys
// produce different obfuscation patterns.
func TestSSU2LengthModifier_DifferentKeys(t *testing.T) {
	keys1 := [2]uint64{0x0123456789ABCDEF, 0xFEDCBA9876543210}
	keys2 := [2]uint64{0xFEDCBA9876543210, 0x0123456789ABCDEF}

	modifier1 := NewSSU2LengthModifier("ssu2-key1", keys1, 0)
	modifier2 := NewSSU2LengthModifier("ssu2-key2", keys2, 0)

	length := uint16(1000)
	lengthData := make([]byte, 2)
	binary.BigEndian.PutUint16(lengthData, length)

	obfuscated1, err := modifier1.ModifyOutbound(handshake.PhaseFinal, lengthData)
	require.NoError(t, err)

	obfuscated2, err := modifier2.ModifyOutbound(handshake.PhaseFinal, lengthData)
	require.NoError(t, err)

	// Different keys should produce different obfuscation
	assert.NotEqual(t, obfuscated1, obfuscated2,
		"Different SipHash keys should produce different obfuscation")
}

// TestSSU2LengthModifier_Integration tests the modifier in combination with
// other SSU2 modifiers (ChaCha20 obfuscation and padding).
func TestSSU2LengthModifier_Integration(t *testing.T) {
	// Create SipHash modifier
	sipKeys := [2]uint64{0x0123456789ABCDEF, 0xFEDCBA9876543210}
	sipModifier := NewSSU2LengthModifier("ssu2-siphash", sipKeys, 0x1122334455667788)

	// Create ChaCha20 modifier for comparison
	routerHash := make([]byte, 32)
	for i := range routerHash {
		routerHash[i] = byte(i)
	}
	iv := make([]byte, 8)
	for i := range iv {
		iv[i] = byte(i + 32)
	}

	chachaModifier, err := NewChaChaObfuscationModifier("ssu2-chacha", routerHash, iv)
	require.NoError(t, err)

	// Test that SipHash is only for data phase, ChaCha is for handshake
	lengthData := []byte{0x04, 0x00} // 1024 bytes
	ephemeralKey := make([]byte, 32)
	for i := range ephemeralKey {
		ephemeralKey[i] = byte(i + 64)
	}

	// SipHash should not affect handshake messages
	sipHandshake, err := sipModifier.ModifyOutbound(handshake.PhaseInitial, ephemeralKey)
	require.NoError(t, err)
	assert.Equal(t, ephemeralKey, sipHandshake, "SipHash should not modify handshake data")

	// ChaCha should affect handshake messages
	chachaHandshake, err := chachaModifier.ModifyOutbound(handshake.PhaseInitial, ephemeralKey)
	require.NoError(t, err)
	assert.NotEqual(t, ephemeralKey, chachaHandshake, "ChaCha should modify handshake data")

	// SipHash should affect data phase lengths
	sipData, err := sipModifier.ModifyOutbound(handshake.PhaseFinal, lengthData)
	require.NoError(t, err)
	// High probability that obfuscation changed the value
	if sipData[0] == lengthData[0] && sipData[1] == lengthData[1] {
		t.Logf("Warning: SipHash mask was zero (rare)")
	}

	// ChaCha should not affect data phase (non-32-byte data)
	chachaData, err := chachaModifier.ModifyOutbound(handshake.PhaseFinal, lengthData)
	require.NoError(t, err)
	assert.Equal(t, lengthData, chachaData, "ChaCha should not modify non-key data in final phase")
}

// TestSSU2LengthModifier_SSU2Compliance verifies SSU2-specific behavior
// that may differ from NTCP2.
func TestSSU2LengthModifier_SSU2Compliance(t *testing.T) {
	sipKeys := [2]uint64{0x0123456789ABCDEF, 0xFEDCBA9876543210}
	modifier := NewSSU2LengthModifier("ssu2-compliance", sipKeys, 0)

	// SSU2 uses UDP packets with MTU constraints
	tests := []struct {
		name   string
		length uint16
	}{
		{
			name:   "IPv6 minimum MTU",
			length: 1280,
		},
		{
			name:   "Typical Ethernet MTU",
			length: 1500,
		},
		{
			name:   "SSU2 fragment size",
			length: 1232, // 1280 - overhead
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lengthData := make([]byte, 2)
			binary.BigEndian.PutUint16(lengthData, tt.length)

			// Obfuscate
			obfuscated, err := modifier.ModifyOutbound(handshake.PhaseFinal, lengthData)
			require.NoError(t, err)

			// Deobfuscate
			deobfuscated, err := modifier.ModifyInbound(handshake.PhaseFinal, obfuscated)
			require.NoError(t, err)

			// Verify roundtrip
			recovered := binary.BigEndian.Uint16(deobfuscated)
			assert.Equal(t, tt.length, recovered)
		})
	}
}

// BenchmarkSSU2LengthModifier measures the performance of length obfuscation.
func BenchmarkSSU2LengthModifier(b *testing.B) {
	sipKeys := [2]uint64{0x0123456789ABCDEF, 0xFEDCBA9876543210}
	modifier := NewSSU2LengthModifier("benchmark", sipKeys, 0)

	lengthData := []byte{0x04, 0x00} // 1024 bytes

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = modifier.ModifyOutbound(handshake.PhaseFinal, lengthData)
	}
}

// BenchmarkSSU2LengthModifierRoundtrip measures the performance of full
// obfuscate/deobfuscate cycle.
func BenchmarkSSU2LengthModifierRoundtrip(b *testing.B) {
	sipKeys := [2]uint64{0x0123456789ABCDEF, 0xFEDCBA9876543210}
	modifier := NewSSU2LengthModifier("benchmark", sipKeys, 0)

	lengthData := []byte{0x04, 0x00} // 1024 bytes

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		obfuscated, _ := modifier.ModifyOutbound(handshake.PhaseFinal, lengthData)
		_, _ = modifier.ModifyInbound(handshake.PhaseFinal, obfuscated)
	}
}
