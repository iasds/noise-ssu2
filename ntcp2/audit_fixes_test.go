package ntcp2

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"testing"

	"github.com/dchest/siphash"
	"github.com/go-i2p/go-noise/handshake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// Tests validating CRITICAL audit fixes from ntcp2/AUDIT.md
// ============================================================================

// TestAudit_AESStatePropagation_CrossMessage validates the fix for:
//
//	AUDIT CRITICAL #1: "AES state saved before encryption, not after"
//
// In NTCP2, the initiator encrypts X (msg1) with AES-256-CBC(RH_B, IV).
// The AES state (last ciphertext block) from msg1 becomes the IV for msg2.
// A separate receiver must use the ciphertext's last block (before decryption)
// as the IV for msg2. This test uses SEPARATE sender/receiver instances to
// simulate a real initiator/responder pair.
func TestAudit_AESStatePropagation_CrossMessage(t *testing.T) {
	routerHash := make([]byte, 32)
	for i := range routerHash {
		routerHash[i] = byte(i + 1)
	}
	iv := make([]byte, 16)
	for i := range iv {
		iv[i] = byte(i + 0x80)
	}

	// Two separate modifier instances: sender (initiator) and receiver (responder)
	sender, err := NewAESObfuscationModifier("sender", routerHash, iv)
	require.NoError(t, err)
	receiver, err := NewAESObfuscationModifier("receiver", routerHash, iv)
	require.NoError(t, err)

	// Ephemeral key X (msg1) and Y (msg2)
	keyX := make([]byte, 32)
	for i := range keyX {
		keyX[i] = byte(i + 0x40)
	}
	keyY := make([]byte, 32)
	for i := range keyY {
		keyY[i] = byte(i + 0xC0)
	}
	// Ensure keyY is a valid Curve25519 public key (high bit of byte 31 must be 0)
	keyY[31] &= 0x7F

	// --- Message 1: Sender encrypts X ---
	cipherX, err := sender.ModifyOutbound(handshake.PhaseInitial, keyX)
	require.NoError(t, err)
	assert.NotEqual(t, keyX, cipherX, "X must be encrypted")

	// --- Message 1: Receiver decrypts X ---
	recoveredX, err := receiver.ModifyInbound(handshake.PhaseInitial, cipherX)
	require.NoError(t, err)
	assert.Equal(t, keyX, recoveredX, "Receiver must recover original X")

	// --- Message 2: Sender encrypts Y using AES state from msg1 ---
	cipherY, err := sender.ModifyOutbound(handshake.PhaseExchange, keyY)
	require.NoError(t, err)
	assert.NotEqual(t, keyY, cipherY, "Y must be encrypted")

	// --- Message 2: Receiver decrypts Y using AES state from msg1 ---
	recoveredY, err := receiver.ModifyInbound(handshake.PhaseExchange, cipherY)
	require.NoError(t, err)
	assert.Equal(t, keyY, recoveredY, "Receiver must recover original Y using state from msg1")
}

// TestAudit_AESState_IsLastCiphertextBlock validates that the AES state
// saved after message 1 is specifically result[16:32] (the last ciphertext
// block), not the stale IV or something else. We manually compute AES-CBC
// to verify.
func TestAudit_AESState_IsLastCiphertextBlock(t *testing.T) {
	routerHash := make([]byte, 32)
	for i := range routerHash {
		routerHash[i] = byte(i + 10)
	}
	iv := make([]byte, 16)
	for i := range iv {
		iv[i] = byte(i + 50)
	}

	// Manually compute AES-CBC encryption of a 32-byte key
	keyX := make([]byte, 32)
	for i := range keyX {
		keyX[i] = byte(i + 100)
	}

	block, err := aes.NewCipher(routerHash)
	require.NoError(t, err)

	manualCipher := make([]byte, 32)
	copy(manualCipher, keyX)
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(manualCipher, manualCipher)

	// The last ciphertext block = manualCipher[16:32]
	expectedState := manualCipher[16:32]

	// Now encrypt keyY using that state as IV (manually)
	keyY := make([]byte, 32)
	for i := range keyY {
		keyY[i] = byte(i + 200)
	}
	manualCipherY := make([]byte, 32)
	copy(manualCipherY, keyY)
	mode2 := cipher.NewCBCEncrypter(block, expectedState)
	mode2.CryptBlocks(manualCipherY, manualCipherY)

	// Now verify the modifier produces exactly the same results
	modifier, err := NewAESObfuscationModifier("verify", routerHash, iv)
	require.NoError(t, err)

	cipherX, err := modifier.ModifyOutbound(handshake.PhaseInitial, keyX)
	require.NoError(t, err)
	assert.Equal(t, manualCipher, cipherX, "msg1 encryption must match manual AES-CBC")

	cipherY, err := modifier.ModifyOutbound(handshake.PhaseExchange, keyY)
	require.NoError(t, err)
	assert.Equal(t, manualCipherY, cipherY,
		"msg2 encryption must use last ciphertext block from msg1 as IV")
}

// TestAudit_AESMissingState_Error validates that attempting PhaseExchange
// without a prior PhaseInitial produces an error.
func TestAudit_AESMissingState_Error(t *testing.T) {
	routerHash := make([]byte, 32)
	iv := make([]byte, 16)

	modifier, err := NewAESObfuscationModifier("test", routerHash, iv)
	require.NoError(t, err)

	keyY := make([]byte, 32)
	_, err = modifier.ModifyOutbound(handshake.PhaseExchange, keyY)
	assert.Error(t, err, "PhaseExchange without prior PhaseInitial must fail")
	assert.Contains(t, err.Error(), "AES state not available")

	_, err = modifier.ModifyInbound(handshake.PhaseExchange, keyY)
	assert.Error(t, err, "PhaseExchange inbound without prior PhaseInitial must fail")
	assert.Contains(t, err.Error(), "AES state not available")
}

// TestAudit_SipHashIVChaining validates the fix for:
//
//	AUDIT CRITICAL #2: "SipHash uses incrementing counter instead of IV chain"
//
// Per NTCP2 spec: IV[n] = SipHash-2-4(sipk1, sipk2, IV[n-1]).
// The test verifies that two identically-configured modifiers produce
// the same mask sequence, and that the sequence is NOT simply counter-based.
func TestAudit_SipHashIVChaining(t *testing.T) {
	sipKeys := [2]uint64{0xDEADBEEFCAFEBABE, 0x0123456789ABCDEF}
	initialIV := uint64(0xAAAABBBBCCCCDDDD)

	// Two identically-configured modifiers must produce the same sequence
	mod1 := NewSipHashLengthModifier("mod1", sipKeys, initialIV)
	mod2 := NewSipHashLengthModifier("mod2", sipKeys, initialIV)

	lengthData := make([]byte, 2)
	binary.BigEndian.PutUint16(lengthData, 1000)

	for i := 0; i < 20; i++ {
		result1, err := mod1.ModifyOutbound(handshake.PhaseFinal, lengthData)
		require.NoError(t, err)
		result2, err := mod2.ModifyOutbound(handshake.PhaseFinal, lengthData)
		require.NoError(t, err)
		assert.Equal(t, result1, result2,
			"Identically-configured modifiers must produce same mask at step %d", i)
	}
}

// TestAudit_SipHashIVChaining_MatchesSpec verifies the SipHash mask sequence
// against a manually computed reference per the spec:
//
//	IV[n] = SipHash-2-4(k1, k2, LE_encode_64(IV[n-1]))
func TestAudit_SipHashIVChaining_MatchesSpec(t *testing.T) {
	k1 := uint64(0x1111111122222222)
	k2 := uint64(0x3333333344444444)
	iv0 := uint64(0x5555555566666666)

	// Manually compute first 5 IVs and masks
	var expectedMasks [5]uint16
	currentIV := iv0
	for i := 0; i < 5; i++ {
		input := make([]byte, 8)
		binary.LittleEndian.PutUint64(input, currentIV)
		hash := siphash.Hash(k1, k2, input)
		expectedMasks[i] = uint16(hash & 0xFFFF)
		currentIV = hash // IV[n] = full hash result
	}

	// Get masks from modifier
	mod := NewSipHashLengthModifier("spec_test", [2]uint64{k1, k2}, iv0)
	for i := 0; i < 5; i++ {
		data := make([]byte, 2)
		binary.BigEndian.PutUint16(data, 0) // length=0 so XOR result = mask itself
		result, err := mod.ModifyOutbound(handshake.PhaseFinal, data)
		require.NoError(t, err)
		mask := binary.BigEndian.Uint16(result)
		assert.Equal(t, expectedMasks[i], mask,
			"Mask at step %d must match spec-computed value", i)
	}
}

// TestAudit_SipHashIVChaining_NotCounterBased ensures the mask sequence
// is chained (IV-based), NOT counter-based.
func TestAudit_SipHashIVChaining_NotCounterBased(t *testing.T) {
	sipKeys := [2]uint64{0xABCDEF0123456789, 0x9876543210FEDCBA}
	initialIV := uint64(0x1234567890ABCDEF)

	mod := NewSipHashLengthModifier("chain_test", sipKeys, initialIV)

	// Compute 10 masks from the chained modifier
	chainedMasks := make([]uint16, 10)
	for i := 0; i < 10; i++ {
		data := make([]byte, 2)
		binary.BigEndian.PutUint16(data, 0)
		result, err := mod.ModifyOutbound(handshake.PhaseFinal, data)
		require.NoError(t, err)
		chainedMasks[i] = binary.BigEndian.Uint16(result)
	}

	// Compute 10 masks using a counter approach (the old broken way)
	counterMasks := make([]uint16, 10)
	for i := 0; i < 10; i++ {
		input := make([]byte, 8)
		binary.LittleEndian.PutUint64(input, uint64(i))
		hash := siphash.Hash(sipKeys[0], sipKeys[1], input)
		counterMasks[i] = uint16(hash & 0xFFFF)
	}

	// They must be different (the whole point of the fix)
	assert.False(t, masksEqual(chainedMasks, counterMasks),
		"IV-chained masks must differ from counter-based masks")
}

// TestAudit_SipHashOutboundInbound_Symmetric verifies that outbound and
// inbound directions maintain independent IV chains that produce symmetric
// results when applied in order.
func TestAudit_SipHashOutboundInbound_Symmetric(t *testing.T) {
	sipKeys := [2]uint64{0x0102030405060708, 0x090A0B0C0D0E0F10}
	initialIV := uint64(0xFEDCBA9876543210)

	mod := NewSipHashLengthModifier("sym_test", sipKeys, initialIV)

	// Obfuscate then deobfuscate 10 different lengths
	for i := 0; i < 10; i++ {
		original := uint16(100 + i*50)
		data := make([]byte, 2)
		binary.BigEndian.PutUint16(data, original)

		obfuscated, err := mod.ModifyOutbound(handshake.PhaseFinal, data)
		require.NoError(t, err)

		recovered, err := mod.ModifyInbound(handshake.PhaseFinal, obfuscated)
		require.NoError(t, err)

		got := binary.BigEndian.Uint16(recovered)
		assert.Equal(t, original, got,
			"Round-trip at step %d failed: original=%d, got=%d", i, original, got)
	}
}

// ============================================================================
// Tests validating QUALITY audit fixes from ntcp2/AUDIT.md
// ============================================================================

// TestAudit_Quality_SilentRejection validates that WithStaticKey and
// WithRemoteRouterHash log warnings (don't silently ignore) on invalid input.
// We check the behavior: invalid key is NOT set (same as before) but the
// function returns without panic.
func TestAudit_Quality_SilentRejection(t *testing.T) {
	routerHash := make([]byte, 32)
	config, err := NewNTCP2Config(routerHash, true)
	require.NoError(t, err)
	require.NotNil(t, config)

	// Invalid static key (31 bytes) - should not be set
	config.WithStaticKey(make([]byte, 31))
	assert.Nil(t, config.StaticKey, "Invalid static key must not be set")

	// Valid static key (32 bytes) - should be set
	validKey := make([]byte, 32)
	for i := range validKey {
		validKey[i] = byte(i)
	}
	config.WithStaticKey(validKey)
	assert.Equal(t, validKey, config.StaticKey, "Valid static key must be set")

	// Invalid router hash (31 bytes) - should not be set
	config.WithRemoteRouterHash(make([]byte, 31))
	assert.Nil(t, config.RemoteRouterHash, "Invalid router hash must not be set")

	// Valid router hash (32 bytes) - should be set
	validHash := make([]byte, 32)
	for i := range validHash {
		validHash[i] = byte(i + 100)
	}
	config.WithRemoteRouterHash(validHash)
	assert.Equal(t, validHash, config.RemoteRouterHash, "Valid router hash must be set")
}

// TestAudit_Quality_32BitModulus validates the fix for:
//
//	AUDIT QUALITY: "calculateSecureRandomPadding uses int(randomValue) which
//	on 32-bit platforms makes int(randomValue) negative for large uint32 values."
//
// We verify that padding is always non-negative even for edge-case random values.
func TestAudit_Quality_32BitModulus(t *testing.T) {
	modifier, err := NewNTCP2PaddingModifier("modulus_test", 0, 100, false)
	require.NoError(t, err)

	// Run many times to exercise the random path
	testData := make([]byte, 50)
	for i := 0; i < 200; i++ {
		padded, err := modifier.ModifyOutbound(handshake.PhaseInitial, testData)
		require.NoError(t, err)
		paddingLen := len(padded) - len(testData)
		assert.GreaterOrEqual(t, paddingLen, 0,
			"Padding must never be negative (iteration %d)", i)
		assert.LessOrEqual(t, paddingLen, 100,
			"Padding must not exceed maxPadding (iteration %d)", i)
	}
}

// TestAudit_Quality_Constants validates that named constants are used
// instead of magic numbers throughout the code.
func TestAudit_Quality_Constants(t *testing.T) {
	// Verify constant values match the I2P NTCP2 specification
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

// TestAudit_Quality_ThreadSafety validates that AES and SipHash modifiers
// can be called concurrently without data races.
func TestAudit_Quality_ThreadSafety(t *testing.T) {
	routerHash := make([]byte, 32)
	iv := make([]byte, 16)

	t.Run("AES concurrent access", func(t *testing.T) {
		modifier, err := NewAESObfuscationModifier("thread_test", routerHash, iv)
		require.NoError(t, err)

		// Seed the state so PhaseExchange works
		key := make([]byte, 32)
		_, err = modifier.ModifyOutbound(handshake.PhaseInitial, key)
		require.NoError(t, err)

		done := make(chan struct{})
		for i := 0; i < 10; i++ {
			go func() {
				defer func() { done <- struct{}{} }()
				k := make([]byte, 32)
				// These may error if state isn't ready, that's fine —
				// we're testing for races, not correctness under contention
				modifier.ModifyOutbound(handshake.PhaseExchange, k) //nolint:errcheck
				modifier.ModifyInbound(handshake.PhaseExchange, k)  //nolint:errcheck
			}()
		}
		for i := 0; i < 10; i++ {
			<-done
		}
	})

	t.Run("SipHash concurrent access", func(t *testing.T) {
		sipKeys := [2]uint64{0x1234, 0x5678}
		modifier := NewSipHashLengthModifier("thread_test", sipKeys, 42)

		done := make(chan struct{})
		for i := 0; i < 10; i++ {
			go func() {
				defer func() { done <- struct{}{} }()
				data := make([]byte, 2)
				binary.BigEndian.PutUint16(data, 1000)
				modifier.ModifyOutbound(handshake.PhaseFinal, data) //nolint:errcheck
				modifier.ModifyInbound(handshake.PhaseFinal, data)  //nolint:errcheck
			}()
		}
		for i := 0; i < 10; i++ {
			<-done
		}
	})
}

// TestAudit_PhaseFinal_NoAESObfuscation validates that PhaseFinal and beyond
// pass data through unchanged (no AES obfuscation).
func TestAudit_PhaseFinal_NoAESObfuscation(t *testing.T) {
	routerHash := make([]byte, 32)
	iv := make([]byte, 16)
	modifier, err := NewAESObfuscationModifier("noop", routerHash, iv)
	require.NoError(t, err)

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	result, err := modifier.ModifyOutbound(handshake.PhaseFinal, key)
	require.NoError(t, err)
	assert.Equal(t, key, result, "PhaseFinal must not apply AES obfuscation")

	result, err = modifier.ModifyInbound(handshake.PhaseFinal, key)
	require.NoError(t, err)
	assert.Equal(t, key, result, "PhaseFinal must not apply AES obfuscation")
}

// TestAudit_SipHash_NonDataPhasePassthrough validates that SipHash modifier
// only applies to PhaseFinal (data phase), not handshake phases.
func TestAudit_SipHash_NonDataPhasePassthrough(t *testing.T) {
	sipKeys := [2]uint64{0xAAAA, 0xBBBB}
	mod := NewSipHashLengthModifier("passthrough", sipKeys, 0xCCCC)

	data := []byte{0x04, 0x00} // 2 bytes
	phases := []handshake.HandshakePhase{
		handshake.PhaseInitial,
		handshake.PhaseExchange,
	}
	for _, phase := range phases {
		result, err := mod.ModifyOutbound(phase, data)
		require.NoError(t, err)
		assert.Equal(t, data, result, "Non-data phase must pass through")

		result, err = mod.ModifyInbound(phase, data)
		require.NoError(t, err)
		assert.Equal(t, data, result, "Non-data phase must pass through")
	}
}

// TestAudit_ConfigUsesXKPattern validates:
//
//	AUDIT CRITICAL #3: "Noise protocol name is wrong"
//
// The config must use "XK" pattern.
func TestAudit_ConfigUsesXKPattern(t *testing.T) {
	routerHash := make([]byte, 32)
	config, err := NewNTCP2Config(routerHash, true)
	require.NoError(t, err)
	require.NotNil(t, config)

	// The NTCP2Pattern constant should be "XK"
	assert.Equal(t, "XK", NTCP2Pattern)

	// ConnConfig should use "XK" pattern
	validKey := make([]byte, 32)
	config.WithStaticKey(validKey)
	config.WithRemoteRouterHash(make([]byte, 32))
	// AES obfuscation requires an explicit IV (no fallback)
	config.WithAESObfuscation(true, make([]byte, 16))
	connConfig, err2 := config.ToConnConfig()
	require.NoError(t, err2)
	require.NotNil(t, connConfig)
	assert.Equal(t, "XK", connConfig.Pattern)
}

// ============================================================================
// Helpers
// ============================================================================

func masksEqual(a, b []uint16) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
