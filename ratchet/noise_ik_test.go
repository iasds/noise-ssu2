package ratchet

import (
	"crypto/sha256"
	"testing"

	"github.com/go-i2p/crypto/rand"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// Noise IK Handshake State
// ============================================================================

func TestNoiseIKState_MixHash(t *testing.T) {
	var respPub [32]byte
	_, err := rand.Read(respPub[:])
	require.NoError(t, err)

	ns1 := initNoiseIK(respPub)
	ns2 := initNoiseIK(respPub)

	assert.Equal(t, ns1.h, ns2.h, "Same inputs should produce same initial state")

	ns1.mixHash([]byte("test data"))
	assert.NotEqual(t, ns1.h, ns2.h, "MixHash should change the state")

	ns2.mixHash([]byte("test data"))
	assert.Equal(t, ns1.h, ns2.h, "Same MixHash inputs should produce same state")
}

func TestNoiseIKState_MixKey(t *testing.T) {
	var respPub [32]byte
	_, err := rand.Read(respPub[:])
	require.NoError(t, err)

	ns := initNoiseIK(respPub)
	assert.False(t, ns.hasKey, "No cipher key before MixKey")

	ikm := make([]byte, 32)
	_, err = rand.Read(ikm)
	require.NoError(t, err)

	oldCK := ns.ck
	ns.mixKey(ikm)

	assert.True(t, ns.hasKey, "MixKey should set hasKey")
	assert.NotEqual(t, oldCK, ns.ck, "MixKey should update chaining key")
	assert.Equal(t, uint64(0), ns.n, "MixKey should reset nonce to 0")
}

func TestNoiseIKState_EncryptDecryptAndHash(t *testing.T) {
	var respPub [32]byte
	_, err := rand.Read(respPub[:])
	require.NoError(t, err)

	// Create two identical states
	encState := initNoiseIK(respPub)
	decState := initNoiseIK(respPub)

	// Set same key
	ikm := make([]byte, 32)
	_, err = rand.Read(ikm)
	require.NoError(t, err)
	encState.mixKey(ikm)
	decState.mixKey(ikm)

	// Encrypt
	plaintext := []byte("hello noise protocol")
	ciphertext, err := encState.encryptAndHash(plaintext)
	require.NoError(t, err)
	assert.NotEqual(t, plaintext, ciphertext[:len(plaintext)], "Ciphertext should differ from plaintext")
	assert.Equal(t, len(plaintext)+16, len(ciphertext), "Ciphertext should include 16-byte AEAD tag")

	// Decrypt
	decrypted, err := decState.decryptAndHash(ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)

	// States should match after symmetric operations
	assert.Equal(t, encState.h, decState.h, "Handshake hash should match after encrypt/decrypt")
	assert.Equal(t, encState.n, decState.n, "Nonce counters should match")
}

func TestNoiseIKState_EncryptAndHash_NoKey(t *testing.T) {
	var respPub [32]byte
	_, err := rand.Read(respPub[:])
	require.NoError(t, err)

	ns := initNoiseIK(respPub)
	assert.False(t, ns.hasKey)

	data := []byte("plaintext pass-through")
	result, err := ns.encryptAndHash(data)
	require.NoError(t, err)
	assert.Equal(t, data, result, "Without key, encryptAndHash should pass through")
}

func TestNoiseIKState_DecryptAndHash_TooShort(t *testing.T) {
	var respPub [32]byte
	_, err := rand.Read(respPub[:])
	require.NoError(t, err)

	ns := initNoiseIK(respPub)
	ikm := make([]byte, 32)
	_, err = rand.Read(ikm)
	require.NoError(t, err)
	ns.mixKey(ikm)

	_, err = ns.decryptAndHash(make([]byte, 10))
	assert.Error(t, err, "Should reject ciphertext shorter than 16 bytes")
}

func TestNoiseIKState_ProtocolName(t *testing.T) {
	// Protocol name should be longer than 32 bytes, so it gets hashed
	assert.Greater(t, len(noiseProtocolName), 32,
		"Protocol name should exceed HASHLEN to trigger hashing")

	var respPub [32]byte
	ns := initNoiseIK(respPub)

	expectedH := sha256.Sum256([]byte(noiseProtocolName))
	// After MixHash(Hash(respPub)), h should differ from initial
	assert.NotEqual(t, expectedH, ns.h,
		"After pre-message processing, h should differ from initial hash")
}

func TestNoiseIKState_Hs2Modification(t *testing.T) {
	var respPub1, respPub2 [32]byte
	_, err := rand.Read(respPub1[:])
	require.NoError(t, err)
	_, err = rand.Read(respPub2[:])
	require.NoError(t, err)

	ns1 := initNoiseIK(respPub1)
	ns2 := initNoiseIK(respPub2)

	assert.NotEqual(t, ns1.h, ns2.h,
		"Different responder keys should produce different initial states")
}

// ============================================================================
// Noise IK Message Round-trip
// ============================================================================

func TestWriteReadNoiseIKMessage1_Roundtrip(t *testing.T) {
	initiator := createTestSessionManager(t)
	responder := createTestSessionManager(t)

	plaintext := []byte("hello through Noise IK!")

	msg, iKeys, err := writeNoiseIKMessage1(
		initiator.ourPrivateKey, initiator.ourPublicKey,
		responder.ourPublicKey, plaintext,
	)
	require.NoError(t, err)
	require.NotNil(t, iKeys)

	// Verify wire format size: 32 (e) + 48 (s) + len(plaintext) + 16 (payload tag)
	expectedSize := 32 + 48 + len(plaintext) + 16
	assert.Equal(t, expectedSize, len(msg), "Wire message size should match Noise IK format")

	decrypted, initiatorPub, rKeys, err := readNoiseIKMessage1(
		responder.ourPrivateKey, responder.ourPublicKey, msg,
	)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
	assert.Equal(t, initiator.ourPublicKey, initiatorPub,
		"Responder should recover initiator's static public key")

	// Both sides should derive the same session keys
	assert.Equal(t, iKeys.rootKey, rKeys.rootKey, "Root keys should match")
	assert.Equal(t, iKeys.symKey, rKeys.symKey, "Symmetric keys should match")
	assert.Equal(t, iKeys.tagKey, rKeys.tagKey, "Tag keys should match")
}

func TestWriteReadNoiseIKMessage1_EmptyPayload(t *testing.T) {
	initiator := createTestSessionManager(t)
	responder := createTestSessionManager(t)

	msg, _, err := writeNoiseIKMessage1(
		initiator.ourPrivateKey, initiator.ourPublicKey,
		responder.ourPublicKey, []byte{},
	)
	require.NoError(t, err)

	// Minimum size: 32 + 48 + 16 = 96 bytes
	assert.Equal(t, noiseIKMinMessageSize, len(msg))

	decrypted, _, _, err := readNoiseIKMessage1(
		responder.ourPrivateKey, responder.ourPublicKey, msg,
	)
	require.NoError(t, err)
	assert.Empty(t, decrypted)
}

func TestWriteReadNoiseIKMessage1_LargePayload(t *testing.T) {
	initiator := createTestSessionManager(t)
	responder := createTestSessionManager(t)

	plaintext := make([]byte, 64*1024) // 64KB
	_, err := rand.Read(plaintext)
	require.NoError(t, err)

	msg, _, err := writeNoiseIKMessage1(
		initiator.ourPrivateKey, initiator.ourPublicKey,
		responder.ourPublicKey, plaintext,
	)
	require.NoError(t, err)

	decrypted, _, _, err := readNoiseIKMessage1(
		responder.ourPrivateKey, responder.ourPublicKey, msg,
	)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestReadNoiseIKMessage1_TooShort(t *testing.T) {
	var priv, pub [32]byte
	_, err := rand.Read(priv[:])
	require.NoError(t, err)
	_, err = rand.Read(pub[:])
	require.NoError(t, err)

	_, _, _, err = readNoiseIKMessage1(priv, pub, make([]byte, 50))
	assert.Error(t, err, "Should reject messages shorter than minimum size")
}

func TestReadNoiseIKMessage1_WrongKey(t *testing.T) {
	initiator := createTestSessionManager(t)
	responder := createTestSessionManager(t)
	wrongRecipient := createTestSessionManager(t)

	plaintext := []byte("not for you")
	msg, _, err := writeNoiseIKMessage1(
		initiator.ourPrivateKey, initiator.ourPublicKey,
		responder.ourPublicKey, plaintext,
	)
	require.NoError(t, err)

	// Wrong recipient should fail to decrypt
	_, _, _, err = readNoiseIKMessage1(
		wrongRecipient.ourPrivateKey, wrongRecipient.ourPublicKey, msg,
	)
	assert.Error(t, err, "Wrong recipient should fail to decrypt")
}

func TestReadNoiseIKMessage1_TamperedMessage(t *testing.T) {
	initiator := createTestSessionManager(t)
	responder := createTestSessionManager(t)

	msg, _, err := writeNoiseIKMessage1(
		initiator.ourPrivateKey, initiator.ourPublicKey,
		responder.ourPublicKey, []byte("secret"),
	)
	require.NoError(t, err)

	// Tamper with the encrypted static section
	msg[40] ^= 0xFF

	_, _, _, err = readNoiseIKMessage1(
		responder.ourPrivateKey, responder.ourPublicKey, msg,
	)
	assert.Error(t, err, "Tampered message should fail authentication")
}

func TestWriteNoiseIKMessage1_NonDeterministic(t *testing.T) {
	initiator := createTestSessionManager(t)
	responder := createTestSessionManager(t)

	payload := []byte("same payload")

	msg1, _, err := writeNoiseIKMessage1(
		initiator.ourPrivateKey, initiator.ourPublicKey,
		responder.ourPublicKey, payload,
	)
	require.NoError(t, err)

	msg2, _, err := writeNoiseIKMessage1(
		initiator.ourPrivateKey, initiator.ourPublicKey,
		responder.ourPublicKey, payload,
	)
	require.NoError(t, err)

	assert.NotEqual(t, msg1, msg2,
		"Each message should use a fresh Elligator2 ephemeral key, producing unique ciphertext")
}

// ============================================================================
// HKDF and HMAC Helpers
// ============================================================================

func TestNoiseHKDF2_Deterministic(t *testing.T) {
	ck := make([]byte, 32)
	ikm := make([]byte, 32)
	_, err := rand.Read(ck)
	require.NoError(t, err)
	_, err = rand.Read(ikm)
	require.NoError(t, err)

	o1a, o2a := noiseHKDF2(ck, ikm)
	o1b, o2b := noiseHKDF2(ck, ikm)

	assert.Equal(t, o1a, o1b)
	assert.Equal(t, o2a, o2b)
	assert.NotEqual(t, o1a, o2a, "HKDF outputs should differ")
}

func TestNoiseNonce(t *testing.T) {
	nonce := noiseNonce(0)
	assert.Equal(t, 12, len(nonce))
	assert.Equal(t, make([]byte, 12), nonce, "Nonce 0 should be all zeros")

	nonce = noiseNonce(1)
	assert.Equal(t, byte(1), nonce[4], "Counter should be at offset 4 (LE)")
	assert.Equal(t, byte(0), nonce[0], "First 4 bytes should be zero padding")
}

func TestHmacSHA256_KnownOutput(t *testing.T) {
	key := []byte("test key")
	data := []byte("test data")

	result1 := hmacSHA256(key, data)
	result2 := hmacSHA256(key, data)
	assert.Equal(t, result1, result2, "HMAC-SHA256 should be deterministic")

	result3 := hmacSHA256(key, []byte("different data"))
	assert.NotEqual(t, result1, result3, "Different data should produce different HMAC")
}
