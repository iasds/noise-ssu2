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

// hashPubKey computes SHA-256(pubKey) to create a session hash, matching
// how session_manager.go uses types.SHA256 for session lookup keys.
func hashPubKey(pub [32]byte) [32]byte {
	return sha256.Sum256(pub[:])
}

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
	// After MixHash(null prologue) + MixHash(Hash(respPub)), h should differ from initial
	assert.NotEqual(t, expectedH, ns.h,
		"After pre-message processing, h should differ from initial hash")
}

// TestInitNoiseIK_NullPrologue verifies the exact handshake transcript for
// initNoiseIK, pinning the spec-required null-prologue step.
//
// The I2P ECIES-X25519-AEAD-Ratchet spec mandates this three-step sequence:
//
//	h0 = SHA-256(protocolName)           InitializeSymmetric
//	h1 = SHA-256(h0 || "")               MixHash(null prologue)
//	h2 = SHA-256(h1 || SHA-256(respPub)) MixHash(Hash(rs)) — hs2
//
// If any step is reordered or omitted, the test will fail with a mismatch,
// signaling an interoperability break with conformant I2P routers.
func TestInitNoiseIK_NullPrologue(t *testing.T) {
	var respPub [32]byte
	_, err := rand.Read(respPub[:])
	require.NoError(t, err)

	ns := initNoiseIK(respPub)

	// Step 1: InitializeSymmetric — h0 = SHA-256(protocolName)
	h0 := sha256.Sum256([]byte(noiseProtocolName))

	// Step 2: MixHash(null prologue) — h1 = SHA-256(h0 || "")
	h1 := sha256.Sum256(h0[:])

	// Step 3: MixHash(Hash(rs)) per hs2 — h2 = SHA-256(h1 || SHA-256(respPub))
	rsHash := sha256.Sum256(respPub[:])
	hasher := sha256.New()
	hasher.Write(h1[:])
	hasher.Write(rsHash[:])
	var expectedH [32]byte
	copy(expectedH[:], hasher.Sum(nil))

	assert.Equal(t, expectedH, ns.h,
		"initNoiseIK transcript must include MixHash(null prologue) before hs2 pre-message; "+
			"omitting this breaks interoperability with conformant I2P routers")
	assert.Equal(t, h0, ns.ck,
		"chaining key must equal SHA-256(protocolName) and must not change during pre-message phase")
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

	msg, iKeys, iHS, err := writeNoiseIKMessage1(
		initiator.ourPrivateKey, initiator.ourPublicKey,
		responder.ourPublicKey, plaintext,
	)
	require.NoError(t, err)
	require.NotNil(t, iKeys)
	require.NotNil(t, iHS, "Initiator handshake state should be retained")

	// Verify wire format size: 32 (e) + 48 (s) + len(plaintext) + 16 (payload tag)
	expectedSize := 32 + 48 + len(plaintext) + 16
	assert.Equal(t, expectedSize, len(msg), "Wire message size should match Noise IK format")

	decrypted, initiatorPub, rKeys, rHS, _, err := readNoiseIKMessage1(
		responder.ourPrivateKey, responder.ourPublicKey, msg,
	)
	require.NotNil(t, rHS, "Responder handshake state should be retained")
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

	msg, _, _, err := writeNoiseIKMessage1(
		initiator.ourPrivateKey, initiator.ourPublicKey,
		responder.ourPublicKey, []byte{},
	)
	require.NoError(t, err)

	// Minimum size: 32 + 48 + 16 = 96 bytes
	assert.Equal(t, noiseIKMinMessageSize, len(msg))

	decrypted, _, _, _, _, err := readNoiseIKMessage1(
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

	msg, _, _, err := writeNoiseIKMessage1(
		initiator.ourPrivateKey, initiator.ourPublicKey,
		responder.ourPublicKey, plaintext,
	)
	require.NoError(t, err)

	decrypted, _, _, _, _, err := readNoiseIKMessage1(
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

	_, _, _, _, _, err = readNoiseIKMessage1(priv, pub, make([]byte, 50))
	assert.Error(t, err, "Should reject messages shorter than minimum size")
}

func TestReadNoiseIKMessage1_WrongKey(t *testing.T) {
	initiator := createTestSessionManager(t)
	responder := createTestSessionManager(t)
	wrongRecipient := createTestSessionManager(t)

	plaintext := []byte("not for you")
	msg, _, _, err := writeNoiseIKMessage1(
		initiator.ourPrivateKey, initiator.ourPublicKey,
		responder.ourPublicKey, plaintext,
	)
	require.NoError(t, err)

	// Wrong recipient should fail to decrypt
	_, _, _, _, _, err = readNoiseIKMessage1(
		wrongRecipient.ourPrivateKey, wrongRecipient.ourPublicKey, msg,
	)
	assert.Error(t, err, "Wrong recipient should fail to decrypt")
}

func TestReadNoiseIKMessage1_TamperedMessage(t *testing.T) {
	initiator := createTestSessionManager(t)
	responder := createTestSessionManager(t)

	msg, _, _, err := writeNoiseIKMessage1(
		initiator.ourPrivateKey, initiator.ourPublicKey,
		responder.ourPublicKey, []byte("secret"),
	)
	require.NoError(t, err)

	// Tamper with the encrypted static section
	msg[40] ^= 0xFF

	_, _, _, _, _, err = readNoiseIKMessage1(
		responder.ourPrivateKey, responder.ourPublicKey, msg,
	)
	assert.Error(t, err, "Tampered message should fail authentication")
}

func TestWriteNoiseIKMessage1_NonDeterministic(t *testing.T) {
	initiator := createTestSessionManager(t)
	responder := createTestSessionManager(t)

	payload := []byte("same payload")

	msg1, _, _, err := writeNoiseIKMessage1(
		initiator.ourPrivateKey, initiator.ourPublicKey,
		responder.ourPublicKey, payload,
	)
	require.NoError(t, err)

	msg2, _, _, err := writeNoiseIKMessage1(
		initiator.ourPrivateKey, initiator.ourPublicKey,
		responder.ourPublicKey, payload,
	)
	require.NoError(t, err)

	assert.NotEqual(t, msg1, msg2,
		"Each message should use a fresh Elligator2 ephemeral key, producing unique ciphertext")
}

// ============================================================================
// Unbound (N-pattern) New Session — writeNoiseIKMessage1Unbound
// ============================================================================

// TestWriteReadNoiseIKMessage1Unbound_Roundtrip verifies that an unbound NS
// message written by the sender can be decrypted by the receiver, that the
// receiver correctly identifies the message as unbound (isUnbound=true), and
// that the decrypted payload matches the original.
func TestWriteReadNoiseIKMessage1Unbound_Roundtrip(t *testing.T) {
	responder := createTestSessionManager(t)

	plaintext := []byte("unbound one-way message")

	msg, wKeys, err := writeNoiseIKMessage1Unbound(responder.ourPublicKey, plaintext)
	require.NoError(t, err)
	require.NotNil(t, wKeys, "Session keys should be derived even for unbound messages")

	// Minimum wire size: 32 (ephemeral) + 48 (flags section) + 16 (empty payload tag) = 96
	// With non-empty payload: 32 + 48 + len(plaintext) + 16
	expectedSize := 32 + 48 + len(plaintext) + 16
	assert.Equal(t, expectedSize, len(msg), "Unbound NS wire format should match §1c spec")

	decrypted, initiatorStaticPub, rKeys, hs, isUnbound, err := readNoiseIKMessage1(
		responder.ourPrivateKey, responder.ourPublicKey, msg,
	)
	require.NoError(t, err)
	assert.True(t, isUnbound, "Receiver should detect unbound (N-pattern) message")
	assert.Equal(t, plaintext, decrypted, "Decrypted payload should match original")
	assert.Equal(t, [32]byte{}, initiatorStaticPub, "No initiator static key for unbound messages")
	assert.Nil(t, hs, "No handshake state retained for unbound (non-repliable) sessions")
	assert.NotNil(t, rKeys, "Receiver should derive session keys from unbound handshake")

	// Both sides derive session keys from the same chaining key; verify they match.
	assert.Equal(t, wKeys.rootKey, rKeys.rootKey, "Root keys should match across unbound session")
	assert.Equal(t, wKeys.symKey, rKeys.symKey, "Symmetric keys should match")
	assert.Equal(t, wKeys.tagKey, rKeys.tagKey, "Tag keys should match")
}

// TestWriteReadNoiseIKMessage1Unbound_EmptyPayload verifies behaviour with an
// empty payload: minimum wire size (96 bytes) and successful decryption.
func TestWriteReadNoiseIKMessage1Unbound_EmptyPayload(t *testing.T) {
	responder := createTestSessionManager(t)

	msg, _, err := writeNoiseIKMessage1Unbound(responder.ourPublicKey, []byte{})
	require.NoError(t, err)
	// Minimum: 32 + 48 + 16 = 96 bytes (same as bound minimum).
	assert.Equal(t, noiseIKMinMessageSize, len(msg))

	decrypted, _, _, _, isUnbound, err := readNoiseIKMessage1(
		responder.ourPrivateKey, responder.ourPublicKey, msg,
	)
	require.NoError(t, err)
	assert.True(t, isUnbound)
	assert.Empty(t, decrypted)
}

// TestReadNoiseIKMessage1_Bound_IsNotUnbound verifies that a normal (bound, IK)
// New Session message returns isUnbound=false.
func TestReadNoiseIKMessage1_Bound_IsNotUnbound(t *testing.T) {
	initiator := createTestSessionManager(t)
	responder := createTestSessionManager(t)

	msg, _, _, err := writeNoiseIKMessage1(
		initiator.ourPrivateKey, initiator.ourPublicKey,
		responder.ourPublicKey, []byte("bound message"),
	)
	require.NoError(t, err)

	_, initiatorPub, _, hs, isUnbound, err := readNoiseIKMessage1(
		responder.ourPrivateKey, responder.ourPublicKey, msg,
	)
	require.NoError(t, err)
	assert.False(t, isUnbound, "Bound IK message should not be flagged as unbound")
	assert.Equal(t, initiator.ourPublicKey, initiatorPub, "Bound: initiator static key recovered")
	assert.NotNil(t, hs, "Bound: handshake state retained for NSR")
}

// TestWriteNoiseIKMessage1Unbound_NonDeterministic verifies that each unbound
// message uses a fresh Elligator2 ephemeral key, producing unique ciphertexts
// even for the same payload.
func TestWriteNoiseIKMessage1Unbound_NonDeterministic(t *testing.T) {
	responder := createTestSessionManager(t)

	payload := []byte("same unbound payload")

	msg1, _, err := writeNoiseIKMessage1Unbound(responder.ourPublicKey, payload)
	require.NoError(t, err)
	msg2, _, err := writeNoiseIKMessage1Unbound(responder.ourPublicKey, payload)
	require.NoError(t, err)

	assert.NotEqual(t, msg1, msg2,
		"Each unbound message should use a fresh ephemeral key (non-deterministic)")
}

// TestWriteNoiseIKMessage1Unbound_WrongRecipient verifies that an unbound message
// encrypted for one recipient cannot be decrypted by another.
func TestWriteNoiseIKMessage1Unbound_WrongRecipient(t *testing.T) {
	responder := createTestSessionManager(t)
	wrongRecipient := createTestSessionManager(t)

	msg, _, err := writeNoiseIKMessage1Unbound(responder.ourPublicKey, []byte("secret"))
	require.NoError(t, err)

	_, _, _, _, _, err = readNoiseIKMessage1(
		wrongRecipient.ourPrivateKey, wrongRecipient.ourPublicKey, msg,
	)
	assert.Error(t, err, "Wrong recipient should fail to decrypt unbound message")
}

// TestWriteNoiseIKMessage1Unbound_TamperedFlagsSection verifies that tampering
// with the encrypted flags section causes authentication failure.
func TestWriteNoiseIKMessage1Unbound_TamperedFlagsSection(t *testing.T) {
	responder := createTestSessionManager(t)

	msg, _, err := writeNoiseIKMessage1Unbound(responder.ourPublicKey, []byte("payload"))
	require.NoError(t, err)

	// Tamper with the encrypted flags section (bytes 32..79).
	msg[40] ^= 0xFF

	_, _, _, _, _, err = readNoiseIKMessage1(
		responder.ourPrivateKey, responder.ourPublicKey, msg,
	)
	assert.Error(t, err, "Tampered flags section should fail authentication")
}

// TestIsAllZeros verifies the isAllZeros helper.
func TestIsAllZeros(t *testing.T) {
	assert.True(t, isAllZeros(make([]byte, 32)), "All-zero slice should return true")
	assert.True(t, isAllZeros(nil), "Nil slice (empty) should return true")
	assert.True(t, isAllZeros([]byte{}), "Empty slice should return true")

	nonzero := make([]byte, 32)
	nonzero[16] = 1
	assert.False(t, isAllZeros(nonzero), "Slice with non-zero byte should return false")

	allFF := make([]byte, 32)
	for i := range allFF {
		allFF[i] = 0xFF
	}
	assert.False(t, isAllZeros(allFF), "All-0xFF slice should return false")
}

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

// ============================================================================
// standardHKDF
// ============================================================================

func TestStandardHKDF_Deterministic(t *testing.T) {
	salt := make([]byte, 32)
	ikm := make([]byte, 32)
	_, err := rand.Read(salt)
	require.NoError(t, err)
	_, err = rand.Read(ikm)
	require.NoError(t, err)

	out1 := standardHKDF(salt, ikm, []byte("test_info"), 64)
	out2 := standardHKDF(salt, ikm, []byte("test_info"), 64)
	assert.Equal(t, out1, out2, "Same inputs should produce identical HKDF output")
	assert.Equal(t, 64, len(out1))
}

func TestStandardHKDF_DifferentInputs(t *testing.T) {
	salt := make([]byte, 32)
	ikm := make([]byte, 32)
	_, err := rand.Read(salt)
	require.NoError(t, err)
	_, err = rand.Read(ikm)
	require.NoError(t, err)

	out1 := standardHKDF(salt, ikm, []byte("info_a"), 32)
	out2 := standardHKDF(salt, ikm, []byte("info_b"), 32)
	assert.NotEqual(t, out1, out2, "Different info strings should produce different output")

	out3 := standardHKDF(salt, nil, []byte("info_a"), 32)
	assert.NotEqual(t, out1, out3, "Different IKM should produce different output")
}

func TestStandardHKDF_VariableLengths(t *testing.T) {
	salt := make([]byte, 32)
	_, err := rand.Read(salt)
	require.NoError(t, err)

	out32 := standardHKDF(salt, nil, []byte("test"), 32)
	out64 := standardHKDF(salt, nil, []byte("test"), 64)
	assert.Equal(t, 32, len(out32))
	assert.Equal(t, 64, len(out64))
	// First 32 bytes of 64-byte output should match the 32-byte output
	assert.Equal(t, out32, out64[:32], "HKDF expand should produce consistent prefix")
}

// ============================================================================
// NSR Tag Ratchet Derivation
// ============================================================================

func TestDeriveNSRTagRatchet_BothSidesMatch(t *testing.T) {
	// Both initiator and responder should derive the same NSR tag ratchet
	// from the same chain key.
	var chainKey [32]byte
	_, err := rand.Read(chainKey[:])
	require.NoError(t, err)

	tr1, err := deriveNSRTagRatchet(chainKey)
	require.NoError(t, err)
	require.NotNil(t, tr1)

	tr2, err := deriveNSRTagRatchet(chainKey)
	require.NoError(t, err)
	require.NotNil(t, tr2)

	// Both should generate the same first tag
	tag1, err := tr1.GenerateNextTag()
	require.NoError(t, err)
	tag2, err := tr2.GenerateNextTag()
	require.NoError(t, err)
	assert.Equal(t, tag1, tag2, "Same chain key should produce same NSR tags")
}

func TestDeriveNSRTagRatchet_DifferentChainKeys(t *testing.T) {
	var ck1, ck2 [32]byte
	_, err := rand.Read(ck1[:])
	require.NoError(t, err)
	_, err = rand.Read(ck2[:])
	require.NoError(t, err)

	tr1, err := deriveNSRTagRatchet(ck1)
	require.NoError(t, err)
	tr2, err := deriveNSRTagRatchet(ck2)
	require.NoError(t, err)

	tag1, err := tr1.GenerateNextTag()
	require.NoError(t, err)
	tag2, err := tr2.GenerateNextTag()
	require.NoError(t, err)
	assert.NotEqual(t, tag1, tag2, "Different chain keys should produce different tags")
}

// ============================================================================
// NSR Message Round-trip (writeNoiseIKMessage2 / readNoiseIKMessage2)
// ============================================================================

func TestWriteReadNoiseIKMessage2_Roundtrip(t *testing.T) {
	initiator := createTestSessionManager(t)
	responder := createTestSessionManager(t)

	// Step 1: Initiator sends New Session (message 1)
	nsPayload := []byte("hello from Alice")
	msg1, _, iHS, err := writeNoiseIKMessage1(
		initiator.ourPrivateKey, initiator.ourPublicKey,
		responder.ourPublicKey, nsPayload,
	)
	require.NoError(t, err)
	require.NotNil(t, iHS, "Initiator handshake state should be retained")

	// Step 2: Responder reads New Session and retains handshake state

	_, _, _, rHS, _, err := readNoiseIKMessage1(
		responder.ourPrivateKey, responder.ourPublicKey, msg1,
	)
	require.NoError(t, err)
	require.NotNil(t, rHS, "Responder handshake state should be retained")

	// Step 3: Responder writes New Session Reply (message 2)
	nsrPayload := []byte("hello from Bob")
	nsrTag, nsrWire, respKeys, err := writeNoiseIKMessage2(rHS, nsrPayload)
	require.NoError(t, err)
	require.NotNil(t, respKeys)
	assert.NotEqual(t, [8]byte{}, nsrTag, "NSR tag should not be zero")

	// Verify wire format: [tag(8)] + [eph(32)] + [mac(16)] + [payload+mac(N+16)]
	expectedSize := 8 + 32 + 16 + len(nsrPayload) + 16
	assert.Equal(t, expectedSize, len(nsrWire), "NSR wire message size should match format")

	// Step 4: Initiator reads New Session Reply
	decrypted, initKeys, err := readNoiseIKMessage2(iHS, initiator.ourPrivateKey, nsrWire)
	require.NoError(t, err)
	assert.Equal(t, nsrPayload, decrypted, "Initiator should recover NSR payload")

	// Both sides should derive matching directional keys
	assert.Equal(t, respKeys.keyAB, initKeys.keyAB, "keyAB should match")
	assert.Equal(t, respKeys.keyBA, initKeys.keyBA, "keyBA should match")
	assert.Equal(t, respKeys.chainKey, initKeys.chainKey, "chainKey should match")
}

func TestWriteReadNoiseIKMessage2_EmptyPayload(t *testing.T) {
	initiator := createTestSessionManager(t)
	responder := createTestSessionManager(t)

	msg1, _, iHS, err := writeNoiseIKMessage1(
		initiator.ourPrivateKey, initiator.ourPublicKey,
		responder.ourPublicKey, []byte("ns"),
	)
	require.NoError(t, err)

	_, _, _, rHS, _, err := readNoiseIKMessage1(
		responder.ourPrivateKey, responder.ourPublicKey, msg1,
	)
	require.NoError(t, err)

	_, nsrWire, _, err := writeNoiseIKMessage2(rHS, []byte{})
	require.NoError(t, err)

	// Minimum NSR size: 8 + 32 + 16 + 16 = 72
	assert.Equal(t, nsrMinMessageSize, len(nsrWire))

	decrypted, _, err := readNoiseIKMessage2(iHS, initiator.ourPrivateKey, nsrWire)
	require.NoError(t, err)
	assert.Empty(t, decrypted)
}

func TestReadNoiseIKMessage2_TooShort(t *testing.T) {
	var priv [32]byte
	_, err := rand.Read(priv[:])
	require.NoError(t, err)

	hs := &noiseHandshakeState{}
	_, _, err = readNoiseIKMessage2(hs, priv, make([]byte, 50))
	assert.Error(t, err, "Should reject NSR messages shorter than minimum size")
}

func TestReadNoiseIKMessage2_TamperedMessage(t *testing.T) {
	initiator := createTestSessionManager(t)
	responder := createTestSessionManager(t)

	msg1, _, iHS, err := writeNoiseIKMessage1(
		initiator.ourPrivateKey, initiator.ourPublicKey,
		responder.ourPublicKey, []byte("ns"),
	)
	require.NoError(t, err)

	_, _, _, rHS, _, err := readNoiseIKMessage1(
		responder.ourPrivateKey, responder.ourPublicKey, msg1,
	)
	require.NoError(t, err)

	_, nsrWire, _, err := writeNoiseIKMessage2(rHS, []byte("nsr payload"))
	require.NoError(t, err)

	// Tamper with the key section MAC
	nsrWire[42] ^= 0xFF

	_, _, err = readNoiseIKMessage2(iHS, initiator.ourPrivateKey, nsrWire)
	assert.Error(t, err, "Tampered NSR should fail authentication")
}

func TestWriteNoiseIKMessage2_NonDeterministic(t *testing.T) {
	initiator := createTestSessionManager(t)
	responder := createTestSessionManager(t)

	msg1, _, _, err := writeNoiseIKMessage1(
		initiator.ourPrivateKey, initiator.ourPublicKey,
		responder.ourPublicKey, []byte("ns"),
	)
	require.NoError(t, err)

	_, _, _, rHS, _, err := readNoiseIKMessage1(
		responder.ourPrivateKey, responder.ourPublicKey, msg1,
	)
	require.NoError(t, err)

	// Write two NSR messages from same state — different ephemeral keys each time
	_, wire1, _, err := writeNoiseIKMessage2(rHS, []byte("nsr"))
	require.NoError(t, err)
	_, wire2, _, err := writeNoiseIKMessage2(rHS, []byte("nsr"))
	require.NoError(t, err)

	assert.NotEqual(t, wire1, wire2,
		"Each NSR should use a fresh ephemeral key, producing unique ciphertext")
}

// ============================================================================
// NSR Payload Encryption/Decryption
// ============================================================================

func TestEncryptDecryptNSRPayload_Roundtrip(t *testing.T) {
	// Create matched states (same h, ck)
	var h, ck [32]byte
	_, err := rand.Read(h[:])
	require.NoError(t, err)
	_, err = rand.Read(ck[:])
	require.NoError(t, err)

	// Encryption state
	encNS := &noiseIKState{h: h, ck: ck}
	payload := []byte("garlic clove response data")
	encrypted, eKeys, err := encryptNSRPayload(encNS, payload)
	require.NoError(t, err)
	require.NotNil(t, eKeys)
	assert.Equal(t, len(payload)+16, len(encrypted), "Encrypted output includes 16-byte tag")

	// Decryption state (same h, ck)
	decNS := &noiseIKState{h: h, ck: ck}
	decrypted, dKeys, err := decryptNSRPayload(decNS, encrypted)
	require.NoError(t, err)
	assert.Equal(t, payload, decrypted)

	assert.Equal(t, eKeys.keyAB, dKeys.keyAB, "AB keys should match")
	assert.Equal(t, eKeys.keyBA, dKeys.keyBA, "BA keys should match")
}

// ============================================================================
// SessionManager NSR Integration
// ============================================================================

func TestSessionManager_EncryptNewSessionReply(t *testing.T) {
	initiator := createTestSessionManager(t)
	responder := createTestSessionManager(t)

	// Send NS from initiator → responder
	nsPayload := []byte("initial garlic clove")
	encrypted, err := initiator.EncryptGarlicMessage(
		hashPubKey(responder.ourPublicKey), responder.ourPublicKey, nsPayload,
	)
	require.NoError(t, err)

	// Responder decrypts NS
	decrypted, _, _, err := responder.DecryptGarlicMessage(encrypted)
	require.NoError(t, err)
	assert.Equal(t, nsPayload, decrypted)

	// Responder sends NSR
	sessionHash := hashPubKey(initiator.ourPublicKey)
	nsrPayload := []byte("reply garlic clove")
	nsrMsg, err := responder.EncryptNewSessionReply(sessionHash, nsrPayload)
	require.NoError(t, err)
	require.NotNil(t, nsrMsg)
	assert.GreaterOrEqual(t, len(nsrMsg), nsrMinMessageSize)
}

func TestSessionManager_EncryptNewSessionReply_NoSession(t *testing.T) {
	sm := createTestSessionManager(t)
	var fakeHash [32]byte
	_, err := rand.Read(fakeHash[:])
	require.NoError(t, err)

	_, err = sm.EncryptNewSessionReply(fakeHash, []byte("payload"))
	assert.Error(t, err, "Should fail when no session exists")
}

func TestSessionManager_EncryptNewSessionReply_InitiatorCantSendNSR(t *testing.T) {
	initiator := createTestSessionManager(t)
	responder := createTestSessionManager(t)

	// Create a session as initiator
	_, err := initiator.EncryptGarlicMessage(
		hashPubKey(responder.ourPublicKey), responder.ourPublicKey, []byte("hello"),
	)
	require.NoError(t, err)

	// Initiator should NOT be able to send NSR
	_, err = initiator.EncryptNewSessionReply(hashPubKey(responder.ourPublicKey), []byte("nsr"))
	assert.Error(t, err, "Initiator should not be able to send NSR")
}

func TestSessionManager_EncryptNewSessionReply_ClearsHandshakeState(t *testing.T) {
	initiator := createTestSessionManager(t)
	responder := createTestSessionManager(t)

	// Send NS from initiator → responder
	encrypted, err := initiator.EncryptGarlicMessage(
		hashPubKey(responder.ourPublicKey), responder.ourPublicKey, []byte("ns"),
	)
	require.NoError(t, err)

	_, _, _, err = responder.DecryptGarlicMessage(encrypted)
	require.NoError(t, err)

	sessionHash := hashPubKey(initiator.ourPublicKey)

	// First NSR should succeed
	_, err = responder.EncryptNewSessionReply(sessionHash, []byte("nsr1"))
	require.NoError(t, err)

	// Second NSR should fail (handshake state cleared)
	_, err = responder.EncryptNewSessionReply(sessionHash, []byte("nsr2"))
	assert.Error(t, err, "Second NSR should fail after handshake state is cleared")
}
