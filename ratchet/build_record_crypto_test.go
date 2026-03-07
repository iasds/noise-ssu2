package ratchet

import (
	"bytes"
	"sync"
	"testing"

	"github.com/go-i2p/crypto/chacha20poly1305"
	"github.com/go-i2p/crypto/ecies"
	"github.com/go-i2p/crypto/rand"
	"github.com/go-i2p/crypto/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testECIESMaterial holds pre-generated ECIES key material and a 222-byte
// cleartext buffer for build-request encryption tests.
type testECIESMaterial struct {
	pubKey       []byte
	privKey      []byte
	pubKeyArr    [32]byte
	cleartext    []byte
	identityHash [32]byte
}

// testReplyMaterial holds pre-generated material for reply record crypto tests.
type testReplyMaterial struct {
	crypto     *BuildRecordCrypto
	replyKey   [32]byte
	replyIV    [16]byte
	randomData [495]byte
	cleartext  []byte
	encrypted  []byte
}

// newTestReplyMaterial generates random key/IV/data, computes the response
// record hash, serializes the cleartext, and encrypts it — providing all the
// pieces needed by the reply-record test functions.
func newTestReplyMaterial(t *testing.T) testReplyMaterial {
	t.Helper()
	m := testReplyMaterial{crypto: NewBuildRecordCrypto()}
	rand.Read(m.replyKey[:])
	rand.Read(m.replyIV[:])
	rand.Read(m.randomData[:])

	hash := CreateBuildResponseRecordRaw(0, m.randomData)
	m.cleartext = SerializeResponseRecord(hash, m.randomData, 0)

	var err error
	m.encrypted, err = m.crypto.EncryptReplyRecord(m.cleartext, m.replyKey, m.replyIV)
	require.NoError(t, err)
	return m
}

// newTestECIESMaterial generates a fresh X25519 keypair, a random 222-byte
// cleartext, and the SHA-256 identity hash derived from the public key.
func newTestECIESMaterial(t *testing.T) testECIESMaterial {
	t.Helper()
	pubKey, privKey, err := ecies.GenerateKeyPair()
	require.NoError(t, err)

	cleartext := make([]byte, 222)
	rand.Read(cleartext)

	identityHash := types.SHA256(pubKey)
	var pubKeyArr [32]byte
	copy(pubKeyArr[:], pubKey)

	return testECIESMaterial{
		pubKey:       pubKey,
		privKey:      privKey,
		pubKeyArr:    pubKeyArr,
		cleartext:    cleartext,
		identityHash: identityHash,
	}
}

// ============================================================================
// Reply Record Encryption Tests (ChaCha20-Poly1305)
// ============================================================================

// TestEncryptDecryptReplyRecord tests the round-trip encrypt/decrypt of reply records.
func TestEncryptDecryptReplyRecord(t *testing.T) {
	crypto := NewBuildRecordCrypto()

	var replyKey [32]byte
	var replyIV [16]byte
	_, err := rand.Read(replyKey[:])
	require.NoError(t, err)
	_, err = rand.Read(replyIV[:])
	require.NoError(t, err)

	// Create a valid 528-byte cleartext using SerializeResponseRecord
	var randomData [495]byte
	_, err = rand.Read(randomData[:])
	require.NoError(t, err)

	hash := CreateBuildResponseRecordRaw(0, randomData)
	cleartext := SerializeResponseRecord(hash, randomData, 0)
	assert.Equal(t, 528, len(cleartext))

	// Encrypt
	encrypted, err := crypto.EncryptReplyRecord(cleartext, replyKey, replyIV)
	require.NoError(t, err)
	assert.Equal(t, 544, len(encrypted), "ChaCha20-Poly1305: 528 + 16 tag")

	// Decrypt
	decrypted, err := crypto.DecryptReplyRecord(encrypted, replyKey, replyIV)
	require.NoError(t, err)
	assert.Equal(t, cleartext, decrypted, "Round-trip should preserve cleartext")
}

// TestEncryptReplyRecordDeterminism verifies same key/IV produces same output.
func TestEncryptReplyRecordDeterminism(t *testing.T) {
	m := newTestReplyMaterial(t)

	encrypted2, err := m.crypto.EncryptReplyRecord(m.cleartext, m.replyKey, m.replyIV)
	require.NoError(t, err)

	assert.True(t, bytes.Equal(m.encrypted, encrypted2), "Should be deterministic")
}

// TestDecryptReplyRecordWrongKey tests decryption with wrong key fails.
func TestDecryptReplyRecordWrongKey(t *testing.T) {
	m := newTestReplyMaterial(t)

	var wrongKey [32]byte
	rand.Read(wrongKey[:])

	_, err := m.crypto.DecryptReplyRecord(m.encrypted, wrongKey, m.replyIV)
	assert.Error(t, err, "Wrong key should fail")
}

// TestDecryptReplyRecordInvalidSize tests error handling for bad sizes.
func TestDecryptReplyRecordInvalidSize(t *testing.T) {
	crypto := NewBuildRecordCrypto()
	var key [32]byte
	var iv [16]byte

	tests := []struct {
		name string
		size int
	}{
		{"Too small", 527},
		{"Too large", 600},
		{"Empty", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := crypto.DecryptReplyRecord(make([]byte, tt.size), key, iv)
			assert.Error(t, err)
		})
	}
}

// TestEncryptReplyRecordInvalidSize tests encryption with wrong cleartext size.
func TestEncryptReplyRecordInvalidSize(t *testing.T) {
	crypto := NewBuildRecordCrypto()
	var key [32]byte
	var iv [16]byte

	_, err := crypto.EncryptReplyRecord(make([]byte, 100), key, iv)
	assert.Error(t, err, "Non-528 cleartext should fail")
}

// TestCreateBuildResponseRecordRaw verifies hash computation.
func TestCreateBuildResponseRecordRaw(t *testing.T) {
	var randomData [495]byte
	rand.Read(randomData[:])

	hash := CreateBuildResponseRecordRaw(0, randomData)

	// Manual hash computation
	data := make([]byte, 496)
	copy(data[0:495], randomData[:])
	data[495] = 0
	expected := types.SHA256(data)

	assert.Equal(t, expected, hash, "Hash should match SHA-256 of data+reply")
}

// TestVerifyResponseRecordHash tests hash verification.
func TestVerifyResponseRecordHash(t *testing.T) {
	var randomData [495]byte
	rand.Read(randomData[:])

	hash := CreateBuildResponseRecordRaw(0, randomData)

	// Valid hash
	err := VerifyResponseRecordHash(hash, randomData, 0)
	assert.NoError(t, err, "Valid hash should pass")

	// Tampered hash
	badHash := hash
	badHash[0] ^= 0xFF
	err = VerifyResponseRecordHash(badHash, randomData, 0)
	assert.Error(t, err, "Tampered hash should fail")
}

// TestSerializeResponseRecord verifies wire format.
func TestSerializeResponseRecord(t *testing.T) {
	var randomData [495]byte
	rand.Read(randomData[:])

	hash := CreateBuildResponseRecordRaw(42, randomData)
	buf := SerializeResponseRecord(hash, randomData, 42)

	assert.Equal(t, 528, len(buf))
	assert.Equal(t, hash[:], buf[0:32])
	assert.Equal(t, randomData[:], buf[32:527])
	assert.Equal(t, byte(42), buf[527])
}

// TestChaCha20Poly1305_AuthenticationTag verifies AEAD auth tags.
func TestChaCha20Poly1305_AuthenticationTag(t *testing.T) {
	m := newTestReplyMaterial(t)

	assert.Equal(t, 544, len(m.encrypted))

	// Auth tag is last 16 bytes and should not be all zeros
	authTag := m.encrypted[528:]
	allZero := true
	for _, b := range authTag {
		if b != 0 {
			allZero = false
			break
		}
	}
	assert.False(t, allZero, "Auth tag should not be all zeros")
}

// TestChaCha20Poly1305_TamperDetection verifies tampering detection.
func TestChaCha20Poly1305_TamperDetection(t *testing.T) {
	m := newTestReplyMaterial(t)

	tamperCases := []struct {
		name      string
		tamperFn  func([]byte) []byte
		expectErr bool
	}{
		{
			"flip bit in ciphertext",
			func(data []byte) []byte {
				tampered := make([]byte, len(data))
				copy(tampered, data)
				tampered[100] ^= 0x01
				return tampered
			},
			true,
		},
		{
			"flip bit in auth tag",
			func(data []byte) []byte {
				tampered := make([]byte, len(data))
				copy(tampered, data)
				tampered[540] ^= 0x01
				return tampered
			},
			true,
		},
		{
			"untampered",
			func(data []byte) []byte { return data },
			false,
		},
	}

	for _, tc := range tamperCases {
		t.Run(tc.name, func(t *testing.T) {
			tampered := tc.tamperFn(m.encrypted)
			_, err := m.crypto.DecryptReplyRecord(tampered, m.replyKey, m.replyIV)
			if tc.expectErr {
				assert.Error(t, err, "Should detect tampering: %s", tc.name)
			} else {
				assert.NoError(t, err, "Untampered should work: %s", tc.name)
			}
		})
	}
}

// TestDifferentNoncesProduceDifferentCiphertext verifies IV uniqueness.
func TestDifferentNoncesProduceDifferentCiphertext(t *testing.T) {
	crypto := NewBuildRecordCrypto()

	var replyKey [32]byte
	rand.Read(replyKey[:])

	var randomData [495]byte
	rand.Read(randomData[:])

	hash := CreateBuildResponseRecordRaw(0, randomData)
	cleartext := SerializeResponseRecord(hash, randomData, 0)

	ciphertexts := make([][]byte, 5)
	for i := 0; i < 5; i++ {
		var iv [16]byte
		rand.Read(iv[:])
		ct, err := crypto.EncryptReplyRecord(cleartext, replyKey, iv)
		require.NoError(t, err)
		ciphertexts[i] = ct
	}

	for i := 0; i < len(ciphertexts); i++ {
		for j := i + 1; j < len(ciphertexts); j++ {
			assert.False(t, bytes.Equal(ciphertexts[i], ciphertexts[j]),
				"Different IVs should produce different ciphertexts")
		}
	}
}

// TestMultipleRecordsWithDifferentKeys tests 8-hop tunnel build simulation.
func TestMultipleRecordsWithDifferentKeys(t *testing.T) {
	crypto := NewBuildRecordCrypto()
	const numRecords = 8

	var keys [numRecords][32]byte
	var ivs [numRecords][16]byte
	var cleartexts [numRecords][]byte

	for i := 0; i < numRecords; i++ {
		rand.Read(keys[i][:])
		rand.Read(ivs[i][:])

		var randomData [495]byte
		rand.Read(randomData[:])
		hash := CreateBuildResponseRecordRaw(byte(i), randomData)
		cleartexts[i] = SerializeResponseRecord(hash, randomData, byte(i))
	}

	encrypted := make([][]byte, numRecords)
	for i := 0; i < numRecords; i++ {
		var err error
		encrypted[i], err = crypto.EncryptReplyRecord(cleartexts[i], keys[i], ivs[i])
		require.NoError(t, err)
	}

	for i := 0; i < numRecords; i++ {
		decrypted, err := crypto.DecryptReplyRecord(encrypted[i], keys[i], ivs[i])
		require.NoError(t, err)
		assert.Equal(t, cleartexts[i], decrypted)
	}
}

// TestConcurrentAccess verifies thread safety.
func TestConcurrentAccess(t *testing.T) {
	crypto := NewBuildRecordCrypto()

	var wg sync.WaitGroup
	numGoroutines := 10
	numOpsPerGoroutine := 50

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			for j := 0; j < numOpsPerGoroutine; j++ {
				var key [32]byte
				var iv [16]byte
				rand.Read(key[:])
				rand.Read(iv[:])

				var randomData [495]byte
				rand.Read(randomData[:])

				hash := CreateBuildResponseRecordRaw(byte(j%256), randomData)
				cleartext := SerializeResponseRecord(hash, randomData, byte(j%256))

				encrypted, err := crypto.EncryptReplyRecord(cleartext, key, iv)
				if err != nil {
					t.Errorf("Goroutine %d: encryption failed: %v", idx, err)
					continue
				}

				decrypted, err := crypto.DecryptReplyRecord(encrypted, key, iv)
				if err != nil {
					t.Errorf("Goroutine %d: decryption failed: %v", idx, err)
					continue
				}

				if !bytes.Equal(cleartext, decrypted) {
					t.Errorf("Goroutine %d: round-trip mismatch", idx)
				}
			}
		}(i)
	}

	wg.Wait()
}

// TestZeroKey tests behavior with zero key (edge case).
func TestZeroKey(t *testing.T) {
	crypto := NewBuildRecordCrypto()

	var zeroKey [32]byte
	var iv [16]byte
	rand.Read(iv[:])

	var randomData [495]byte
	rand.Read(randomData[:])

	hash := CreateBuildResponseRecordRaw(0, randomData)
	cleartext := SerializeResponseRecord(hash, randomData, 0)

	encrypted, err := crypto.EncryptReplyRecord(cleartext, zeroKey, iv)
	require.NoError(t, err)

	decrypted, err := crypto.DecryptReplyRecord(encrypted, zeroKey, iv)
	require.NoError(t, err)
	assert.Equal(t, cleartext, decrypted)
}

// TestBuildResponseRecordHashTamper verifies hash tamper detection through full round-trip.
func TestBuildResponseRecordHashTamper(t *testing.T) {
	crypto := NewBuildRecordCrypto()

	var replyKey [32]byte
	var replyIV [16]byte
	rand.Read(replyKey[:])
	rand.Read(replyIV[:])

	var randomData [495]byte
	rand.Read(randomData[:])

	// Create record with correct hash, then tamper
	hash := CreateBuildResponseRecordRaw(0, randomData)
	hash[0] ^= 0xFF // Tamper with hash
	cleartext := SerializeResponseRecord(hash, randomData, 0)

	// Encrypt with tampered hash
	var keyArr [32]byte
	copy(keyArr[:], replyKey[:])
	aead, err := chacha20poly1305.NewAEAD(keyArr)
	require.NoError(t, err)

	nonce := replyIV[:12]
	ct, tag, err := aead.Encrypt(cleartext, nil, nonce)
	require.NoError(t, err)
	ciphertext := make([]byte, len(ct)+len(tag))
	copy(ciphertext, ct)
	copy(ciphertext[len(ct):], tag[:])

	// Decrypt should succeed (AEAD is valid)
	decrypted, err := crypto.DecryptReplyRecord(ciphertext, replyKey, replyIV)
	require.NoError(t, err)

	// But hash verification should fail (caller's responsibility)
	var decryptedHash [32]byte
	copy(decryptedHash[:], decrypted[0:32])
	var decryptedRandom [495]byte
	copy(decryptedRandom[:], decrypted[32:527])
	decryptedReply := decrypted[527]

	err = VerifyResponseRecordHash(decryptedHash, decryptedRandom, decryptedReply)
	assert.Error(t, err, "Hash verification should fail for tampered record")
}

// ============================================================================
// Build Request ECIES Tests
// ============================================================================

// TestEncryptDecryptBuildRequest tests ECIES encrypt/decrypt round-trip.
func TestEncryptDecryptBuildRequest(t *testing.T) {
	crypto := NewBuildRecordCrypto()
	m := newTestECIESMaterial(t)

	// Encrypt
	encrypted, err := crypto.EncryptBuildRequest(m.cleartext, m.pubKeyArr, m.identityHash)
	require.NoError(t, err)

	// Verify identity hash prefix
	for i := 0; i < 16; i++ {
		assert.Equal(t, m.identityHash[i], encrypted[i], "Identity hash prefix byte %d", i)
	}

	// Decrypt
	decrypted, err := crypto.DecryptBuildRequest(encrypted, m.privKey)
	require.NoError(t, err)
	assert.Equal(t, m.cleartext, decrypted, "Round-trip should preserve cleartext")
}

// TestEncryptBuildRequestNonDeterministic verifies ephemeral keys differ.
func TestEncryptBuildRequestNonDeterministic(t *testing.T) {
	crypto := NewBuildRecordCrypto()
	m := newTestECIESMaterial(t)

	encrypted1, err := crypto.EncryptBuildRequest(m.cleartext, m.pubKeyArr, m.identityHash)
	require.NoError(t, err)

	encrypted2, err := crypto.EncryptBuildRequest(m.cleartext, m.pubKeyArr, m.identityHash)
	require.NoError(t, err)

	// Identity hash prefix should match
	assert.Equal(t, encrypted1[:16], encrypted2[:16], "Identity prefix should match")
	// Ciphertext should differ (different ephemeral keys)
	assert.NotEqual(t, encrypted1[16:], encrypted2[16:], "Ciphertext should differ")
}

// TestDecryptBuildRequestWrongKey verifies wrong key fails.
func TestDecryptBuildRequestWrongKey(t *testing.T) {
	crypto := NewBuildRecordCrypto()
	m := newTestECIESMaterial(t)

	_, privKey2, err := ecies.GenerateKeyPair()
	require.NoError(t, err)

	encrypted, err := crypto.EncryptBuildRequest(m.cleartext, m.pubKeyArr, m.identityHash)
	require.NoError(t, err)

	_, err = crypto.DecryptBuildRequest(encrypted, privKey2)
	assert.Error(t, err, "Wrong key should fail")
}

// TestVerifyIdentityHashRaw tests identity hash verification.
func TestVerifyIdentityHashRaw(t *testing.T) {
	crypto := NewBuildRecordCrypto()
	m := newTestECIESMaterial(t)

	encrypted, err := crypto.EncryptBuildRequest(m.cleartext, m.pubKeyArr, m.identityHash)
	require.NoError(t, err)

	// Should match our identity hash
	assert.True(t, crypto.VerifyIdentityHash(encrypted, m.identityHash))

	// Should not match a different identity hash
	var wrongHash [32]byte
	rand.Read(wrongHash[:])
	assert.False(t, crypto.VerifyIdentityHash(encrypted, wrongHash))
}

// TestExtractIdentityHashPrefixRaw tests prefix extraction.
func TestExtractIdentityHashPrefixRaw(t *testing.T) {
	var encrypted [528]byte
	rand.Read(encrypted[:])

	prefix := ExtractIdentityHashPrefixRaw(encrypted)

	for i := 0; i < 16; i++ {
		assert.Equal(t, encrypted[i], prefix[i])
	}
	for i := 16; i < 32; i++ {
		assert.Equal(t, byte(0), prefix[i])
	}
}

// TestComputeIdentityHash tests SHA-256 computation.
func TestComputeIdentityHash(t *testing.T) {
	data := make([]byte, 64)
	rand.Read(data)

	hash := ComputeIdentityHash(data)
	expected := types.SHA256(data)
	assert.Equal(t, expected, hash)
}

// TestEncryptBuildRequestInvalidCleartext tests bad cleartext sizes.
func TestEncryptBuildRequestInvalidCleartext(t *testing.T) {
	crypto := NewBuildRecordCrypto()
	m := newTestECIESMaterial(t)

	_, err := crypto.EncryptBuildRequest(make([]byte, 100), m.pubKeyArr, m.identityHash)
	assert.Error(t, err, "Non-222 cleartext should fail")
}

// TestDecryptBuildRequestInvalidKeySize tests bad key sizes.
func TestDecryptBuildRequestInvalidKeySize(t *testing.T) {
	crypto := NewBuildRecordCrypto()

	var encrypted [528]byte
	_, err := crypto.DecryptBuildRequest(encrypted, make([]byte, 16))
	assert.Error(t, err, "Non-32 byte key should fail")
}

// TestMultipleEncryptDecryptCycles tests repeated encrypt/decrypt cycles.
func TestMultipleEncryptDecryptCycles(t *testing.T) {
	crypto := NewBuildRecordCrypto()
	m := newTestECIESMaterial(t)

	for i := 0; i < 10; i++ {
		cleartext := make([]byte, 222)
		rand.Read(cleartext)

		encrypted, err := crypto.EncryptBuildRequest(cleartext, m.pubKeyArr, m.identityHash)
		require.NoError(t, err, "Cycle %d encrypt", i)

		decrypted, err := crypto.DecryptBuildRequest(encrypted, m.privKey)
		require.NoError(t, err, "Cycle %d decrypt", i)

		assert.Equal(t, cleartext, decrypted, "Cycle %d round-trip", i)
	}
}

// replyRecordBenchFixture holds the shared crypto material for reply record benchmarks.
type replyRecordBenchFixture struct {
	crypto    *BuildRecordCrypto
	key       [32]byte
	iv        [16]byte
	cleartext []byte
	encrypted []byte
}

// newReplyRecordBenchFixture creates a BuildRecordCrypto, random key/iv,
// and a serialized response record suitable for encrypt/decrypt benchmarks.
func newReplyRecordBenchFixture(b *testing.B) replyRecordBenchFixture {
	b.Helper()
	crypto := NewBuildRecordCrypto()

	var key [32]byte
	var iv [16]byte
	var randomData [495]byte

	rand.Read(key[:])
	rand.Read(iv[:])
	rand.Read(randomData[:])

	hash := CreateBuildResponseRecordRaw(0, randomData)
	cleartext := SerializeResponseRecord(hash, randomData, 0)

	encrypted, err := crypto.EncryptReplyRecord(cleartext, key, iv)
	if err != nil {
		b.Fatal(err)
	}
	return replyRecordBenchFixture{crypto: crypto, key: key, iv: iv, cleartext: cleartext, encrypted: encrypted}
}

// BenchmarkEncryptReplyRecord benchmarks reply record encryption.
func BenchmarkEncryptReplyRecord(b *testing.B) {
	f := newReplyRecordBenchFixture(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := f.crypto.EncryptReplyRecord(f.cleartext, f.key, f.iv)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkDecryptReplyRecord benchmarks reply record decryption.
func BenchmarkDecryptReplyRecord(b *testing.B) {
	f := newReplyRecordBenchFixture(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := f.crypto.DecryptReplyRecord(f.encrypted, f.key, f.iv)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkEncryptBuildRequest benchmarks ECIES build request encryption.
func BenchmarkEncryptBuildRequest(b *testing.B) {
	crypto := NewBuildRecordCrypto()

	pubKey, _, err := ecies.GenerateKeyPair()
	require.NoError(b, err)

	identityHash := types.SHA256(pubKey)
	var pubKeyArr [32]byte
	copy(pubKeyArr[:], pubKey)

	cleartext := make([]byte, 222)
	rand.Read(cleartext)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := crypto.EncryptBuildRequest(cleartext, pubKeyArr, identityHash)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkDecryptBuildRequest benchmarks ECIES build request decryption.
func BenchmarkDecryptBuildRequest(b *testing.B) {
	crypto := NewBuildRecordCrypto()

	pubKey, privKey, err := ecies.GenerateKeyPair()
	require.NoError(b, err)

	identityHash := types.SHA256(pubKey)
	var pubKeyArr [32]byte
	copy(pubKeyArr[:], pubKey)

	cleartext := make([]byte, 222)
	rand.Read(cleartext)

	encrypted, err := crypto.EncryptBuildRequest(cleartext, pubKeyArr, identityHash)
	require.NoError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := crypto.DecryptBuildRequest(encrypted, privKey)
		if err != nil {
			b.Fatal(err)
		}
	}
}
