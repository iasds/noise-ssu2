package ratchet

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/go-i2p/crypto/ecies"
	"github.com/go-i2p/crypto/rand"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// generateTestKeyPair generates a random X25519 key pair for testing.
func generateTestKeyPair(t testing.TB) [32]byte {
	t.Helper()
	_, privBytes, err := ecies.GenerateKeyPair()
	require.NoError(t, err, "failed to generate key pair")
	var priv [32]byte
	copy(priv[:], privBytes)
	return priv
}

// createTestSessionManager creates a SessionManager for testing.
func createTestSessionManager(t testing.TB) *SessionManager {
	t.Helper()
	privKey := generateTestKeyPair(t)
	sm, err := NewSessionManager(privKey)
	require.NoError(t, err)
	return sm
}

// createLinkedManagers creates two session managers that can communicate.
func createLinkedManagers(t testing.TB) (sender, receiver *SessionManager) {
	t.Helper()
	sender = createTestSessionManager(t)
	receiver = createTestSessionManager(t)
	return sender, receiver
}

// ============================================================================
// Session Manager Creation
// ============================================================================

func TestNewSessionManager(t *testing.T) {
	privKey := generateTestKeyPair(t)
	sm, err := NewSessionManager(privKey)
	require.NoError(t, err)
	assert.NotNil(t, sm)
	assert.Equal(t, 0, sm.GetSessionCount())
}

func TestGenerateSessionManager(t *testing.T) {
	sm, err := GenerateSessionManager()
	require.NoError(t, err)
	assert.NotNil(t, sm)
	assert.Equal(t, 0, sm.GetSessionCount())
}

// ============================================================================
// Encrypt/Decrypt Round-trip
// ============================================================================

func TestNewSessionEncryptDecrypt(t *testing.T) {
	sender, receiver := createLinkedManagers(t)

	plaintext := []byte("hello, garlic world!")
	var destHash [32]byte
	copy(destHash[:], receiver.ourPublicKey[:])

	// Encrypt
	encrypted, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, plaintext)
	require.NoError(t, err)
	assert.NotEmpty(t, encrypted)

	// New Session message: [ephemeralPubKey(32)] + [nonce(12)] + [ciphertext(N)] + [tag(16)]
	assert.GreaterOrEqual(t, len(encrypted), 32+12+16)

	// Decrypt
	decrypted, sessionTag, err := receiver.DecryptGarlicMessage(encrypted)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
	assert.Equal(t, [8]byte{}, sessionTag, "New Session should have zero session tag")
}

func TestExistingSessionEncryptDecrypt(t *testing.T) {
	sender, receiver := createLinkedManagers(t)

	var destHash [32]byte
	copy(destHash[:], receiver.ourPublicKey[:])

	// First message: creates session
	plaintext1 := []byte("first message")
	enc1, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, plaintext1)
	require.NoError(t, err)
	dec1, _, err := receiver.DecryptGarlicMessage(enc1)
	require.NoError(t, err)
	assert.Equal(t, plaintext1, dec1)

	// Second message: uses existing session
	plaintext2 := []byte("second message via existing session")
	enc2, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, plaintext2)
	require.NoError(t, err)

	// Existing Session message should differ from New Session
	assert.NotEqual(t, enc1, enc2)

	dec2, sessionTag, err := receiver.DecryptGarlicMessage(enc2)
	require.NoError(t, err)
	assert.Equal(t, plaintext2, dec2)
	assert.NotEqual(t, [8]byte{}, sessionTag, "Existing Session should have non-zero tag")
}

func TestMultipleMessages(t *testing.T) {
	sender, receiver := createLinkedManagers(t)

	var destHash [32]byte
	copy(destHash[:], receiver.ourPublicKey[:])

	for i := 0; i < 10; i++ {
		plaintext := []byte("message " + string(rune('A'+i)))
		enc, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, plaintext)
		require.NoError(t, err)
		dec, _, err := receiver.DecryptGarlicMessage(enc)
		require.NoError(t, err)
		assert.Equal(t, plaintext, dec, "Message %d should round-trip", i)
	}
}

// ============================================================================
// Key Derivation
// ============================================================================

func TestDeriveDirectionalKeys_Distinct(t *testing.T) {
	var baseKey [32]byte
	_, err := rand.Read(baseKey[:])
	require.NoError(t, err)

	sendKey, recvKey := deriveDirectionalKeys(baseKey, true)
	assert.NotEqual(t, sendKey, recvKey, "Send and receive keys must differ")
}

func TestDeriveDirectionalKeys_Symmetry(t *testing.T) {
	var baseKey [32]byte
	_, err := rand.Read(baseKey[:])
	require.NoError(t, err)

	initSend, initRecv := deriveDirectionalKeys(baseKey, true)
	respSend, respRecv := deriveDirectionalKeys(baseKey, false)

	assert.Equal(t, initSend, respRecv, "Initiator send == Responder receive")
	assert.Equal(t, initRecv, respSend, "Initiator receive == Responder send")
}

func TestDeriveDirectionalKeys_Deterministic(t *testing.T) {
	var baseKey [32]byte
	_, err := rand.Read(baseKey[:])
	require.NoError(t, err)

	s1, r1 := deriveDirectionalKeys(baseKey, true)
	s2, r2 := deriveDirectionalKeys(baseKey, true)
	assert.Equal(t, s1, s2, "Same key should produce same send key")
	assert.Equal(t, r1, r2, "Same key should produce same recv key")
}

func TestDeriveDirectionalKeys_DifferentBaseKeys(t *testing.T) {
	var key1, key2 [32]byte
	_, err := rand.Read(key1[:])
	require.NoError(t, err)
	_, err = rand.Read(key2[:])
	require.NoError(t, err)

	s1, _ := deriveDirectionalKeys(key1, true)
	s2, _ := deriveDirectionalKeys(key2, true)
	assert.NotEqual(t, s1, s2, "Different base keys should produce different results")
}

func TestSessionManagerKeyDerivation(t *testing.T) {
	var privKey [32]byte
	_, err := rand.Read(privKey[:])
	require.NoError(t, err)

	sm1, err := NewSessionManager(privKey)
	require.NoError(t, err)
	sm2, err := NewSessionManager(privKey)
	require.NoError(t, err)

	assert.Equal(t, sm1.ourPublicKey, sm2.ourPublicKey,
		"Same private key should derive same public key")
}

// ============================================================================
// Session Tag Lookup
// ============================================================================

func TestSessionTagLookup(t *testing.T) {
	sender, receiver := createLinkedManagers(t)

	var destHash [32]byte
	copy(destHash[:], receiver.ourPublicKey[:])

	// Create session
	plaintext := []byte("initial message")
	enc, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, plaintext)
	require.NoError(t, err)
	_, _, err = receiver.DecryptGarlicMessage(enc)
	require.NoError(t, err)

	// After New Session decryption, receiver should have tags indexed
	receiver.mu.RLock()
	tagCount := len(receiver.tagIndex)
	receiver.mu.RUnlock()
	assert.Greater(t, tagCount, 0, "Tag index should have entries after new session")
}

func TestTagWindowReplenishment(t *testing.T) {
	sender, receiver := createLinkedManagers(t)

	var destHash [32]byte
	copy(destHash[:], receiver.ourPublicKey[:])

	// Create initial session
	enc, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, []byte("init"))
	require.NoError(t, err)
	_, _, err = receiver.DecryptGarlicMessage(enc)
	require.NoError(t, err)

	// Send multiple messages to consume tags
	for i := 0; i < 8; i++ {
		enc, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, []byte("msg"))
		require.NoError(t, err)
		_, _, err = receiver.DecryptGarlicMessage(enc)
		require.NoError(t, err)
	}

	// Tags should have been replenished
	receiver.mu.RLock()
	tagCount := len(receiver.tagIndex)
	receiver.mu.RUnlock()
	assert.Greater(t, tagCount, 0, "Tags should be replenished after consumption")
}

// ============================================================================
// DH Ratchet
// ============================================================================

func TestDHRatchetInterval(t *testing.T) {
	assert.Equal(t, uint32(50), uint32(DHRatchetInterval))
}

func TestDHRatchetRotation(t *testing.T) {
	sender, receiver := createLinkedManagers(t)

	var destHash [32]byte
	copy(destHash[:], receiver.ourPublicKey[:])

	// Send messages up to but not exceeding the DH ratchet interval.
	// DH ratchet rotation happens after DHRatchetInterval messages. Once the
	// sender rotates, it produces new tag/symmetric ratchets from the new DH
	// chain. The receiver needs ProcessIncomingDHRatchet to learn the new
	// keys, which requires bidirectional communication. For this test we
	// verify that:
	// 1) Messages up to the rotation threshold work fine
	// 2) After rotation, the sender can still encrypt (no panic/error)
	// 3) The receiver can't decrypt post-rotation (expected: mismatched keys)

	// Send DHRatchetInterval messages successfully. The dhRatchetCounter starts
	// at 0 and increments before the comparison, so rotation triggers when
	// counter reaches DHRatchetInterval (on the DHRatchetInterval+1'th message).
	for i := 0; i < DHRatchetInterval; i++ {
		enc, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, []byte("msg"))
		require.NoError(t, err, "Message %d encrypt should succeed", i)
		_, _, err = receiver.DecryptGarlicMessage(enc)
		require.NoError(t, err, "Message %d decrypt should succeed", i)
	}

	// This message triggers DH ratchet rotation on sender
	enc, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, []byte("rotation-trigger"))
	require.NoError(t, err, "Encryption after rotation should succeed")

	// Receiver can't decrypt because sender's ratchet keys changed
	_, _, err = receiver.DecryptGarlicMessage(enc)
	assert.Error(t, err, "Post-rotation decryption should fail without ProcessIncomingDHRatchet")
}

func TestCreateSessionInitializesRatchets(t *testing.T) {
	var pubKey, privKey [32]byte
	_, err := rand.Read(pubKey[:])
	require.NoError(t, err)
	_, err = rand.Read(privKey[:])
	require.NoError(t, err)

	keys := &sessionKeys{}
	_, err = rand.Read(keys.rootKey[:])
	require.NoError(t, err)
	_, err = rand.Read(keys.symKey[:])
	require.NoError(t, err)
	_, err = rand.Read(keys.tagKey[:])
	require.NoError(t, err)

	session := createSession(pubKey, keys, privKey, true)

	assert.NotNil(t, session.DHRatchet, "DHRatchet should be initialized")
	assert.NotNil(t, session.SymmetricRatchet, "SymmetricRatchet should be initialized")
	assert.NotNil(t, session.TagRatchet, "TagRatchet should be initialized")
	assert.NotNil(t, session.RecvSymmetricRatchet, "RecvSymmetricRatchet should be initialized")
	assert.NotNil(t, session.RecvTagRatchet, "RecvTagRatchet should be initialized")
	assert.Equal(t, pubKey, session.RemotePublicKey)
	assert.Equal(t, uint32(1), session.MessageCounter, "MessageCounter starts at 1 (msg 0 is New Session)")
	assert.Equal(t, uint32(1), session.recvCounter, "recvCounter starts at 1 (msg 0 is New Session)")
}

func TestCreateSession_DirectionalKeyIsolation(t *testing.T) {
	var pubKey, privKey [32]byte
	_, err := rand.Read(pubKey[:])
	require.NoError(t, err)
	_, err = rand.Read(privKey[:])
	require.NoError(t, err)

	keys := &sessionKeys{}
	_, err = rand.Read(keys.rootKey[:])
	require.NoError(t, err)
	_, err = rand.Read(keys.tagKey[:])
	require.NoError(t, err)

	initiator := createSession(pubKey, keys, privKey, true)
	responder := createSession(pubKey, keys, privKey, false)

	// Initiator's sending keys should differ from responder's sending keys
	initSendKey, _, _ := initiator.SymmetricRatchet.DeriveMessageKeyAndAdvance(0)
	respSendKey, _, _ := responder.SymmetricRatchet.DeriveMessageKeyAndAdvance(0)
	assert.NotEqual(t, initSendKey, respSendKey,
		"Initiator and responder should have different sending keys")
}

// ============================================================================
// Session Cleanup
// ============================================================================

func TestCleanupExpiredSessions(t *testing.T) {
	sm := createTestSessionManager(t)
	sm.sessionTimeout = 50 * time.Millisecond

	// Manually create a session
	var hash [32]byte
	_, err := rand.Read(hash[:])
	require.NoError(t, err)

	keys := &sessionKeys{}
	_, err = rand.Read(keys.rootKey[:])
	require.NoError(t, err)
	_, err = rand.Read(keys.tagKey[:])
	require.NoError(t, err)

	var pubKey [32]byte
	_, err = rand.Read(pubKey[:])
	require.NoError(t, err)

	session := createSession(pubKey, keys, sm.ourPrivateKey, true)
	session.LastUsed = time.Now().Add(-time.Second) // Already expired

	sm.mu.Lock()
	sm.sessions[hash] = session
	sm.mu.Unlock()

	assert.Equal(t, 1, sm.GetSessionCount())

	removed := sm.CleanupExpiredSessions()
	assert.Equal(t, 1, removed)
	assert.Equal(t, 0, sm.GetSessionCount())
}

func TestCleanupLoop(t *testing.T) {
	sm := createTestSessionManager(t)

	ctx, cancel := context.WithCancel(context.Background())
	sm.StartCleanupLoop(ctx)

	// Should not panic
	time.Sleep(10 * time.Millisecond)
	cancel()
	time.Sleep(10 * time.Millisecond)
}

// ============================================================================
// LRU Eviction
// ============================================================================

func TestLRUEviction(t *testing.T) {
	sm := createTestSessionManager(t)

	sm.mu.Lock()
	// Fill sessions up to max + 1
	for i := 0; i < MaxGarlicSessions+1; i++ {
		var hash [32]byte
		hash[0] = byte(i)
		hash[1] = byte(i >> 8)
		hash[2] = byte(i >> 16)

		sm.sessions[hash] = &Session{
			LastUsed: time.Now().Add(time.Duration(-i) * time.Second),
		}
	}
	sm.mu.Unlock()

	// Should have evicted down or be at max
	sm.mu.RLock()
	count := len(sm.sessions)
	sm.mu.RUnlock()
	assert.Equal(t, MaxGarlicSessions+1, count)

	// Next storeNewSessionState should evict
	keys := &sessionKeys{}
	_, _ = rand.Read(keys.rootKey[:])
	_, _ = rand.Read(keys.tagKey[:])
	var dh, dp [32]byte
	_, _ = rand.Read(dh[:])
	_, _ = rand.Read(dp[:])

	err := sm.storeNewSessionState(dh, dp, keys)
	require.NoError(t, err)

	sm.mu.RLock()
	count = len(sm.sessions)
	sm.mu.RUnlock()
	assert.LessOrEqual(t, count, MaxGarlicSessions+1)
}

// ============================================================================
// Concurrency
// ============================================================================

func TestConcurrentEncrypt(t *testing.T) {
	sender, receiver := createLinkedManagers(t)

	var wg sync.WaitGroup
	const goroutines = 10

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			var destHash [32]byte
			destHash[0] = byte(idx) // Different destinations
			plaintext := []byte("concurrent message")

			_, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, plaintext)
			assert.NoError(t, err, "Goroutine %d: encryption should succeed", idx)
		}(i)
	}

	wg.Wait()
}

func TestConcurrentEncryptDecrypt(t *testing.T) {
	sender, receiver := createLinkedManagers(t)

	var destHash [32]byte
	copy(destHash[:], receiver.ourPublicKey[:])

	// Create initial session
	enc, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, []byte("init"))
	require.NoError(t, err)
	_, _, err = receiver.DecryptGarlicMessage(enc)
	require.NoError(t, err)

	var wg sync.WaitGroup
	const goroutines = 5

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			for j := 0; j < 5; j++ {
				enc, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, []byte("msg"))
				if err != nil {
					t.Errorf("Goroutine %d: encrypt failed: %v", idx, err)
					return
				}
				_, _, err = receiver.DecryptGarlicMessage(enc)
				if err != nil {
					// Expected: concurrent decryption may fail due to ratchet state contention
					// This tests that no panics/races occur, not that all succeed
					continue
				}
			}
		}(i)
	}

	wg.Wait()
}

// ============================================================================
// Message Format
// ============================================================================

func TestNewSessionMessageFormat(t *testing.T) {
	sender, receiver := createLinkedManagers(t)

	var destHash [32]byte
	copy(destHash[:], receiver.ourPublicKey[:])

	plaintext := []byte("test message format")
	encrypted, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, plaintext)
	require.NoError(t, err)

	// New Session: [ephemeralPubKey(32)] + [nonce(12)] + [ciphertext(N)] + [tag(16)]
	assert.GreaterOrEqual(t, len(encrypted), 32+12+16)

	// First 32 bytes are ephemeral public key
	ephPub := encrypted[0:32]
	allZero := true
	for _, b := range ephPub {
		if b != 0 {
			allZero = false
			break
		}
	}
	assert.False(t, allZero, "Ephemeral public key should not be all zeros")
}

func TestExistingSessionMessageFormat(t *testing.T) {
	sender, receiver := createLinkedManagers(t)

	var destHash [32]byte
	copy(destHash[:], receiver.ourPublicKey[:])

	// First message to create session
	enc1, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, []byte("init"))
	require.NoError(t, err)
	_, _, err = receiver.DecryptGarlicMessage(enc1)
	require.NoError(t, err)

	// Second message uses existing session
	enc2, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, []byte("existing"))
	require.NoError(t, err)

	// Existing Session: [sessionTag(8)] + [nonce(12)] + [ciphertext(N)] + [tag(16)]
	assert.GreaterOrEqual(t, len(enc2), 8+12+16)
}

// ============================================================================
// Error Cases
// ============================================================================

func TestDecryptTooShort(t *testing.T) {
	sm := createTestSessionManager(t)

	_, _, err := sm.DecryptGarlicMessage([]byte{1, 2, 3})
	assert.Error(t, err, "Should reject messages shorter than 8 bytes")
}

func TestDecryptGarbage(t *testing.T) {
	sm := createTestSessionManager(t)

	garbage := make([]byte, 100)
	_, err := rand.Read(garbage)
	require.NoError(t, err)

	_, _, err = sm.DecryptGarlicMessage(garbage)
	assert.Error(t, err, "Should fail to decrypt garbage data")
}

func TestDecryptWrongKey(t *testing.T) {
	sender := createTestSessionManager(t)
	receiver := createTestSessionManager(t)
	wrongReceiver := createTestSessionManager(t)

	var destHash [32]byte
	copy(destHash[:], receiver.ourPublicKey[:])

	plaintext := []byte("secret message")
	enc, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, plaintext)
	require.NoError(t, err)

	_, _, err = wrongReceiver.DecryptGarlicMessage(enc)
	assert.Error(t, err, "Should fail to decrypt with wrong private key")
}

// ============================================================================
// Interface Compliance
// ============================================================================

func TestSessionManager_ImplementsGarlicSessionManager(t *testing.T) {
	// Compile-time check (var _ GarlicSessionManager = (*SessionManager)(nil))
	// is in session_manager.go. This test verifies at runtime.
	var iface GarlicSessionManager = createTestSessionManager(t)
	assert.NotNil(t, iface)
}

// ============================================================================
// Benchmarks
// ============================================================================

func BenchmarkNewSessionEncrypt(b *testing.B) {
	privKey := [32]byte{}
	_, _ = rand.Read(privKey[:])
	sender, _ := NewSessionManager(privKey)
	_, _ = rand.Read(privKey[:])
	receiver, _ := NewSessionManager(privKey)

	plaintext := make([]byte, 1024)
	_, _ = rand.Read(plaintext)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var destHash [32]byte
		destHash[0] = byte(i)
		destHash[1] = byte(i >> 8)
		_, _ = sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, plaintext)
	}
}

func BenchmarkExistingSessionEncrypt(b *testing.B) {
	privKey := [32]byte{}
	_, _ = rand.Read(privKey[:])
	sender, _ := NewSessionManager(privKey)
	_, _ = rand.Read(privKey[:])
	receiver, _ := NewSessionManager(privKey)

	var destHash [32]byte
	copy(destHash[:], receiver.ourPublicKey[:])

	plaintext := make([]byte, 1024)
	_, _ = rand.Read(plaintext)

	// Create initial session
	enc, _ := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, plaintext)
	_, _, _ = receiver.DecryptGarlicMessage(enc)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, plaintext)
	}
}

func BenchmarkDecryptGarlicMessage(b *testing.B) {
	privKey := [32]byte{}
	_, _ = rand.Read(privKey[:])
	sender, _ := NewSessionManager(privKey)
	_, _ = rand.Read(privKey[:])
	receiver, _ := NewSessionManager(privKey)

	var destHash [32]byte
	copy(destHash[:], receiver.ourPublicKey[:])

	plaintext := make([]byte, 1024)
	_, _ = rand.Read(plaintext)

	// Encrypt one message
	enc, _ := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, plaintext)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// We can only decrypt the same New Session message once (ratchet advances),
		// so we must encrypt fresh each iteration for a real benchmark.
		b.StopTimer()
		enc, _ = sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, plaintext)
		b.StartTimer()
		_, _, _ = receiver.DecryptGarlicMessage(enc)
	}
}
