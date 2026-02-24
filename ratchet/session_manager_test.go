package ratchet

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/go-i2p/crypto/ecies"
	"github.com/go-i2p/crypto/rand"
	"github.com/go-i2p/crypto/types"
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

	// New Session message (Noise IK): [Elligator2(e)(32)] + [encrypted_s(48)] + [encrypted_payload(N+16)]
	assert.GreaterOrEqual(t, len(encrypted), noiseIKMinMessageSize)

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

	sendKey, recvKey, err := deriveDirectionalKeys(baseKey, true)
	require.NoError(t, err)
	assert.NotEqual(t, sendKey, recvKey, "Send and receive keys must differ")
}

func TestDeriveDirectionalKeys_Symmetry(t *testing.T) {
	var baseKey [32]byte
	_, err := rand.Read(baseKey[:])
	require.NoError(t, err)

	initSend, initRecv, err := deriveDirectionalKeys(baseKey, true)
	require.NoError(t, err)
	respSend, respRecv, err := deriveDirectionalKeys(baseKey, false)
	require.NoError(t, err)

	assert.Equal(t, initSend, respRecv, "Initiator send == Responder receive")
	assert.Equal(t, initRecv, respSend, "Initiator receive == Responder send")
}

func TestDeriveDirectionalKeys_Deterministic(t *testing.T) {
	var baseKey [32]byte
	_, err := rand.Read(baseKey[:])
	require.NoError(t, err)

	s1, r1, err := deriveDirectionalKeys(baseKey, true)
	require.NoError(t, err)
	s2, r2, err := deriveDirectionalKeys(baseKey, true)
	require.NoError(t, err)
	assert.Equal(t, s1, s2, "Same key should produce same send key")
	assert.Equal(t, r1, r2, "Same key should produce same recv key")
}

func TestDeriveDirectionalKeys_DifferentBaseKeys(t *testing.T) {
	var key1, key2 [32]byte
	_, err := rand.Read(key1[:])
	require.NoError(t, err)
	_, err = rand.Read(key2[:])
	require.NoError(t, err)

	s1, _, err := deriveDirectionalKeys(key1, true)
	require.NoError(t, err)
	s2, _, err := deriveDirectionalKeys(key2, true)
	require.NoError(t, err)
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

	session, err := createSession(pubKey, keys, privKey, true)
	require.NoError(t, err)

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

	initiator, err := createSession(pubKey, keys, privKey, true)
	require.NoError(t, err)
	responder, err := createSession(pubKey, keys, privKey, false)
	require.NoError(t, err)

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

	session, err := createSession(pubKey, keys, sm.ourPrivateKey, true)
	require.NoError(t, err)
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

// TestClose verifies Close() stops cleanup, clears sessions, and zeroes the key.
func TestClose(t *testing.T) {
	sender := createTestSessionManager(t)
	receiver := createTestSessionManager(t)

	// Establish a session
	destHash := types.SHA256(receiver.ourPublicKey[:])
	_, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, []byte("hello"))
	require.NoError(t, err)
	assert.Equal(t, 1, sender.GetSessionCount())

	// Close should succeed
	err = sender.Close()
	require.NoError(t, err)

	// Sessions and tags should be cleared
	assert.Equal(t, 0, sender.GetSessionCount())

	// Private key should be zeroed
	var zeroKey [32]byte
	assert.Equal(t, zeroKey, sender.ourPrivateKey, "Private key should be zeroed after Close")
}

// TestCloseIdempotent verifies Close() can be called multiple times safely.
func TestCloseIdempotent(t *testing.T) {
	sm := createTestSessionManager(t)

	err := sm.Close()
	require.NoError(t, err)

	// Second call should not panic or error
	err = sm.Close()
	require.NoError(t, err)
}

// TestCloseStopsCleanupLoop verifies Close() terminates the cleanup goroutine.
func TestCloseStopsCleanupLoop(t *testing.T) {
	sm := createTestSessionManager(t)

	ctx := context.Background()
	sm.StartCleanupLoop(ctx)

	time.Sleep(10 * time.Millisecond)

	// Close should stop the cleanup loop (context.Background() never cancels,
	// but the internal context does)
	err := sm.Close()
	require.NoError(t, err)

	// Allow goroutine to exit
	time.Sleep(10 * time.Millisecond)
}

// ============================================================================
// Tag Collision Detection
// ============================================================================

// TestTagCollisionDetection verifies that generateTagWindow does not silently
// overwrite another session's tag when a collision occurs. Instead, it should
// skip the colliding tag and generate the next one.
func TestTagCollisionDetection(t *testing.T) {
	sm := createTestSessionManager(t)
	sender, receiver := createLinkedManagers(t)

	// Establish two sessions so we can have two different sessions with tags
	destHash1 := types.SHA256(receiver.ourPublicKey[:])
	_, err := sender.EncryptGarlicMessage(destHash1, receiver.ourPublicKey, []byte("session1"))
	require.NoError(t, err)

	destHash2 := types.SHA256(sm.ourPublicKey[:])
	_, err = sender.EncryptGarlicMessage(destHash2, sm.ourPublicKey, []byte("session2"))
	require.NoError(t, err)

	// Both sessions should exist and have their own tag windows
	assert.Equal(t, 2, sender.GetSessionCount())

	// Verify that tags from different sessions point to different session objects
	sender.mu.RLock()
	session1 := sender.sessions[destHash1]
	session2 := sender.sessions[destHash2]
	sender.mu.RUnlock()

	require.NotNil(t, session1)
	require.NotNil(t, session2)

	// Tags should not cross-reference
	sender.mu.RLock()
	for _, tag := range session1.pendingTags {
		if indexed, ok := sender.tagIndex[tag]; ok {
			assert.Equal(t, session1, indexed,
				"Session1 tag should point to session1, not another session")
		}
	}
	for _, tag := range session2.pendingTags {
		if indexed, ok := sender.tagIndex[tag]; ok {
			assert.Equal(t, session2, indexed,
				"Session2 tag should point to session2, not another session")
		}
	}
	sender.mu.RUnlock()
}

// TestGenerateTagWindowSameSessionNoCollision verifies that re-generating tags
// for the same session doesn't treat its own existing tags as collisions.
func TestGenerateTagWindowSameSessionNoCollision(t *testing.T) {
	sender := createTestSessionManager(t)
	receiver := createTestSessionManager(t)

	destHash := types.SHA256(receiver.ourPublicKey[:])
	_, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, []byte("hello"))
	require.NoError(t, err)

	sender.mu.Lock()
	session := sender.sessions[destHash]
	require.NotNil(t, session)

	// Consume some tags to force replenishment
	initialCount := len(session.pendingTags)
	if initialCount > 2 {
		// Remove tags from both pendingTags and tagIndex
		removed := session.pendingTags[:2]
		session.pendingTags = session.pendingTags[2:]
		for _, tag := range removed {
			delete(sender.tagIndex, tag)
		}
	}

	// Regenerate — should not hit any collision since same session owns the remaining tags
	err = sender.generateTagWindow(session)
	sender.mu.Unlock()

	require.NoError(t, err)
	assert.Equal(t, tagWindowSize, len(session.pendingTags))
}

// ============================================================================
// Empty Plaintext Validation
// ============================================================================

// TestEncryptEmptyPlaintextReturnsError verifies that encrypting with empty
// plaintext returns a clear error rather than producing an empty garlic message.
func TestEncryptEmptyPlaintextReturnsError(t *testing.T) {
	sender := createTestSessionManager(t)
	receiver := createTestSessionManager(t)

	destHash := types.SHA256(receiver.ourPublicKey[:])

	// nil plaintext
	_, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, nil)
	assert.Error(t, err, "nil plaintext should be rejected")
	assert.Contains(t, err.Error(), "non-empty")

	// zero-length plaintext
	_, err = sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, []byte{})
	assert.Error(t, err, "zero-length plaintext should be rejected")
	assert.Contains(t, err.Error(), "non-empty")
}

// TestEncryptNonEmptyPlaintextSucceeds confirms that non-empty plaintext works normally.
func TestEncryptNonEmptyPlaintextSucceeds(t *testing.T) {
	sender := createTestSessionManager(t)
	receiver := createTestSessionManager(t)

	destHash := types.SHA256(receiver.ourPublicKey[:])

	// Single byte should succeed
	encrypted, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, []byte{0x42})
	require.NoError(t, err)
	assert.NotEmpty(t, encrypted)
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

	err := sm.storeNewSessionState(dh, dp, keys, nil, true)
	require.NoError(t, err)

	sm.mu.RLock()
	count = len(sm.sessions)
	sm.mu.RUnlock()
	assert.LessOrEqual(t, count, MaxGarlicSessions+1)
}

func TestInboundSessionEnforcesMaxGarlicSessions(t *testing.T) {
	sm := createTestSessionManager(t)

	// Fill sessions to exactly MaxGarlicSessions with stale timestamps
	// so the eviction picks the oldest.
	sm.mu.Lock()
	for i := 0; i < MaxGarlicSessions; i++ {
		var hash [32]byte
		hash[0] = byte(i)
		hash[1] = byte(i >> 8)
		hash[2] = byte(i >> 16)

		sm.sessions[hash] = &Session{
			LastUsed: time.Now().Add(time.Duration(-i) * time.Second),
		}
	}
	sm.mu.Unlock()

	sm.mu.RLock()
	countBefore := len(sm.sessions)
	sm.mu.RUnlock()
	assert.Equal(t, MaxGarlicSessions, countBefore)

	// Simulate an inbound session being created via initializeInboundRatchetState.
	// This should evict one session before storing the new one.
	keys := &sessionKeys{}
	_, _ = rand.Read(keys.rootKey[:])
	_, _ = rand.Read(keys.tagKey[:])
	var remotePub [32]byte
	_, _ = rand.Read(remotePub[:])

	err := sm.initializeInboundRatchetState(remotePub, keys, nil)
	require.NoError(t, err)

	sm.mu.RLock()
	countAfter := len(sm.sessions)
	sm.mu.RUnlock()

	// After eviction + adding the new inbound session, count should stay at MaxGarlicSessions.
	assert.Equal(t, MaxGarlicSessions, countAfter,
		"inbound path should enforce MaxGarlicSessions by evicting before storing")
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

	// New Session (Noise IK): [Elligator2(e)(32)] + [encrypted_s(48)] + [encrypted_payload(N+16)]
	assert.GreaterOrEqual(t, len(encrypted), noiseIKMinMessageSize)

	// First 32 bytes are Elligator2-encoded ephemeral public key
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

	// Existing Session: [sessionTag(8)] + [ciphertext(N)] + [authTag(16)]
	// Nonce is counter-based and not transmitted on the wire.
	assert.GreaterOrEqual(t, len(enc2), 8+16)
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
// Counter-based Nonce & Max Message Number
// ============================================================================

func TestExistingSessionMessageNoExplicitNonce(t *testing.T) {
	sender, receiver := createLinkedManagers(t)

	var destHash [32]byte
	copy(destHash[:], receiver.ourPublicKey[:])

	// First message to create session
	enc1, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, []byte("init"))
	require.NoError(t, err)
	_, _, err = receiver.DecryptGarlicMessage(enc1)
	require.NoError(t, err)

	// Second message uses existing session with counter-based nonce
	payload := []byte("counter nonce test")
	enc2, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, payload)
	require.NoError(t, err)

	// Wire format: [sessionTag(8)] + [ciphertext(N)] + [authTag(16)]
	// No 12-byte nonce on the wire. Total = 8 + len(payload) + 16 (AEAD overhead) + 16 (auth tag)
	// With ChaCha20-Poly1305, ciphertext length == plaintext length, so:
	// total = 8 + len(payload) + 16
	expectedMin := 8 + len(payload) + 16
	assert.Equal(t, expectedMin, len(enc2),
		"Existing session message should not include explicit nonce on wire")

	// Verify it decrypts correctly
	dec2, sessionTag, err := receiver.DecryptGarlicMessage(enc2)
	require.NoError(t, err)
	assert.Equal(t, payload, dec2)
	assert.NotEqual(t, [8]byte{}, sessionTag)
}

func TestCounterNonceDeterministic(t *testing.T) {
	// Two sessions with the same keys at the same counter should produce the same nonce.
	// This is tested implicitly: if sender encrypts with counter N and receiver decrypts
	// with counter N, it must succeed. We verify by sending multiple messages.
	sender, receiver := createLinkedManagers(t)

	var destHash [32]byte
	copy(destHash[:], receiver.ourPublicKey[:])

	// Create session
	enc, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, []byte("session init"))
	require.NoError(t, err)
	_, _, err = receiver.DecryptGarlicMessage(enc)
	require.NoError(t, err)

	// Send 20 messages, each must decrypt with matching counter
	for i := 0; i < 20; i++ {
		payload := []byte("msg " + string(rune('A'+i)))
		enc, err = sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, payload)
		require.NoError(t, err, "Encrypt message %d", i)

		dec, _, err := receiver.DecryptGarlicMessage(enc)
		require.NoError(t, err, "Decrypt message %d", i)
		assert.Equal(t, payload, dec, "Message %d round-trip", i)
	}
}

func TestMaxMessageNumberEnforced(t *testing.T) {
	sender, receiver := createLinkedManagers(t)

	var destHash [32]byte
	copy(destHash[:], receiver.ourPublicKey[:])

	// Create session
	enc, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, []byte("init"))
	require.NoError(t, err)
	_, _, err = receiver.DecryptGarlicMessage(enc)
	require.NoError(t, err)

	// Artificially set message counter to MaxMessageNumber
	sender.mu.RLock()
	session := sender.sessions[destHash]
	sender.mu.RUnlock()
	require.NotNil(t, session)

	session.mu.Lock()
	session.MessageCounter = MaxMessageNumber
	session.mu.Unlock()

	// This message should still succeed (counter == MaxMessageNumber, which is <= MaxMessageNumber)
	_, err = sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, []byte("at limit"))
	require.NoError(t, err, "Encryption at MaxMessageNumber should succeed")

	// After incrementing, counter is now MaxMessageNumber+1
	// The next attempt should fail
	_, err = sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, []byte("past limit"))
	assert.Error(t, err, "Encryption past MaxMessageNumber should fail")
	assert.Contains(t, err.Error(), "exceeds maximum")
}

func TestMaxMessageNumberConstant(t *testing.T) {
	assert.Equal(t, uint32(65535), uint32(MaxMessageNumber),
		"MaxMessageNumber should be 65535 per the ECIES-Ratchet spec")
}

func TestBuildExistingSessionMessageFormat(t *testing.T) {
	var sessionTag [8]byte
	copy(sessionTag[:], []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08})
	ciphertext := []byte("encrypted data here")
	var authTag [16]byte
	copy(authTag[:], []byte{
		0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
		0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
	})

	msg := buildExistingSessionMessage(sessionTag, ciphertext, authTag)

	// Format: [tag(8)] + [ct(N)] + [authTag(16)]
	assert.Equal(t, 8+len(ciphertext)+16, len(msg))
	assert.Equal(t, sessionTag[:], msg[0:8])
	assert.Equal(t, ciphertext, msg[8:8+len(ciphertext)])
	assert.Equal(t, authTag[:], msg[8+len(ciphertext):])
}

func TestParseExistingSessionMessage(t *testing.T) {
	// Valid message
	ct := []byte("test ciphertext")
	var tag [16]byte
	_, err := rand.Read(tag[:])
	require.NoError(t, err)

	msg := append(ct, tag[:]...)
	parsedCT, parsedTag, err := parseExistingSessionMessage(msg)
	require.NoError(t, err)
	assert.Equal(t, ct, parsedCT)
	assert.Equal(t, tag, parsedTag)
}

func TestParseExistingSessionMessage_TooShort(t *testing.T) {
	_, _, err := parseExistingSessionMessage(make([]byte, 15))
	assert.Error(t, err, "Should reject message shorter than 16 bytes (minimum for auth tag only)")
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
// TagResolver Interface
// ============================================================================

func TestFindSessionByTagReturnsTrue(t *testing.T) {
	sender, receiver := createLinkedManagers(t)

	var destHash [32]byte
	copy(destHash[:], receiver.ourPublicKey[:])

	// Establish a session so the receiver has tags in its index.
	enc, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, []byte("setup"))
	require.NoError(t, err)
	_, _, err = receiver.DecryptGarlicMessage(enc)
	require.NoError(t, err)

	// Grab a pending tag from the receiver's tag index.
	receiver.mu.RLock()
	var knownTag [8]byte
	found := false
	for tag := range receiver.tagIndex {
		knownTag = tag
		found = true
		break
	}
	receiver.mu.RUnlock()
	require.True(t, found, "receiver should have tags in its index after session setup")

	// FindSessionByTag should return true and consume the tag.
	result := receiver.FindSessionByTag(knownTag)
	assert.True(t, result, "FindSessionByTag should return true for a known tag")

	// Tag should be consumed — looking it up again returns false.
	result = receiver.FindSessionByTag(knownTag)
	assert.False(t, result, "FindSessionByTag should return false for a consumed tag")
}

func TestFindSessionByTagReturnsFalseForUnknown(t *testing.T) {
	sm := createTestSessionManager(t)

	var unknownTag [8]byte
	unknownTag[0] = 0xFF
	unknownTag[7] = 0xAB

	result := sm.FindSessionByTag(unknownTag)
	assert.False(t, result, "FindSessionByTag should return false for unknown tags")
}

func TestFindSessionByTagReturnsFalseForExpiredSession(t *testing.T) {
	sender, receiver := createLinkedManagers(t)
	receiver.sessionTimeout = 1 * time.Millisecond // very short timeout

	var destHash [32]byte
	copy(destHash[:], receiver.ourPublicKey[:])

	enc, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, []byte("expire me"))
	require.NoError(t, err)
	_, _, err = receiver.DecryptGarlicMessage(enc)
	require.NoError(t, err)

	// Grab a pending tag.
	receiver.mu.RLock()
	var tag [8]byte
	found := false
	for t := range receiver.tagIndex {
		tag = t
		found = true
		break
	}
	receiver.mu.RUnlock()
	require.True(t, found)

	// Wait for the session to expire.
	time.Sleep(5 * time.Millisecond)

	result := receiver.FindSessionByTag(tag)
	assert.False(t, result, "FindSessionByTag should return false for expired session tags")
}

func TestTagResolverInterfaceSatisfied(t *testing.T) {
	sm := createTestSessionManager(t)
	// Verify SessionManager satisfies TagResolver at runtime too.
	var resolver TagResolver = sm
	assert.NotNil(t, resolver)
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
