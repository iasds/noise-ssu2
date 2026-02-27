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

// mustCompleteNSR completes the NSR handshake after the sender has sent an NS message
// that the receiver has already decrypted (returning sessionHash). After this call,
// the sender (initiator) can send Existing Session messages per ratchet.md §1g.
func mustCompleteNSR(t testing.TB, sender, receiver *SessionManager, sessionHash [32]byte) {
	t.Helper()
	nsrEnc, err := receiver.EncryptNewSessionReply(sessionHash, []byte("nsr"))
	require.NoError(t, err, "mustCompleteNSR: EncryptNewSessionReply")
	_, _, _, err = sender.DecryptGarlicMessage(nsrEnc)
	require.NoError(t, err, "mustCompleteNSR: sender DecryptGarlicMessage(NSR)")
}

// mustBootstrapSession creates a fully established NS→NSR session between sender
// and receiver. It returns destHash for use in subsequent EncryptGarlicMessage calls.
// After this call, sender can send Existing Session messages immediately.
func mustBootstrapSession(t testing.TB, sender, receiver *SessionManager) [32]byte {
	t.Helper()
	var destHash [32]byte
	copy(destHash[:], receiver.ourPublicKey[:])
	nsEnc, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, mustBuildNSPayload(t, []byte("bootstrap")))
	require.NoError(t, err, "mustBootstrapSession: NS encrypt")
	_, _, sessionHash, err := receiver.DecryptGarlicMessage(nsEnc)
	require.NoError(t, err, "mustBootstrapSession: NS decrypt")
	require.NotNil(t, sessionHash, "mustBootstrapSession: receiver must return sessionHash")
	mustCompleteNSR(t, sender, receiver, *sessionHash)
	return destHash
}

// mustBuildNSPayload wraps raw garlic data in a spec-compliant New Session
// payload: DateTime block (required first) + GarlicClove block.
// Fails the test immediately if BuildNSPayload returns an error.
func mustBuildNSPayload(t testing.TB, data []byte) []byte {
	t.Helper()
	payload, err := BuildNSPayload(data)
	require.NoError(t, err, "mustBuildNSPayload: BuildNSPayload failed")
	return payload
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

	// NS payload must begin with a DateTime block per spec (ratchet.md §1b).
	plaintext := mustBuildNSPayload(t, []byte("hello, garlic world!"))
	var destHash [32]byte
	copy(destHash[:], receiver.ourPublicKey[:])

	// Encrypt
	encrypted, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, plaintext)
	require.NoError(t, err)
	assert.NotEmpty(t, encrypted)

	// New Session message (Noise IK): [Elligator2(e)(32)] + [encrypted_s(48)] + [encrypted_payload(N+16)]
	assert.GreaterOrEqual(t, len(encrypted), noiseIKMinMessageSize)

	// Decrypt
	decrypted, sessionTag, _, err := receiver.DecryptGarlicMessage(encrypted)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
	assert.Equal(t, [8]byte{}, sessionTag, "New Session should have zero session tag")
}

func TestExistingSessionEncryptDecrypt(t *testing.T) {
	sender, receiver := createLinkedManagers(t)

	var destHash [32]byte
	copy(destHash[:], receiver.ourPublicKey[:])

	// First message: creates session — must be a valid NS payload (DateTime block required).
	plaintext1 := mustBuildNSPayload(t, []byte("first message"))
	enc1, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, plaintext1)
	require.NoError(t, err)
	dec1, _, nsHash1, err := receiver.DecryptGarlicMessage(enc1)
	require.NoError(t, err)
	assert.Equal(t, plaintext1, dec1)
	require.NotNil(t, nsHash1)
	mustCompleteNSR(t, sender, receiver, *nsHash1)

	// Second message: uses existing session
	plaintext2 := []byte("second message via existing session")
	enc2, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, plaintext2)
	require.NoError(t, err)

	// Existing Session message should differ from New Session
	assert.NotEqual(t, enc1, enc2)

	dec2, sessionTag, _, err := receiver.DecryptGarlicMessage(enc2)
	require.NoError(t, err)
	assert.Equal(t, plaintext2, dec2)
	assert.NotEqual(t, [8]byte{}, sessionTag, "Existing Session should have non-zero tag")
}

func TestMultipleMessages(t *testing.T) {
	sender, receiver := createLinkedManagers(t)

	var destHash [32]byte
	copy(destHash[:], receiver.ourPublicKey[:])

	// Establish the session with a valid NS payload before the loop so that
	// every loop iteration uses the Existing Session path (no DateTime req).
	initPayload := mustBuildNSPayload(t, []byte("init"))
	initEnc, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, initPayload)
	require.NoError(t, err)
	_, _, initNSHash, err := receiver.DecryptGarlicMessage(initEnc)
	require.NoError(t, err)
	require.NotNil(t, initNSHash)
	mustCompleteNSR(t, sender, receiver, *initNSHash)

	for i := 0; i < 10; i++ {
		plaintext := []byte("message " + string(rune('A'+i)))
		enc, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, plaintext)
		require.NoError(t, err)
		dec, _, _, err := receiver.DecryptGarlicMessage(enc)
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

	// Create session — NS payload must begin with DateTime block.
	enc, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, mustBuildNSPayload(t, []byte("initial message")))
	require.NoError(t, err)
	_, _, _, err = receiver.DecryptGarlicMessage(enc)
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

	// Create initial session with valid NS payload.
	enc, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, mustBuildNSPayload(t, []byte("init")))
	require.NoError(t, err)
	_, _, tagNSHash, err := receiver.DecryptGarlicMessage(enc)
	require.NoError(t, err)
	require.NotNil(t, tagNSHash)
	mustCompleteNSR(t, sender, receiver, *tagNSHash)

	// Send multiple messages to consume tags
	for i := 0; i < 8; i++ {
		enc, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, []byte("msg"))
		require.NoError(t, err)
		_, _, _, err = receiver.DecryptGarlicMessage(enc)
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

	// Establish session with valid NS payload before the DH ratchet loop.
	initEnc, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, mustBuildNSPayload(t, []byte("init")))
	require.NoError(t, err, "Initial NS encrypt should succeed")
	_, _, dhNSHash, err := receiver.DecryptGarlicMessage(initEnc)
	require.NoError(t, err, "Initial NS decrypt should succeed")
	require.NotNil(t, dhNSHash)
	mustCompleteNSR(t, sender, receiver, *dhNSHash)

	// Send DHRatchetInterval-1 ES messages successfully — the NS message above consumed
	// one slot, so we need one fewer ES messages here to avoid triggering DH ratchet rotation
	// within the loop. Rotation triggers when dhRatchetCounter reaches DHRatchetInterval
	// (on the DHRatchetInterval+1'th total message = the "rotation-trigger" below).
	for i := 0; i < DHRatchetInterval-1; i++ {
		enc, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, []byte("msg"))
		require.NoError(t, err, "Message %d encrypt should succeed", i)
		_, _, _, err = receiver.DecryptGarlicMessage(enc)
		require.NoError(t, err, "Message %d decrypt should succeed", i)
	}

	// This message triggers DH ratchet rotation on sender
	enc, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, []byte("rotation-trigger"))
	require.NoError(t, err, "Encryption after rotation should succeed")

	// Receiver can't decrypt because sender's ratchet keys changed
	_, _, _, err = receiver.DecryptGarlicMessage(enc)
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
	assert.Equal(t, uint32(1), session.recvWindowBase, "recvWindowBase starts at 1 (msg 0 is New Session)")
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
	_, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, mustBuildNSPayload(t, []byte("hello")))
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
	_, err := sender.EncryptGarlicMessage(destHash1, receiver.ourPublicKey, mustBuildNSPayload(t, []byte("session1")))
	require.NoError(t, err)

	destHash2 := types.SHA256(sm.ourPublicKey[:])
	_, err = sender.EncryptGarlicMessage(destHash2, sm.ourPublicKey, mustBuildNSPayload(t, []byte("session2")))
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
	_, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, mustBuildNSPayload(t, []byte("hello")))
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

// TestEncryptNonEmptyPlaintextSucceeds confirms that a non-empty, spec-compliant NS payload
// (with DateTime block) is accepted by EncryptGarlicMessage.
func TestEncryptNonEmptyPlaintextSucceeds(t *testing.T) {
	sender := createTestSessionManager(t)
	receiver := createTestSessionManager(t)

	destHash := types.SHA256(receiver.ourPublicKey[:])

	// Validly-structured NS payload must succeed.
	nsPayload := mustBuildNSPayload(t, []byte{0x42})
	encrypted, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, nsPayload)
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
			destHash[0] = byte(idx) // Different destinations → each is a new NS
			nsPayload := mustBuildNSPayload(t, []byte("concurrent message"))

			_, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, nsPayload)
			assert.NoError(t, err, "Goroutine %d: encryption should succeed", idx)
		}(i)
	}

	wg.Wait()
}

func TestConcurrentEncryptDecrypt(t *testing.T) {
	sender, receiver := createLinkedManagers(t)

	var destHash [32]byte
	copy(destHash[:], receiver.ourPublicKey[:])

	// Create initial session with valid NS payload.
	enc, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, mustBuildNSPayload(t, []byte("init")))
	require.NoError(t, err)
	_, _, concNSHash, err := receiver.DecryptGarlicMessage(enc)
	require.NoError(t, err)
	require.NotNil(t, concNSHash)
	mustCompleteNSR(t, sender, receiver, *concNSHash)

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
				_, _, _, err = receiver.DecryptGarlicMessage(enc)
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

	plaintext := mustBuildNSPayload(t, []byte("test message format"))
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

	// First message to create session — must be valid NS payload.
	enc1, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, mustBuildNSPayload(t, []byte("init")))
	require.NoError(t, err)
	_, _, fmtNSHash, err := receiver.DecryptGarlicMessage(enc1)
	require.NoError(t, err)
	require.NotNil(t, fmtNSHash)
	mustCompleteNSR(t, sender, receiver, *fmtNSHash)

	// Second message uses existing session (no DateTime block req for ES).
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

	_, _, _, err := sm.DecryptGarlicMessage([]byte{1, 2, 3})
	assert.Error(t, err, "Should reject messages shorter than 8 bytes")
}

func TestDecryptGarbage(t *testing.T) {
	sm := createTestSessionManager(t)

	garbage := make([]byte, 100)
	_, err := rand.Read(garbage)
	require.NoError(t, err)

	_, _, _, err = sm.DecryptGarlicMessage(garbage)
	assert.Error(t, err, "Should fail to decrypt garbage data")
}

func TestDecryptWrongKey(t *testing.T) {
	sender := createTestSessionManager(t)
	receiver := createTestSessionManager(t)
	wrongReceiver := createTestSessionManager(t)

	var destHash [32]byte
	copy(destHash[:], receiver.ourPublicKey[:])

	plaintext := mustBuildNSPayload(t, []byte("secret message"))
	enc, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, plaintext)
	require.NoError(t, err)

	_, _, _, err = wrongReceiver.DecryptGarlicMessage(enc)
	assert.Error(t, err, "Should fail to decrypt with wrong private key")
}

// ============================================================================
// Counter-based Nonce & Max Message Number
// ============================================================================

func TestExistingSessionMessageNoExplicitNonce(t *testing.T) {
	sender, receiver := createLinkedManagers(t)

	var destHash [32]byte
	copy(destHash[:], receiver.ourPublicKey[:])

	// First message to create session with valid NS payload.
	enc1, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, mustBuildNSPayload(t, []byte("init")))
	require.NoError(t, err)
	_, _, nonceNSHash, err := receiver.DecryptGarlicMessage(enc1)
	require.NoError(t, err)
	require.NotNil(t, nonceNSHash)
	mustCompleteNSR(t, sender, receiver, *nonceNSHash)

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
	dec2, sessionTag, _, err := receiver.DecryptGarlicMessage(enc2)
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

	// Create session with valid NS payload.
	enc, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, mustBuildNSPayload(t, []byte("session init")))
	require.NoError(t, err)
	_, _, ctrNSHash, err := receiver.DecryptGarlicMessage(enc)
	require.NoError(t, err)
	require.NotNil(t, ctrNSHash)
	mustCompleteNSR(t, sender, receiver, *ctrNSHash)

	// Send 20 messages, each must decrypt with matching counter
	for i := 0; i < 20; i++ {
		payload := []byte("msg " + string(rune('A'+i)))
		enc, err = sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, payload)
		require.NoError(t, err, "Encrypt message %d", i)

		dec, _, _, err := receiver.DecryptGarlicMessage(enc)
		require.NoError(t, err, "Decrypt message %d", i)
		assert.Equal(t, payload, dec, "Message %d round-trip", i)
	}
}

func TestMaxMessageNumberEnforced(t *testing.T) {
	sender, receiver := createLinkedManagers(t)

	var destHash [32]byte
	copy(destHash[:], receiver.ourPublicKey[:])

	// Create session with valid NS payload.
	enc, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, mustBuildNSPayload(t, []byte("init")))
	require.NoError(t, err)
	_, _, maxNSHash, err := receiver.DecryptGarlicMessage(enc)
	require.NoError(t, err)
	require.NotNil(t, maxNSHash)
	mustCompleteNSR(t, sender, receiver, *maxNSHash)

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
	enc, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, mustBuildNSPayload(t, []byte("setup")))
	require.NoError(t, err)
	_, _, _, err = receiver.DecryptGarlicMessage(enc)
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

	enc, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, mustBuildNSPayload(t, []byte("expire me")))
	require.NoError(t, err)
	_, _, _, err = receiver.DecryptGarlicMessage(enc)
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

	// Build a valid NS payload once; every iteration is a new session (new destHash).
	nsPayload, _ := BuildNSPayload(make([]byte, 512))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var destHash [32]byte
		destHash[0] = byte(i)
		destHash[1] = byte(i >> 8)
		_, _ = sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, nsPayload)
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

	// Create initial session with a valid NS payload.
	nsPayload, _ := BuildNSPayload(make([]byte, 32))
	enc, _ := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, nsPayload)
	_, _, _, _ = receiver.DecryptGarlicMessage(enc)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// ES path: no DateTime validation required.
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

	// Build a valid NS payload for benchmark iterations (each iteration re-encrypts NS).
	nsPayload, _ := BuildNSPayload(make([]byte, 32))

	// Encrypt initial session message.
	enc, _ := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, nsPayload)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// We can only decrypt the same New Session message once (ratchet advances),
		// so we must encrypt fresh each iteration for a real benchmark.
		b.StopTimer()
		enc, _ = sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, nsPayload)
		b.StartTimer()
		_, _, _, _ = receiver.DecryptGarlicMessage(enc)
	}
}

// ============================================================================
// NSR Flow — end-to-end tests (Recommendations 2, 3, 4 from ratchet/AUDIT.md)
// ============================================================================

// TestDecryptGarlicMessage_ReturnsSessionHashForNewSession verifies that
// DecryptGarlicMessage returns a non-nil session hash (SHA-256 of the
// initiator's static public key) only for New Session messages, and nil
// for Existing Session messages. This enables the responder to call
// EncryptNewSessionReply with the correct key.
func TestDecryptGarlicMessage_ReturnsSessionHashForNewSession(t *testing.T) {
	initiator, responder := createLinkedManagers(t)

	destHash := types.SHA256(responder.ourPublicKey[:])
	// NS payload must begin with DateTime block per spec (ratchet.md §1b).
	nsPayload := mustBuildNSPayload(t, []byte("new session payload"))

	// Encrypt NS
	encrypted, err := initiator.EncryptGarlicMessage(destHash, responder.ourPublicKey, nsPayload)
	require.NoError(t, err)

	// Decrypt NS — sessionHash must be non-nil and equal SHA256(initiator pub)
	plaintext, _, sessionHash, err := responder.DecryptGarlicMessage(encrypted)
	require.NoError(t, err)
	assert.Equal(t, nsPayload, plaintext)
	require.NotNil(t, sessionHash, "New Session decryption must return a non-nil session hash")

	expectedHash := types.SHA256(initiator.ourPublicKey[:])
	assert.Equal(t, expectedHash, *sessionHash,
		"Session hash should be SHA-256 of the initiator's static public key")
}

// TestDecryptGarlicMessage_NilSessionHashForExistingSession verifies that
// Existing Session messages produce a nil session hash — callers must not
// try to send an NSR in response to an ES message.
func TestDecryptGarlicMessage_NilSessionHashForExistingSession(t *testing.T) {
	initiator, responder := createLinkedManagers(t)

	destHash := types.SHA256(responder.ourPublicKey[:])

	// Establish session via first NS — must be a valid NS payload.
	enc1, err := initiator.EncryptGarlicMessage(destHash, responder.ourPublicKey, mustBuildNSPayload(t, []byte("ns")))
	require.NoError(t, err)
	_, _, nilNSHash, err := responder.DecryptGarlicMessage(enc1)
	require.NoError(t, err)
	require.NotNil(t, nilNSHash)
	mustCompleteNSR(t, initiator, responder, *nilNSHash)

	// Second message is ES — session hash must be nil
	enc2, err := initiator.EncryptGarlicMessage(destHash, responder.ourPublicKey, []byte("es"))
	require.NoError(t, err)

	_, _, sessionHash, err := responder.DecryptGarlicMessage(enc2)
	require.NoError(t, err)
	assert.Nil(t, sessionHash, "Existing Session decryption should return nil session hash")
}

// TestNSNSRESFlow_EndToEnd exercises the full NS→NSR→ES round-trip:
//
//  1. Alice sends a New Session (NS) to Bob.
//  2. Bob decrypts NS, gets the session hash, and replies with a New Session Reply (NSR).
//  3. Alice receives the NSR via DecryptGarlicMessage — which dispatches to the NSR path,
//     applies the post-handshake keys (ee DH), and re-initializes both ratchets.
//  4. Both sides exchange Existing Session (ES) messages encrypted with NSR-derived keys.
//
// This validates items 2 (NSR dispatch), 3 (apply NSR keys), and 4 (session hash) from
// the ratchet/AUDIT.md Recommendations.
func TestNSNSRESFlow_EndToEnd(t *testing.T) {
	alice, err := GenerateSessionManager()
	require.NoError(t, err)
	bob, err := GenerateSessionManager()
	require.NoError(t, err)

	// ── Step 1: Alice → Bob: New Session ──────────────────────────────────
	aliceToBobHash := types.SHA256(bob.ourPublicKey[:])
	// NS payload must begin with DateTime block per spec (ratchet.md §1b).
	nsPayload := mustBuildNSPayload(t, []byte("Hello Bob, session request"))

	nsMsg, err := alice.EncryptGarlicMessage(aliceToBobHash, bob.ourPublicKey, nsPayload)
	require.NoError(t, err)

	// ── Step 2: Bob decrypts NS and sends NSR ─────────────────────────────
	decNS, _, sessionHash, err := bob.DecryptGarlicMessage(nsMsg)
	require.NoError(t, err)
	assert.Equal(t, nsPayload, decNS, "Bob should recover Alice's NS payload")
	require.NotNil(t, sessionHash, "Bob must receive session hash to send NSR")

	nsrPayload := []byte("Hello Alice, session accepted")
	nsrMsg, err := bob.EncryptNewSessionReply(*sessionHash, nsrPayload)
	require.NoError(t, err)
	require.NotNil(t, nsrMsg)

	// ── Step 3: Alice receives NSR via DecryptGarlicMessage ───────────────
	decNSR, nsrTag, nsrHash, err := alice.DecryptGarlicMessage(nsrMsg)
	require.NoError(t, err, "Alice must successfully decrypt Bob's NSR")
	assert.Equal(t, nsrPayload, decNSR, "Alice should recover Bob's NSR payload")
	assert.Equal(t, [8]byte{}, nsrTag, "NSR messages use zero session tag (tag is in wire prefix)")
	assert.Nil(t, nsrHash, "NSR messages should return nil session hash")

	// ── Step 4: ES exchange using NSR-derived keys ────────────────────────
	// Alice sends ES to Bob
	esPayload1 := []byte("ES from Alice after NSR")
	esMsg1, err := alice.EncryptGarlicMessage(aliceToBobHash, bob.ourPublicKey, esPayload1)
	require.NoError(t, err)

	decES1, esTag1, _, err := bob.DecryptGarlicMessage(esMsg1)
	require.NoError(t, err, "Bob must decrypt Alice's post-NSR ES message")
	assert.Equal(t, esPayload1, decES1)
	assert.NotEqual(t, [8]byte{}, esTag1, "ES messages must have non-zero tag")

	// Bob sends ES to Alice
	bobToAliceHash := types.SHA256(alice.ourPublicKey[:])
	esPayload2 := []byte("ES from Bob after NSR")
	esMsg2, err := bob.EncryptGarlicMessage(bobToAliceHash, alice.ourPublicKey, esPayload2)
	require.NoError(t, err)

	decES2, esTag2, _, err := alice.DecryptGarlicMessage(esMsg2)
	require.NoError(t, err, "Alice must decrypt Bob's post-NSR ES message")
	assert.Equal(t, esPayload2, decES2)
	assert.NotEqual(t, [8]byte{}, esTag2, "ES messages must have non-zero tag")
}

// TestEncryptNewSessionReply_UsesReturnedSessionHash verifies that the session
// hash returned by DecryptGarlicMessage is directly usable with EncryptNewSessionReply,
// without requiring the responder to independently recompute SHA-256(initiatorPub).
func TestEncryptNewSessionReply_UsesReturnedSessionHash(t *testing.T) {
	initiator, responder := createLinkedManagers(t)

	destHash := types.SHA256(responder.ourPublicKey[:])

	encrypted, err := initiator.EncryptGarlicMessage(destHash, responder.ourPublicKey, mustBuildNSPayload(t, []byte("ns")))
	require.NoError(t, err)

	_, _, sessionHash, err := responder.DecryptGarlicMessage(encrypted)
	require.NoError(t, err)
	require.NotNil(t, sessionHash)

	// Use the returned hash directly — no manual SHA-256 computation
	nsrMsg, err := responder.EncryptNewSessionReply(*sessionHash, []byte("nsr"))
	require.NoError(t, err)
	assert.NotEmpty(t, nsrMsg)
}

// TestNSRTag_RegisteredAndConsumedOnReceipt verifies that:
//   - After sending a New Session, the initiator's nsrTagIndex has one entry.
//   - After receiving the NSR, the nsrTagIndex entry is consumed.
//   - The initiator's nsrTag field on the session is cleared.
func TestNSRTag_RegisteredAndConsumedOnReceipt(t *testing.T) {
	initiator, responder := createLinkedManagers(t)

	destHash := types.SHA256(responder.ourPublicKey[:])

	// Step 1: Alice sends NS — must be a valid NS payload; registers an NSR tag.
	nsMsg, err := initiator.EncryptGarlicMessage(destHash, responder.ourPublicKey, mustBuildNSPayload(t, []byte("ns")))
	require.NoError(t, err)

	initiator.mu.RLock()
	nsrTagCount := len(initiator.nsrTagIndex)
	initiator.mu.RUnlock()
	assert.Equal(t, 1, nsrTagCount, "After sending NS, initiator should have one NSR tag registered")

	// Step 2: Bob processes NS and sends NSR
	_, _, sessionHash, err := responder.DecryptGarlicMessage(nsMsg)
	require.NoError(t, err)
	require.NotNil(t, sessionHash)

	nsrMsg, err := responder.EncryptNewSessionReply(*sessionHash, []byte("nsr"))
	require.NoError(t, err)

	// Step 3: Alice receives NSR — NSR tag should be consumed
	_, _, _, err = initiator.DecryptGarlicMessage(nsrMsg)
	require.NoError(t, err)

	initiator.mu.RLock()
	nsrTagCountAfter := len(initiator.nsrTagIndex)
	initiator.mu.RUnlock()
	assert.Equal(t, 0, nsrTagCountAfter, "After receiving NSR, nsrTagIndex should be empty")

	// Initiator session should also have nsrTag cleared
	initiator.mu.RLock()
	session := initiator.sessions[destHash]
	initiator.mu.RUnlock()
	require.NotNil(t, session)

	session.mu.Lock()
	nsrTagPtr := session.nsrTag
	session.mu.Unlock()
	assert.Nil(t, nsrTagPtr, "Session nsrTag should be nil after NSR receipt")
}

// TestNSRKeys_RatchetsUpdatedAfterNSR verifies that the session's ratchet keys
// change when the NSR is processed (both initiator and responder).
// This ensures the post-handshake ee DH provides forward secrecy beyond the NS.
func TestNSRKeys_RatchetsUpdatedAfterNSR(t *testing.T) {
	initiator, responder := createLinkedManagers(t)

	destHash := types.SHA256(responder.ourPublicKey[:])

	// Send NS — must be a valid NS payload.
	nsMsg, err := initiator.EncryptGarlicMessage(destHash, responder.ourPublicKey, mustBuildNSPayload(t, []byte("ns")))
	require.NoError(t, err)

	_, _, sessionHash, err := responder.DecryptGarlicMessage(nsMsg)
	require.NoError(t, err)
	require.NotNil(t, sessionHash)

	// Capture responder's pre-NSR send tag for comparison
	responder.mu.RLock()
	respSession := responder.sessions[*sessionHash]
	responder.mu.RUnlock()
	require.NotNil(t, respSession)

	respSession.mu.Lock()
	preNSRTagRatchetAddr := respSession.TagRatchet
	respSession.mu.Unlock()

	// Send NSR
	nsrMsg, err := responder.EncryptNewSessionReply(*sessionHash, []byte("nsr"))
	require.NoError(t, err)

	// After NSR, responder's TagRatchet should be a new object (replaced)
	respSession.mu.Lock()
	postNSRTagRatchetAddr := respSession.TagRatchet
	respSession.mu.Unlock()
	assert.NotSame(t, preNSRTagRatchetAddr, postNSRTagRatchetAddr,
		"Responder's TagRatchet must be replaced after sending NSR")

	// Initiator receives NSR — its ratchets must also be replaced
	initiator.mu.RLock()
	initSession := initiator.sessions[destHash]
	initiator.mu.RUnlock()
	require.NotNil(t, initSession)

	initSession.mu.Lock()
	preNSRInitTagRatchet := initSession.TagRatchet
	initSession.mu.Unlock()

	_, _, _, err = initiator.DecryptGarlicMessage(nsrMsg)
	require.NoError(t, err)

	initSession.mu.Lock()
	postNSRInitTagRatchet := initSession.TagRatchet
	initSession.mu.Unlock()
	assert.NotSame(t, preNSRInitTagRatchet, postNSRInitTagRatchet,
		"Initiator's TagRatchet must be replaced after receiving NSR")
}

// ============================================================================
// generateTagWindow — nil RecvTagRatchet
// ============================================================================

// TestGenerateTagWindow_NilRecvTagRatchet_ReturnsError verifies that
// generateTagWindow returns an explicit error when session.RecvTagRatchet is
// nil rather than silently falling back to the send-direction TagRatchet.
//
// Inserting send-direction tags into the incoming tag index would cause every
// inbound existing-session message to fail tag lookup without any diagnostic
// output, which is far harder to debug than an early error.
func TestGenerateTagWindow_NilRecvTagRatchet_ReturnsError(t *testing.T) {
	sm := createTestSessionManager(t)

	var pubKey, privKey [32]byte
	_, _ = rand.Read(pubKey[:])
	_, _ = rand.Read(privKey[:])

	keys := &sessionKeys{}
	_, _ = rand.Read(keys.rootKey[:])
	_, _ = rand.Read(keys.tagKey[:])

	session, err := createSession(pubKey, keys, privKey, true)
	require.NoError(t, err)

	// Deliberately nil out the receive ratchet to simulate a partially
	// constructed session (e.g., after a failed ratchet update).
	session.RecvTagRatchet = nil

	sm.mu.Lock()
	genErr := sm.generateTagWindow(session)
	sm.mu.Unlock()

	require.Error(t, genErr, "generateTagWindow must return an error when RecvTagRatchet is nil")
	assert.Contains(t, genErr.Error(), "RecvTagRatchet is nil",
		"error message should identify the nil ratchet")

	// The tag index must remain empty — no send-direction tags were inserted.
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	for _, sess := range sm.tagIndex {
		assert.NotSame(t, sess, session,
			"no tags for the broken session should appear in the index")
	}
}

// ============================================================================
// Unbound (N-pattern) New Session — EncryptUnboundGarlicMessage
// ============================================================================

// TestEncryptUnboundGarlicMessage_Roundtrip encrypts a garlic message as an
// unbound (N-pattern) New Session and verifies the receiver can decrypt it.
// Crucially, no session state is created on the receiver side and the returned
// sessionHash is nil — the sender's static key was not transmitted.
func TestEncryptUnboundGarlicMessage_Roundtrip(t *testing.T) {
	sender := createTestSessionManager(t)
	receiver := createTestSessionManager(t)

	// Unbound NS messages also require a DateTime block as the first payload block.
	plaintext := mustBuildNSPayload(t, []byte("unbound one-way garlic message"))

	// Sender encrypts an unbound message (no static key on the wire).
	ciphertext, err := sender.EncryptUnboundGarlicMessage(receiver.ourPublicKey, plaintext)
	require.NoError(t, err)
	require.NotEmpty(t, ciphertext)

	// The receiver decrypts it. sessionHash must be nil (no initiator static key).
	decrypted, sessionTag, sessionHash, err := receiver.DecryptGarlicMessage(ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted, "Decrypted payload should match original")
	assert.Equal(t, [8]byte{}, sessionTag, "Unbound NS messages carry no session tag")
	assert.Nil(t, sessionHash, "sessionHash must be nil for unbound messages — no static key")
}

// TestEncryptUnboundGarlicMessage_EmptyPayloadRejected ensures an empty payload
// is rejected with an error, matching the EncryptGarlicMessage contract.
func TestEncryptUnboundGarlicMessage_EmptyPayloadRejected(t *testing.T) {
	sm := createTestSessionManager(t)
	var destPub [32]byte
	_, _ = rand.Read(destPub[:])

	_, err := sm.EncryptUnboundGarlicMessage(destPub, nil)
	assert.Error(t, err, "nil payload should be rejected")

	_, err = sm.EncryptUnboundGarlicMessage(destPub, []byte{})
	assert.Error(t, err, "empty payload should be rejected")
}

// TestEncryptUnboundGarlicMessage_NoSessionStateStored verifies that after a
// receiver processes an unbound New Session message, no inbound session is
// registered for the sender (non-repliable: no return path exists).
func TestEncryptUnboundGarlicMessage_NoSessionStateStored(t *testing.T) {
	sender := createTestSessionManager(t)
	receiver := createTestSessionManager(t)

	initialSessions := receiver.GetSessionCount()

	ciphertext, err := sender.EncryptUnboundGarlicMessage(receiver.ourPublicKey, mustBuildNSPayload(t, []byte("datagram")))
	require.NoError(t, err)

	_, _, _, err = receiver.DecryptGarlicMessage(ciphertext)
	require.NoError(t, err)

	// Receiver must NOT have created a session for the (anonymous) sender.
	assert.Equal(t, initialSessions, receiver.GetSessionCount(),
		"unbound session must not register any inbound session state")
}

// TestEncryptUnboundGarlicMessage_MultipleUnboundMessages verifies that
// multiple unbound messages from the same sender can each be decrypted
// independently, since every unbound message is a fresh one-shot frame.
func TestEncryptUnboundGarlicMessage_MultipleUnboundMessages(t *testing.T) {
	sender := createTestSessionManager(t)
	receiver := createTestSessionManager(t)

	// Unbound NS messages require DateTime block as first payload block.
	payloads := [][]byte{
		mustBuildNSPayload(t, []byte("first unbound")),
		mustBuildNSPayload(t, []byte("second unbound")),
		mustBuildNSPayload(t, []byte("third unbound")),
	}

	for i, payload := range payloads {
		ct, err := sender.EncryptUnboundGarlicMessage(receiver.ourPublicKey, payload)
		require.NoError(t, err, "message %d encrypt", i)

		pt, _, sessionHash, err := receiver.DecryptGarlicMessage(ct)
		require.NoError(t, err, "message %d decrypt", i)
		assert.Equal(t, payload, pt, "message %d payload mismatch", i)
		assert.Nil(t, sessionHash, "message %d: sessionHash must be nil for unbound", i)
	}

	// Receiver still has no persistent session for the anonymous sender.
	assert.Equal(t, 0, receiver.GetSessionCount(),
		"receiver must not accumulate sessions from unbound messages")
}

// TestEncryptUnboundGarlicMessage_WrongRecipientFails verifies that an unbound
// message cannot be decrypted by a recipient with a different key pair.
func TestEncryptUnboundGarlicMessage_WrongRecipientFails(t *testing.T) {
	sender := createTestSessionManager(t)
	receiver := createTestSessionManager(t)
	wrongReceiver := createTestSessionManager(t)

	ct, err := sender.EncryptUnboundGarlicMessage(receiver.ourPublicKey, mustBuildNSPayload(t, []byte("secret")))
	require.NoError(t, err)

	_, _, _, err = wrongReceiver.DecryptGarlicMessage(ct)
	assert.Error(t, err, "Wrong recipient must not decrypt an unbound message")
}

// TestEncryptUnboundGarlicMessage_IsNonRepliable verifies that receiving an
// unbound message does NOT cause the receiver to register an NSR tag — there
// is no reply path for unbound sessions.
func TestEncryptUnboundGarlicMessage_IsNonRepliable(t *testing.T) {
	sender := createTestSessionManager(t)
	receiver := createTestSessionManager(t)

	ct, err := sender.EncryptUnboundGarlicMessage(receiver.ourPublicKey, mustBuildNSPayload(t, []byte("one-way")))
	require.NoError(t, err)

	_, _, _, err = receiver.DecryptGarlicMessage(ct)
	require.NoError(t, err)

	receiver.mu.RLock()
	nsrCount := len(receiver.nsrTagIndex)
	receiver.mu.RUnlock()
	assert.Equal(t, 0, nsrCount, "No NSR tag should be registered for an unbound session")
}

// ============================================================================
// [SPEC] NS payload DateTime validation — AUDIT item
// ============================================================================

// TestEncryptGarlicMessage_RejectsNSPayloadWithoutDateTime verifies that
// EncryptGarlicMessage returns an error when the caller attempts to send a New
// Session message whose payload does not begin with a DateTime block,
// enforcing ratchet.md §1b.
func TestEncryptGarlicMessage_RejectsNSPayloadWithoutDateTime(t *testing.T) {
	sender := createTestSessionManager(t)
	receiver := createTestSessionManager(t)

	var destHash [32]byte
	copy(destHash[:], receiver.ourPublicKey[:])

	// Raw bytes have no DateTime block → must be rejected.
	_, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, []byte("raw payload without datetime"))
	require.Error(t, err, "NS path must reject payload lacking DateTimeBlock")
	assert.Contains(t, err.Error(), "new session payload rejected",
		"error must identify the rejection source")
}

// TestEncryptUnboundGarlicMessage_RejectsPayloadWithoutDateTime verifies that
// EncryptUnboundGarlicMessage also enforces the DateTime validation.
func TestEncryptUnboundGarlicMessage_RejectsPayloadWithoutDateTime(t *testing.T) {
	sender := createTestSessionManager(t)
	receiver := createTestSessionManager(t)

	_, err := sender.EncryptUnboundGarlicMessage(receiver.ourPublicKey, []byte("raw payload"))
	require.Error(t, err, "Unbound NS path must reject payload lacking DateTimeBlock")
	assert.Contains(t, err.Error(), "unbound new session payload rejected")
}

// TestEncryptGarlicMessage_AcceptsValidNSPayload verifies the happy path: a
// properly built NS payload (with leading DateTime block) is accepted.
func TestEncryptGarlicMessage_AcceptsValidNSPayload(t *testing.T) {
	sender, receiver := createLinkedManagers(t)

	var destHash [32]byte
	copy(destHash[:], receiver.ourPublicKey[:])

	payload := mustBuildNSPayload(t, []byte("valid payload"))
	_, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, payload)
	assert.NoError(t, err, "valid NS payload must be accepted")
}

// ============================================================================
// [EDGE] Lock splitting — AUDIT item
// ============================================================================

// TestReplenishTagWindowOutsideLock_DoesNotDeadlock verifies that concurrent
// goroutines performing encrypt+decrypt operations do not deadlock when tag
// replenishment runs outside sm.mu.  This guards against a regression where
// replenishTagWindowOutsideLock acquires sm.mu while session.mu is already
// held (or vice-versa), forming a lock-order cycle.
//
// Strategy: run many sender→receiver pairs concurrently.  Each pair exchanges
// enough messages to trigger at least one replenishment cycle.  If the lock
// ordering is wrong, the test will deadlock and be caught by -timeout.
func TestReplenishTagWindowOutsideLock_DoesNotDeadlock(t *testing.T) {
	const goroutines = 8
	const msgsPerPair = 20 // enough to cross the replenish threshold (tagWindowSize=10, threshold=5)

	done := make(chan struct{}, goroutines)

	for g := 0; g < goroutines; g++ {
		go func(id int) {
			defer func() { done <- struct{}{} }()
			sender, receiver := createLinkedManagers(t)

			var destHash [32]byte
			copy(destHash[:], receiver.ourPublicKey[:])

			// Establish session.
			enc, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, mustBuildNSPayload(t, []byte("init")))
			if err != nil {
				t.Errorf("goroutine %d: NS encrypt failed: %v", id, err)
				return
			}
			_, _, goNSHash, nsErr := receiver.DecryptGarlicMessage(enc)
			if nsErr != nil {
				t.Errorf("goroutine %d: NS decrypt failed: %v", id, nsErr)
				return
			}
			if goNSHash == nil {
				t.Errorf("goroutine %d: NS sessionHash is nil", id)
				return
			}
			mustCompleteNSR(t, sender, receiver, *goNSHash)

			// Exchange ES messages; replenishment will fire around message 6 and again ~12.
			for i := 0; i < msgsPerPair; i++ {
				enc, err = sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, []byte("ping"))
				if err != nil {
					t.Errorf("goroutine %d: ES encrypt %d failed: %v", id, i, err)
					return
				}
				if _, _, _, err = receiver.DecryptGarlicMessage(enc); err != nil {
					t.Errorf("goroutine %d: ES decrypt %d failed: %v", id, i, err)
					return
				}
			}
		}(g)
	}

	for i := 0; i < goroutines; i++ {
		<-done
	}
}

// TestReplenishTagWindowOutsideLock_ReplenishesCorrectly verifies that after
// consuming more than tagWindowSize messages the tag window is continuously
// replenished so that no decrypt attempt ever fails with "tag not found".
// This is the functional regression test for the lock-split refactor.
func TestReplenishTagWindowOutsideLock_ReplenishesCorrectly(t *testing.T) {
	sender, receiver := createLinkedManagers(t)

	var destHash [32]byte
	copy(destHash[:], receiver.ourPublicKey[:])

	// Establish session.
	enc, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, mustBuildNSPayload(t, []byte("bootstrap")))
	require.NoError(t, err)
	_, _, repNSHash, err := receiver.DecryptGarlicMessage(enc)
	require.NoError(t, err)
	require.NotNil(t, repNSHash)
	mustCompleteNSR(t, sender, receiver, *repNSHash)

	// Exchange 3× tagWindowSize messages — each full window cycle triggers at
	// least one replenishment.  All must succeed.
	const n = tagWindowSize * 3
	for i := 0; i < n; i++ {
		enc, err = sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, []byte("data"))
		require.NoError(t, err, "ES encrypt %d must succeed", i)
		_, _, _, err = receiver.DecryptGarlicMessage(enc)
		require.NoError(t, err, "ES decrypt %d must succeed — tag window was not replenished", i)
	}
}

// TestConcurrentEncryptWithCleanup exercises the race condition fix where
// EncryptGarlicMessage now holds sm.mu.RLock through the encryptExistingSession
// call, preventing concurrent CleanupExpiredSessions from evicting the session
// (and its tags from tagIndex) between lookup and encryption.
//
// This test runs many goroutines: some continuously encrypting ES messages,
// others continuously calling CleanupExpiredSessions. With the race detector
// enabled (-race), any unsafe concurrent access would be flagged. The test
// also verifies that no encrypt calls fail due to session eviction while the
// session is actively being used.
func TestConcurrentEncryptWithCleanup(t *testing.T) {
	sender, receiver := createLinkedManagers(t)
	sender.sessionTimeout = 200 * time.Millisecond

	destHash := mustBootstrapSession(t, sender, receiver)

	const (
		encryptGoroutines = 5
		cleanupGoroutines = 3
		messagesPerGor    = 20
	)

	var wg sync.WaitGroup
	encryptErrors := make(chan error, encryptGoroutines*messagesPerGor)

	// Goroutines that continuously encrypt ES messages.
	for i := 0; i < encryptGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < messagesPerGor; j++ {
				_, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, []byte("concurrent-es"))
				if err != nil {
					encryptErrors <- err
				}
			}
		}()
	}

	// Goroutines that continuously try to clean up expired sessions.
	for i := 0; i < cleanupGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < messagesPerGor; j++ {
				sender.CleanupExpiredSessions()
			}
		}()
	}

	wg.Wait()
	close(encryptErrors)

	// The session is actively used, so CleanupExpiredSessions should not evict
	// it. No encrypt call should fail due to session eviction.
	for err := range encryptErrors {
		t.Errorf("unexpected encrypt error during concurrent cleanup: %v", err)
	}

	// Session must still exist after concurrent access.
	assert.Equal(t, 1, sender.GetSessionCount(), "session should survive concurrent cleanup when actively used")
}
