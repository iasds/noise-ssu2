package ratchet

import (
	"testing"

	"github.com/go-i2p/crypto/rand"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// Session NextKey State
// ============================================================================

func TestSession_InitialNextKeyState(t *testing.T) {
	var pubKey, privKey [32]byte
	_, err := rand.Read(pubKey[:])
	require.NoError(t, err)
	_, err = rand.Read(privKey[:])
	require.NoError(t, err)

	keys := &sessionKeys{}
	_, _ = rand.Read(keys.rootKey[:])
	_, _ = rand.Read(keys.tagKey[:])

	session, err := createSession(pubKey, keys, privKey, true)
	require.NoError(t, err)

	sendKeyID, recvKeyID, awaiting := session.NextKeyState()
	assert.Equal(t, uint16(0), sendKeyID, "Initial sendKeyID should be 0")
	assert.Equal(t, uint16(0), recvKeyID, "Initial recvKeyID should be 0")
	assert.False(t, awaiting, "Should not be awaiting reverse key initially")
	assert.False(t, session.HasPendingNextKeys(), "No pending NextKeys initially")
	assert.Nil(t, session.GetPendingNextKeys(), "GetPendingNextKeys should return nil initially")
}

func TestSession_IncrementSendKeyID(t *testing.T) {
	var pubKey, privKey [32]byte
	_, _ = rand.Read(pubKey[:])
	_, _ = rand.Read(privKey[:])

	keys := &sessionKeys{}
	_, _ = rand.Read(keys.rootKey[:])
	_, _ = rand.Read(keys.tagKey[:])

	session, err := createSession(pubKey, keys, privKey, true)
	require.NoError(t, err)

	err = session.IncrementSendKeyID()
	require.NoError(t, err)

	sendKeyID, _, _ := session.NextKeyState()
	assert.Equal(t, uint16(1), sendKeyID)
}

func TestSession_IncrementSendKeyID_MaxReached(t *testing.T) {
	var pubKey, privKey [32]byte
	_, _ = rand.Read(pubKey[:])
	_, _ = rand.Read(privKey[:])

	keys := &sessionKeys{}
	_, _ = rand.Read(keys.rootKey[:])
	_, _ = rand.Read(keys.tagKey[:])

	session, err := createSession(pubKey, keys, privKey, true)
	require.NoError(t, err)
	session.sendKeyID = MaxKeyID

	err = session.IncrementSendKeyID()
	assert.Error(t, err, "Should error when key ID at maximum")
	assert.Contains(t, err.Error(), "maximum")
}

// ============================================================================
// DH Ratchet Step Queues NextKey Block
// ============================================================================

func TestPerformDHRatchetStep_QueuesNextKey(t *testing.T) {
	var pubKey, privKey [32]byte
	_, _ = rand.Read(pubKey[:])
	_, _ = rand.Read(privKey[:])

	keys := &sessionKeys{}
	_, _ = rand.Read(keys.rootKey[:])
	_, _ = rand.Read(keys.tagKey[:])

	session, err := createSession(pubKey, keys, privKey, true)
	require.NoError(t, err)

	// Perform a DH ratchet step — this should queue a NextKey block.
	err = performDHRatchetStep(session)
	require.NoError(t, err)

	assert.True(t, session.HasPendingNextKeys(), "Should have pending NextKey after DH rotation")
	assert.NotNil(t, session.newEphemeralPub, "newEphemeralPub should be set")

	blocks := session.GetPendingNextKeys()
	require.Len(t, blocks, 1, "Should have exactly one pending NextKey block")

	// Verify the NextKey block contents.
	info, err := blocks[0].NextKey()
	require.NoError(t, err)
	assert.True(t, info.KeyPresent, "Forward NextKey should include the public key")
	assert.False(t, info.Reverse, "Should be a forward key")
	assert.True(t, info.RequestReverse, "First rotation should request reverse")
	assert.Equal(t, uint16(0), info.KeyID, "First key ID should be 0")
	assert.Equal(t, *session.newEphemeralPub, info.PublicKey, "Key should match newEphemeralPub")

	// After GetPendingNextKeys, the queue should be empty.
	assert.False(t, session.HasPendingNextKeys(), "Pending queue should be cleared after Get")
	assert.True(t, session.awaitingReverseKey, "Should be awaiting reverse key")
}

func TestPerformDHRatchetStep_ConsecutiveRotations(t *testing.T) {
	var pubKey, privKey [32]byte
	_, _ = rand.Read(pubKey[:])
	_, _ = rand.Read(privKey[:])

	keys := &sessionKeys{}
	_, _ = rand.Read(keys.rootKey[:])
	_, _ = rand.Read(keys.tagKey[:])

	session, err := createSession(pubKey, keys, privKey, true)
	require.NoError(t, err)

	// Two consecutive DH ratchets should each queue a NextKey block.
	err = performDHRatchetStep(session)
	require.NoError(t, err)
	err = performDHRatchetStep(session)
	require.NoError(t, err)

	blocks := session.GetPendingNextKeys()
	assert.Len(t, blocks, 2, "Two rotations should queue two NextKey blocks")
}

// ============================================================================
// ProcessReceivedNextKey — Forward Key
// ============================================================================

func TestProcessReceivedNextKey_ForwardKey(t *testing.T) {
	sender, receiver := createLinkedManagers(t)

	var destHash [32]byte
	copy(destHash[:], receiver.ourPublicKey[:])

	// Establish a session.
	enc, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, []byte("init"))
	require.NoError(t, err)
	_, _, err = receiver.DecryptGarlicMessage(enc)
	require.NoError(t, err)

	// Get a valid session tag from the receiver's tag index.
	sessionTag := getAnyTag(t, receiver)

	// Simulate a forward NextKey from the sender.
	var newKey [32]byte
	_, _ = rand.Read(newKey[:])

	info := NextKeyInfo{
		KeyPresent:     true,
		Reverse:        false,
		RequestReverse: false,
		KeyID:          0,
		PublicKey:       newKey,
	}

	err = receiver.ProcessReceivedNextKey(sessionTag, info)
	require.NoError(t, err, "Processing forward NextKey should succeed")
}

func TestProcessReceivedNextKey_ForwardKeyRequestsReverse(t *testing.T) {
	sender, receiver := createLinkedManagers(t)

	var destHash [32]byte
	copy(destHash[:], receiver.ourPublicKey[:])

	enc, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, []byte("init"))
	require.NoError(t, err)
	_, _, err = receiver.DecryptGarlicMessage(enc)
	require.NoError(t, err)

	sessionTag := getAnyTag(t, receiver)

	var newKey [32]byte
	_, _ = rand.Read(newKey[:])

	info := NextKeyInfo{
		KeyPresent:     true,
		Reverse:        false,
		RequestReverse: true,
		KeyID:          0,
		PublicKey:       newKey,
	}

	err = receiver.ProcessReceivedNextKey(sessionTag, info)
	require.NoError(t, err)

	// The receiver should now have a pending reverse NextKey to send back.
	session := lookupSessionByAnyTag(t, receiver)
	require.NotNil(t, session)

	session.mu.Lock()
	hasPending := session.HasPendingNextKeys()
	session.mu.Unlock()

	assert.True(t, hasPending, "Should have queued a reverse NextKey response")
}

// ============================================================================
// ProcessReceivedNextKey — Reverse Key
// ============================================================================

func TestProcessReceivedNextKey_ReverseKey(t *testing.T) {
	sender, receiver := createLinkedManagers(t)

	var destHash [32]byte
	copy(destHash[:], receiver.ourPublicKey[:])

	enc, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, []byte("init"))
	require.NoError(t, err)
	_, _, err = receiver.DecryptGarlicMessage(enc)
	require.NoError(t, err)

	sessionTag := getAnyTag(t, receiver)

	// Set awaitingReverseKey on the session to simulate having sent a forward key.
	session := lookupSessionByAnyTag(t, receiver)
	session.mu.Lock()
	session.awaitingReverseKey = true
	session.mu.Unlock()

	var reverseKey [32]byte
	_, _ = rand.Read(reverseKey[:])

	info := NextKeyInfo{
		KeyPresent:     true,
		Reverse:        true,
		RequestReverse: false,
		KeyID:          0,
		PublicKey:       reverseKey,
	}

	err = receiver.ProcessReceivedNextKey(sessionTag, info)
	require.NoError(t, err)

	session.mu.Lock()
	_, _, awaiting := session.NextKeyState()
	session.mu.Unlock()

	assert.False(t, awaiting, "awaitingReverseKey should be cleared after receiving reverse key")
}

// ============================================================================
// ProcessReceivedNextKey — Ack (No Key)
// ============================================================================

func TestProcessReceivedNextKey_AckNoKey(t *testing.T) {
	sender, receiver := createLinkedManagers(t)

	var destHash [32]byte
	copy(destHash[:], receiver.ourPublicKey[:])

	enc, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, []byte("init"))
	require.NoError(t, err)
	_, _, err = receiver.DecryptGarlicMessage(enc)
	require.NoError(t, err)

	sessionTag := getAnyTag(t, receiver)

	// Ack with no key: peer acknowledges with their existing key.
	info := NextKeyInfo{
		KeyPresent:     false,
		Reverse:        true,
		RequestReverse: false,
		KeyID:          0,
	}

	err = receiver.ProcessReceivedNextKey(sessionTag, info)
	require.NoError(t, err, "Processing NextKey ack should succeed")
}

// ============================================================================
// ProcessReceivedNextKey — Error Cases
// ============================================================================

func TestProcessReceivedNextKey_UnknownTag(t *testing.T) {
	sm := createTestSessionManager(t)

	var unknownTag [8]byte
	unknownTag[0] = 0xFF

	info := NextKeyInfo{
		KeyPresent: true,
		KeyID:      0,
	}

	err := sm.ProcessReceivedNextKey(unknownTag, info)
	assert.Error(t, err, "Should error for unknown session tag")
	assert.Contains(t, err.Error(), "no session found")
}

// ============================================================================
// ProcessIncomingDHRatchet — Coverage Tests
// ============================================================================

func TestProcessIncomingDHRatchet_Success(t *testing.T) {
	sender, receiver := createLinkedManagers(t)

	var destHash [32]byte
	copy(destHash[:], receiver.ourPublicKey[:])

	// Establish a session.
	enc, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, []byte("init"))
	require.NoError(t, err)
	_, _, err = receiver.DecryptGarlicMessage(enc)
	require.NoError(t, err)

	// Get a valid session tag.
	sessionTag := getAnyTag(t, receiver)

	// Generate a new DH key to simulate a peer ratchet.
	var newPubKey [32]byte
	_, _ = rand.Read(newPubKey[:])

	err = receiver.ProcessIncomingDHRatchet(sessionTag, newPubKey)
	require.NoError(t, err, "ProcessIncomingDHRatchet should succeed with valid tag and key")
}

func TestProcessIncomingDHRatchet_UnknownTag(t *testing.T) {
	sm := createTestSessionManager(t)

	var unknownTag [8]byte
	unknownTag[0] = 0xDE

	var pubKey [32]byte
	_, _ = rand.Read(pubKey[:])

	err := sm.ProcessIncomingDHRatchet(unknownTag, pubKey)
	assert.Error(t, err, "Should error for unknown session tag")
	assert.Contains(t, err.Error(), "no session found")
}

func TestProcessIncomingDHRatchet_UpdatesReceivingChain(t *testing.T) {
	sender, receiver := createLinkedManagers(t)

	var destHash [32]byte
	copy(destHash[:], receiver.ourPublicKey[:])

	enc, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, []byte("init"))
	require.NoError(t, err)
	_, _, err = receiver.DecryptGarlicMessage(enc)
	require.NoError(t, err)

	sessionTag := getAnyTag(t, receiver)

	// Get the original receiving ratchets.
	session := lookupSessionByAnyTag(t, receiver)
	require.NotNil(t, session)

	session.mu.Lock()
	origRecvSym := session.RecvSymmetricRatchet
	origRecvTag := session.RecvTagRatchet
	session.mu.Unlock()

	// Process a DH ratchet.
	var newPubKey [32]byte
	_, _ = rand.Read(newPubKey[:])
	err = receiver.ProcessIncomingDHRatchet(sessionTag, newPubKey)
	require.NoError(t, err)

	session.mu.Lock()
	newRecvSym := session.RecvSymmetricRatchet
	newRecvTag := session.RecvTagRatchet
	remotePub := session.RemotePublicKey
	session.mu.Unlock()

	assert.NotEqual(t, origRecvSym, newRecvSym, "RecvSymmetricRatchet should be replaced")
	assert.NotEqual(t, origRecvTag, newRecvTag, "RecvTagRatchet should be replaced")
	assert.Equal(t, newPubKey, remotePub, "RemotePublicKey should be updated")
}

func TestProcessIncomingDHRatchet_MultipleRotations(t *testing.T) {
	sender, receiver := createLinkedManagers(t)

	var destHash [32]byte
	copy(destHash[:], receiver.ourPublicKey[:])

	enc, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, []byte("init"))
	require.NoError(t, err)
	_, _, err = receiver.DecryptGarlicMessage(enc)
	require.NoError(t, err)

	// Process multiple DH ratchets with different keys.
	for i := 0; i < 3; i++ {
		sessionTag := getAnyTag(t, receiver)

		var newPubKey [32]byte
		newPubKey[0] = byte(i + 1)
		_, _ = rand.Read(newPubKey[1:])

		err = receiver.ProcessIncomingDHRatchet(sessionTag, newPubKey)
		require.NoError(t, err, "DH ratchet %d should succeed", i)
	}
}

// ============================================================================
// Full NextKey Exchange Flow
// ============================================================================

func TestNextKeyExchange_FullFlow(t *testing.T) {
	sender, receiver := createLinkedManagers(t)

	var destHash [32]byte
	copy(destHash[:], receiver.ourPublicKey[:])

	// 1. Establish initial session.
	enc, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, []byte("init"))
	require.NoError(t, err)
	_, _, err = receiver.DecryptGarlicMessage(enc)
	require.NoError(t, err)

	// 2. Trigger DH ratchet on sender (artificially advance counter).
	sender.mu.RLock()
	senderSession := sender.sessions[destHash]
	sender.mu.RUnlock()
	require.NotNil(t, senderSession)

	senderSession.mu.Lock()
	senderSession.dhRatchetCounter = DHRatchetInterval - 1 // Will trigger on next encrypt
	senderSession.mu.Unlock()

	// 3. Encrypt a message — this triggers DH ratchet and queues a NextKey block.
	enc, err = sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, []byte("trigger-ratchet"))
	require.NoError(t, err)

	// 4. Verify the sender has the NextKey block queued.
	senderSession.mu.Lock()
	hasPending := senderSession.HasPendingNextKeys()
	blocks := senderSession.GetPendingNextKeys()
	senderSession.mu.Unlock()

	assert.True(t, hasPending, "Sender should have pending NextKey after DH rotation")
	require.NotEmpty(t, blocks, "Should have at least one NextKey block")

	// 5. Parse the NextKey block.
	info, err := blocks[0].NextKey()
	require.NoError(t, err)
	assert.True(t, info.KeyPresent)
	assert.False(t, info.Reverse)
	assert.True(t, info.RequestReverse)

	// 6. Simulate the receiver processing this NextKey.
	recvTag := getAnyTag(t, receiver)
	err = receiver.ProcessReceivedNextKey(recvTag, info)
	require.NoError(t, err)

	// 7. Receiver should have a reverse NextKey queued.
	recvSession := lookupSessionByAnyTag(t, receiver)
	require.NotNil(t, recvSession)

	recvSession.mu.Lock()
	reverseBlocks := recvSession.GetPendingNextKeys()
	recvSession.mu.Unlock()

	require.NotEmpty(t, reverseBlocks, "Receiver should have queued a reverse NextKey")

	reverseInfo, err := reverseBlocks[0].NextKey()
	require.NoError(t, err)
	assert.True(t, reverseInfo.KeyPresent)
	assert.True(t, reverseInfo.Reverse)
	assert.False(t, reverseInfo.RequestReverse)
}

// ============================================================================
// MaxKeyID
// ============================================================================

func TestMaxKeyIDConstant(t *testing.T) {
	assert.Equal(t, uint16(32767), uint16(MaxKeyID),
		"MaxKeyID should be 32767 per the spec")
}

func TestGenerateReverseNextKey_MaxKeyID(t *testing.T) {
	sender, receiver := createLinkedManagers(t)

	var destHash [32]byte
	copy(destHash[:], receiver.ourPublicKey[:])

	enc, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, []byte("init"))
	require.NoError(t, err)
	_, _, err = receiver.DecryptGarlicMessage(enc)
	require.NoError(t, err)

	sessionTag := getAnyTag(t, receiver)

	// Set the session's sendKeyID to MaxKeyID so reverse key generation fails.
	session := lookupSessionByAnyTag(t, receiver)
	session.mu.Lock()
	session.sendKeyID = MaxKeyID
	session.mu.Unlock()

	var newKey [32]byte
	_, _ = rand.Read(newKey[:])

	info := NextKeyInfo{
		KeyPresent:     true,
		Reverse:        false,
		RequestReverse: true,
		KeyID:          0,
		PublicKey:       newKey,
	}

	err = receiver.ProcessReceivedNextKey(sessionTag, info)
	assert.Error(t, err, "Should error when send key ID is at maximum")
}

// ============================================================================
// GetPublicKey (was at 0% coverage)
// ============================================================================

func TestGetPublicKey(t *testing.T) {
	sm := createTestSessionManager(t)
	pubKey := sm.GetPublicKey()

	allZero := true
	for _, b := range pubKey {
		if b != 0 {
			allZero = false
			break
		}
	}
	assert.False(t, allZero, "Public key should not be all zeros")
}

func TestGetPublicKey_DifferentManagers(t *testing.T) {
	sm1 := createTestSessionManager(t)
	sm2 := createTestSessionManager(t)

	assert.NotEqual(t, sm1.GetPublicKey(), sm2.GetPublicKey(),
		"Different managers should have different public keys")
}

// ============================================================================
// Helpers
// ============================================================================

// getAnyTag extracts a tag from the session manager's tag index.
// It grabs a fresh tag by peeking at the index. The tag IS consumed by this lookup.
func getAnyTag(t testing.TB, sm *SessionManager) [8]byte {
	t.Helper()
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	for tag := range sm.tagIndex {
		return tag
	}
	t.Fatal("no tags in session manager's tag index")
	return [8]byte{}
}

// lookupSessionByAnyTag finds a session from the tag index without consuming the tag.
func lookupSessionByAnyTag(t testing.TB, sm *SessionManager) *Session {
	t.Helper()
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	for _, session := range sm.tagIndex {
		return session
	}
	t.Fatal("no sessions in tag index")
	return nil
}
