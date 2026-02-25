package ratchet

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// Receive Window Tests (AUDIT item #8)
// ============================================================================

// TestReceiveWindow_OutOfOrder verifies that up to tagWindowSize ES messages
// delivered in a shuffled order all decrypt successfully.
func TestReceiveWindow_OutOfOrder(t *testing.T) {
	sender, receiver := createLinkedManagers(t)

	var destHash [32]byte
	copy(destHash[:], receiver.ourPublicKey[:])

	// Establish session: the first EncryptGarlicMessage sends a New Session
	// message; the receiver processes it and sets up the ratchet state.
	const n = 5
	payloads := make([][]byte, n)
	encrypted := make([][]byte, n)

	// Encrypt n distinct messages.  The sender's session is created on the
	// first call; subsequent calls produce Existing Session messages.
	for i := 0; i < n; i++ {
		raw := []byte("window-test message " + string(rune('A'+i)))
		if i == 0 {
			payloads[i] = mustBuildNSPayload(t, raw)
		} else {
			payloads[i] = raw
		}
		enc, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, payloads[i])
		require.NoError(t, err, "encrypt message %d", i)
		encrypted[i] = enc
	}

	// The receiver must first process message 0 (New Session) to set up key
	// material; messages 1..n-1 are Existing Session messages.
	// Deliver message 0 in-order to bootstrap the session …
	pt0, _, _, err := receiver.DecryptGarlicMessage(encrypted[0])
	require.NoError(t, err, "decrypt NS message 0")
	assert.Equal(t, payloads[0], pt0)

	// … then deliver the remaining messages in shuffled order.
	indices := []int{2, 4, 1, 3} // out-of-order subset of [1..4]
	received := make(map[int][]byte)
	for _, idx := range indices {
		pt, _, _, decErr := receiver.DecryptGarlicMessage(encrypted[idx])
		require.NoError(t, decErr, "decrypt out-of-order message %d", idx)
		received[idx] = pt
	}

	for _, idx := range indices {
		assert.Equal(t, payloads[idx], received[idx], "payload mismatch for message %d", idx)
	}
}

// TestReceiveWindow_InOrderStillWorks is a regression test ensuring that
// strictly in-order delivery still works after the window refactor.
func TestReceiveWindow_InOrderStillWorks(t *testing.T) {
	sender, receiver := createLinkedManagers(t)

	var destHash [32]byte
	copy(destHash[:], receiver.ourPublicKey[:])

	for i := 0; i < 8; i++ {
		raw := []byte("in-order " + string(rune('0'+i)))
		var payload []byte
		if i == 0 {
			payload = mustBuildNSPayload(t, raw)
		} else {
			payload = raw
		}
		enc, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, payload)
		require.NoError(t, err)
		pt, _, _, decErr := receiver.DecryptGarlicMessage(enc)
		require.NoError(t, decErr)
		assert.Equal(t, payload, pt, "message %d should round-trip", i)
	}
}

// TestReceiveWindow_BaseAdvances verifies that recvWindowBase advances past
// leading consumed counters as messages are delivered.
func TestReceiveWindow_BaseAdvances(t *testing.T) {
	sender, receiver := createLinkedManagers(t)

	var destHash [32]byte
	copy(destHash[:], receiver.ourPublicKey[:])

	const n = 4
	encrypted := make([][]byte, n)
	for i := 0; i < n; i++ {
		var payload []byte
		if i == 0 {
			payload = mustBuildNSPayload(t, []byte("msg"))
		} else {
			payload = []byte("msg")
		}
		enc, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, payload)
		require.NoError(t, err)
		encrypted[i] = enc
	}

	// Deliver message 0 (NS): bootstraps the session.
	_, _, _, err := receiver.DecryptGarlicMessage(encrypted[0])
	require.NoError(t, err)

	// Retrieve the receiver's session so we can inspect internal state.
	var msgTag [8]byte
	copy(msgTag[:], encrypted[1][:8])
	receiver.mu.RLock()
	session := receiver.tagIndex[msgTag]
	receiver.mu.RUnlock()
	require.NotNil(t, session, "session must exist after NS")

	// Deliver ES messages 1, 2, 3 in order; base should advance after each.
	session.mu.Lock()
	baseBefore := session.recvWindowBase
	session.mu.Unlock()
	assert.Equal(t, uint32(1), baseBefore, "initial recvWindowBase should be 1")

	for i := 1; i < n; i++ {
		_, _, _, decErr := receiver.DecryptGarlicMessage(encrypted[i])
		require.NoError(t, decErr, "decrypt message %d", i)
	}

	session.mu.Lock()
	baseAfter := session.recvWindowBase
	session.mu.Unlock()
	// After consuming ES counters 1, 2, 3 the base should have advanced to 4.
	assert.Equal(t, uint32(n), baseAfter, "recvWindowBase should be %d after %d ES messages", n, n-1)
}

// TestReceiveWindow_OutOfOrder_BaseAdvancesOnlyAfterGap verifies that the
// window base stays put when a gap exists (lower counter not yet delivered).
func TestReceiveWindow_OutOfOrder_BaseStaysOnGap(t *testing.T) {
	sender, receiver := createLinkedManagers(t)

	var destHash [32]byte
	copy(destHash[:], receiver.ourPublicKey[:])

	const n = 4
	encrypted := make([][]byte, n)
	for i := 0; i < n; i++ {
		var payload []byte
		if i == 0 {
			payload = mustBuildNSPayload(t, []byte("gap test"))
		} else {
			payload = []byte("gap test")
		}
		enc, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, payload)
		require.NoError(t, err)
		encrypted[i] = enc
	}

	// Bootstrap with NS (index 0).
	_, _, _, err := receiver.DecryptGarlicMessage(encrypted[0])
	require.NoError(t, err)

	// Look up session from the tag of message 1.
	var msgTag [8]byte
	copy(msgTag[:], encrypted[1][:8])
	receiver.mu.RLock()
	session := receiver.tagIndex[msgTag]
	receiver.mu.RUnlock()
	require.NotNil(t, session)

	// Deliver message 3 (ES counter 3) — skipping counters 1 and 2.
	_, _, _, err = receiver.DecryptGarlicMessage(encrypted[3])
	require.NoError(t, err)

	session.mu.Lock()
	baseAfterSkip := session.recvWindowBase
	session.mu.Unlock()
	// Base must remain at 1 because counters 1 and 2 are still pending.
	assert.Equal(t, uint32(1), baseAfterSkip, "base must not advance past pending gap")

	// Now deliver counter 1.
	_, _, _, err = receiver.DecryptGarlicMessage(encrypted[1])
	require.NoError(t, err)

	session.mu.Lock()
	baseAfter1 := session.recvWindowBase
	session.mu.Unlock()
	// Still 2 because counter 2 is pending.
	assert.Equal(t, uint32(2), baseAfter1, "base should advance to 2 after filling counter 1")

	// Deliver counter 2 to plug the gap fully.
	_, _, _, err = receiver.DecryptGarlicMessage(encrypted[2])
	require.NoError(t, err)

	session.mu.Lock()
	baseFull := session.recvWindowBase
	session.mu.Unlock()
	assert.Equal(t, uint32(4), baseFull, "base should reach 4 after all gaps filled")
}

// TestReceiveWindow_RandomOrder tests correctness with a pseudo-random delivery
// order for a batch of messages that fits within the tag window.
func TestReceiveWindow_RandomOrder(t *testing.T) {
	sender, receiver := createLinkedManagers(t)

	var destHash [32]byte
	copy(destHash[:], receiver.ourPublicKey[:])

	// Keep batch small enough to fit within the initial tag window (10 slots).
	const n = 7
	payloads := make([][]byte, n)
	encrypted := make([][]byte, n)
	for i := 0; i < n; i++ {
		raw := []byte("random-order " + string(rune('a'+i)))
		if i == 0 {
			payloads[i] = mustBuildNSPayload(t, raw)
		} else {
			payloads[i] = raw
		}
		enc, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, payloads[i])
		require.NoError(t, err)
		encrypted[i] = enc
	}

	// Always deliver the NS first.
	pt, _, _, err := receiver.DecryptGarlicMessage(encrypted[0])
	require.NoError(t, err)
	assert.Equal(t, payloads[0], pt)

	// Shuffle indices [1..n-1] and deliver.
	rng := rand.New(rand.NewSource(42))
	indices := rng.Perm(n - 1) // [0..n-2], each shifted by 1 below
	for _, i := range indices {
		idx := i + 1
		pt, _, _, decErr := receiver.DecryptGarlicMessage(encrypted[idx])
		require.NoError(t, decErr, "decrypt shuffled message %d (shuffled as %d)", idx, i)
		assert.Equal(t, payloads[idx], pt)
	}
}

// TestReceiveWindow_KeyCachePreFilled verifies that fillRecvKeyCache pre-derives
// keys for exactly the window range and that the fill mark advances.
func TestReceiveWindow_KeyCachePreFilled(t *testing.T) {
	_, receiver := createLinkedManagers(t)

	var destHash [32]byte
	copy(destHash[:], receiver.ourPublicKey[:])

	// Send a NS so the receiver has a session with a real RecvSymmetricRatchet.
	sender, _ := createLinkedManagers(t)
	enc, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, mustBuildNSPayload(t, []byte("bootstrap")))
	require.NoError(t, err)
	_, _, _, err = receiver.DecryptGarlicMessage(enc)
	require.NoError(t, err)

	// Pick any active session.
	receiver.mu.RLock()
	var sess *Session
	for _, s := range receiver.sessions {
		sess = s
		break
	}
	receiver.mu.RUnlock()
	require.NotNil(t, sess)

	// Fill an explicit window and check that the cache has the right keys.
	sess.mu.Lock()
	err = fillRecvKeyCache(sess, sess.recvWindowBase+recvWindowSize)
	require.NoError(t, err)
	cacheLen := len(sess.recvKeyCache)
	fillMark := sess.recvFillMark
	sess.mu.Unlock()

	assert.Equal(t, int(recvWindowSize), cacheLen,
		"cache should contain exactly recvWindowSize entries")
	assert.Equal(t, uint32(1)+recvWindowSize, fillMark,
		"fillMark should be recvWindowBase+recvWindowSize after first fill")
}

// TestRecvWindowReset_AfterNSR verifies that the receive window is correctly
// reset when the session is updated by a New Session Reply.
func TestRecvWindowReset_AfterNSR(t *testing.T) {
	sender, receiver := createLinkedManagers(t)

	var destHash [32]byte
	copy(destHash[:], receiver.ourPublicKey[:])

	// Step 1: NS from initiator → responder.
	nsEnc, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, mustBuildNSPayload(t, []byte("ns")))
	require.NoError(t, err)
	_, _, sessionHash, err := receiver.DecryptGarlicMessage(nsEnc)
	require.NoError(t, err)
	require.NotNil(t, sessionHash)

	// Step 2: NSR from responder → initiator.
	nsrEnc, err := receiver.EncryptNewSessionReply(*sessionHash, []byte("nsr"))
	require.NoError(t, err)
	_, _, _, err = sender.DecryptGarlicMessage(nsrEnc)
	require.NoError(t, err)

	// Retrieve the initiator's session (post-NSR).
	var senderSess *Session
	sender.mu.RLock()
	for _, s := range sender.sessions {
		senderSess = s
		break
	}
	sender.mu.RUnlock()
	require.NotNil(t, senderSess)

	senderSess.mu.Lock()
	base := senderSess.recvWindowBase
	fillMark := senderSess.recvFillMark
	cacheNil := senderSess.recvKeyCache == nil
	senderSess.mu.Unlock()

	assert.Equal(t, uint32(1), base, "recvWindowBase resets to 1 after NSR")
	assert.Equal(t, uint32(1), fillMark, "recvFillMark resets to 1 after NSR")
	assert.False(t, cacheNil, "recvKeyCache must not be nil after NSR reset")

	// Verify ES messages still work after NSR.
	for i := 0; i < 3; i++ {
		payload := []byte("post-nsr " + string(rune('0'+i)))
		enc, encErr := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, payload)
		require.NoError(t, encErr)
		pt, _, _, decErr := receiver.DecryptGarlicMessage(enc)
		require.NoError(t, decErr)
		assert.Equal(t, payload, pt)
	}
}

// TestSendTagPollution_RecvWindowStillWorks is a regression test for the bug where
// generateAndTrackSessionTag appended outbound send-direction tags to
// session.pendingTags, which is meant to hold only incoming recv-direction tags.
//
// After 10+ outgoing ES messages the old code filled pendingTags with send tags,
// preventing the replenishment threshold check from ever firing, which silently
// emptied the actual recv window and caused all subsequent inbound ES decrypts
// to fail with "no matching session tag".
//
// The fix: generateAndTrackSessionTag no longer writes to pendingTags.
// This test verifies:
//  1. Alice sends 15 outgoing ES messages to Bob (> tagWindowSize == 10).
//  2. Bob can still send ES messages back to Alice after that.
//  3. Alice's pendingTags count stays bounded at tagWindowSize (no pollution).
func TestSendTagPollution_RecvWindowStillWorks(t *testing.T) {
	alice, bob := createLinkedManagers(t)

	var bobDestHash [32]byte
	copy(bobDestHash[:], bob.ourPublicKey[:])

	// Step 1: Alice sends NS to Bob. Bob learns Alice's static key.
	nsPayload := mustBuildNSPayload(t, []byte("ns from alice"))
	nsEnc, err := alice.EncryptGarlicMessage(bobDestHash, bob.ourPublicKey, nsPayload)
	require.NoError(t, err)
	_, _, sessionHash, err := bob.DecryptGarlicMessage(nsEnc)
	require.NoError(t, err)
	require.NotNil(t, sessionHash, "DecryptGarlicMessage must return sessionHash for NS")

	// Step 2: Bob sends NSR to Alice. This completes the bidirectional handshake
	// and initialises both alice.RecvTagRatchet and alice.pendingTags correctly.
	nsrEnc, err := bob.EncryptNewSessionReply(*sessionHash, []byte("nsr from bob"))
	require.NoError(t, err)
	_, _, _, err = alice.DecryptGarlicMessage(nsrEnc)
	require.NoError(t, err)

	// Step 3: Alice sends 15 outgoing ES messages to Bob. With the old bug this
	// would fill alice's session.pendingTags with 15 send-direction tags
	// (> tagWindowSize == 10), preventing recv-window replenishment.
	const outgoingCount = 15
	for i := 0; i < outgoingCount; i++ {
		payload := []byte("alice→bob message " + string(rune('A'+i)))
		enc, encErr := alice.EncryptGarlicMessage(bobDestHash, bob.ourPublicKey, payload)
		require.NoError(t, encErr, "alice ES send %d should succeed", i)
		pt, _, _, decErr := bob.DecryptGarlicMessage(enc)
		require.NoError(t, decErr, "bob ES recv %d should succeed", i)
		assert.Equal(t, payload, pt, "payload mismatch on message %d", i)
	}

	// Step 4: Verify alice's pendingTags is not polluted (capped at tagWindowSize,
	// not bloated with send-direction tags).
	alice.mu.RLock()
	var aliceSess *Session
	for _, s := range alice.sessions {
		aliceSess = s
		break
	}
	alice.mu.RUnlock()
	require.NotNil(t, aliceSess, "alice must have a session after outgoing ES messages")

	aliceSess.mu.Lock()
	pendingCount := len(aliceSess.pendingTags)
	aliceSess.mu.Unlock()

	assert.LessOrEqual(t, pendingCount, tagWindowSize,
		"alice.pendingTags must not exceed tagWindowSize=%d (send-tag pollution check); got %d",
		tagWindowSize, pendingCount)

	// Step 5: Bob sends 3 ES messages back to Alice. Bob's session for Alice is
	// keyed by sessionHash (SHA-256 of Alice's pubkey), which is what was returned
	// by DecryptGarlicMessage when Bob processed Alice's NS message. With the old
	// bug these would fail because Alice's tagIndex never got replenished
	// (pendingTags was full of useless send tags). With the fix, the recv window
	// is correctly maintained.
	for i := 0; i < 3; i++ {
		payload := []byte("bob→alice reply " + string(rune('0'+i)))
		enc, encErr := bob.EncryptGarlicMessage(*sessionHash, alice.ourPublicKey, payload)
		require.NoError(t, encErr, "bob ES send %d should succeed", i)
		pt, tag, _, decErr := alice.DecryptGarlicMessage(enc)
		require.NoError(t, decErr, "alice ES recv %d must succeed — recv window should be intact", i)
		assert.Equal(t, payload, pt, "alice must recover exact payload on recv %d", i)
		assert.NotEqual(t, [8]byte{}, tag, "ES message must carry a non-zero session tag")
	}
}
