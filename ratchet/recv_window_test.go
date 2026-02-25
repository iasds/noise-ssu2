package ratchet

import (
	"math/rand"
	"testing"
	"time"

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

	// Establish session: message 0 is NS; messages 1-4 are ES pre-encrypted after
	// NSR completes so the initiator's ratchet is in the correct state.
	const n = 5
	payloads := make([][]byte, n)
	encrypted := make([][]byte, n)

	// Step 1: Encrypt the NS (message 0) and bootstrap the session with NSR.
	raw0 := []byte("window-test message A")
	payloads[0] = mustBuildNSPayload(t, raw0)
	enc0, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, payloads[0])
	require.NoError(t, err, "encrypt NS message 0")
	encrypted[0] = enc0

	pt0, _, ooNSHash, err := receiver.DecryptGarlicMessage(encrypted[0])
	require.NoError(t, err, "decrypt NS message 0")
	assert.Equal(t, payloads[0], pt0)
	require.NotNil(t, ooNSHash)
	mustCompleteNSR(t, sender, receiver, *ooNSHash)

	// Step 2: Encrypt ES messages 1..n-1 now that NSR is complete.
	for i := 1; i < n; i++ {
		raw := []byte("window-test message " + string(rune('A'+i)))
		payloads[i] = raw
		enc, encErr := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, payloads[i])
		require.NoError(t, encErr, "encrypt ES message %d", i)
		encrypted[i] = enc
	}

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
		pt, _, inOrderNSHash, decErr := receiver.DecryptGarlicMessage(enc)
		require.NoError(t, decErr)
		assert.Equal(t, payload, pt, "message %d should round-trip", i)
		if i == 0 {
			// Complete NSR so sender can send ES from message 1 onward.
			require.NotNil(t, inOrderNSHash)
			mustCompleteNSR(t, sender, receiver, *inOrderNSHash)
		}
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

	// Encrypt NS (message 0), deliver it and complete NSR before pre-encrypting ES.
	enc0, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, mustBuildNSPayload(t, []byte("msg")))
	require.NoError(t, err)
	encrypted[0] = enc0
	_, _, baseNSHash, err := receiver.DecryptGarlicMessage(encrypted[0])
	require.NoError(t, err)
	require.NotNil(t, baseNSHash)
	mustCompleteNSR(t, sender, receiver, *baseNSHash)

	// Encrypt ES messages 1..n-1 with the NSR-derived ratchet.
	for i := 1; i < n; i++ {
		enc, encErr := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, []byte("msg"))
		require.NoError(t, encErr)
		encrypted[i] = enc
	}

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

	// Encrypt NS (message 0), deliver, complete NSR, then pre-encrypt ES messages.
	enc0, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, mustBuildNSPayload(t, []byte("gap test")))
	require.NoError(t, err)
	encrypted[0] = enc0
	_, _, gapNSHash, err := receiver.DecryptGarlicMessage(encrypted[0])
	require.NoError(t, err)
	require.NotNil(t, gapNSHash)
	mustCompleteNSR(t, sender, receiver, *gapNSHash)

	// Encrypt ES messages 1..n-1 with the NSR-derived ratchet.
	for i := 1; i < n; i++ {
		enc, encErr := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, []byte("gap test"))
		require.NoError(t, encErr)
		encrypted[i] = enc
	}

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

	// Encrypt NS (message 0), deliver, complete NSR, then pre-encrypt ES messages.
	raw0 := []byte("random-order a")
	payloads[0] = mustBuildNSPayload(t, raw0)
	enc0, err := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, payloads[0])
	require.NoError(t, err)
	encrypted[0] = enc0

	pt, _, rndNSHash, err := receiver.DecryptGarlicMessage(encrypted[0])
	require.NoError(t, err)
	assert.Equal(t, payloads[0], pt)
	require.NotNil(t, rndNSHash)
	mustCompleteNSR(t, sender, receiver, *rndNSHash)

	// Encrypt ES messages 1..n-1 now that NSR is complete.
	for i := 1; i < n; i++ {
		raw := []byte("random-order " + string(rune('a'+i)))
		payloads[i] = raw
		enc, encErr := sender.EncryptGarlicMessage(destHash, receiver.ourPublicKey, payloads[i])
		require.NoError(t, encErr)
		encrypted[i] = enc
	}

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

// ============================================================================
// Security Tests (AUDIT items: replay prevention, ES-before-NSR, NS freshness)
// ============================================================================

// TestESReplayRejection verifies that re-submitting an already-decrypted
// Existing Session ciphertext returns an error on the second attempt.
//
// When decryptExistingSession succeeds it removes the used message key from
// recvKeyCache. The next attempt to decrypt the same wire-frame finds no key
// for the counter and fails with "no counter in recv window", preventing replay.
//
// Spec ref: ratchet.md §"Existing Session" — each message key is consumed once.
func TestESReplayRejection(t *testing.T) {
	alice, bob := createLinkedManagers(t)

	var bobDestHash [32]byte
	copy(bobDestHash[:], bob.ourPublicKey[:])

	// Establish session: NS from alice → bob.
	nsPayload := mustBuildNSPayload(t, []byte("ns"))
	nsEnc, err := alice.EncryptGarlicMessage(bobDestHash, bob.ourPublicKey, nsPayload)
	require.NoError(t, err)
	_, _, sessionHash, err := bob.DecryptGarlicMessage(nsEnc)
	require.NoError(t, err)
	require.NotNil(t, sessionHash)

	// NSR from bob → alice to complete bidirectional key setup.
	nsrEnc, err := bob.EncryptNewSessionReply(*sessionHash, []byte("nsr"))
	require.NoError(t, err)
	_, _, _, err = alice.DecryptGarlicMessage(nsrEnc)
	require.NoError(t, err)

	// Alice sends one ES message to bob.
	esEnc, err := alice.EncryptGarlicMessage(bobDestHash, bob.ourPublicKey, []byte("secret message"))
	require.NoError(t, err)

	// First decrypt: must succeed.
	pt, _, _, err := bob.DecryptGarlicMessage(esEnc)
	require.NoError(t, err, "first decrypt of ES must succeed")
	assert.Equal(t, []byte("secret message"), pt)

	// Second decrypt of the SAME ciphertext: must fail (key was consumed).
	_, _, _, err = bob.DecryptGarlicMessage(esEnc)
	assert.Error(t, err, "replayed ES ciphertext must be rejected")
}

// TestESBeforeNSRRejected verifies that the initiator cannot send Existing
// Session messages before it has received the New Session Reply.
//
// Spec ref: ratchet.md §1g — "Alice must receive one of Bob's NSR messages
// before sending Existing Session messages."
func TestESBeforeNSRRejected(t *testing.T) {
	alice, bob := createLinkedManagers(t)

	var bobDestHash [32]byte
	copy(bobDestHash[:], bob.ourPublicKey[:])

	// Alice sends NS to bob — this creates alice's outbound session but NSR
	// has not been received yet, so handshakeState is still non-nil.
	nsPayload := mustBuildNSPayload(t, []byte("ns"))
	nsEnc, err := alice.EncryptGarlicMessage(bobDestHash, bob.ourPublicKey, nsPayload)
	require.NoError(t, err)

	// Bob receives the NS (needed to create his responder session).
	_, _, sessionHash, err := bob.DecryptGarlicMessage(nsEnc)
	require.NoError(t, err)
	require.NotNil(t, sessionHash)

	// Alice immediately tries to send an ES message before receiving NSR.
	_, err = alice.EncryptGarlicMessage(bobDestHash, bob.ourPublicKey, []byte("premature es"))
	require.Error(t, err, "initiator must not be allowed to send ES before receiving NSR")
	assert.Contains(t, err.Error(), "must receive New Session Reply",
		"error message should explain the spec ordering constraint")

	// Now bob sends NSR and alice receives it.
	nsrEnc, err := bob.EncryptNewSessionReply(*sessionHash, []byte("nsr"))
	require.NoError(t, err)
	_, _, _, err = alice.DecryptGarlicMessage(nsrEnc)
	require.NoError(t, err)

	// After NSR, alice can now send ES messages successfully.
	esEnc, err := alice.EncryptGarlicMessage(bobDestHash, bob.ourPublicKey, []byte("post-nsr es"))
	require.NoError(t, err, "alice must be able to send ES after receiving NSR")
	pt, _, _, err := bob.DecryptGarlicMessage(esEnc)
	require.NoError(t, err)
	assert.Equal(t, []byte("post-nsr es"), pt)
}

// TestNSDateTimeFreshnessRejected verifies that a New Session message whose
// DateTime block is older than nsMaxAge is rejected by the receiver.
//
// This prevents an attacker from replaying a captured NS to overwrite an active
// live session (resetting its ratchet chain). An old NS has a stale timestamp
// that falls outside the ±nsMaxAge acceptance window.
//
// Spec ref: ratchet.md §1b — DateTime block required; freshness prevents replay.
func TestNSDateTimeFreshnessRejected(t *testing.T) {
	alice, bob := createLinkedManagers(t)

	var bobDestHash [32]byte
	copy(bobDestHash[:], bob.ourPublicKey[:])

	// Alice builds and encrypts an NS message with the real current time.
	nsPayload := mustBuildNSPayload(t, []byte("real ns"))
	nsEnc, err := alice.EncryptGarlicMessage(bobDestHash, bob.ourPublicKey, nsPayload)
	require.NoError(t, err)

	// Override nowFunc so that when bob tries to decrypt the NS, the current time
	// appears to be well past the freshness window (nsMaxAge + 1 minute).
	savedNowFunc := nowFunc
	t.Cleanup(func() { nowFunc = savedNowFunc })
	nowFunc = func() time.Time {
		return time.Now().Add(nsMaxAge + time.Minute)
	}

	// Bob attempts to decrypt the NS — must fail because the timestamp is stale.
	_, _, _, err = bob.DecryptGarlicMessage(nsEnc)
	require.Error(t, err, "NS with stale timestamp must be rejected")
	assert.Contains(t, err.Error(), "freshness", "error must mention freshness check")
}

// ============================================================================
// Tag Window Replenishment Tests (AUDIT items: collision skip, retry)
// ============================================================================

// TestInstallGeneratedTagsLocked_CollisionSkip verifies that
// installGeneratedTagsLocked skips tags already owned by a different session
// (simulating a cross-session hash collision) and only installs the
// non-colliding subset.
//
// This is a unit test of the internal install path.  It ensures:
//  1. The colliding tag is not re-attributed to the new session.
//  2. The phantom session's ownership of the colliding tag is preserved.
//  3. The non-colliding tags are correctly appended to pendingTags / tagIndex.
func TestInstallGeneratedTagsLocked_CollisionSkip(t *testing.T) {
	sm, err := GenerateSessionManager()
	require.NoError(t, err)

	// Phantom session: represents another, pre-existing session.
	phantom := &Session{}

	// Real session: the session we are trying to replenish.
	real := &Session{
		pendingTags: make([][8]byte, 0),
	}
	sm.mu.Lock()

	// Three test tags — tagB is owned by phantom (simulated collision).
	var tagA, tagB, tagC [8]byte
	tagA[0] = 0xAA
	tagB[0] = 0xBB
	tagC[0] = 0xCC
	sm.tagIndex[tagB] = phantom

	sm.installGeneratedTagsLocked(real, [][8]byte{tagA, tagB, tagC})
	sm.mu.Unlock()

	// Only tagA and tagC should be installed; tagB was skipped.
	require.Equal(t, 2, len(real.pendingTags),
		"pendingTags should contain only non-colliding tags")
	assert.Equal(t, tagA, real.pendingTags[0], "first installed tag should be tagA")
	assert.Equal(t, tagC, real.pendingTags[1], "second installed tag should be tagC")

	// tagIndex must reflect the correct ownership.
	sm.mu.RLock()
	assert.Equal(t, real, sm.tagIndex[tagA], "tagIndex[tagA] should point to real session")
	assert.Equal(t, phantom, sm.tagIndex[tagB], "phantom must still own tagB")
	assert.Equal(t, real, sm.tagIndex[tagC], "tagIndex[tagC] should point to real session")
	sm.mu.RUnlock()
}

// TestReplenishTagWindow_FullReplenishment verifies that replenishTagWindowOutsideLock
// fully restores the tag window after it has been drained to zero.
//
// This exercises the happy path of the retry loop: the first attempt should
// successfully generate and install tagWindowSize entries with no collisions.
func TestReplenishTagWindow_FullReplenishment(t *testing.T) {
	sender, receiver := createLinkedManagers(t)
	_ = mustBootstrapSession(t, sender, receiver)

	// Locate the receiver's active session.
	receiver.mu.RLock()
	var sess *Session
	for _, s := range receiver.sessions {
		sess = s
		break
	}
	receiver.mu.RUnlock()
	require.NotNil(t, sess, "receiver must have a session after bootstrap")

	// Drain the current pendingTags so the window starts empty.
	receiver.mu.Lock()
	sess.mu.Lock()
	for _, tag := range sess.pendingTags {
		delete(receiver.tagIndex, tag)
	}
	sess.pendingTags = sess.pendingTags[:0]
	sess.mu.Unlock()
	receiver.mu.Unlock()

	// Confirm the window is empty.
	sess.mu.Lock()
	require.Equal(t, 0, len(sess.pendingTags), "pendingTags must be empty before replenishment")
	sess.mu.Unlock()

	// Run replenishment (no collisions expected; ratchet generates fresh tags).
	receiver.replenishTagWindowOutsideLock(sess)

	// Verify the window was fully restored.
	sess.mu.Lock()
	count := len(sess.pendingTags)
	sess.mu.Unlock()

	assert.Equal(t, tagWindowSize, count,
		"tag window must be fully replenished to tagWindowSize=%d after drain; got %d",
		tagWindowSize, count)
}

// TestReplenishTagWindow_PartialCollisionRetries verifies that when
// installGeneratedTagsLocked skips some tags due to collisions, the retry loop
// in replenishTagWindowOutsideLock continues generating until the window is full.
//
// Setup: after the first replenishment call installs fewer than tagWindowSize
// entries (because we pre-occupied some slots with another session's tags), we
// verify that the final window size equals tagWindowSize.
//
// Implementation note: forcing a deterministic collision requires knowing the
// ratchet's next output in advance.  We achieve this by:
//  1. Running one full replenishment to learn the tags (and thus the ratchet's
//     current output window).
//  2. Draining pendingTags and re-occupying the FIRST tag in tagIndex with a
//     phantom session.
//  3. Calling replenishment again — the first attempt will skip the phantom tag,
//     but the retry loop will generate one additional tag to compensate.
func TestReplenishTagWindow_PartialCollisionRetries(t *testing.T) {
	sender, receiver := createLinkedManagers(t)
	_ = mustBootstrapSession(t, sender, receiver)

	// Locate the receiver's active session.
	receiver.mu.RLock()
	var sess *Session
	for _, s := range receiver.sessions {
		sess = s
		break
	}
	receiver.mu.RUnlock()
	require.NotNil(t, sess, "receiver must have a session after bootstrap")

	// Do a first replenishment so the tag ratchet has produced a full window.
	receiver.replenishTagWindowOutsideLock(sess)
	sess.mu.Lock()
	require.Equal(t, tagWindowSize, len(sess.pendingTags), "precondition: first replenishment must fill window")
	// Record one of the live tags — it will become a collision trigger.
	collidingTag := sess.pendingTags[0]
	// Drain the window.
	for _, tag := range sess.pendingTags {
		receiver.mu.Lock()
		delete(receiver.tagIndex, tag)
		receiver.mu.Unlock()
	}
	sess.pendingTags = sess.pendingTags[:0]
	sess.mu.Unlock()

	// Occupy the colliding tag with a phantom session.
	phantom := &Session{}
	receiver.mu.Lock()
	receiver.tagIndex[collidingTag] = phantom
	receiver.mu.Unlock()

	// Run replenishment.  The first attempt will skip collidingTag (owned by
	// phantom), leaving the window one short.  The retry generates a further tag
	// to bring the window back to tagWindowSize.
	receiver.replenishTagWindowOutsideLock(sess)

	sess.mu.Lock()
	count := len(sess.pendingTags)
	sess.mu.Unlock()

	// Clean up phantom ownership to avoid leaking into tagIndex.
	receiver.mu.Lock()
	if receiver.tagIndex[collidingTag] == phantom {
		delete(receiver.tagIndex, collidingTag)
	}
	receiver.mu.Unlock()

	assert.Equal(t, tagWindowSize, count,
		"retry loop must compensate for one collision so window reaches tagWindowSize")
}
