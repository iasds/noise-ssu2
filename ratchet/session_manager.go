package ratchet

import (
	"context"
	"fmt"
	"sync"
	"time"

	i2pcurve25519 "github.com/go-i2p/crypto/curve25519"
	"github.com/go-i2p/crypto/ecies"
	"github.com/go-i2p/go-noise/mod/replaycache"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// Compile-time interface checks.
var (
	_ GarlicSessionManager = (*SessionManager)(nil)
	_ TagResolver          = (*SessionManager)(nil)
)

const (
	// MaxGarlicSessions is the upper bound on active garlic sessions.
	MaxGarlicSessions = 5000

	// MaxSessionsPerPeer caps the number of concurrent garlic sessions that
	// may exist for a single remote static public key. An attacker who can
	// replay many NS messages from a forged or reused identity cannot use up
	// more than this fraction of the global session table (AUDIT L-4).
	// When exceeded, the oldest session for that peer is evicted first,
	// protecting sessions from other honest peers from LRU churn.
	MaxSessionsPerPeer = 32

	// defaultNSMaxPastAge is the maximum acceptable age of the DateTime block
	// in a New Session message. Default: 5 minutes per ratchet.md §"Parameters".
	defaultNSMaxPastAge = 5 * time.Minute

	// defaultNSMaxFutureAge is the maximum acceptable forward skew of the DateTime
	// block in a New Session message. Default: 2 minutes per ratchet.md §"Parameters".
	defaultNSMaxFutureAge = 2 * time.Minute
)

// SessionManagerOption configures optional SessionManager parameters.
type SessionManagerOption func(*SessionManager)

// WithNSMaxPastAge overrides the default maximum past age for NS DateTime freshness.
func WithNSMaxPastAge(d time.Duration) SessionManagerOption {
	return func(sm *SessionManager) {
		sm.nsMaxPastAge = d
	}
}

// WithNSMaxFutureAge overrides the default maximum future age for NS DateTime freshness.
func WithNSMaxFutureAge(d time.Duration) SessionManagerOption {
	return func(sm *SessionManager) {
		sm.nsMaxFutureAge = d
	}
}

// validateNSDateTimeFreshness parses the decrypted NS payload, locates the
// required DateTime block (first block per ratchet.md §1b), and verifies that
// its timestamp is within the asymmetric freshness window:
//   - Past: at most nsMaxPastAge ago (default 5 minutes)
//   - Future: at most nsMaxFutureAge ahead (default 2 minutes)
//
// Spec ref: ratchet.md §"Parameters" — max clock skew: −5 minutes to +2 minutes.
func (sm *SessionManager) validateNSDateTimeFreshness(payload []byte) error {
	log.WithFields(logger.Fields{"pkg": "ratchet", "func": "validateNSDateTimeFreshness", "payload_len": len(payload)}).Debug("Validating NS DateTime freshness")
	blocks, err := ParsePayload(payload)
	if err != nil {
		return oops.Wrapf(err, "NS payload parse failed during freshness check")
	}
	if len(blocks) == 0 || blocks[0].Type != BlockDateTime {
		return oops.Errorf("NS payload is missing required DateTime block at position 0")
	}
	msgTime, err := blocks[0].DateTime()
	if err != nil {
		return oops.Wrapf(err, "NS DateTime block is malformed")
	}
	elapsed := nowFunc().Sub(msgTime)
	if elapsed > sm.nsMaxPastAge {
		return oops.Errorf(
			"NS DateTime block fails freshness check: message is %v old, max past age is %v (stale or replay)",
			elapsed, sm.nsMaxPastAge,
		)
	}
	if elapsed < -sm.nsMaxFutureAge {
		return oops.Errorf(
			"NS DateTime block fails freshness check: message is %v in the future, max future skew is %v",
			-elapsed, sm.nsMaxFutureAge,
		)
	}
	return nil
}

// nsReplayCacheTTL computes the replay cache TTL from the freshness window.
// The +1 minute buffer beyond the freshness window accounts for:
//   - Clock skew between sender and receiver (beyond the configured tolerance)
//   - Network jitter and packet reordering delays
//   - Race conditions at window boundaries during concurrent processing
//
// This ensures that legitimate messages near the window edge are not incorrectly
// rejected as replays while still preventing long-lived replay attacks.
func nsReplayCacheTTL(pastAge, futureAge time.Duration) time.Duration {
	return pastAge + futureAge + time.Minute // +1m for clock skew + network jitter
}

// nsReplayCacheMaxSize is the maximum number of NS ephemeral keys tracked
// before forced eviction. This prevents memory exhaustion under attack.
const nsReplayCacheMaxSize = 50000

// nsReplayCacheCleanupInterval controls how often expired NS replay entries
// are evicted.
const nsReplayCacheCleanupInterval = 30 * time.Second

// SessionManager manages ECIES-X25519-AEAD-Ratchet sessions for garlic encryption.
// It maintains session state for ongoing encrypted communication with remote
// destinations, using [32]byte keys throughout (no I2P-specific types).
//
// Session lifecycle:
//  1. New Session: First message uses ephemeral-static DH (ECIES)
//  2. Existing Session: Subsequent messages use ratchet for forward secrecy
//  3. Session Expiry: Sessions expire after inactivity timeout
type SessionManager struct {
	mu       sync.RWMutex
	sessions map[[32]byte]*Session
	tagIndex map[[8]byte]*Session
	// nsrTagIndex maps the expected NSR tag (derived from the NS chain key) to the
	// initiator session waiting for the corresponding New Session Reply. Unlike
	// tagIndex (which tracks Existing Session tags), nsrTagIndex is keyed on the
	// unique 8-byte NSR tag that the responder will prefix on its NSR message.
	nsrTagIndex     map[[8]byte]*Session
	tagCounterIndex map[[8]byte]uint32
	// oneTimeKeys holds one-time symmetric garlic keys derived from STBM Noise
	// transcript hashes via HKDF("AttachLayerEncryption"). Each key is used
	// exactly once to decrypt the OBEP's garlic-wrapped ShortTunnelBuildReply,
	// then deleted. Keyed by the last 8 bytes of the 32-byte HKDF output.
	oneTimeKeys    map[[8]byte][32]byte
	ourPrivateKey  [32]byte
	ourPublicKey   [32]byte
	sessionTimeout time.Duration
	ctx            context.Context
	cancel         context.CancelFunc

	// nsMaxPastAge is the maximum acceptable age for NS DateTime freshness.
	nsMaxPastAge time.Duration
	// nsMaxFutureAge is the maximum acceptable future skew for NS DateTime freshness.
	nsMaxFutureAge time.Duration

	// nsReplayCache tracks recently-seen NS ephemeral keys (first 32 bytes of the
	// NS message) to prevent replay attacks within the freshness window.
	// Spec ref: ratchet.md §"DateTime" — "Bob must implement a Bloom filter or
	// other mechanism to prevent replay attacks, if the time is valid."
	nsReplayCache *replaycache.TTLCache
}

// NewSessionManager creates a new session manager with the given private key.
func NewSessionManager(privateKey [32]byte, opts ...SessionManagerOption) (*SessionManager, error) {
	log.WithFields(logger.Fields{"pkg": "ratchet", "func": "NewSessionManager"}).Debug("Creating new garlic session manager")

	var publicKey [32]byte
	privKey, err := i2pcurve25519.NewCurve25519PrivateKey(privateKey[:])
	if err != nil {
		return nil, oops.Wrapf(err, "failed to create private key for public key derivation")
	}
	pubKeyIface, err := privKey.Public()
	if err != nil {
		return nil, oops.Wrapf(err, "failed to derive public key from private key")
	}
	copy(publicKey[:], pubKeyIface.Bytes())

	ctx, cancel := context.WithCancel(context.Background())

	sm := &SessionManager{
		sessions:        make(map[[32]byte]*Session),
		tagIndex:        make(map[[8]byte]*Session),
		nsrTagIndex:     make(map[[8]byte]*Session),
		tagCounterIndex: make(map[[8]byte]uint32),
		oneTimeKeys:     make(map[[8]byte][32]byte),
		ourPrivateKey:   privateKey,
		ourPublicKey:    publicKey,
		sessionTimeout:  10 * time.Minute,
		nsMaxPastAge:    defaultNSMaxPastAge,
		nsMaxFutureAge:  defaultNSMaxFutureAge,
		ctx:             ctx,
		cancel:          cancel,
	}

	for _, opt := range opts {
		opt(sm)
	}

	sm.nsReplayCache = replaycache.New(replaycache.Config{
		TTL:             nsReplayCacheTTL(sm.nsMaxPastAge, sm.nsMaxFutureAge),
		MaxSize:         nsReplayCacheMaxSize,
		CleanupInterval: nsReplayCacheCleanupInterval,
		NowFunc:         nowFunc,
	})

	return sm, nil
}

// GenerateSessionManager creates a session manager with a freshly generated key pair.
func GenerateSessionManager() (*SessionManager, error) {
	log.WithFields(logger.Fields{"pkg": "ratchet", "func": "GenerateSessionManager"}).Debug("Generating new session manager with fresh key pair")
	_, privBytes, err := ecies.GenerateKeyPair()
	if err != nil {
		return nil, oops.Wrapf(err, "failed to generate session manager key pair")
	}

	var privateKey [32]byte
	copy(privateKey[:], privBytes)
	return NewSessionManager(privateKey)
}

// EncryptGarlicMessage, encryptNewSession, storeNewSessionState,
// encryptExistingSession, EncryptUnboundGarlicMessage, and EncryptNewSessionReply
// are defined in session_encrypt.go.

// DecryptGarlicMessage, decryptNewSession, initializeInboundRatchetState,
// registerNSRTagLocked, decryptIncomingNSR, applyNSRKeysToSessionWhileLocked,
// decryptExistingSession, tryCounterHintDecrypt, scanWindowDecrypt,
// processDecryptedESBlocks, processAckRequest, and processAck
// are defined in session_decrypt.go.

// RegisterOneTimeKey registers a one-time symmetric garlic key derived from a
// STBM Noise transcript hash via HKDF("AttachLayerEncryption"). The OBEP will
// use the corresponding key to wrap its ShortTunnelBuildReply in a garlic
// message; this key is looked up by tag and deleted after a single use.
//
// tag is garlicKeyMaterial[24:32] (last 8 bytes of the 32-byte HKDF output).
// key is garlicKeyMaterial[0:32] (the full 32-byte output used as the ChaCha20 key).
func (sm *SessionManager) RegisterOneTimeKey(tag [8]byte, key [32]byte) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.oneTimeKeys[tag] = key
	log.WithFields(logger.Fields{
		"pkg":  "ratchet",
		"func": "RegisterOneTimeKey",
		"tag":  fmt.Sprintf("%x", tag),
	}).Debug("Registered one-time garlic reply key")
}

// removeSessionByPointer locates a session in sm.sessions by pointer equality
// and removes it along with all its tags from sm.tagIndex and sm.nsrTagIndex.
//
// This is used when we have a *Session reference (e.g., from a tag lookup)
// but not the session hash key. The linear scan is acceptable because it runs
// at most once per Termination block (a rare, session-lifetime event).
func (sm *SessionManager) removeSessionByPointer(session *Session) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	var foundHash [32]byte
	found := false
	for hash, s := range sm.sessions {
		if s == session {
			foundHash = hash
			found = true
			break
		}
	}
	if !found {
		return // already removed (e.g., by concurrent cleanup)
	}

	// Clean up all index entries for this session.
	for _, tag := range session.pendingTags {
		delete(sm.tagIndex, tag)
		delete(sm.tagCounterIndex, tag)
	}
	if session.nsrTag != nil {
		delete(sm.nsrTagIndex, *session.nsrTag)
	}
	delete(sm.sessions, foundHash)

	log.WithFields(logger.Fields{
		"pkg":             "ratchet",
		"func":            "removeSessionByPointer",
		"remaining_count": len(sm.sessions),
	}).Debug("Session removed after termination")
}

// ProcessIncomingDHRatchet processes a DH ratchet key received from a peer.
// The session is found by tag lookup using the sessionTag parameter.
func (sm *SessionManager) ProcessIncomingDHRatchet(sessionTag [8]byte, newRemotePubKey [32]byte) error {
	session, err := sm.lookupLockedSession(sessionTag)
	if err != nil {
		return err
	}
	defer session.mu.Unlock()

	if err := session.DHRatchet.UpdateKeys(newRemotePubKey[:]); err != nil {
		return oops.Wrapf(err, "failed to update remote DH public key")
	}

	if err := applyRecvRatchetKeys(session); err != nil {
		return err
	}

	session.RemotePublicKey = newRemotePubKey

	log.WithFields(logger.Fields{
		"pkg":             "ratchet",
		"func":            "ProcessIncomingDHRatchet",
		"message_counter": session.MessageCounter,
	}).Debug("Processed incoming DH ratchet from peer")

	return nil
}

// FindSessionByTag checks if a session tag matches a known session.
// Returns true if the tag was found (and consumed), false otherwise.
// This implements the TagResolver interface for independent tag-only resolution.
//
// Two-phase locking: the global index lookup (sm.mu) and per-session validation
// (session.mu) are performed in separate, non-overlapping critical sections.
// Tag replenishment (HKDF) is performed outside both locks.
func (sm *SessionManager) FindSessionByTag(tag [8]byte) bool {
	log.WithFields(logger.Fields{"pkg": "ratchet", "func": "FindSessionByTag"}).Debug("Finding session by tag")
	sm.mu.Lock()
	session, _ := sm.lookupSessionByTag(tag)
	sm.mu.Unlock()

	if session == nil {
		return false
	}

	valid, needsReplenish := sm.validateAndConsumeTagFromSession(session, tag)
	if !valid {
		return false
	}

	if needsReplenish {
		sm.replenishTagWindowOutsideLock(session)
	}
	return true
}

// lookupSessionByTag locates the session for tag and atomically removes it
// from sm.tagIndex and sm.tagCounterIndex. Must be called with sm.mu held
// (write lock).
//
// Returns the session and a counter hint. If the counter is non-nil, it is
// the ES message counter associated with this tag, enabling O(1) AEAD
// decryption in decryptExistingSession instead of a window scan.
//
// Design — two-phase lock separation:
// This function intentionally does NOT acquire session.mu. Validation and
// pendingTags cleanup are deferred to validateAndConsumeTagFromSession, which
// the caller invokes AFTER releasing sm.mu. Keeping the locks separate
// eliminates the nested sm.mu → session.mu acquisition that would deadlock if
// any future session callback re-enters SessionManager under session.mu.
//
// Tag removal from the global index happens here (under sm.mu) so that no
// other goroutine can claim the same tag between the lookup and the per-session
// validation step.
func (sm *SessionManager) lookupSessionByTag(tag [8]byte) (*Session, *uint32) {
	log.WithFields(logger.Fields{"pkg": "ratchet", "func": "lookupSessionByTag"}).Debug("Looking up session by tag in index")
	session, exists := sm.tagIndex[tag]
	if !exists {
		return nil, nil
	}
	// Remove from global index now, under sm.mu, to prevent double-consumption.
	delete(sm.tagIndex, tag)
	counter, hasCounter := sm.tagCounterIndex[tag]
	if hasCounter {
		delete(sm.tagCounterIndex, tag)
	}
	if hasCounter {
		return session, &counter
	}
	return session, nil
}

// validateAndConsumeTagFromSession checks whether session is still valid (not
// expired) and removes tag from session.pendingTags. Must be called AFTER
// sm.mu has been released, so that sm.mu and session.mu are never held
// simultaneously.
//
// Returns:
//
//	valid          — false if the session has expired; callers should discard it.
//	needsReplenish — true when pendingTags falls below tagReplenishThreshold.
func (sm *SessionManager) validateAndConsumeTagFromSession(session *Session, tag [8]byte) (valid, needsReplenish bool) {
	log.WithFields(logger.Fields{"pkg": "ratchet", "func": "validateAndConsumeTagFromSession"}).Debug("Validating and consuming tag from session")
	session.mu.Lock()
	defer session.mu.Unlock()

	if !sm.isSessionValid(session) {
		return false, false
	}
	sm.removeTagFromPendingList(tag, session)
	return true, len(session.pendingTags) < tagReplenishThreshold
}

func (sm *SessionManager) isSessionValid(session *Session) bool {
	return time.Since(session.LastUsed) <= sm.sessionTimeout
}

func (sm *SessionManager) removeTagFromPendingList(tag [8]byte, session *Session) {
	log.WithFields(logger.Fields{"pkg": "ratchet", "func": "removeTagFromPendingList", "pending_count": len(session.pendingTags)}).Debug("Removing tag from session pending list")
	for i, pendingTag := range session.pendingTags {
		if pendingTag == tag {
			session.pendingTags[i] = session.pendingTags[len(session.pendingTags)-1]
			session.pendingTags = session.pendingTags[:len(session.pendingTags)-1]
			break
		}
	}
}

// tagReplenishThreshold is the minimum number of pending tags remaining after
// which replenishment is triggered. Checked after releasing sm.mu so that the
// HKDF derivation does not block the global write lock.
const tagReplenishThreshold = tagWindowSize / 2

// replenishTagWindowOutsideLock generates new session tags and installs them
// without holding sm.mu during the cryptographic (HKDF) work.
//
// Design: tag derivation (the slow path) runs under session.mu only, then the
// results are installed into sm.tagIndex under a brief sm.mu write lock.
// This prevents the global write lock from serialising all goroutines for the
// duration of SHA-256 / HKDF rounds at high message rates.
//
// Collision handling: if installGeneratedTagsLocked skips some tags due to
// cross-session hash collisions, the window can end up under-sized after the
// first install pass.  We retry up to maxReplenishAttempts times so that the
// window reaches tagWindowSize despite isolated collisions.  If the window is
// still under-sized after all retries, a warning is logged so the condition is
// visible rather than silent.
func (sm *SessionManager) replenishTagWindowOutsideLock(session *Session) {
	const maxReplenishAttempts = 3

	for attempt := 0; attempt < maxReplenishAttempts; attempt++ {
		// Phase 1: derive tags under session lock only — sm.mu is NOT held here.
		session.mu.Lock()
		stillNeeded := tagWindowSize - len(session.pendingTags)
		if stillNeeded <= 0 {
			session.mu.Unlock()
			return // already full; another goroutine may have replenished already
		}
		newTags, err := generateTagsOutsideLock(session)
		session.mu.Unlock()

		if err != nil {
			log.WithFields(logger.Fields{
				"pkg":           "ratchet",
				"func":          "replenishTagWindowOutsideLock",
				"remote_pubkey": fmt.Sprintf("%x", session.RemotePublicKey[:8]),
				"attempt":       attempt + 1,
				"error":         err.Error(),
			}).Warn("Failed to generate tags during replenishment")
			return
		}
		if len(newTags) == 0 {
			return
		}

		// Phase 2: install pre-derived tags — brief sm.mu write lock, no HKDF.
		sm.mu.Lock()
		session.mu.Lock()
		sm.installGeneratedTagsLocked(session, newTags)
		remaining := tagWindowSize - len(session.pendingTags)
		session.mu.Unlock()
		sm.mu.Unlock()

		if remaining <= 0 {
			return // window fully replenished
		}
		// Window still under-sized due to collisions; retry with a fresh batch.
	}

	// All attempts exhausted: check final state and warn if still under-sized.
	session.mu.Lock()
	finalRemaining := tagWindowSize - len(session.pendingTags)
	session.mu.Unlock()

	if finalRemaining > 0 {
		log.WithFields(logger.Fields{
			"pkg":           "ratchet",
			"func":          "replenishTagWindowOutsideLock",
			"remote_pubkey": fmt.Sprintf("%x", session.RemotePublicKey[:8]),
			"missing_tags":  finalRemaining,
			"max_attempts":  maxReplenishAttempts,
		}).Warn("Tag window still under-sized after max replenishment attempts due to hash collisions; incoming ES messages may fail until next replenishment")
	}
}

// tagWithCounter pairs a pre-derived session tag with the ES message counter
// it corresponds to. Used to transfer tag→counter mappings between the
// generation phase (under session.mu) and the installation phase (under sm.mu).
type tagWithCounter struct {
	tag     [8]byte
	counter uint32
}

// generateTagsOutsideLock advances session.RecvTagRatchet to produce the tags
// needed to refill the window up to tagWindowSize. The caller must hold
// session.mu but must NOT hold sm.mu; the HKDF derivations run here.
// Returns the new tags with their associated counters, which are not yet
// registered in sm.tagIndex or sm.tagCounterIndex.
func generateTagsOutsideLock(session *Session) ([]tagWithCounter, error) {
	log.WithFields(logger.Fields{"pkg": "ratchet", "func": "generateTagsOutsideLock", "pending_count": len(session.pendingTags), "window_size": tagWindowSize}).Debug("Generating tags outside lock")
	if session.RecvTagRatchet == nil {
		return nil, oops.Errorf("RecvTagRatchet is nil for session — cannot replenish incoming tag window")
	}
	needed := tagWindowSize - len(session.pendingTags)
	if needed <= 0 {
		return nil, nil
	}
	newTags := make([]tagWithCounter, 0, needed)
	for i := 0; i < needed; i++ {
		tag, err := session.RecvTagRatchet.GenerateNextTag()
		if err != nil {
			return newTags, oops.Wrapf(err, "failed to generate session tag at index %d", i)
		}
		counter := session.nextRecvTagCounter
		session.nextRecvTagCounter++
		newTags = append(newTags, tagWithCounter{tag: tag, counter: counter})
	}
	return newTags, nil
}

// installGeneratedTagsLocked writes pre-derived tags into sm.tagIndex,
// sm.tagCounterIndex, and session.pendingTags.  Tags that collide with a
// different session are logged and skipped.  Must be called with both
// sm.mu (write) and session.mu held.
func (sm *SessionManager) installGeneratedTagsLocked(session *Session, newTags []tagWithCounter) {
	for _, tc := range newTags {
		if len(session.pendingTags) >= tagWindowSize {
			// Another goroutine may have already replenished; stop early.
			break
		}
		if existing, ok := sm.tagIndex[tc.tag]; ok && existing != session {
			log.WithFields(logger.Fields{
				"pkg":  "ratchet",
				"func": "installGeneratedTagsLocked",
				"tag":  fmt.Sprintf("%x", tc.tag),
			}).Warn("Tag collision detected, skipping duplicate tag")
			continue
		}
		session.pendingTags = append(session.pendingTags, tc.tag)
		sm.tagIndex[tc.tag] = session
		sm.tagCounterIndex[tc.tag] = tc.counter
	}
}

// generateTagWindow pre-generates a window of session tags for a session.
// If a generated tag collides with an existing tag from another session,
// the collision is logged and the colliding tag is skipped to avoid
// silently overwriting another session's tag slot.
// Returns an error if RecvTagRatchet is nil; using the send-direction TagRatchet
// as a fallback would populate the tag index with outgoing tags, causing all
// incoming existing-session messages to fail lookup silently.
// Must be called with sm.mu held for writing.
func (sm *SessionManager) generateTagWindow(session *Session) error {
	tagRatchet := session.RecvTagRatchet
	if tagRatchet == nil {
		return oops.Errorf("RecvTagRatchet is nil for session — cannot populate incoming tag index")
	}
	for len(session.pendingTags) < tagWindowSize {
		tag, err := tagRatchet.GenerateNextTag()
		if err != nil {
			return oops.Wrapf(err, "failed to generate session tag")
		}
		counter := session.nextRecvTagCounter
		session.nextRecvTagCounter++
		if existing, ok := sm.tagIndex[tag]; ok && existing != session {
			log.WithFields(logger.Fields{
				"pkg":  "ratchet",
				"func": "generateTagWindow",
				"tag":  fmt.Sprintf("%x", tag),
			}).Warn("Tag collision detected, skipping duplicate tag")
			continue
		}
		session.pendingTags = append(session.pendingTags, tag)
		sm.tagIndex[tag] = session
		sm.tagCounterIndex[tag] = counter
	}
	return nil
}

// bytesLess returns true if a is lexicographically less than b.
// Used as a deterministic tiebreaker for LRU eviction when timestamps are equal.
func bytesLess(a, b []byte) bool {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] < b[i] {
			return true
		}
		if a[i] > b[i] {
			return false
		}
	}
	return len(a) < len(b)
}

// evictLRUSessionLocked removes the least-recently-used session.
// Must be called with sm.mu held for writing.
//
// Tiebreaker: When multiple sessions have identical LastUsed timestamps,
// the session with the lexicographically smallest session hash is evicted
// to ensure deterministic behavior (avoids map iteration order dependency).
func (sm *SessionManager) evictLRUSessionLocked() {
	var oldestHash [32]byte
	var oldestTime time.Time
	first := true

	for hash, session := range sm.sessions {
		// Select this session if:
		// 1. It's the first session we've seen, OR
		// 2. It has an older LastUsed time, OR
		// 3. It has the same LastUsed time but a lexicographically smaller hash (deterministic tiebreaker)
		if first || session.LastUsed.Before(oldestTime) ||
			(session.LastUsed.Equal(oldestTime) && bytesLess(hash[:], oldestHash[:])) {
			oldestHash = hash
			oldestTime = session.LastUsed
			first = false
		}
	}

	if !first {
		if evicted, ok := sm.sessions[oldestHash]; ok {
			for _, tag := range evicted.pendingTags {
				delete(sm.tagIndex, tag)
				delete(sm.tagCounterIndex, tag)
			}
			if evicted.nsrTag != nil {
				delete(sm.nsrTagIndex, *evicted.nsrTag)
			}
			delete(sm.sessions, oldestHash)
			log.WithFields(logger.Fields{
				"pkg":             "ratchet",
				"func":            "evictLRUSessionLocked",
				"last_used":       oldestTime,
				"remaining_count": len(sm.sessions),
			}).Warn("Evicted least-recently-used garlic session")
		}
	}
}

// enforcePerPeerQuotaLocked enforces the MaxSessionsPerPeer cap for the given
// remote public key. If a peer is already at or above the cap, the oldest
// session belonging to that peer is evicted first. This protects sessions
// from other honest peers from being evicted via LRU churn when a single
// hostile identity floods the manager with NS messages (AUDIT L-4).
//
// Eviction bias: Prefer evicting established sessions (handshakeState == nil)
// over initiator sessions awaiting NSR (nsrTag != nil). This prevents self-DoS
// when a caller repeatedly creates outbound sessions to the same destination.
// If all sessions for a peer are awaiting NSR, the oldest is evicted.
//
// Must be called with sm.mu held for writing.
func (sm *SessionManager) enforcePerPeerQuotaLocked(remotePubKey [32]byte) {
	var oldestHash [32]byte
	var oldestTime time.Time
	var oldestEstablishedHash [32]byte
	var oldestEstablishedTime time.Time
	count := 0
	haveOldest := false
	haveOldestEstablished := false

	for hash, session := range sm.sessions {
		if session.RemotePublicKey != remotePubKey {
			continue
		}
		count++

		// Track oldest overall
		if !haveOldest || session.LastUsed.Before(oldestTime) {
			oldestHash = hash
			oldestTime = session.LastUsed
			haveOldest = true
		}

		// Track oldest established session (prefer evicting these)
		if session.nsrTag == nil && session.handshakeState == nil {
			if !haveOldestEstablished || session.LastUsed.Before(oldestEstablishedTime) {
				oldestEstablishedHash = hash
				oldestEstablishedTime = session.LastUsed
				haveOldestEstablished = true
			}
		}
	}

	if count < MaxSessionsPerPeer {
		return
	}

	// Guard against zero-hash eviction: if the iteration found no sessions
	// matching remotePubKey (e.g., due to concurrent deletion or edge case),
	// haveOldest will be false and hashToEvict will remain zero. We must not
	// attempt to delete sm.sessions[zero], as this could evict an unrelated
	// session if the zero hash happens to be in use.
	if !haveOldest {
		return
	}

	// Prefer evicting established sessions; fall back to oldest if all are pending NSR
	hashToEvict := oldestEstablishedHash
	lastUsedTime := oldestEstablishedTime
	if !haveOldestEstablished {
		// We already checked haveOldest above, so we know oldestHash is valid
		hashToEvict = oldestHash
		lastUsedTime = oldestTime
	}

	if evicted, ok := sm.sessions[hashToEvict]; ok {
		for _, tag := range evicted.pendingTags {
			delete(sm.tagIndex, tag)
			delete(sm.tagCounterIndex, tag)
		}
		if evicted.nsrTag != nil {
			delete(sm.nsrTagIndex, *evicted.nsrTag)
		}
		delete(sm.sessions, hashToEvict)
		log.WithFields(logger.Fields{
			"pkg":                "ratchet",
			"func":               "enforcePerPeerQuotaLocked",
			"peer_session_count": count,
			"last_used":          lastUsedTime,
			"nsr_pending":        evicted.nsrTag != nil,
		}).Warn("Evicted oldest session for peer exceeding per-peer quota")
	}
}

// CleanupExpiredSessions removes sessions that haven't been used recently.
func (sm *SessionManager) CleanupExpiredSessions() int {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	now := time.Now()
	removed := 0

	for hash, session := range sm.sessions {
		session.mu.Lock()
		expired := now.Sub(session.LastUsed) > sm.sessionTimeout
		var tags [][8]byte
		var nsrTag *[8]byte
		if expired {
			tags = make([][8]byte, len(session.pendingTags))
			copy(tags, session.pendingTags)
			nsrTag = session.nsrTag
		}
		session.mu.Unlock()

		if expired {
			delete(sm.sessions, hash)
			for _, tag := range tags {
				delete(sm.tagIndex, tag)
				delete(sm.tagCounterIndex, tag)
			}
			if nsrTag != nil {
				delete(sm.nsrTagIndex, *nsrTag)
			}
			removed++
		}
	}

	if removed > 0 {
		log.WithFields(logger.Fields{
			"pkg":                    "ratchet",
			"func":                   "CleanupExpiredSessions",
			"removed_sessions":       removed,
			"remaining_sessions":     len(sm.sessions),
			"remaining_indexed_tags": len(sm.tagIndex),
		}).Info("Expired sessions cleaned up")
	}

	return removed
}

// GetSessionCount returns the number of active sessions.
func (sm *SessionManager) GetSessionCount() int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return len(sm.sessions)
}

// GetPublicKey returns this session manager's X25519 public key.
func (sm *SessionManager) GetPublicKey() [32]byte {
	return sm.ourPublicKey
}

// Close stops the cleanup loop, removes all sessions, and zeroes the private key.
// It is safe to call Close multiple times.
func (sm *SessionManager) Close() error {
	sm.cancel()

	// Stop the NS replay cache cleanup goroutine.
	sm.nsReplayCache.Close()

	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Clear all session state
	for k := range sm.sessions {
		delete(sm.sessions, k)
	}
	for k := range sm.tagIndex {
		delete(sm.tagIndex, k)
	}
	for k := range sm.tagCounterIndex {
		delete(sm.tagCounterIndex, k)
	}
	for k := range sm.nsrTagIndex {
		delete(sm.nsrTagIndex, k)
	}
	sm.nsReplayCache.Reset()

	// Zero the private key material
	for i := range sm.ourPrivateKey {
		sm.ourPrivateKey[i] = 0
	}

	log.WithFields(logger.Fields{"pkg": "ratchet", "func": "Close"}).Debug("SessionManager closed")
	return nil
}

// StartCleanupLoop starts periodic cleanup of expired sessions in a background
// goroutine. The loop stops when EITHER of the following occurs:
//
//  1. The caller-supplied ctx is cancelled.
//  2. Close() is called on this SessionManager (which cancels the internal
//     context regardless of the caller's ctx).
//
// Dual-stop behaviour: callers that hold only the GarlicSessionManager interface
// value should be aware that Close() can terminate the loop independently of
// the ctx they supplied here. This is intentional — it prevents orphaned cleanup
// goroutines when the SessionManager is shut down. If the caller wants to stop
// the loop without destroying the SessionManager, cancel the ctx passed here;
// to stop both the loop and the manager, call Close().
func (sm *SessionManager) StartCleanupLoop(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(2 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				sm.CleanupExpiredSessions()
			case <-ctx.Done():
				return
			case <-sm.ctx.Done():
				return
			}
		}
	}()

	log.WithFields(logger.Fields{
		"pkg":      "ratchet",
		"func":     "StartCleanupLoop",
		"interval": "2m",
	}).Debug("Started garlic session cleanup loop")
}
