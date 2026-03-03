package ratchet

import (
	"context"
	"fmt"
	"sync"
	"time"

	i2pcurve25519 "github.com/go-i2p/crypto/curve25519"
	"github.com/go-i2p/crypto/ecies"
	"github.com/go-i2p/crypto/ratchet"
	"github.com/go-i2p/crypto/types"
	"github.com/samber/oops"
)

// Compile-time interface checks.
var _ GarlicSessionManager = (*SessionManager)(nil)
var _ TagResolver = (*SessionManager)(nil)

const (
	// MaxGarlicSessions is the upper bound on active garlic sessions.
	MaxGarlicSessions = 5000
)

// nsMaxPastAge is the maximum acceptable age of the DateTime block in a New
// Session message. NS messages whose timestamp is more than nsMaxPastAge in the
// past are rejected to prevent replay-based session reset attacks.
//
// Tests may temporarily modify this value via t.Cleanup to restore the original.
// Default is 5 minutes per ratchet.md §"Parameters": max clock skew −5 minutes.
var nsMaxPastAge = 5 * time.Minute

// nsMaxFutureAge is the maximum acceptable forward skew of the DateTime block
// in a New Session message. NS messages timestamped more than nsMaxFutureAge
// into the future are rejected to limit the replay window.
//
// Default is 2 minutes per ratchet.md §"Parameters": max clock skew +2 minutes.
var nsMaxFutureAge = 2 * time.Minute

// validateNSDateTimeFreshness parses the decrypted NS payload, locates the
// required DateTime block (first block per ratchet.md §1b), and verifies that
// its timestamp is within the asymmetric freshness window:
//   - Past: at most nsMaxPastAge ago (default 5 minutes)
//   - Future: at most nsMaxFutureAge ahead (default 2 minutes)
//
// Spec ref: ratchet.md §"Parameters" — max clock skew: −5 minutes to +2 minutes.
//
// A stale or excessively future timestamp indicates either a replay of an old
// session or a severe clock skew; both must be rejected to prevent an attacker
// from resetting an active live session by replaying a captured NS message.
func validateNSDateTimeFreshness(payload []byte) error {
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
	if elapsed > nsMaxPastAge {
		return oops.Errorf(
			"NS DateTime block fails freshness check: message is %v old, max past age is %v (stale or replay)",
			elapsed, nsMaxPastAge,
		)
	}
	if elapsed < -nsMaxFutureAge {
		return oops.Errorf(
			"NS DateTime block fails freshness check: message is %v in the future, max future skew is %v",
			-elapsed, nsMaxFutureAge,
		)
	}
	return nil
}

// nsReplayCacheTTL is the time-to-live for NS replay cache entries.
// Set to nsMaxPastAge + nsMaxFutureAge + 1 minute margin to cover the full
// freshness window plus clock skew tolerance.
var nsReplayCacheTTL = nsMaxPastAge + nsMaxFutureAge + time.Minute

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
	ourPrivateKey   [32]byte
	ourPublicKey    [32]byte
	sessionTimeout  time.Duration
	ctx             context.Context
	cancel          context.CancelFunc

	// nsReplayCache tracks recently-seen NS ephemeral keys (first 32 bytes of the
	// NS message) to prevent replay attacks within the freshness window.
	// Spec ref: ratchet.md §"DateTime" — "Bob must implement a Bloom filter or
	// other mechanism to prevent replay attacks, if the time is valid."
	nsReplayCache map[[32]byte]time.Time
	nsReplayDone  chan struct{}
}

// NewSessionManager creates a new session manager with the given private key.
func NewSessionManager(privateKey [32]byte) (*SessionManager, error) {
	log.Debug("Creating new garlic session manager")

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
		ourPrivateKey:   privateKey,
		ourPublicKey:    publicKey,
		sessionTimeout:  10 * time.Minute,
		ctx:             ctx,
		cancel:          cancel,
		nsReplayCache:   make(map[[32]byte]time.Time),
		nsReplayDone:    make(chan struct{}),
	}
	go sm.nsReplayCleanupLoop()

	return sm, nil
}

// GenerateSessionManager creates a session manager with a freshly generated key pair.
func GenerateSessionManager() (*SessionManager, error) {
	_, privBytes, err := ecies.GenerateKeyPair()
	if err != nil {
		return nil, oops.Wrapf(err, "failed to generate session manager key pair")
	}

	var privateKey [32]byte
	copy(privateKey[:], privBytes)
	return NewSessionManager(privateKey)
}

// EncryptGarlicMessage encrypts a plaintext garlic message for the given destination.
// The plaintext must be non-empty; the I2P spec requires at least one payload block.
// Returns an error if plaintext is nil or zero-length.
//
// Thread safety: when an existing session is found, sm.mu.RLock is held through the
// entire encryptExistingSession call. This prevents concurrent CleanupExpiredSessions
// or evictLRUSessionLocked (which require sm.mu.Lock) from removing the session and
// its tags between lookup and encryption, which would produce ES messages with
// unregistered tags that the receiver cannot match.
func (sm *SessionManager) EncryptGarlicMessage(
	destinationHash, destinationPubKey [32]byte,
	plaintextGarlic []byte,
) ([]byte, error) {
	if len(plaintextGarlic) == 0 {
		return nil, oops.Errorf("plaintext must be non-empty: garlic messages require at least one payload block")
	}

	log.WithFields(map[string]interface{}{
		"at":             "EncryptGarlicMessage",
		"plaintext_size": len(plaintextGarlic),
	}).Debug("Encrypting garlic message")

	// Hold RLock through the encrypt dispatch to prevent concurrent session
	// eviction. encryptExistingSession is CPU-only (no network I/O), so
	// holding RLock during encryption does not create a bottleneck.
	sm.mu.RLock()
	session, exists := sm.sessions[destinationHash]
	if exists {
		result, err := sm.encryptExistingSession(session, plaintextGarlic)
		sm.mu.RUnlock()
		return result, err
	}
	sm.mu.RUnlock()

	return sm.encryptNewSession(destinationHash, destinationPubKey, plaintextGarlic)
}

// encryptNewSession creates a new session and encrypts using the Noise IK handshake.
// The payload must begin with a DateTime block per ratchet.md §1b; ValidateNewSessionPayload
// is called here to surface non-compliant payloads immediately rather than silently
// producing an interoperability-breaking message.
func (sm *SessionManager) encryptNewSession(
	destinationHash, destinationPubKey [32]byte,
	plaintextGarlic []byte,
) ([]byte, error) {
	if err := ValidateNewSessionPayload(plaintextGarlic); err != nil {
		return nil, oops.Wrapf(err, "new session payload rejected")
	}

	msg, keys, hs, err := writeNoiseIKMessage1(
		sm.ourPrivateKey, sm.ourPublicKey, destinationPubKey, plaintextGarlic,
	)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to construct Noise IK New Session message")
	}

	if err := sm.storeNewSessionState(destinationHash, destinationPubKey, keys, hs, true); err != nil {
		return nil, err
	}

	return msg, nil
}

// storeNewSessionState initializes and stores ratchet state for future messages.
func (sm *SessionManager) storeNewSessionState(
	destinationHash, destinationPubKey [32]byte,
	keys *sessionKeys,
	hs *noiseHandshakeState,
	isInitiator bool,
) error {
	session, err := createSession(destinationPubKey, keys, sm.ourPrivateKey, isInitiator)
	if err != nil {
		return oops.Wrapf(err, "failed to create outbound session")
	}

	session.handshakeState = hs
	session.isInitiator = isInitiator

	sm.mu.Lock()
	defer sm.mu.Unlock()

	if len(sm.sessions) >= MaxGarlicSessions {
		sm.evictLRUSessionLocked()
	}

	sm.sessions[destinationHash] = session

	// Register the expected NSR tag for initiator sessions so that
	// DecryptGarlicMessage can recognize the responder's reply and dispatch
	// it to decryptIncomingNSR instead of trying to parse it as a New Session.
	if isInitiator && hs != nil {
		if err := sm.registerNSRTagLocked(session, hs); err != nil {
			// Non-fatal: NSR dispatch won't work, but NS-derived ES will still function.
			log.WithError(err).Warn("Failed to register NSR tag for initiator session")
		}
	}

	if err := sm.generateTagWindow(session); err != nil {
		return oops.Wrapf(err, "failed to generate tag window")
	}

	log.WithFields(map[string]interface{}{
		"at":            "storeNewSessionState",
		"session_count": len(sm.sessions),
	}).Debug("New session state stored")

	return nil
}

// encryptExistingSession encrypts using ratchet state for an established session.
func (sm *SessionManager) encryptExistingSession(
	session *Session,
	plaintextGarlic []byte,
) ([]byte, error) {
	session.mu.Lock()
	defer session.mu.Unlock()

	// Spec §1g: the initiator must not send Existing Session messages before it
	// has received the New Session Reply from the responder. The NSR completes
	// the initial Noise IK handshake and installs the ee forward-secrecy keys;
	// sending ES on the pre-NSR NS-derived ratchet is a spec violation that would
	// also break receiver key synchronisation.
	//
	// handshakeState is consumed (set to nil) when NSR is processed in
	// decryptIncomingNSR, so a non-nil value here means NSR has not arrived yet.
	if session.isInitiator && session.handshakeState != nil {
		return nil, oops.Errorf(
			"spec violation (ratchet.md §1g): initiator must receive New Session Reply before sending Existing Session messages",
		)
	}

	// Spec §"Notes" after §1g: Bob must receive an ES message from Alice before
	// sending ES messages. This ensures the initiator has processed the NSR and
	// can decrypt ES from the responder. The flag is set after EncryptNewSessionReply
	// and cleared when the first inbound ES is decrypted for this session.
	if !session.isInitiator && session.awaitingFirstES {
		return nil, oops.Errorf(
			"spec violation (ratchet.md §Notes): responder must receive an ES message from initiator before sending ES",
		)
	}

	messageKey, sessionTag, err := advanceRatchets(session)
	if err != nil {
		return nil, err
	}

	// Spec §"Next DH Ratchet Public Key": if a DH ratchet rotation occurred,
	// the resulting NextKey blocks must be serialized into the encrypted payload
	// so the peer can process the key rotation and maintain forward secrecy.
	payload, err := prependPendingNextKeys(session, plaintextGarlic)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to prepend NextKey blocks to payload")
	}

	ciphertext, tag, err := encryptWithSessionKey(messageKey, payload, sessionTag, session.MessageCounter)
	if err != nil {
		return nil, err
	}

	msg := buildExistingSessionMessage(sessionTag, ciphertext, tag)

	session.LastUsed = time.Now()
	session.MessageCounter++

	return msg, nil
}

// DecryptGarlicMessage decrypts an encrypted garlic message.
// Handles New Session, New Session Reply, and Existing Session message types.
//
// Returns:
//   - plaintext: the decrypted garlic payload
//   - sessionTag: the 8-byte tag used to identify the session (zero for NS and NSR)
//   - sessionHash: SHA-256(initiatorStaticPub) for New Session messages; nil otherwise.
//     Callers that need to send a New Session Reply must pass this value to EncryptNewSessionReply.
func (sm *SessionManager) DecryptGarlicMessage(encryptedGarlic []byte) ([]byte, [8]byte, *[32]byte, error) {
	if len(encryptedGarlic) < 8 {
		return nil, [8]byte{}, nil, oops.Errorf("encrypted garlic message too short: %d bytes", len(encryptedGarlic))
	}

	var msgTag [8]byte
	copy(msgTag[:], encryptedGarlic[0:8])

	// Check Existing Session tag index first (most common path).
	// Phase 1: under sm.mu — look up and atomically remove tag from global index.
	// Phase 2: under session.mu only — validate session and clean pendingTags.
	// This two-phase approach ensures sm.mu and session.mu are never held
	// simultaneously (see lookupSessionByTag for the rationale).
	sm.mu.Lock()
	session, counterHint := sm.lookupSessionByTag(msgTag)
	sm.mu.Unlock()

	var needsReplenish bool
	if session != nil {
		var valid bool
		valid, needsReplenish = sm.validateAndConsumeTagFromSession(session, msgTag)
		if !valid {
			session = nil
		}
	}

	if session != nil {
		plaintext, sessionTag, err := sm.decryptExistingSession(session, encryptedGarlic[8:], msgTag, counterHint)
		if needsReplenish {
			sm.replenishTagWindowOutsideLock(session)
		}
		if err == nil {
			sm.processDecryptedESBlocks(session, plaintext)
		}
		return plaintext, sessionTag, nil, err
	}

	// Check NSR tag index: initiator receiving a reply to its New Session.
	sm.mu.Lock()
	nsrSession, isNSR := sm.nsrTagIndex[msgTag]
	if isNSR {
		delete(sm.nsrTagIndex, msgTag)
		if nsrSession.nsrTag != nil && *nsrSession.nsrTag == msgTag {
			nsrSession.nsrTag = nil
		}
	}
	sm.mu.Unlock()

	if isNSR && nsrSession != nil {
		plaintext, err := sm.decryptIncomingNSR(nsrSession, encryptedGarlic)
		return plaintext, [8]byte{}, nil, err
	}

	// Fallthrough: New Session (Noise IK / ECIES).
	plaintext, sessionHash, err := sm.decryptNewSession(encryptedGarlic)
	if err != nil {
		return nil, [8]byte{}, nil, oops.Wrapf(err, "failed to decrypt garlic message")
	}
	return plaintext, [8]byte{}, sessionHash, nil
}

// decryptNewSession decrypts a New Session message using the Noise IK handshake.
// Handles both the bound (IK, with initiator static key) and unbound (N-pattern,
// flags section = all-zeros) variants.
//
// For bound messages: stores inbound ratchet state and returns
// SHA-256(initiatorStaticPub) so the caller can dispatch a New Session Reply.
// For unbound messages: no session state is stored (non-repliable) and
// sessionHash is nil.
func (sm *SessionManager) decryptNewSession(msg []byte) ([]byte, *[32]byte, error) {
	plaintext, initiatorStaticPub, keys, hs, isUnbound, err := readNoiseIKMessage1(
		sm.ourPrivateKey, sm.ourPublicKey, msg,
	)
	if err != nil {
		return nil, nil, oops.Wrapf(err, "failed to process Noise IK New Session message")
	}

	// Unbound sessions are non-repliable: the initiator sent no static key,
	// so there is no identity to key the session on and no NSR can be sent.
	// Spec §1c: "Bob ratchets once when creating an unbound inbound session,
	// and does not create a corresponding outbound session."
	if isUnbound {
		log.Debug("Received unbound (N-pattern) New Session message — no session state stored")
		return plaintext, nil, nil
	}

	// Spec §1b / replay-prevention: reject NS messages whose DateTime block
	// is too old or too far in the future. A captured NS can otherwise be
	// replayed to reset the active session keyed on the initiator's static key.
	if err := validateNSDateTimeFreshness(plaintext); err != nil {
		return nil, nil, oops.Wrapf(err, "New Session message rejected")
	}

	// Spec §"DateTime": "Bob must implement a Bloom filter or other mechanism
	// to prevent replay attacks, if the time is valid."
	// Check the NS ephemeral key (first 32 bytes) against the replay cache.
	if len(msg) >= 32 {
		var ephKey [32]byte
		copy(ephKey[:], msg[:32])
		if sm.checkNSReplay(ephKey) {
			return nil, nil, oops.Errorf(
				"NS replay detected: ephemeral key %x has been seen within the freshness window",
				ephKey[:8],
			)
		}
	}

	if err := sm.initializeInboundRatchetState(initiatorStaticPub, keys, hs); err != nil {
		return nil, nil, err
	}

	sessionHash := types.SHA256(initiatorStaticPub[:])
	return plaintext, &sessionHash, nil
}

// EncryptUnboundGarlicMessage encrypts a plaintext garlic message as an
// unbound (N-pattern, §1c) New Session without advertising the sender's static
// key. Use this for raw-datagram or one-time-send traffic where sender anonymity
// is required.
//
// Unlike EncryptGarlicMessage, no session state is created: the message is
// always a fresh one-shot IK/N-pattern frame and no reply is possible. The
// caller must supply the recipient's raw X25519 public key.
func (sm *SessionManager) EncryptUnboundGarlicMessage(
	destinationPubKey [32]byte,
	plaintextGarlic []byte,
) ([]byte, error) {
	if len(plaintextGarlic) == 0 {
		return nil, oops.Errorf("plaintext must be non-empty: garlic messages require at least one payload block")
	}

	log.WithFields(map[string]interface{}{
		"at":             "EncryptUnboundGarlicMessage",
		"plaintext_size": len(plaintextGarlic),
	}).Debug("Encrypting unbound garlic message")

	if err := ValidateNewSessionPayload(plaintextGarlic); err != nil {
		return nil, oops.Wrapf(err, "unbound new session payload rejected")
	}

	msg, _, err := writeNoiseIKMessage1Unbound(destinationPubKey, plaintextGarlic)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to construct unbound New Session message")
	}
	return msg, nil
}

// initializeInboundRatchetState creates and stores ratchet state for incoming sessions.
func (sm *SessionManager) initializeInboundRatchetState(remotePubKey [32]byte, keys *sessionKeys, hs *noiseHandshakeState) error {
	session, err := createSession(remotePubKey, keys, sm.ourPrivateKey, false)
	if err != nil {
		return oops.Wrapf(err, "failed to create inbound session")
	}

	session.handshakeState = hs
	session.isInitiator = false

	sessionHash := types.SHA256(remotePubKey[:])

	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Enforce MaxGarlicSessions to prevent memory exhaustion from malicious peers
	// sending many New Session messages with different ephemeral keys.
	if len(sm.sessions) >= MaxGarlicSessions {
		sm.evictLRUSessionLocked()
	}

	sm.sessions[sessionHash] = session

	if err := sm.generateTagWindow(session); err != nil {
		return oops.Wrapf(err, "failed to generate inbound tag window")
	}

	log.WithFields(map[string]interface{}{
		"at":            "initializeInboundRatchetState",
		"session_count": len(sm.sessions),
		"tag_count":     len(sm.tagIndex),
	}).Debug("Inbound ratchet session stored")

	return nil
}

// registerNSRTagLocked derives the expected NSR tag for an initiator session
// and registers it in sm.nsrTagIndex. Must be called with sm.mu held for writing.
// The tag is derived from the same chain key that the responder will use when
// constructing its NSR, ensuring both sides agree on the routing tag.
func (sm *SessionManager) registerNSRTagLocked(session *Session, hs *noiseHandshakeState) error {
	nsrTagRatchet, err := deriveNSRTagRatchet(hs.ck)
	if err != nil {
		return oops.Wrapf(err, "failed to derive NSR tag ratchet for initiator registration")
	}
	tag, err := nsrTagRatchet.GenerateNextTag()
	if err != nil {
		return oops.Wrapf(err, "failed to generate NSR tag for initiator registration")
	}
	session.nsrTag = &tag
	sm.nsrTagIndex[tag] = session
	return nil
}

// decryptIncomingNSR processes a received New Session Reply for an initiator session.
// It verifies the responder's Noise IK message 2, then replaces the NS-derived
// ratchet roots with the post-handshake NSR keys, providing ee forward secrecy.
func (sm *SessionManager) decryptIncomingNSR(session *Session, message []byte) ([]byte, error) {
	// Phase 1: read handshake state and run NSR crypto under session lock only.
	session.mu.Lock()
	if session.handshakeState == nil {
		session.mu.Unlock()
		return nil, oops.Errorf("no pending handshake state for NSR: session may have already processed NSR")
	}
	hs := session.handshakeState
	session.handshakeState = nil // consume immediately; duplicate NSRs are rejected
	session.mu.Unlock()

	plaintext, nsrKeys, err := readNoiseIKMessage2(hs, sm.ourPrivateKey, message)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to process New Session Reply")
	}

	// Phase 2: apply NSR keys — requires sm.mu (write) + session.mu.
	// Initiator sends in keyAB direction (A→B) and receives in keyBA direction (B→A).
	sm.mu.Lock()
	session.mu.Lock()
	if applyErr := sm.applyNSRKeysToSessionWhileLocked(session, nsrKeys, true); applyErr != nil {
		session.mu.Unlock()
		sm.mu.Unlock()
		return nil, oops.Wrapf(applyErr, "failed to apply NSR keys to initiator session ratchets")
	}
	session.LastUsed = time.Now()
	session.mu.Unlock()
	sm.mu.Unlock()

	log.WithFields(map[string]interface{}{
		"at": "decryptIncomingNSR",
	}).Debug("New Session Reply received, ratchets updated with NSR keys")

	return plaintext, nil
}

// applyNSRKeysToSessionWhileLocked replaces a session's NS-derived ratchet roots
// with the NSR post-handshake directional keys. Must be called with both
// sm.mu (write) and session.mu held.
//
// nsrSessionKeys.keyAB is the initiator→responder direction key;
// nsrSessionKeys.keyBA is the responder→initiator direction key.
// If isInitiator is true, sendKey = keyAB and recvKey = keyBA; vice versa otherwise.
func (sm *SessionManager) applyNSRKeysToSessionWhileLocked(session *Session, nsrKeys *nsrSessionKeys, isInitiator bool) error {
	var sendKey, recvKey [32]byte
	if isInitiator {
		sendKey = nsrKeys.keyAB // A sends to B
		recvKey = nsrKeys.keyBA // A receives from B
	} else {
		sendKey = nsrKeys.keyBA // B sends to A
		recvKey = nsrKeys.keyAB // B receives from A
	}

	sendTagKey, sendSymKey, err := deriveTagAndSymKeysFromChainKey(sendKey)
	if err != nil {
		return oops.Wrapf(err, "failed to derive NSR send-direction ratchet keys")
	}
	recvTagKey, recvSymKey, err := deriveTagAndSymKeysFromChainKey(recvKey)
	if err != nil {
		return oops.Wrapf(err, "failed to derive NSR recv-direction ratchet keys")
	}

	// Purge old NS-derived recv tags from tagIndex before replacing the ratchet.
	for _, tag := range session.pendingTags {
		delete(sm.tagIndex, tag)
		delete(sm.tagCounterIndex, tag)
	}
	session.pendingTags = session.pendingTags[:0]

	// Install post-handshake ratchets.
	session.SymmetricRatchet = ratchet.NewSymmetricRatchet(sendSymKey)
	session.TagRatchet = ratchet.NewTagRatchet(sendTagKey)
	session.RecvSymmetricRatchet = ratchet.NewSymmetricRatchet(recvSymKey)
	session.RecvTagRatchet = ratchet.NewTagRatchet(recvTagKey)

	// Reset message counters: the session restarts at 1 with NSR keys.
	session.MessageCounter = 1
	resetRecvWindow(session)

	// Regenerate recv tag window with the new NSR-derived recv ratchet.
	return sm.generateTagWindow(session)
}

// EncryptNewSessionReply constructs a New Session Reply (NSR) for a session
// that was created by receiving a New Session message. The responder calls this
// to send a reply back to the initiator, completing the Noise IK handshake.
//
// sessionHash identifies the session. Pass the *[32]byte returned by
// DecryptGarlicMessage when it processed the peer's New Session message
// (dereference to obtain the [32]byte value: `*sessionHash`).
// payload is the reply plaintext.
//
// After sending the NSR, the session's ratchet state is updated with the
// post-handshake keys (kAB/kBA from the NSR split), replacing the NS-derived
// roots and providing the ephemeral-ephemeral forward secrecy required by the spec.
func (sm *SessionManager) EncryptNewSessionReply(
	sessionHash [32]byte,
	payload []byte,
) ([]byte, error) {
	sm.mu.RLock()
	session, exists := sm.sessions[sessionHash]
	sm.mu.RUnlock()

	if !exists {
		return nil, oops.Errorf("no session found for hash %x", sessionHash[:8])
	}

	// Phase 1: crypto under session lock only (no sm.mu needed for key derivation).
	session.mu.Lock()

	if session.handshakeState == nil {
		session.mu.Unlock()
		return nil, oops.Errorf("session has no pending handshake state for NSR")
	}
	if session.isInitiator {
		session.mu.Unlock()
		return nil, oops.Errorf("only the responder can send a New Session Reply")
	}

	_, wireMsg, nsrKeys, err := writeNoiseIKMessage2(session.handshakeState, payload)
	session.handshakeState = nil // consumed; NSR can only be sent once
	session.mu.Unlock()

	if err != nil {
		return nil, oops.Wrapf(err, "failed to construct New Session Reply")
	}

	// Phase 2: apply NSR-derived ratchet keys — requires sm.mu (write) + session.mu.
	// Responder sends in keyBA direction (B→A) and receives in keyAB direction (A→B).
	sm.mu.Lock()
	session.mu.Lock()
	if applyErr := sm.applyNSRKeysToSessionWhileLocked(session, nsrKeys, false); applyErr != nil {
		session.mu.Unlock()
		sm.mu.Unlock()
		return nil, oops.Wrapf(applyErr, "failed to apply NSR keys to responder session ratchets")
	}
	session.awaitingFirstES = true
	session.LastUsed = time.Now()
	session.mu.Unlock()
	sm.mu.Unlock()

	log.WithFields(map[string]interface{}{
		"at":           "EncryptNewSessionReply",
		"payload_size": len(payload),
	}).Debug("New Session Reply sent, ratchets updated with NSR keys")

	return wireMsg, nil
}

// decryptExistingSession decrypts an Existing Session message using ratchet state.
//
// It implements a receive window to handle out-of-order delivery without
// desynchronising the receive counter.  The window covers
// [recvWindowBase, recvWindowBase+recvWindowSize) counters.  Message keys are
// pre-derived for every counter in the window; on a successful decrypt the used
// key is removed and the window base is advanced past any trailing consumed
// counters.
//
// counterHint, when non-nil, provides the ES message counter associated with
// the session tag (from tagCounterIndex). This enables O(1) AEAD decryption
// by trying the exact counter first, avoiding the window scan. A nil hint
// falls back to the full window scan for robustness.
//
// Spec ref: ratchet.md §"Existing Session" — "Maintain handling of out-of-order
// messages", window ≤128.
func (sm *SessionManager) decryptExistingSession(
	session *Session,
	msg []byte,
	sessionTag [8]byte,
	counterHint *uint32,
) ([]byte, [8]byte, error) {
	session.mu.Lock()
	defer session.mu.Unlock()

	ciphertext, tag, err := parseExistingSessionMessage(msg)
	if err != nil {
		return nil, [8]byte{}, err
	}

	// Ensure the key cache covers the full current window.
	windowEnd := session.recvWindowBase + recvWindowSize
	if err := fillRecvKeyCache(session, windowEnd); err != nil {
		return nil, [8]byte{}, err
	}

	var (
		plaintext   []byte
		usedCounter uint32
		found       bool
	)

	// O(1) fast path: if a counter hint is available (from tag→counter index),
	// try that counter directly. This avoids scanning up to 64 AEAD trial
	// decryptions per message.
	if counterHint != nil {
		c := *counterHint
		if c >= session.recvWindowBase && c < windowEnd {
			if messageKey, inCache := session.recvKeyCache[c]; inCache {
				pt, decErr := decryptWithSessionTag(messageKey, ciphertext, tag, sessionTag, c)
				if decErr == nil {
					plaintext = pt
					usedCounter = c
					found = true
				}
			}
		}
	}

	// Fallback: scan candidate counters from the window base upward if the
	// hint was unavailable or did not decrypt successfully.
	if !found {
		for counter := session.recvWindowBase; counter < windowEnd; counter++ {
			messageKey, inCache := session.recvKeyCache[counter]
			if !inCache {
				// Already consumed; skip.
				continue
			}
			pt, decErr := decryptWithSessionTag(messageKey, ciphertext, tag, sessionTag, counter)
			if decErr != nil {
				continue
			}
			plaintext = pt
			usedCounter = counter
			found = true
			break
		}
	}
	if !found {
		return nil, [8]byte{}, oops.Errorf(
			"decrypt failed: message does not match any counter in recv window [%d, %d)",
			session.recvWindowBase, windowEnd,
		)
	}

	// Consume the key and advance the window base past any leading gap of
	// already-consumed counters.
	delete(session.recvKeyCache, usedCounter)
	for session.recvWindowBase < session.recvFillMark {
		if _, stillPending := session.recvKeyCache[session.recvWindowBase]; stillPending {
			break
		}
		session.recvWindowBase++
	}

	// GAP-3: Clear the responder's awaitingFirstES flag upon successfully
	// decrypting the first inbound ES message from the initiator.
	if !session.isInitiator && session.awaitingFirstES {
		session.awaitingFirstES = false
		log.WithFields(map[string]interface{}{
			"at":      "decryptExistingSession",
			"counter": usedCounter,
		}).Debug("First inbound ES received; responder may now send ES")
	}

	session.LastUsed = time.Now()
	return plaintext, sessionTag, nil
}

// processDecryptedESBlocks inspects a decrypted Existing Session payload for
// control blocks that require session-level side effects:
//
//   - BlockTermination: signals session teardown. The session is removed from
//     sm.sessions and sm.tagIndex. Per ratchet.md §"Unencrypted data", a
//     Termination block in an ES message means the peer is closing the session.
//
//   - BlockMessageNumber: carries the PN value (previous tag set message count).
//     Per ratchet.md §"Message Numbers", on receiving a MessageNumber block the
//     recipient should trim pre-derived keys beyond PN from the previous tag set
//     to bound memory.
//
//   - BlockAckRequest: the peer is requesting acknowledgment. An Ack block is
//     queued for inclusion in the next outgoing ES message.
//     Spec ref: ratchet.md §"Ack Request".
//
//   - BlockAck: the peer is acknowledging previously received messages. The
//     ack entries are stored on the session for caller inspection.
//     Spec ref: ratchet.md §"Ack".
//
// This function is called from DecryptGarlicMessage after decryptExistingSession
// returns successfully, with neither sm.mu nor session.mu held.
func (sm *SessionManager) processDecryptedESBlocks(session *Session, plaintext []byte) {
	blocks, err := ParsePayload(plaintext)
	if err != nil {
		// Non-fatal: the payload was already AEAD-authenticated, so a parse
		// failure here is a local framing bug, not a security issue.
		log.WithError(err).Warn("Failed to parse decrypted ES payload for control blocks")
		return
	}

	for _, block := range blocks {
		switch block.Type {
		case BlockTermination:
			reason, _, _ := block.TerminationInfo()
			sm.removeSessionByPointer(session)
			log.WithFields(map[string]interface{}{
				"at":     "processDecryptedESBlocks",
				"reason": reason,
			}).Info("Session terminated by peer via Termination block")
			return // no further block processing after teardown

		case BlockMessageNumber:
			pn, pnErr := block.MessageNumber()
			if pnErr != nil {
				log.WithError(pnErr).Warn("Malformed MessageNumber block in ES payload")
				continue
			}
			trimRecvWindowByPN(session, pn)

		case BlockAckRequest:
			sm.processAckRequest(session)

		case BlockAck:
			sm.processAck(session, block)
		}
	}
}

// processAckRequest queues an Ack block for the next outgoing ES message.
// The ack acknowledges the current recv window state: it reports the recv key ID
// and the highest consumed message counter.
//
// Spec ref: ratchet.md §"Ack Request" — on receiving request, queue an Ack response.
func (sm *SessionManager) processAckRequest(session *Session) {
	session.mu.Lock()
	defer session.mu.Unlock()

	// Build an Ack that reports our recvKeyID and the highest consumed counter
	// (recvWindowBase - 1, since recvWindowBase is the next expected counter).
	highestConsumed := uint16(0)
	if session.recvWindowBase > 1 {
		base := session.recvWindowBase - 1
		if base > uint32(MaxMessageNumber) {
			base = uint32(MaxMessageNumber)
		}
		highestConsumed = uint16(base)
	}
	ackBlock := NewAckBlock([]AckEntry{{
		TagSetID: session.recvKeyID,
		N:        highestConsumed,
	}})
	session.pendingAcks = append(session.pendingAcks, ackBlock)

	log.WithFields(map[string]interface{}{
		"at":        "processAckRequest",
		"recv_key":  session.recvKeyID,
		"highest_n": highestConsumed,
	}).Debug("Queued Ack block in response to AckRequest")
}

// processAck records Ack entries received from the peer.
//
// Spec ref: ratchet.md §"Ack" — acknowledgment of received messages.
func (sm *SessionManager) processAck(session *Session, block PayloadBlock) {
	acks, err := block.Acks()
	if err != nil {
		log.WithError(err).Warn("Malformed Ack block in ES payload")
		return
	}

	session.mu.Lock()
	session.lastAckedEntries = acks
	session.mu.Unlock()

	log.WithFields(map[string]interface{}{
		"at":    "processAck",
		"count": len(acks),
	}).Debug("Received Ack block from peer")
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

	log.WithFields(map[string]interface{}{
		"at":              "removeSessionByPointer",
		"remaining_count": len(sm.sessions),
	}).Debug("Session removed after termination")
}

// ProcessIncomingDHRatchet processes a DH ratchet key received from a peer.
// The session is found by tag lookup using the sessionTag parameter.
func (sm *SessionManager) ProcessIncomingDHRatchet(sessionTag [8]byte, newRemotePubKey [32]byte) error {
	sm.mu.RLock()
	session, exists := sm.tagIndex[sessionTag]
	sm.mu.RUnlock()

	if !exists {
		return oops.Errorf("no session found for tag %x", sessionTag)
	}

	session.mu.Lock()
	defer session.mu.Unlock()

	if err := session.DHRatchet.UpdateKeys(newRemotePubKey[:]); err != nil {
		return oops.Wrapf(err, "failed to update remote DH public key")
	}

	_, receivingChainKey, err := session.DHRatchet.PerformRatchet()
	if err != nil {
		return oops.Wrapf(err, "failed to perform receiving DH ratchet")
	}

	tagKey, symKey, err := deriveTagAndSymKeysFromChainKey(receivingChainKey)
	if err != nil {
		return oops.Wrapf(err, "failed to derive receiving tag and symmetric keys after DH ratchet")
	}

	session.RecvSymmetricRatchet = ratchet.NewSymmetricRatchet(symKey)
	session.RecvTagRatchet = ratchet.NewTagRatchet(tagKey)

	session.RemotePublicKey = newRemotePubKey

	log.WithFields(map[string]interface{}{
		"at":              "ProcessIncomingDHRatchet",
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
			log.WithFields(map[string]interface{}{
				"at":            "replenishTagWindowOutsideLock",
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
		log.WithFields(map[string]interface{}{
			"at":            "replenishTagWindowOutsideLock",
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
			log.WithFields(map[string]interface{}{
				"at":  "installGeneratedTagsLocked",
				"tag": fmt.Sprintf("%x", tc.tag),
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
			log.WithFields(map[string]interface{}{
				"at":  "generateTagWindow",
				"tag": fmt.Sprintf("%x", tag),
			}).Warn("Tag collision detected, skipping duplicate tag")
			continue
		}
		session.pendingTags = append(session.pendingTags, tag)
		sm.tagIndex[tag] = session
		sm.tagCounterIndex[tag] = counter
	}
	return nil
}

// evictLRUSessionLocked removes the least-recently-used session.
// Must be called with sm.mu held for writing.
func (sm *SessionManager) evictLRUSessionLocked() {
	var oldestHash [32]byte
	var oldestTime time.Time
	first := true

	for hash, session := range sm.sessions {
		if first || session.LastUsed.Before(oldestTime) {
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
			log.WithFields(map[string]interface{}{
				"at":              "evictLRUSessionLocked",
				"last_used":       oldestTime,
				"remaining_count": len(sm.sessions),
			}).Warn("Evicted least-recently-used garlic session")
		}
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
		log.WithFields(map[string]interface{}{
			"at":                     "CleanupExpiredSessions",
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
	select {
	case <-sm.nsReplayDone:
		// Already closed.
	default:
		close(sm.nsReplayDone)
	}

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
	for k := range sm.nsReplayCache {
		delete(sm.nsReplayCache, k)
	}

	// Zero the private key material
	for i := range sm.ourPrivateKey {
		sm.ourPrivateKey[i] = 0
	}

	log.Debug("SessionManager closed")
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

	log.WithFields(map[string]interface{}{
		"at":       "SessionManager.StartCleanupLoop",
		"interval": "2m",
	}).Debug("Started garlic session cleanup loop")
}

// checkNSReplay checks whether the NS ephemeral key has been seen before.
// If the key is new, it is added to the cache and false is returned (not a replay).
// If the key has been seen within nsReplayCacheTTL, true is returned (replay).
//
// Spec ref: ratchet.md §"DateTime" — "Bob must implement a Bloom filter or
// other mechanism to prevent replay attacks, if the time is valid."
func (sm *SessionManager) checkNSReplay(ephemeralKey [32]byte) bool {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	now := nowFunc()

	if firstSeen, exists := sm.nsReplayCache[ephemeralKey]; exists {
		if now.Sub(firstSeen) < nsReplayCacheTTL {
			return true // replay detected
		}
		// Entry expired — treat as new.
	}

	if len(sm.nsReplayCache) >= nsReplayCacheMaxSize {
		sm.evictOldestNSReplayEntriesLocked()
	}

	sm.nsReplayCache[ephemeralKey] = now
	return false
}

// evictOldestNSReplayEntriesLocked removes the oldest 10% of NS replay cache
// entries. Must be called with sm.mu held for writing.
func (sm *SessionManager) evictOldestNSReplayEntriesLocked() {
	evictCount := len(sm.nsReplayCache) / 10
	if evictCount < 1 {
		evictCount = 1
	}

	cutoff := nowFunc().Add(-nsReplayCacheTTL / 2)
	evicted := 0
	for key, firstSeen := range sm.nsReplayCache {
		if evicted >= evictCount {
			break
		}
		if firstSeen.Before(cutoff) {
			delete(sm.nsReplayCache, key)
			evicted++
		}
	}

	// If not enough expired entries, delete any entries to stay under limit.
	for key := range sm.nsReplayCache {
		if evicted >= evictCount {
			break
		}
		delete(sm.nsReplayCache, key)
		evicted++
	}
}

// nsReplayCleanupLoop periodically evicts expired entries from the NS replay cache.
func (sm *SessionManager) nsReplayCleanupLoop() {
	ticker := time.NewTicker(nsReplayCacheCleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-sm.nsReplayDone:
			return
		case <-sm.ctx.Done():
			return
		case <-ticker.C:
			sm.evictExpiredNSReplayEntries()
		}
	}
}

// evictExpiredNSReplayEntries removes all NS replay entries older than nsReplayCacheTTL.
func (sm *SessionManager) evictExpiredNSReplayEntries() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	cutoff := nowFunc().Add(-nsReplayCacheTTL)
	for key, firstSeen := range sm.nsReplayCache {
		if firstSeen.Before(cutoff) {
			delete(sm.nsReplayCache, key)
		}
	}
}
