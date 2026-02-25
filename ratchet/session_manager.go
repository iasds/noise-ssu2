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

// nsMaxAge is the maximum acceptable age (or skew into the future) of the
// DateTime block in a New Session message. NS messages whose timestamp falls
// outside [now-nsMaxAge, now+nsMaxAge] are rejected to prevent replay-based
// session reset attacks.
//
// Tests may temporarily modify this value via t.Cleanup to restore the original.
// Default is 5 minutes, matching common I2P router practice.
var nsMaxAge = 5 * time.Minute

// validateNSDateTimeFreshness parses the decrypted NS payload, locates the
// required DateTime block (first block per ratchet.md §1b), and verifies that
// its timestamp is within nsMaxAge of the current time.
//
// A stale timestamp indicates either a replay of an old session or a severe
// clock skew; both must be rejected to prevent an attacker from resetting an
// active live session by replaying a captured NS message.
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
	age := nowFunc().Sub(msgTime)
	if age < 0 {
		age = -age // treat future timestamps symmetrically
	}
	if age > nsMaxAge {
		return oops.Errorf(
			"NS DateTime block fails freshness check: age=%v max=%v (replay or severe clock skew)",
			age, nsMaxAge,
		)
	}
	return nil
}

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
	nsrTagIndex    map[[8]byte]*Session
	ourPrivateKey  [32]byte
	ourPublicKey   [32]byte
	sessionTimeout time.Duration
	ctx            context.Context
	cancel         context.CancelFunc
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

	return &SessionManager{
		sessions:       make(map[[32]byte]*Session),
		tagIndex:       make(map[[8]byte]*Session),
		nsrTagIndex:    make(map[[8]byte]*Session),
		ourPrivateKey:  privateKey,
		ourPublicKey:   publicKey,
		sessionTimeout: 10 * time.Minute,
		ctx:            ctx,
		cancel:         cancel,
	}, nil
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

	sm.mu.RLock()
	session, exists := sm.sessions[destinationHash]
	sm.mu.RUnlock()

	if !exists {
		sm.mu.Lock()
		session, exists = sm.sessions[destinationHash]
		if exists {
			sm.mu.Unlock()
			return sm.encryptExistingSession(session, plaintextGarlic)
		}
		sm.mu.Unlock()

		return sm.encryptNewSession(destinationHash, destinationPubKey, plaintextGarlic)
	}

	return sm.encryptExistingSession(session, plaintextGarlic)
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

	messageKey, sessionTag, err := advanceRatchets(session)
	if err != nil {
		return nil, err
	}

	ciphertext, tag, err := encryptWithSessionKey(messageKey, plaintextGarlic, sessionTag, session.MessageCounter)
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
	session := sm.lookupSessionByTag(msgTag)
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
		plaintext, sessionTag, err := sm.decryptExistingSession(session, encryptedGarlic[8:], msgTag)
		if needsReplenish {
			sm.replenishTagWindowOutsideLock(session)
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
// Spec ref: ratchet.md §"Existing Session" — "Maintain handling of out-of-order
// messages", window ≤128.
func (sm *SessionManager) decryptExistingSession(
	session *Session,
	msg []byte,
	sessionTag [8]byte,
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

	// Scan candidate counters from the window base upward.  We do not transmit
	// the counter on the wire so we must try each candidate until the AEAD tag
	// verifies.
	var (
		plaintext   []byte
		usedCounter uint32
		found       bool
	)
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

	session.LastUsed = time.Now()
	return plaintext, sessionTag, nil
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
	session := sm.lookupSessionByTag(tag)
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
// from sm.tagIndex. Must be called with sm.mu held (write lock).
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
func (sm *SessionManager) lookupSessionByTag(tag [8]byte) *Session {
	session, exists := sm.tagIndex[tag]
	if !exists {
		return nil
	}
	// Remove from global index now, under sm.mu, to prevent double-consumption.
	delete(sm.tagIndex, tag)
	return session
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
const tagReplenishThreshold = 5

// replenishTagWindowOutsideLock generates new session tags and installs them
// without holding sm.mu during the cryptographic (HKDF) work.
//
// Design: tag derivation (the slow path) runs under session.mu only, then the
// results are installed into sm.tagIndex under a brief sm.mu write lock.
// This prevents the global write lock from serialising all goroutines for the
// duration of SHA-256 / HKDF rounds at high message rates.
func (sm *SessionManager) replenishTagWindowOutsideLock(session *Session) {
	// Phase 1: derive tags under session lock only — sm.mu is NOT held here.
	session.mu.Lock()
	newTags, err := generateTagsOutsideLock(session)
	session.mu.Unlock()

	if err != nil {
		log.WithFields(map[string]interface{}{
			"at":            "replenishTagWindowOutsideLock",
			"remote_pubkey": fmt.Sprintf("%x", session.RemotePublicKey[:8]),
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
	session.mu.Unlock()
	sm.mu.Unlock()
}

// generateTagsOutsideLock advances session.RecvTagRatchet to produce the tags
// needed to refill the window up to tagWindowSize. The caller must hold
// session.mu but must NOT hold sm.mu; the HKDF derivations run here.
// Returns the new tags, which are not yet registered in sm.tagIndex.
func generateTagsOutsideLock(session *Session) ([][8]byte, error) {
	if session.RecvTagRatchet == nil {
		return nil, oops.Errorf("RecvTagRatchet is nil for session — cannot replenish incoming tag window")
	}
	needed := tagWindowSize - len(session.pendingTags)
	if needed <= 0 {
		return nil, nil
	}
	newTags := make([][8]byte, 0, needed)
	for i := 0; i < needed; i++ {
		tag, err := session.RecvTagRatchet.GenerateNextTag()
		if err != nil {
			return newTags, oops.Wrapf(err, "failed to generate session tag at index %d", i)
		}
		newTags = append(newTags, tag)
	}
	return newTags, nil
}

// installGeneratedTagsLocked writes pre-derived tags into sm.tagIndex and
// session.pendingTags.  Tags that collide with a different session are logged
// and skipped.  Must be called with both sm.mu (write) and session.mu held.
func (sm *SessionManager) installGeneratedTagsLocked(session *Session, newTags [][8]byte) {
	for _, tag := range newTags {
		if len(session.pendingTags) >= tagWindowSize {
			// Another goroutine may have already replenished; stop early.
			break
		}
		if existing, ok := sm.tagIndex[tag]; ok && existing != session {
			log.WithFields(map[string]interface{}{
				"at":  "installGeneratedTagsLocked",
				"tag": fmt.Sprintf("%x", tag),
			}).Warn("Tag collision detected, skipping duplicate tag")
			continue
		}
		session.pendingTags = append(session.pendingTags, tag)
		sm.tagIndex[tag] = session
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
		if existing, ok := sm.tagIndex[tag]; ok && existing != session {
			log.WithFields(map[string]interface{}{
				"at":  "generateTagWindow",
				"tag": fmt.Sprintf("%x", tag),
			}).Warn("Tag collision detected, skipping duplicate tag")
			continue
		}
		session.pendingTags = append(session.pendingTags, tag)
		sm.tagIndex[tag] = session
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
		if now.Sub(session.LastUsed) > sm.sessionTimeout {
			delete(sm.sessions, hash)
			for _, tag := range session.pendingTags {
				delete(sm.tagIndex, tag)
			}
			if session.nsrTag != nil {
				delete(sm.nsrTagIndex, *session.nsrTag)
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

	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Clear all session state
	for k := range sm.sessions {
		delete(sm.sessions, k)
	}
	for k := range sm.tagIndex {
		delete(sm.tagIndex, k)
	}
	for k := range sm.nsrTagIndex {
		delete(sm.nsrTagIndex, k)
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
