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

// Compile-time interface check.
var _ GarlicSessionManager = (*SessionManager)(nil)

const (
	// MaxGarlicSessions is the upper bound on active garlic sessions.
	MaxGarlicSessions = 5000
)

// SessionManager manages ECIES-X25519-AEAD-Ratchet sessions for garlic encryption.
// It maintains session state for ongoing encrypted communication with remote
// destinations, using [32]byte keys throughout (no I2P-specific types).
//
// Session lifecycle:
//  1. New Session: First message uses ephemeral-static DH (ECIES)
//  2. Existing Session: Subsequent messages use ratchet for forward secrecy
//  3. Session Expiry: Sessions expire after inactivity timeout
type SessionManager struct {
	mu             sync.RWMutex
	sessions       map[[32]byte]*Session
	tagIndex       map[[8]byte]*Session
	ourPrivateKey  [32]byte
	ourPublicKey   [32]byte
	sessionTimeout time.Duration
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

	return &SessionManager{
		sessions:       make(map[[32]byte]*Session),
		tagIndex:       make(map[[8]byte]*Session),
		ourPrivateKey:  privateKey,
		ourPublicKey:   publicKey,
		sessionTimeout: 10 * time.Minute,
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
func (sm *SessionManager) EncryptGarlicMessage(
	destinationHash, destinationPubKey [32]byte,
	plaintextGarlic []byte,
) ([]byte, error) {
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
func (sm *SessionManager) encryptNewSession(
	destinationHash, destinationPubKey [32]byte,
	plaintextGarlic []byte,
) ([]byte, error) {
	msg, keys, err := writeNoiseIKMessage1(
		sm.ourPrivateKey, sm.ourPublicKey, destinationPubKey, plaintextGarlic,
	)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to construct Noise IK New Session message")
	}

	if err := sm.storeNewSessionState(destinationHash, destinationPubKey, keys); err != nil {
		return nil, err
	}

	return msg, nil
}

// storeNewSessionState initializes and stores ratchet state for future messages.
func (sm *SessionManager) storeNewSessionState(
	destinationHash, destinationPubKey [32]byte,
	keys *sessionKeys,
) error {
	session, err := createSession(destinationPubKey, keys, sm.ourPrivateKey, true)
	if err != nil {
		return oops.Wrapf(err, "failed to create outbound session")
	}

	sm.mu.Lock()
	defer sm.mu.Unlock()

	if len(sm.sessions) >= MaxGarlicSessions {
		sm.evictLRUSessionLocked()
	}

	sm.sessions[destinationHash] = session

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
// Handles both New Session and Existing Session message types.
func (sm *SessionManager) DecryptGarlicMessage(encryptedGarlic []byte) ([]byte, [8]byte, error) {
	if len(encryptedGarlic) < 8 {
		return nil, [8]byte{}, oops.Errorf("encrypted garlic message too short: %d bytes", len(encryptedGarlic))
	}

	var sessionTag [8]byte
	copy(sessionTag[:], encryptedGarlic[0:8])

	sm.mu.Lock()
	session := sm.findSessionByTag(sessionTag)
	sm.mu.Unlock()

	if session != nil {
		return sm.decryptExistingSession(session, encryptedGarlic[8:], sessionTag)
	}

	plaintext, err := sm.decryptNewSession(encryptedGarlic)
	if err != nil {
		return nil, [8]byte{}, oops.Wrapf(err, "failed to decrypt garlic message")
	}

	return plaintext, [8]byte{}, nil
}

// decryptNewSession decrypts a New Session message using the Noise IK handshake.
func (sm *SessionManager) decryptNewSession(msg []byte) ([]byte, error) {
	plaintext, initiatorStaticPub, keys, err := readNoiseIKMessage1(
		sm.ourPrivateKey, sm.ourPublicKey, msg,
	)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to process Noise IK New Session message")
	}

	if err := sm.initializeInboundRatchetState(initiatorStaticPub, keys); err != nil {
		return nil, err
	}

	return plaintext, nil
}

// initializeInboundRatchetState creates and stores ratchet state for incoming sessions.
func (sm *SessionManager) initializeInboundRatchetState(remotePubKey [32]byte, keys *sessionKeys) error {
	session, err := createSession(remotePubKey, keys, sm.ourPrivateKey, false)
	if err != nil {
		return oops.Wrapf(err, "failed to create inbound session")
	}

	sessionHash := types.SHA256(remotePubKey[:])

	sm.mu.Lock()
	defer sm.mu.Unlock()

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

// decryptExistingSession decrypts an Existing Session message using ratchet state.
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

	messageKey, err := deriveDecryptionKey(session)
	if err != nil {
		return nil, [8]byte{}, err
	}

	plaintext, err := decryptWithSessionTag(messageKey, ciphertext, tag, sessionTag, session.recvCounter)
	if err != nil {
		return nil, [8]byte{}, err
	}

	session.LastUsed = time.Now()
	session.recvCounter++

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

	session.RecvSymmetricRatchet = ratchet.NewSymmetricRatchet(receivingChainKey)

	tagKeyInput := types.SHA256(append(receivingChainKey[:], []byte("TagRatchetKey")...))
	session.RecvTagRatchet = ratchet.NewTagRatchet(tagKeyInput)

	session.RemotePublicKey = newRemotePubKey

	log.WithFields(map[string]interface{}{
		"at":              "ProcessIncomingDHRatchet",
		"message_counter": session.MessageCounter,
	}).Debug("Processed incoming DH ratchet from peer")

	return nil
}

// findSessionByTag searches for a session that expects the given tag.
// Must be called with sm.mu held for writing.
func (sm *SessionManager) findSessionByTag(tag [8]byte) *Session {
	session, exists := sm.tagIndex[tag]
	if !exists {
		return nil
	}

	session.mu.Lock()
	defer session.mu.Unlock()

	if !sm.isSessionValid(session) {
		sm.cleanupExpiredTag(tag)
		return nil
	}

	sm.consumeTag(tag, session)
	sm.replenishTagWindowIfNeeded(session)

	return session
}

func (sm *SessionManager) isSessionValid(session *Session) bool {
	return time.Since(session.LastUsed) <= sm.sessionTimeout
}

func (sm *SessionManager) cleanupExpiredTag(tag [8]byte) {
	delete(sm.tagIndex, tag)
}

func (sm *SessionManager) consumeTag(tag [8]byte, session *Session) {
	delete(sm.tagIndex, tag)
	sm.removeTagFromPendingList(tag, session)
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

func (sm *SessionManager) replenishTagWindowIfNeeded(session *Session) {
	if len(session.pendingTags) < 5 {
		if err := sm.generateTagWindow(session); err != nil {
			log.WithFields(map[string]interface{}{
				"at":              "replenishTagWindowIfNeeded",
				"remote_pubkey":   fmt.Sprintf("%x", session.RemotePublicKey[:8]),
				"pending_tags":    len(session.pendingTags),
				"message_counter": session.MessageCounter,
				"error":           err.Error(),
			}).Warn("Failed to replenish session tag window")
		}
	}
}

// generateTagWindow pre-generates a window of session tags for a session.
// Must be called with sm.mu held for writing.
func (sm *SessionManager) generateTagWindow(session *Session) error {
	tagRatchet := session.RecvTagRatchet
	if tagRatchet == nil {
		tagRatchet = session.TagRatchet
	}
	for len(session.pendingTags) < tagWindowSize {
		tag, err := tagRatchet.GenerateNextTag()
		if err != nil {
			return oops.Wrapf(err, "failed to generate session tag")
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

// StartCleanupLoop starts periodic cleanup of expired sessions.
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
			}
		}
	}()

	log.WithFields(map[string]interface{}{
		"at":       "SessionManager.StartCleanupLoop",
		"interval": "2m",
	}).Debug("Started garlic session cleanup loop")
}
