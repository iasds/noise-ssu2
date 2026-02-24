package ratchet

import (
	"fmt"

	"github.com/go-i2p/crypto/chacha20poly1305"
	"github.com/go-i2p/crypto/kdf"
	"github.com/go-i2p/crypto/ratchet"
	"github.com/samber/oops"
)

// sessionKeys holds the cryptographic keys derived from ECIES key exchange.
type sessionKeys struct {
	rootKey [32]byte
	symKey  [32]byte
	tagKey  [32]byte
}

const (
	// DHRatchetInterval is the number of messages between DH ratchet rotations.
	DHRatchetInterval = 50

	// MaxConsecutiveDHFailures is the maximum consecutive DH ratchet failures
	// before the session is considered degraded and should be reset.
	MaxConsecutiveDHFailures = 3

	// hkdfInfoDHRatchetStep is the HKDF info string for the DH initialization KDF.
	// Used to derive directional chain keys from a root key.
	// Spec ref: ratchet.md §"DH INITIALIZATION KDF" — HKDF(rootKey, k, "KDFDHRatchetStep", 64).
	hkdfInfoDHRatchetStep = "KDFDHRatchetStep"

	// hkdfInfoTagAndKeyGenKeys is the HKDF info string for deriving session tag
	// and symmetric key chain keys from a chain key after DH ratchet.
	// Spec ref: ratchet.md §"DH INITIALIZATION KDF" — HKDF(ck, ZEROLEN, "TagAndKeyGenKeys", 64).
	hkdfInfoTagAndKeyGenKeys = "TagAndKeyGenKeys"

	// tagWindowSize is the number of pre-generated tags per session.
	tagWindowSize = 10

	// MaxMessageNumber is the maximum AEAD message number per the spec.
	// When reached, the session must be ratcheted. Spec ref: ratchet.md
	// §"AEAD (ChaChaPoly)" — "Maximum value is 65535."
	MaxMessageNumber = 65535
)

// deriveDirectionalKeys derives distinct send and receive keys from a base key
// using HKDF with the spec-compliant "KDFDHRatchetStep" info string.
// Produces 64 bytes split into two 32-byte directional keys (a→b and b→a).
// The initiator sends on keys[0] and receives on keys[1]; the responder
// reverses this to maintain symmetric key agreement.
// Returns an error if key derivation fails.
// Spec ref: ratchet.md §"DH INITIALIZATION KDF".
func deriveDirectionalKeys(baseKey [32]byte, isInitiator bool) (sendKey, recvKey [32]byte, err error) {
	kd := kdf.NewKeyDerivation(baseKey)

	keys, err := kd.DeriveKeys([]byte(hkdfInfoDHRatchetStep), 2)
	if err != nil {
		return [32]byte{}, [32]byte{}, oops.Wrapf(err, "failed to derive directional keys via KDFDHRatchetStep")
	}

	if isInitiator {
		return keys[0], keys[1], nil
	}
	return keys[1], keys[0], nil
}

// deriveSessionKeysFromSecret derives root, symmetric, and tag keys from a shared secret.
func deriveSessionKeysFromSecret(sharedSecret []byte) (*sessionKeys, error) {
	var arr [32]byte
	copy(arr[:], sharedSecret)
	kd := kdf.NewKeyDerivation(arr)
	rootKey, symKey, tagKey, err := kd.DeriveSessionKeys()
	if err != nil {
		return nil, oops.Wrapf(err, "failed to derive session keys")
	}
	return &sessionKeys{rootKey: rootKey, symKey: symKey, tagKey: tagKey}, nil
}

// parseExistingSessionMessage parses an Existing Session message (without session tag prefix).
// Format: [ciphertext(N)] + [tag(16)]
// The nonce is derived from the message counter, not transmitted on the wire.
func parseExistingSessionMessage(msg []byte) (ciphertext []byte, tag [16]byte, err error) {
	if len(msg) < 16 {
		return nil, [16]byte{}, oops.Errorf("existing session message too short: %d bytes", len(msg))
	}

	ciphertext = msg[:len(msg)-16]
	copy(tag[:], msg[len(msg)-16:])

	return ciphertext, tag, nil
}

// encryptWithSessionKey encrypts plaintext using ChaCha20-Poly1305 with session tag as AAD.
// The nonce is counter-based: [0,0,0,0 || LE64(messageNumber)] per the spec.
func encryptWithSessionKey(messageKey [32]byte, plaintext []byte, sessionTag [8]byte, messageNumber uint32) (ciphertext []byte, tag [16]byte, err error) {
	aead, err := chacha20poly1305.NewAEAD(messageKey)
	if err != nil {
		return nil, [16]byte{}, oops.Wrapf(err, "failed to create AEAD")
	}

	nonce := noiseNonce(uint64(messageNumber))

	ciphertext, tag, err = aead.Encrypt(plaintext, sessionTag[:], nonce)
	if err != nil {
		return nil, [16]byte{}, oops.Wrapf(err, "failed to encrypt existing session message")
	}

	return ciphertext, tag, nil
}

// decryptWithSessionTag decrypts ciphertext using ChaCha20-Poly1305 with session tag as AAD.
// The nonce is derived from the message number: [0,0,0,0 || LE64(messageNumber)].
func decryptWithSessionTag(messageKey [32]byte, ciphertext []byte, tag [16]byte, sessionTag [8]byte, messageNumber uint32) ([]byte, error) {
	aead, err := chacha20poly1305.NewAEAD(messageKey)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to create AEAD")
	}

	nonce := noiseNonce(uint64(messageNumber))

	plaintext, err := aead.Decrypt(ciphertext, tag[:], sessionTag[:], nonce)
	if err != nil {
		return nil, oops.Wrapf(err, "decryption failed (authentication error)")
	}

	return plaintext, nil
}

// buildExistingSessionMessage constructs the wire format for an Existing Session message.
// Format: [sessionTag(8)] + [ciphertext(N)] + [authTag(16)]
// The nonce is not transmitted; both sides derive it from the message counter.
func buildExistingSessionMessage(sessionTag [8]byte, ciphertext []byte, tag [16]byte) []byte {
	msg := make([]byte, 8+len(ciphertext)+16)
	copy(msg[0:8], sessionTag[:])
	copy(msg[8:8+len(ciphertext)], ciphertext)
	copy(msg[8+len(ciphertext):], tag[:])
	return msg
}

// advanceRatchets advances the symmetric and tag ratchets to generate message key and session tag.
// Returns an error if the message counter exceeds MaxMessageNumber (65535).
func advanceRatchets(session *Session) (messageKey [32]byte, sessionTag [8]byte, err error) {
	if session.MessageCounter > MaxMessageNumber {
		return [32]byte{}, [8]byte{}, oops.Errorf(
			"message number %d exceeds maximum %d, session must be ratcheted",
			session.MessageCounter, MaxMessageNumber)
	}

	if err := attemptDHRatchetRotation(session); err != nil {
		return [32]byte{}, [8]byte{}, err
	}

	messageKey, err = deriveMessageKey(session)
	if err != nil {
		return [32]byte{}, [8]byte{}, err
	}

	sessionTag, err = generateAndTrackSessionTag(session)
	if err != nil {
		return [32]byte{}, [8]byte{}, err
	}

	return messageKey, sessionTag, nil
}

// attemptDHRatchetRotation checks whether a DH ratchet step is due.
func attemptDHRatchetRotation(session *Session) error {
	session.dhRatchetCounter++
	if session.dhRatchetCounter < DHRatchetInterval {
		return nil
	}

	if err := performDHRatchetStep(session); err != nil {
		session.consecutiveDHFailures++
		if session.consecutiveDHFailures >= MaxConsecutiveDHFailures {
			return oops.Wrapf(err,
				"DH ratchet failed %d consecutive times (max %d), forward secrecy compromised",
				session.consecutiveDHFailures, MaxConsecutiveDHFailures)
		}
		log.WithError(err).WithField("consecutive_failures", session.consecutiveDHFailures).
			Warn("DH ratchet rotation failed, continuing with symmetric ratchet")
	} else {
		session.dhRatchetCounter = 0
		session.consecutiveDHFailures = 0
	}
	return nil
}

// deriveMessageKey advances the symmetric ratchet to produce the next message key.
func deriveMessageKey(session *Session) ([32]byte, error) {
	messageKey, _, err := session.SymmetricRatchet.DeriveMessageKeyAndAdvance(session.MessageCounter)
	if err != nil {
		return [32]byte{}, oops.Wrapf(err, "failed to advance symmetric ratchet")
	}
	return messageKey, nil
}

// generateAndTrackSessionTag generates the next session tag from the tag ratchet.
func generateAndTrackSessionTag(session *Session) ([8]byte, error) {
	sessionTag, err := session.TagRatchet.GenerateNextTag()
	if err != nil {
		return [8]byte{}, oops.Wrapf(err, "failed to generate session tag")
	}
	session.pendingTags = append(session.pendingTags, sessionTag)
	return sessionTag, nil
}

// deriveTagAndSymKeysFromChainKey derives session tag and symmetric key chain keys
// from a chain key using HKDF with the spec-compliant "TagAndKeyGenKeys" info string.
// Returns (sessTag_ck, symmKey_ck) per the DH INITIALIZATION KDF:
//
//	keydata = HKDF(ck, ZEROLEN, "TagAndKeyGenKeys", 64)
//	sessTag_ck = keydata[0:31], symmKey_ck = keydata[32:63]
//
// Spec ref: ratchet.md §"DH INITIALIZATION KDF".
func deriveTagAndSymKeysFromChainKey(chainKey [32]byte) (tagKey, symKey [32]byte, err error) {
	kd := kdf.NewKeyDerivation(chainKey)
	keys, err := kd.DeriveKeys([]byte(hkdfInfoTagAndKeyGenKeys), 2)
	if err != nil {
		return [32]byte{}, [32]byte{}, oops.Wrapf(err, "failed to derive tag and symmetric keys via TagAndKeyGenKeys")
	}
	return keys[0], keys[1], nil
}

// performDHRatchetStep performs a Diffie-Hellman ratchet step for forward secrecy.
// After obtaining the new chain key from the DH ratchet, it derives the session tag
// and symmetric key chain keys using HKDF(ck, ZEROLEN, "TagAndKeyGenKeys", 64)
// per the spec's DH INITIALIZATION KDF.
// On success, a NextKey block is queued for inclusion in the next outgoing message.
func performDHRatchetStep(session *Session) error {
	newPubKey, err := session.DHRatchet.GenerateNewKeyPair()
	if err != nil {
		return oops.Wrapf(err, "failed to generate new ephemeral key pair")
	}

	sendingChainKey, _, err := session.DHRatchet.PerformRatchet()
	if err != nil {
		return oops.Wrapf(err, "failed to perform DH ratchet")
	}

	tagKey, symKey, err := deriveTagAndSymKeysFromChainKey(sendingChainKey)
	if err != nil {
		return oops.Wrapf(err, "failed to derive keys after DH ratchet step")
	}

	session.SymmetricRatchet = ratchet.NewSymmetricRatchet(symKey)
	session.TagRatchet = ratchet.NewTagRatchet(tagKey)

	session.newEphemeralPub = &newPubKey

	// Queue a NextKey block for the next outgoing message.
	// Even-numbered tag sets: sender sends new key, requests reverse.
	// Odd-numbered tag sets: sender reuses key, requests reverse.
	// For the first rotation (sendKeyID == 0): always send the key and request reverse.
	requestReverse := true
	nextKeyBlock := NewNextKeyBlock(session.sendKeyID, &newPubKey, false, requestReverse)
	session.pendingNextKeys = append(session.pendingNextKeys, nextKeyBlock)
	session.awaitingReverseKey = true

	log.WithFields(map[string]interface{}{
		"at":              "performDHRatchetStep",
		"message_counter": session.MessageCounter,
		"send_key_id":     session.sendKeyID,
		"new_pub_key":     fmt.Sprintf("%x", newPubKey[:8]),
	}).Debug("DH ratchet rotation completed, NextKey block queued")

	return nil
}

// deriveDecryptionKey derives the message key from the session's receiving ratchet state.
func deriveDecryptionKey(session *Session) ([32]byte, error) {
	recvRatchet := session.RecvSymmetricRatchet
	if recvRatchet == nil {
		recvRatchet = session.SymmetricRatchet
	}
	messageKey, _, err := recvRatchet.DeriveMessageKeyAndAdvance(session.recvCounter)
	if err != nil {
		return [32]byte{}, oops.Wrapf(err, "failed to derive message key")
	}
	return messageKey, nil
}
