package ratchet

import (
	"fmt"

	"github.com/go-i2p/crypto/chacha20poly1305"
	"github.com/go-i2p/crypto/kdf"
	"github.com/go-i2p/crypto/rand"
	"github.com/go-i2p/crypto/ratchet"
	"github.com/go-i2p/crypto/types"
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

	hkdfInfoInitiator = "ECIES-Ratchet-Initiator"
	hkdfInfoResponder = "ECIES-Ratchet-Responder"

	// tagWindowSize is the number of pre-generated tags per session.
	tagWindowSize = 10
)

// deriveDirectionalKeys derives distinct send and receive keys from a base key
// using HKDF with role-specific info strings. Returns an error if key derivation
// fails instead of silently falling back to the base key.
func deriveDirectionalKeys(baseKey [32]byte, isInitiator bool) (sendKey, recvKey [32]byte, err error) {
	kd := kdf.NewKeyDerivation(baseKey)

	initiatorKey, err := kd.DeriveWithInfo(hkdfInfoInitiator)
	if err != nil {
		return [32]byte{}, [32]byte{}, oops.Wrapf(err, "failed to derive initiator directional key")
	}

	responderKey, err := kd.DeriveWithInfo(hkdfInfoResponder)
	if err != nil {
		return [32]byte{}, [32]byte{}, oops.Wrapf(err, "failed to derive responder directional key")
	}

	if isInitiator {
		return initiatorKey, responderKey, nil
	}
	return responderKey, initiatorKey, nil
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
// Format: [nonce(12)] + [ciphertext(N)] + [tag(16)]
func parseExistingSessionMessage(msg []byte) (nonce, ciphertext []byte, tag [16]byte, err error) {
	if len(msg) < 12+16 {
		return nil, nil, [16]byte{}, oops.Errorf("existing session message too short")
	}

	nonce = msg[0:12]
	ctWithTag := msg[12:]

	if len(ctWithTag) < 16 {
		return nil, nil, [16]byte{}, oops.Errorf("ciphertext too short for auth tag")
	}

	ciphertext = ctWithTag[:len(ctWithTag)-16]
	copy(tag[:], ctWithTag[len(ctWithTag)-16:])

	return nonce, ciphertext, tag, nil
}

// encryptWithSessionKey encrypts plaintext using ChaCha20-Poly1305 with session tag as AAD.
func encryptWithSessionKey(messageKey [32]byte, plaintext []byte, sessionTag [8]byte) (ciphertext []byte, tag [16]byte, nonce []byte, err error) {
	aead, err := chacha20poly1305.NewAEAD(messageKey)
	if err != nil {
		return nil, [16]byte{}, nil, oops.Wrapf(err, "failed to create AEAD")
	}

	nonce = make([]byte, chacha20poly1305.NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, [16]byte{}, nil, oops.Wrapf(err, "failed to generate nonce")
	}

	ciphertext, tag, err = aead.Encrypt(plaintext, sessionTag[:], nonce)
	if err != nil {
		return nil, [16]byte{}, nil, oops.Wrapf(err, "failed to encrypt existing session message")
	}

	return ciphertext, tag, nonce, nil
}

// decryptWithSessionTag decrypts ciphertext using ChaCha20-Poly1305 with session tag as AAD.
func decryptWithSessionTag(messageKey [32]byte, ciphertext []byte, tag [16]byte, sessionTag [8]byte, nonce []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewAEAD(messageKey)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to create AEAD")
	}

	plaintext, err := aead.Decrypt(ciphertext, tag[:], sessionTag[:], nonce)
	if err != nil {
		return nil, oops.Wrapf(err, "decryption failed (authentication error)")
	}

	return plaintext, nil
}

// buildExistingSessionMessage constructs the wire format for an Existing Session message.
// Format: [sessionTag(8)] + [nonce(12)] + [ciphertext(N)] + [tag(16)]
func buildExistingSessionMessage(sessionTag [8]byte, nonce, ciphertext []byte, tag [16]byte) []byte {
	msg := make([]byte, 8+12+len(ciphertext)+16)
	copy(msg[0:8], sessionTag[:])
	copy(msg[8:20], nonce)
	copy(msg[20:20+len(ciphertext)], ciphertext)
	copy(msg[20+len(ciphertext):], tag[:])
	return msg
}

// advanceRatchets advances the symmetric and tag ratchets to generate message key and session tag.
func advanceRatchets(session *Session) (messageKey [32]byte, sessionTag [8]byte, err error) {
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

// performDHRatchetStep performs a Diffie-Hellman ratchet step for forward secrecy.
func performDHRatchetStep(session *Session) error {
	newPubKey, err := session.DHRatchet.GenerateNewKeyPair()
	if err != nil {
		return oops.Wrapf(err, "failed to generate new ephemeral key pair")
	}

	sendingChainKey, _, err := session.DHRatchet.PerformRatchet()
	if err != nil {
		return oops.Wrapf(err, "failed to perform DH ratchet")
	}

	session.SymmetricRatchet = ratchet.NewSymmetricRatchet(sendingChainKey)

	tagKeyInput := types.SHA256(append(sendingChainKey[:], []byte("TagRatchetKey")...))
	session.TagRatchet = ratchet.NewTagRatchet(tagKeyInput)

	session.newEphemeralPub = &newPubKey

	log.WithFields(map[string]interface{}{
		"at":              "performDHRatchetStep",
		"message_counter": session.MessageCounter,
		"new_pub_key":     fmt.Sprintf("%x", newPubKey[:8]),
	}).Debug("DH ratchet rotation completed")

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
