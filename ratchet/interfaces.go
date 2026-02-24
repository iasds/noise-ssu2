package ratchet

import (
	"context"
)

// GarlicEncryptor provides ECIES-X25519-AEAD-Ratchet encryption for garlic messages.
// Implementations handle session creation, key exchange, and ratchet advancement.
//
// All parameters use primitive types ([32]byte, []byte) rather than I2P-specific
// types. Callers in go-i2p are responsible for converting common.Hash, SessionKey,
// and other I2P types to raw bytes before calling these methods.
type GarlicEncryptor interface {
	// EncryptGarlicMessage encrypts plaintext for a destination.
	// destinationHash: 32-byte hash identifying the session.
	// destinationPubKey: X25519 public key of the recipient.
	// plaintext: serialized garlic message bytes (from GarlicBuilder.BuildAndSerialize).
	// Returns encrypted bytes (New Session or Existing Session format).
	EncryptGarlicMessage(destinationHash, destinationPubKey [32]byte, plaintext []byte) ([]byte, error)
}

// GarlicDecryptor provides ECIES-X25519-AEAD-Ratchet decryption for garlic messages.
// Implementations handle session tag lookup, key derivation, and AEAD decryption.
type GarlicDecryptor interface {
	// DecryptGarlicMessage decrypts an encrypted garlic message.
	// Returns plaintext, session tag (zero value for New Session messages), and error.
	DecryptGarlicMessage(encrypted []byte) (plaintext []byte, sessionTag [8]byte, err error)
}

// GarlicSessionManager combines encrypt + decrypt + lifecycle management for
// ECIES-X25519-AEAD-Ratchet garlic sessions. This is the primary interface
// consumed by go-i2p's message processor and I2CP message router.
type GarlicSessionManager interface {
	GarlicEncryptor
	GarlicDecryptor

	// ProcessIncomingDHRatchet updates a session's receiving ratchet state
	// when a DH ratchet key is received from a peer.
	// sessionTag: the tag that identified the session.
	// newRemotePubKey: the peer's new ephemeral public key.
	ProcessIncomingDHRatchet(sessionTag [8]byte, newRemotePubKey [32]byte) error

	// GetSessionCount returns the number of active sessions.
	GetSessionCount() int

	// CleanupExpiredSessions removes sessions past the timeout. Returns count removed.
	CleanupExpiredSessions() int

	// StartCleanupLoop starts periodic cleanup. Stops when ctx is cancelled.
	StartCleanupLoop(ctx context.Context)

	// Close stops the cleanup loop, removes all sessions, and zeroes key material.
	Close() error
}

// BuildRecordEncryptor encrypts tunnel build request records using ECIES-X25519.
// It accepts pre-extracted raw key material; go-i2p is responsible for extracting
// keys from RouterInfo before calling these methods.
type BuildRecordEncryptor interface {
	// EncryptBuildRequest encrypts a serialized build request record (222 bytes).
	// cleartext: 222-byte serialized BuildRequestRecord.
	// recipientPubKey: recipient's 32-byte X25519 public key (extracted from RouterInfo by caller).
	// recipientIdentityHash: recipient's 32-byte identity hash (extracted from RouterInfo by caller).
	// Returns 528-byte encrypted record.
	EncryptBuildRequest(cleartext []byte, recipientPubKey, recipientIdentityHash [32]byte) ([528]byte, error)

	// DecryptBuildRequest decrypts a 528-byte encrypted build request record.
	// privateKey: our 32-byte X25519 private key.
	// Returns 222-byte cleartext.
	DecryptBuildRequest(encrypted [528]byte, privateKey []byte) ([]byte, error)

	// VerifyIdentityHash checks if an encrypted record is intended for us.
	// encrypted: 528-byte record. ourIdentityHash: our 32-byte identity hash.
	VerifyIdentityHash(encrypted [528]byte, ourIdentityHash [32]byte) bool
}

// BuildReplyEncryptor encrypts/decrypts tunnel build reply records.
// Implementations use ChaCha20-Poly1305 or AES-256-CBC depending on record type.
type BuildReplyEncryptor interface {
	// EncryptReplyRecord encrypts a reply record.
	// cleartext: serialized response record bytes.
	// replyKey: 32-byte session key.
	// replyIV: 16-byte initialization vector.
	// Returns encrypted bytes (544 for ChaCha20-Poly1305).
	EncryptReplyRecord(cleartext []byte, replyKey [32]byte, replyIV [16]byte) ([]byte, error)

	// DecryptReplyRecord decrypts an encrypted reply record.
	// encrypted: ciphertext bytes.
	// replyKey: 32-byte session key.
	// replyIV: 16-byte initialization vector.
	// Returns plaintext bytes.
	DecryptReplyRecord(encrypted []byte, replyKey [32]byte, replyIV [16]byte) ([]byte, error)
}

// TagResolver provides O(1) session tag lookup for incoming messages.
// This capability is embedded in GarlicSessionManager but can be used
// independently for tag-only resolution without full session management.
type TagResolver interface {
	// FindSessionByTag checks if a session tag matches a known session.
	// Returns true if the tag was found (and consumed), false otherwise.
	FindSessionByTag(tag [8]byte) bool
}
