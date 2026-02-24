// Package ratchet provides ECIES-X25519-AEAD-Ratchet cryptographic primitives.
//
// This file implements tunnel build record encryption/decryption using
// ChaCha20-Poly1305 (I2P 0.9.44+). All function signatures use primitive
// types ([32]byte, [16]byte, []byte) rather than I2P-specific types.
// The go-i2p consumer converts session_key.SessionKey and
// BuildResponseRecord/BuildRequestRecord before calling these APIs.
package ratchet

import (
	"github.com/go-i2p/crypto/chacha20poly1305"
	"github.com/go-i2p/crypto/types"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

var log = logger.GetGoI2PLogger()

// Compile-time interface checks.
var (
	_ BuildReplyEncryptor = (*BuildRecordCrypto)(nil)
)

// BuildRecordCrypto provides encryption/decryption for tunnel build records.
// Uses modern ChaCha20-Poly1305 AEAD encryption (I2P 0.9.44+).
type BuildRecordCrypto struct{}

// NewBuildRecordCrypto creates a new build record crypto handler.
func NewBuildRecordCrypto() *BuildRecordCrypto {
	return &BuildRecordCrypto{}
}

// EncryptReplyRecord encrypts a serialized 528-byte response record using the
// reply key and IV.
//
// Uses ChaCha20-Poly1305 AEAD encryption (I2P 0.9.44+):
//
// Output: 528 bytes encrypted data + 16 bytes authentication tag = 544 bytes
//
// The caller (go-i2p) serializes BuildResponseRecord to cleartext before calling.
func (c *BuildRecordCrypto) EncryptReplyRecord(
	cleartext []byte,
	replyKey [32]byte,
	replyIV [16]byte,
) ([]byte, error) {
	if len(cleartext) != 528 {
		return nil, oops.Errorf("invalid cleartext size: expected 528 bytes, got %d", len(cleartext))
	}

	encrypted, err := c.encryptChaCha20Poly1305(cleartext, replyKey, replyIV)
	if err != nil {
		return nil, oops.Errorf("ChaCha20-Poly1305 encryption failed: %w", err)
	}

	log.WithFields(logger.Fields{
		"encryption": "ChaCha20-Poly1305",
		"size":       len(encrypted),
	}).Debug("Encrypted build response record")

	return encrypted, nil
}

// DecryptReplyRecord decrypts an encrypted reply record.
//
// Uses ChaCha20-Poly1305 AEAD decryption (I2P 0.9.44+).
// Expects 544 bytes input (528 ciphertext + 16 auth tag).
// Returns 528 bytes plaintext; the caller (go-i2p) parses and verifies the hash.
func (c *BuildRecordCrypto) DecryptReplyRecord(
	encryptedData []byte,
	replyKey [32]byte,
	replyIV [16]byte,
) ([]byte, error) {
	if len(encryptedData) != 544 {
		return nil, oops.Errorf("invalid encrypted data size: expected 544 bytes, got %d", len(encryptedData))
	}

	cleartext, err := c.decryptChaCha20Poly1305(encryptedData, replyKey, replyIV)
	if err != nil {
		return nil, oops.Errorf("ChaCha20-Poly1305 decryption failed: %w", err)
	}

	if len(cleartext) != 528 {
		return nil, oops.Errorf("invalid decrypted data size: expected 528 bytes, got %d", len(cleartext))
	}

	log.Debug("Decrypted build response record")
	return cleartext, nil
}

// SerializeResponseRecord converts response record fields to wire format (528 bytes).
//
// Format:
//
// bytes 0-31:   SHA-256 hash of bytes 32-527
// bytes 32-526: Random data (495 bytes)
// byte 527:     Reply status code
func SerializeResponseRecord(hash [32]byte, randomData [495]byte, reply byte) []byte {
	buf := make([]byte, 528)
	copy(buf[0:32], hash[:])
	copy(buf[32:527], randomData[:])
	buf[527] = reply
	return buf
}

// VerifyResponseRecordHash verifies the SHA-256 hash in a serialized response record.
// The hash covers bytes 32-527 (randomData + reply byte).
func VerifyResponseRecordHash(hash [32]byte, randomData [495]byte, reply byte) error {
	data := make([]byte, 496)
	copy(data[0:495], randomData[:])
	data[495] = reply

	expectedHash := types.SHA256(data)

	if hash != expectedHash {
		return oops.Errorf("hash verification failed")
	}

	return nil
}

// CreateBuildResponseRecordRaw creates a valid response record with proper hash.
//
// Parameters:
//   - reply: Status code (0=accept, non-zero=reject reason)
//   - randomData: 495 bytes of random data (should be cryptographically random)
//
// Returns the SHA-256 hash that should be placed in the first 32 bytes of the record.
func CreateBuildResponseRecordRaw(reply byte, randomData [495]byte) [32]byte {
	data := make([]byte, 496)
	copy(data[0:495], randomData[:])
	data[495] = reply
	return types.SHA256(data)
}

// encryptChaCha20Poly1305 encrypts data using ChaCha20-Poly1305 AEAD.
func (c *BuildRecordCrypto) encryptChaCha20Poly1305(
	plaintext []byte,
	key [32]byte,
	iv [16]byte,
) ([]byte, error) {
	if len(plaintext) != 528 {
		return nil, oops.Errorf("plaintext must be 528 bytes, got %d", len(plaintext))
	}

	aead, err := chacha20poly1305.NewAEAD(key)
	if err != nil {
		return nil, oops.Errorf("failed to create ChaCha20-Poly1305 cipher: %w", err)
	}

	// Use the first 12 bytes of the 16-byte IV as the ChaCha20-Poly1305 nonce.
	// The I2P ECIES build-record spec (Proposal 152, §"ChaCha20/Poly1305")
	// explicitly defines the nonce as "the first 12 bytes of the reply IV";
	// the remaining 4 bytes are unused padding introduced by the AES-CBC
	// legacy field size and are not part of the nonce uniqueness domain.
	// This matches the reference Java implementation (RouterContext.elGamalAESEngine).
	nonce := iv[:12]

	ct, tag, err := aead.Encrypt(plaintext, nil, nonce)
	if err != nil {
		return nil, oops.Errorf("failed to encrypt: %w", err)
	}

	// Concatenate ciphertext + tag (528 + 16 = 544 bytes)
	result := make([]byte, len(ct)+len(tag))
	copy(result, ct)
	copy(result[len(ct):], tag[:])

	if len(result) != 544 {
		return nil, oops.Errorf("unexpected ciphertext length: %d", len(result))
	}

	return result, nil
}

// decryptChaCha20Poly1305 decrypts data using ChaCha20-Poly1305 AEAD.
func (c *BuildRecordCrypto) decryptChaCha20Poly1305(
	ciphertext []byte,
	key [32]byte,
	iv [16]byte,
) ([]byte, error) {
	if len(ciphertext) != 544 {
		return nil, oops.Errorf("ciphertext must be 544 bytes (528 + 16 tag), got %d", len(ciphertext))
	}

	aead, err := chacha20poly1305.NewAEAD(key)
	if err != nil {
		return nil, oops.Errorf("failed to create ChaCha20-Poly1305 cipher: %w", err)
	}

	// See encryptChaCha20Poly1305 for nonce derivation rationale.
	nonce := iv[:12]

	// Split into ciphertext (first 528 bytes) and tag (last 16 bytes)
	ct := ciphertext[:528]
	tag := ciphertext[528:]

	plaintext, err := aead.Decrypt(ct, tag, nil, nonce)
	if err != nil {
		return nil, oops.Errorf("decryption failed (authentication error): %w", err)
	}

	if len(plaintext) != 528 {
		return nil, oops.Errorf("unexpected plaintext length: %d", len(plaintext))
	}

	return plaintext, nil
}
