package ssu2

import (
	"github.com/go-i2p/go-noise/handshake"
	"github.com/go-i2p/go-noise/internal"
	"github.com/samber/oops"
	"golang.org/x/crypto/chacha20"
)

// ChaChaObfuscationModifier implements SSU2's ChaCha20-based obfuscation.
// Per the SSU2 specification, SessionRequest and SessionCreated obfuscate
// 48 bytes (header[16:32] || ephemeral_key) with a single ChaCha20 stream
// at nonce n=0 (all-zero 12-byte nonce). This modifier supports both the 48-byte spec-compliant mode
// and 32-byte ephemeral-key-only mode for backward compatibility.
//
// Note: The primary obfuscation path in SSU2 is handled by
// HeaderProtector.encryptLongHeaderExtension, which processes the assembled
// packet. This modifier is available for use in modifier chains where the
// data is processed separately.
type ChaChaObfuscationModifier struct {
	name     string
	introKey []byte // 32-byte intro key (Bob's intro key per SSU2 spec)
}

// nonce0 is the 12-byte all-zero nonce used for SSU2 ChaCha20 header
// obfuscation per the spec (§Header Encryption).
var nonce0 = make([]byte, 12)

// NewChaChaObfuscationModifier creates a new ChaCha20 obfuscation modifier for SSU2.
// introKey must be 32 bytes (Bob's intro key per the SSU2 spec).
// Returns error if parameters are invalid.
func NewChaChaObfuscationModifier(name string, introKey []byte) (*ChaChaObfuscationModifier, error) {
	if len(introKey) != 32 {
		return nil, oops.
			Code("INVALID_INTRO_KEY").
			In("ssu2").
			With("key_length", len(introKey)).
			Errorf("intro key must be exactly 32 bytes")
	}

	// Make defensive copy to prevent external modification
	key := make([]byte, 32)
	copy(key, introKey)

	return &ChaChaObfuscationModifier{
		name:     name,
		introKey: key,
	}, nil
}

// ModifyOutbound applies ChaCha20 obfuscation to handshake messages.
// Accepts 48 bytes (header[16:32] || ephemeral key) per SSU2 spec, or
// 32 bytes (ephemeral key only) for backward compatibility.
// Message 3+: No obfuscation
func (com *ChaChaObfuscationModifier) ModifyOutbound(phase handshake.HandshakePhase, data []byte) ([]byte, error) {
	if len(data) != 48 && len(data) != 32 {
		return data, nil
	}

	switch phase {
	case handshake.PhaseInitial, handshake.PhaseExchange:
		return com.applyChacha(data)
	default:
		return data, nil
	}
}

// ModifyInbound removes ChaCha20 obfuscation from handshake messages.
// ChaCha20 is symmetric (XOR-based), so encryption and decryption are identical.
// Accepts 48 bytes (spec-compliant) or 32 bytes (backward compatibility).
func (com *ChaChaObfuscationModifier) ModifyInbound(phase handshake.HandshakePhase, data []byte) ([]byte, error) {
	if len(data) != 48 && len(data) != 32 {
		return data, nil
	}

	switch phase {
	case handshake.PhaseInitial, handshake.PhaseExchange:
		return com.applyChacha(data)
	default:
		return data, nil
	}
}

// Name returns the modifier name for logging and debugging.
func (com *ChaChaObfuscationModifier) Name() string {
	return com.name
}

// applyChacha creates a ChaCha20 cipher with an all-zero nonce and XORs the data.
// Supports 48-byte (spec-compliant) and 32-byte (ephemeral-only) inputs.
func (com *ChaChaObfuscationModifier) applyChacha(data []byte) ([]byte, error) {
	cipher, err := chacha20.NewUnauthenticatedCipher(com.introKey, nonce0)
	if err != nil {
		return nil, oops.
			Code("CHACHA20_CIPHER_CREATION_FAILED").
			In("ssu2").
			With("modifier_name", com.name).
			Wrap(err)
	}

	result := make([]byte, len(data))
	copy(result, data)
	cipher.XORKeyStream(result, result)
	return result, nil
}

// Close releases resources and zeroes sensitive key material.
func (com *ChaChaObfuscationModifier) Close() error {
	internal.SecureZero(com.introKey)
	return nil
}
