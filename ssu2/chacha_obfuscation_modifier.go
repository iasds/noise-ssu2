package ssu2

import (
	"github.com/go-i2p/go-noise/handshake"
	"github.com/go-i2p/go-noise/internal"
	"github.com/samber/oops"
	"golang.org/x/crypto/chacha20"
)

// ChaChaObfuscationModifier implements SSU2's ChaCha20-based ephemeral key obfuscation.
// This modifier encrypts/decrypts the X and Y ephemeral keys in messages 1 and 2
// using ChaCha20 stream cipher per the SSU2 spec:
//
//	SessionRequest:  ChaCha20(key=Bob's intro key, nonce=1, data)
//	SessionCreated:  ChaCha20(key=Bob's intro key, nonce=1, data)
type ChaChaObfuscationModifier struct {
	name     string
	introKey []byte // 32-byte intro key (Bob's intro key per SSU2 spec)
}

// nonce1 is the 12-byte little-endian encoding of n=1, used for all SSU2
// ChaCha20 obfuscation per the spec.
var nonce1 = []byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

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

// ModifyOutbound applies ChaCha20 obfuscation to ephemeral keys in handshake messages.
// Message 1: XOR X key with ChaCha20(introKey, n=1)
// Message 2: XOR Y key with ChaCha20(introKey, n=1)
// Message 3+: No obfuscation
func (com *ChaChaObfuscationModifier) ModifyOutbound(phase handshake.HandshakePhase, data []byte) ([]byte, error) {
	if len(data) != 32 {
		return data, nil
	}

	switch phase {
	case handshake.PhaseInitial, handshake.PhaseExchange:
		return com.applyChacha(data)
	default:
		return data, nil
	}
}

// ModifyInbound removes ChaCha20 obfuscation from ephemeral keys in handshake messages.
// ChaCha20 is symmetric (XOR-based), so encryption and decryption are identical.
func (com *ChaChaObfuscationModifier) ModifyInbound(phase handshake.HandshakePhase, data []byte) ([]byte, error) {
	if len(data) != 32 {
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

// applyChacha creates a ChaCha20 cipher with fixed nonce n=1 and XORs 32 bytes of data.
func (com *ChaChaObfuscationModifier) applyChacha(data []byte) ([]byte, error) {
	cipher, err := chacha20.NewUnauthenticatedCipher(com.introKey, nonce1)
	if err != nil {
		return nil, oops.
			Code("CHACHA20_CIPHER_CREATION_FAILED").
			In("ssu2").
			With("modifier_name", com.name).
			Wrap(err)
	}

	result := make([]byte, 32)
	copy(result, data)
	cipher.XORKeyStream(result, result)
	return result, nil
}

// Close releases resources and zeroes sensitive key material.
func (com *ChaChaObfuscationModifier) Close() error {
	internal.SecureZero(com.introKey)
	return nil
}
