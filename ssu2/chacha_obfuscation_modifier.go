package ssu2

import (
	"github.com/go-i2p/go-noise/handshake"
	"github.com/samber/oops"
	"golang.org/x/crypto/chacha20"
)

// ChaChaObfuscationModifier implements SSU2's ChaCha20-based ephemeral key obfuscation.
// This modifier encrypts/decrypts the X and Y ephemeral keys in messages 1 and 2
// using ChaCha20 stream cipher with the router hash as key and published IV.
// Key differences from NTCP2's AES: 8-byte IV, XOR-based stream cipher vs block cipher.
type ChaChaObfuscationModifier struct {
	name        string
	routerHash  []byte // 32-byte router hash (RH_B)
	iv          []byte // 8-byte IV from network database
	chachaState []byte // ChaCha20 state for message 2 (derived IV)
}

// NewChaChaObfuscationModifier creates a new ChaCha20 obfuscation modifier for SSU2.
// routerHash must be 32 bytes (RH_B), iv must be 8 bytes from network database.
// Returns error if parameters are invalid.
func NewChaChaObfuscationModifier(name string, routerHash, iv []byte) (*ChaChaObfuscationModifier, error) {
	if len(routerHash) != 32 {
		return nil, oops.
			Code("INVALID_ROUTER_HASH").
			In("ssu2").
			With("hash_length", len(routerHash)).
			Errorf("router hash must be exactly 32 bytes")
	}

	if len(iv) != 8 {
		return nil, oops.
			Code("INVALID_IV").
			In("ssu2").
			With("iv_length", len(iv)).
			Errorf("IV must be exactly 8 bytes")
	}

	// Make defensive copies to prevent external modification
	hash := make([]byte, 32)
	copy(hash, routerHash)

	initIV := make([]byte, 8)
	copy(initIV, iv)

	return &ChaChaObfuscationModifier{
		name:       name,
		routerHash: hash,
		iv:         initIV,
	}, nil
}

// ModifyOutbound applies ChaCha20 obfuscation to ephemeral keys in handshake messages.
// Message 1: XOR X key with ChaCha20(routerHash, iv)
// Message 2: XOR Y key with ChaCha20(routerHash, derived_iv)
// Message 3+: No obfuscation (like NTCP2)
func (com *ChaChaObfuscationModifier) ModifyOutbound(phase handshake.HandshakePhase, data []byte) ([]byte, error) {
	// Only apply to 32-byte ephemeral keys (X or Y values)
	if len(data) != 32 {
		return data, nil
	}

	switch phase {
	case handshake.PhaseInitial:
		return com.encryptMessage1(data)
	case handshake.PhaseExchange:
		return com.encryptMessage2(data)
	default:
		// Message 3 and beyond: no ChaCha20 obfuscation
		return data, nil
	}
}

// ModifyInbound removes ChaCha20 obfuscation from ephemeral keys in handshake messages.
// ChaCha20 is symmetric (XOR-based), so encryption and decryption are identical.
func (com *ChaChaObfuscationModifier) ModifyInbound(phase handshake.HandshakePhase, data []byte) ([]byte, error) {
	// Only apply to 32-byte ephemeral keys (X or Y values)
	if len(data) != 32 {
		return data, nil
	}

	switch phase {
	case handshake.PhaseInitial:
		return com.decryptMessage1(data)
	case handshake.PhaseExchange:
		return com.decryptMessage2(data)
	default:
		// Message 3 and beyond: no ChaCha20 obfuscation
		return data, nil
	}
}

// Name returns the modifier name for logging and debugging.
func (com *ChaChaObfuscationModifier) Name() string {
	return com.name
}

// encryptMessage1 encrypts message 1 using published IV.
// Extracts helper to keep functions under 30 lines.
func (com *ChaChaObfuscationModifier) encryptMessage1(data []byte) ([]byte, error) {
	// Prepare nonce: 8-byte IV + 4 zero bytes (ChaCha20 requires 12-byte nonce)
	nonce := make([]byte, chacha20.NonceSize)
	copy(nonce, com.iv)

	cipher, err := chacha20.NewUnauthenticatedCipher(com.routerHash, nonce)
	if err != nil {
		return nil, oops.
			Code("CHACHA20_CIPHER_CREATION_FAILED").
			In("ssu2").
			With("modifier_name", com.name).
			Wrap(err)
	}

	// XOR data with ChaCha20 keystream
	result := make([]byte, 32)
	copy(result, data)
	cipher.XORKeyStream(result, result)

	// Save derived state for message 2 (last 8 bytes of encrypted data)
	com.chachaState = make([]byte, 8)
	copy(com.chachaState, result[24:32])

	return result, nil
}

// encryptMessage2 encrypts message 2 using derived IV from message 1.
// Extracts helper to keep functions under 30 lines.
func (com *ChaChaObfuscationModifier) encryptMessage2(data []byte) ([]byte, error) {
	if com.chachaState == nil {
		return nil, oops.
			Code("MISSING_CHACHA_STATE").
			In("ssu2").
			With("modifier_name", com.name).
			Errorf("ChaCha20 state not available for message 2")
	}

	// Prepare nonce using derived IV from message 1
	nonce := make([]byte, chacha20.NonceSize)
	copy(nonce, com.chachaState)

	cipher, err := chacha20.NewUnauthenticatedCipher(com.routerHash, nonce)
	if err != nil {
		return nil, oops.
			Code("CHACHA20_CIPHER_CREATION_FAILED").
			In("ssu2").
			With("modifier_name", com.name).
			Wrap(err)
	}

	// XOR data with ChaCha20 keystream
	result := make([]byte, 32)
	copy(result, data)
	cipher.XORKeyStream(result, result)

	return result, nil
}

// decryptMessage1 decrypts message 1 using published IV.
// Must save state from encrypted data for message 2 decryption.
func (com *ChaChaObfuscationModifier) decryptMessage1(encryptedData []byte) ([]byte, error) {
	// Save derived state BEFORE decryption (from last 8 bytes of encrypted data)
	com.chachaState = make([]byte, 8)
	copy(com.chachaState, encryptedData[24:32])

	// Prepare nonce: 8-byte IV + 4 zero bytes
	nonce := make([]byte, chacha20.NonceSize)
	copy(nonce, com.iv)

	cipher, err := chacha20.NewUnauthenticatedCipher(com.routerHash, nonce)
	if err != nil {
		return nil, oops.
			Code("CHACHA20_CIPHER_CREATION_FAILED").
			In("ssu2").
			With("modifier_name", com.name).
			Wrap(err)
	}

	// XOR encrypted data with ChaCha20 keystream to decrypt
	result := make([]byte, 32)
	copy(result, encryptedData)
	cipher.XORKeyStream(result, result)

	return result, nil
}

// decryptMessage2 decrypts message 2 using derived IV from message 1.
// Identical to encryptMessage2 due to XOR symmetry.
func (com *ChaChaObfuscationModifier) decryptMessage2(data []byte) ([]byte, error) {
	return com.encryptMessage2(data)
}
