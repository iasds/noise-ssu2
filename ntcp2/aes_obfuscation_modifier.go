package ntcp2

import (
	"crypto/cipher"
	"sync"

	"github.com/go-i2p/crypto/aes"
	"github.com/go-i2p/go-noise/handshake"
	"github.com/samber/oops"
)

// AESObfuscationModifier implements NTCP2's AES-based ephemeral key obfuscation.
// This modifier encrypts/decrypts the X and Y ephemeral keys in messages 1 and 2
// using AES-256-CBC with the router hash as key and published IV.
//
// Per the NTCP2 spec, the AES state (last ciphertext block) from message 1
// encryption is carried forward as the IV for message 2 encryption.
//
// After AES decryption, received keys are validated per the NTCP2 spec:
// X[31]&0x80 must be 0 (Curve25519 requirement). Invalid keys cause message rejection.
type AESObfuscationModifier struct {
	mu         sync.Mutex
	name       string
	routerHash []byte       // 32-byte router hash (RH_B)
	iv         []byte       // 16-byte IV from network database
	aesState   []byte       // AES state for message 2 (last ciphertext block from message 1)
	block      cipher.Block // cached AES cipher (key schedule computed once)
}

// NewAESObfuscationModifier creates a new AES obfuscation modifier for NTCP2.
// routerHash must be 32 bytes (RH_B), iv must be 16 bytes from network database.
func NewAESObfuscationModifier(name string, routerHash, iv []byte) (*AESObfuscationModifier, error) {
	if len(routerHash) != RouterHashSize {
		return nil, oops.
			Code("INVALID_ROUTER_HASH").
			In("ntcp2").
			With("hash_length", len(routerHash)).
			Errorf("router hash must be exactly %d bytes", RouterHashSize)
	}

	if len(iv) != IVSize {
		return nil, oops.
			Code("INVALID_IV").
			In("ntcp2").
			With("iv_length", len(iv)).
			Errorf("IV must be exactly %d bytes", IVSize)
	}

	// Make defensive copies
	hash := make([]byte, RouterHashSize)
	copy(hash, routerHash)

	initIV := make([]byte, IVSize)
	copy(initIV, iv)

	// Pre-compute AES key schedule once (avoids per-call aes.NewCipher).
	block, err := aes.NewCipher(hash)
	if err != nil {
		return nil, oops.
			Code("AES_CIPHER_CREATION_FAILED").
			In("ntcp2").
			Wrap(err)
	}

	return &AESObfuscationModifier{
		name:       name,
		routerHash: hash,
		iv:         initIV,
		block:      block,
	}, nil
}

// ModifyOutbound applies AES obfuscation to ephemeral keys in handshake messages.
// For message 1: encrypts X key with RH_B and published IV
// For message 2: encrypts Y key with RH_B and AES state from message 1
func (aom *AESObfuscationModifier) ModifyOutbound(phase handshake.HandshakePhase, data []byte) ([]byte, error) {
	aom.mu.Lock()
	defer aom.mu.Unlock()

	// Only apply to 32-byte ephemeral keys (X or Y values)
	if len(data) != StaticKeySize {
		return data, nil
	}

	var mode cipher.BlockMode
	switch phase {
	case handshake.PhaseInitial:
		// Message 1: use published IV
		mode = cipher.NewCBCEncrypter(aom.block, aom.iv)
	case handshake.PhaseExchange:
		// Message 2: use AES state from message 1
		if aom.aesState == nil {
			return nil, oops.
				Code("MISSING_AES_STATE").
				In("ntcp2").
				With("modifier_name", aom.name).
				Errorf("AES state not available for message 2")
		}
		mode = cipher.NewCBCEncrypter(aom.block, aom.aesState)
	default:
		// Message 3 and beyond: no AES obfuscation
		return data, nil
	}

	result := make([]byte, StaticKeySize)
	copy(result, data)
	mode.CryptBlocks(result, result)

	// Per NTCP2 spec: save the last ciphertext block as AES state for message 2.
	// For outbound encryption, the state is result[16:32] captured AFTER encryption.
	if phase == handshake.PhaseInitial {
		aom.aesState = make([]byte, IVSize)
		copy(aom.aesState, result[IVSize:StaticKeySize])
	}

	return result, nil
}

// ModifyInbound removes AES obfuscation from ephemeral keys in handshake messages.
func (aom *AESObfuscationModifier) ModifyInbound(phase handshake.HandshakePhase, data []byte) ([]byte, error) {
	aom.mu.Lock()
	defer aom.mu.Unlock()

	// Only apply to 32-byte ephemeral keys (X or Y values)
	if len(data) != StaticKeySize {
		return data, nil
	}

	// Per NTCP2 spec: for inbound (decryption), save the last ciphertext block
	// BEFORE decryption as the AES state for message 2.
	// The state is data[16:32] (the last ciphertext block of the 32-byte input).
	if phase == handshake.PhaseInitial {
		aom.aesState = make([]byte, IVSize)
		copy(aom.aesState, data[IVSize:StaticKeySize])
	}

	var mode cipher.BlockMode
	switch phase {
	case handshake.PhaseInitial:
		// Message 1: use published IV
		mode = cipher.NewCBCDecrypter(aom.block, aom.iv)
	case handshake.PhaseExchange:
		// Message 2: use AES state from message 1
		if aom.aesState == nil {
			return nil, oops.
				Code("MISSING_AES_STATE").
				In("ntcp2").
				With("modifier_name", aom.name).
				Errorf("AES state not available for message 2")
		}
		mode = cipher.NewCBCDecrypter(aom.block, aom.aesState)
	default:
		// Message 3 and beyond: no AES obfuscation
		return data, nil
	}

	result := make([]byte, StaticKeySize)
	copy(result, data)
	mode.CryptBlocks(result, result)

	// Per NTCP2 spec: validate that the decrypted key is a valid Curve25519 point.
	// The high bit of byte 31 must be 0. Reject the message if this check fails.
	if result[StaticKeySize-1]&0x80 != 0 {
		return nil, oops.
			Code("INVALID_CURVE25519_KEY").
			In("ntcp2").
			With("modifier_name", aom.name).
			With("phase", phase).
			Errorf("decrypted key has high bit set (X[31]&0x80 != 0); invalid Curve25519 point")
	}

	return result, nil
}

// Name returns the modifier name for logging and debugging.
func (aom *AESObfuscationModifier) Name() string {
	return aom.name
}

// Close zeroes the AES key material and IV stored in the modifier to prevent
// sensitive data from lingering in memory after the connection is closed.
// This method is safe for concurrent use.
func (aom *AESObfuscationModifier) Close() error {
	aom.mu.Lock()
	defer aom.mu.Unlock()
	for i := range aom.routerHash {
		aom.routerHash[i] = 0
	}
	for i := range aom.iv {
		aom.iv[i] = 0
	}
	for i := range aom.aesState {
		aom.aesState[i] = 0
	}
	aom.block = nil
	return nil
}
