package ntcp2

import (
	"crypto/aes"
	"crypto/cipher"
	"sync"

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
// TODO(ntcp2-spec): Validate that received ephemeral and static keys are valid
// Curve25519 points before/after AES decryption (spec requires X[31]&0x80==0
// fast check plus full validation).
type AESObfuscationModifier struct {
	mu         sync.Mutex
	name       string
	routerHash []byte // 32-byte router hash (RH_B)
	iv         []byte // 16-byte IV from network database
	aesState   []byte // AES state for message 2 (last ciphertext block from message 1)
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

	return &AESObfuscationModifier{
		name:       name,
		routerHash: hash,
		iv:         initIV,
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

	block, err := aes.NewCipher(aom.routerHash)
	if err != nil {
		return nil, oops.
			Code("AES_CIPHER_CREATION_FAILED").
			In("ntcp2").
			With("modifier_name", aom.name).
			Wrap(err)
	}

	var mode cipher.BlockMode
	switch phase {
	case handshake.PhaseInitial:
		// Message 1: use published IV
		mode = cipher.NewCBCEncrypter(block, aom.iv)
	case handshake.PhaseExchange:
		// Message 2: use AES state from message 1
		if aom.aesState == nil {
			return nil, oops.
				Code("MISSING_AES_STATE").
				In("ntcp2").
				With("modifier_name", aom.name).
				Errorf("AES state not available for message 2")
		}
		mode = cipher.NewCBCEncrypter(block, aom.aesState)
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

	block, err := aes.NewCipher(aom.routerHash)
	if err != nil {
		return nil, oops.
			Code("AES_CIPHER_CREATION_FAILED").
			In("ntcp2").
			With("modifier_name", aom.name).
			Wrap(err)
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
		mode = cipher.NewCBCDecrypter(block, aom.iv)
	case handshake.PhaseExchange:
		// Message 2: use AES state from message 1
		if aom.aesState == nil {
			return nil, oops.
				Code("MISSING_AES_STATE").
				In("ntcp2").
				With("modifier_name", aom.name).
				Errorf("AES state not available for message 2")
		}
		mode = cipher.NewCBCDecrypter(block, aom.aesState)
	default:
		// Message 3 and beyond: no AES obfuscation
		return data, nil
	}

	result := make([]byte, StaticKeySize)
	copy(result, data)
	mode.CryptBlocks(result, result)

	return result, nil
}

// Name returns the modifier name for logging and debugging.
func (aom *AESObfuscationModifier) Name() string {
	return aom.name
}
