package handshake

import "crypto/rand"

// XORModifier implements a simple XOR-based obfuscation modifier.
// It XORs handshake data with a configurable key pattern to provide
// basic obfuscation without compromising Noise protocol security.
// Moved from: handshake/modifiers.go
type XORModifier struct {
	name    string
	xorKey  []byte
	keySize int
}

// NewXORModifier creates a new XOR modifier with the specified key.
// The key is repeated as needed to match the data length.
//
// Security note: if key is nil or empty, a 32-byte cryptographically random
// key is generated automatically. Callers must NOT rely on any particular
// default value — the old well-known default (0xAA) provided no meaningful
// obfuscation and has been replaced by this random fallback.
func NewXORModifier(name string, xorKey []byte) *XORModifier {
	if len(xorKey) == 0 {
		// Generate a cryptographically random 32-byte key so that each modifier
		// instance with no explicit key still produces distinct output.
		// Panic is unreachable in practice: crypto/rand.Read only fails if the
		// OS entropy source is unavailable, which is a fatal system condition.
		randomKey := make([]byte, 32)
		if _, err := rand.Read(randomKey); err != nil {
			// Fall back to a single non-zero byte only if the OS rand source is
			// completely broken.  This is documented as a security regression but
			// is vastly preferable to a silent panic mid-handshake.
			randomKey = []byte{0x01}
		}
		xorKey = randomKey
	}

	// Make a copy to prevent external modification
	key := make([]byte, len(xorKey))
	copy(key, xorKey)

	return &XORModifier{
		name:    name,
		xorKey:  key,
		keySize: len(key),
	}
}

// ModifyOutbound applies XOR obfuscation to outbound handshake data.
func (xm *XORModifier) ModifyOutbound(phase HandshakePhase, data []byte) ([]byte, error) {
	if len(data) == 0 {
		return data, nil
	}

	result := make([]byte, len(data))
	for i, b := range data {
		result[i] = b ^ xm.xorKey[i%xm.keySize]
	}

	return result, nil
}

// ModifyInbound removes XOR obfuscation from inbound handshake data.
// Since XOR is symmetric, this performs the same operation as ModifyOutbound.
func (xm *XORModifier) ModifyInbound(phase HandshakePhase, data []byte) ([]byte, error) {
	return xm.ModifyOutbound(phase, data)
}

// Name returns the name of the XOR modifier for logging and debugging.
func (xm *XORModifier) Name() string {
	return xm.name
}

// Close zeroes the XOR key to prevent session-derived key material from
// lingering in memory after the connection is torn down.
func (xm *XORModifier) Close() error {
	for i := range xm.xorKey {
		xm.xorKey[i] = 0
	}
	return nil
}
