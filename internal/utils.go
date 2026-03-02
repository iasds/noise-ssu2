package internal

import (
	"errors"
	"io"

	"github.com/go-i2p/crypto/rand"
)

// SecureZero zeroes out the given byte slice (best-effort; not guaranteed
// resistant to dead-store elimination by the compiler). The Go compiler
// does not currently eliminate these stores, but the language specification
// does not prohibit it.
func SecureZero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// RandomBytes generates cryptographically secure random bytes.
// Returns an error if n is negative. If n is zero, returns an empty slice.
func RandomBytes(n int) ([]byte, error) {
	if n < 0 {
		return nil, errors.New("internal: negative byte count")
	}
	if n == 0 {
		return []byte{}, nil
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, err
	}
	return b, nil
}

// ValidateKeySize validates that a key has the expected size
func ValidateKeySize(key []byte, expectedSize int) bool {
	return len(key) == expectedSize
}
