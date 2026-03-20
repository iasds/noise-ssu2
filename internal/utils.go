package internal

import (
	"errors"
	"io"
	"runtime"

	"github.com/go-i2p/crypto/rand"
)

// SecureZero zeroes out the given byte slice. Uses runtime.KeepAlive to
// prevent the compiler from eliding the zeroing as a dead store.
func SecureZero(b []byte) {
	clear(b)
	runtime.KeepAlive(b)
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
