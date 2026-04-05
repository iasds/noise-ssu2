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
	log.WithField("len", len(b)).Debug("SecureZero: zeroing key material")
	clear(b)
	runtime.KeepAlive(b)
}

// RandomBytes generates cryptographically secure random bytes.
// Returns an error if n is negative. If n is zero, returns an empty slice.
func RandomBytes(n int) ([]byte, error) {
	log.WithField("n", n).Debug("RandomBytes: generating random bytes")
	if n < 0 {
		log.WithField("n", n).Error("RandomBytes: negative byte count")
		return nil, errors.New("internal: negative byte count")
	}
	if n == 0 {
		return []byte{}, nil
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		log.WithError(err).Error("RandomBytes: failed to read from crypto/rand")
		return nil, err
	}
	return b, nil
}

// ValidateKeySize validates that a key has the expected size
func ValidateKeySize(key []byte, expectedSize int) bool {
	valid := len(key) == expectedSize
	if !valid {
		log.WithField("expected", expectedSize).WithField("actual", len(key)).Warn("ValidateKeySize: key size mismatch")
	}
	return valid
}
