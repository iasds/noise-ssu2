package internal

import (
	"errors"
	"io"
	"runtime"

	"github.com/go-i2p/crypto/rand"
	"github.com/go-i2p/logger"
)

// SecureZero zeroes out the given byte slice. Uses runtime.KeepAlive to
// prevent the compiler from eliding the zeroing as a dead store.
func SecureZero(b []byte) {
	log.WithFields(logger.Fields{"pkg": "internal", "func": "SecureZero", "len": len(b)}).Debug("Zeroing key material")
	clear(b)
	runtime.KeepAlive(b)
}

// RandomBytes generates cryptographically secure random bytes.
// Returns an error if n is negative. If n is zero, returns an empty slice.
func RandomBytes(n int) ([]byte, error) {
	log.WithFields(logger.Fields{"pkg": "internal", "func": "RandomBytes", "n": n}).Debug("Generating random bytes")
	if n < 0 {
		log.WithFields(logger.Fields{"pkg": "internal", "func": "RandomBytes", "n": n}).Error("Negative byte count")
		return nil, errors.New("internal: negative byte count")
	}
	if n == 0 {
		return []byte{}, nil
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		log.WithFields(logger.Fields{"pkg": "internal", "func": "RandomBytes"}).WithError(err).Error("Failed to read from crypto/rand")
		return nil, err
	}
	return b, nil
}

// ValidateKeySize validates that a key has the expected size
func ValidateKeySize(key []byte, expectedSize int) bool {
	valid := len(key) == expectedSize
	if !valid {
		log.WithFields(logger.Fields{"pkg": "internal", "func": "ValidateKeySize", "expected": expectedSize, "actual": len(key)}).Warn("Key size mismatch")
	}
	return valid
}
