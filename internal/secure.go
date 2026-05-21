package internal

import (
	"runtime"

	"github.com/go-i2p/logger"
)

// SecureZero zeroes out the given byte slice. Uses runtime.KeepAlive to
// prevent the compiler from eliding the zeroing as a dead store.
func SecureZero(b []byte) {
	log.WithFields(logger.Fields{"pkg": "internal", "func": "SecureZero", "len": len(b)}).Debug("Zeroing key material")
	clear(b)
	runtime.KeepAlive(b)
}
