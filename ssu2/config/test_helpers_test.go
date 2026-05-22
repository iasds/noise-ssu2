package config

import (
	"github.com/go-i2p/common/data"
	"github.com/go-i2p/crypto/rand"
)

// generateRandomHash creates a random data.Hash for testing.
func generateRandomHash() data.Hash {
	var h data.Hash
	_, _ = rand.Read(h[:])
	return h
}

// hashPtr returns a pointer to the given data.Hash, useful for struct literals.
func hashPtr(h data.Hash) *data.Hash {
	return &h
}
