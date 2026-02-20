package ntcp2

// ReplayDetector checks for replayed ephemeral keys during NTCP2 handshakes.
// Implementations maintain a TTL-based cache of recently seen ephemeral keys
// to prevent handshake replay attacks.
//
// The cache should automatically evict entries older than the configured TTL
// (typically derived from ClockSkewTolerance). Implementations must be safe
// for concurrent use.
type ReplayDetector interface {
	// CheckAndAdd returns true if the ephemeral key has been seen before (replay).
	// If the key is new, it is added to the cache and false is returned.
	CheckAndAdd(ephemeralKey [32]byte) bool

	// Size returns the current number of entries in the replay cache.
	Size() int

	// Close releases resources (stops cleanup goroutine if any).
	Close()
}
