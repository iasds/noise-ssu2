// Package replaycache provides a thread-safe, bounded, TTL-based cache for
// detecting replayed [32]byte keys. It is used by both the ntcp2 and ratchet
// packages to prevent handshake replay attacks within configurable freshness
// windows.
package replaycache

import (
	"sort"
	"sync"
	"time"

	"github.com/go-i2p/logger"
)

// Config holds the parameters for constructing a TTLCache.
type Config struct {
	// TTL is the time-to-live for cache entries. Entries older than TTL
	// are considered expired and will not trigger replay detection.
	TTL time.Duration

	// MaxSize is the maximum number of entries before forced eviction
	// of the oldest entries. This prevents memory exhaustion under attack.
	MaxSize int

	// CleanupInterval controls how often the background goroutine evicts
	// expired entries.
	CleanupInterval time.Duration

	// NowFunc returns the current time. If nil, time.Now is used.
	// This field exists so callers can inject a test clock.
	NowFunc func() time.Time
}

// TTLCache is a thread-safe, bounded, TTL-based cache for detecting
// replayed [32]byte keys. Call New to create an instance and Close
// to release its background goroutine.
type TTLCache struct {
	mu              sync.RWMutex
	entries         map[[32]byte]time.Time
	ttl             time.Duration
	maxSize         int
	cleanupInterval time.Duration
	done            chan struct{}
	closeOnce       sync.Once
	nowFunc         func() time.Time
}

// New creates a new TTLCache and starts a background cleanup goroutine.
// Call Close when the cache is no longer needed.
// Defaults: if CleanupInterval is non-positive, defaults to TTL.
// If MaxSize is non-positive, defaults to 10000 (see LOW-2 audit finding).
func New(cfg Config) *TTLCache {
	log.WithFields(logger.Fields{"pkg": "replaycache", "func": "New", "ttl": cfg.TTL, "max_size": cfg.MaxSize}).Debug("Creating new replay cache")
	nf := cfg.NowFunc
	if nf == nil {
		nf = time.Now
	}

	// Default CleanupInterval to TTL if not specified or non-positive.
	// This ensures time.NewTicker doesn't panic (LOW-2).
	cleanupInterval := cfg.CleanupInterval
	if cleanupInterval <= 0 {
		cleanupInterval = cfg.TTL
	}

	// Default MaxSize to 10000 if not specified or non-positive.
	// This prevents silent weakening of replay detection.
	maxSize := cfg.MaxSize
	if maxSize <= 0 {
		maxSize = 10000
	}

	c := &TTLCache{
		entries:         make(map[[32]byte]time.Time),
		ttl:             cfg.TTL,
		maxSize:         maxSize,
		cleanupInterval: cleanupInterval,
		done:            make(chan struct{}),
		nowFunc:         nf,
	}
	go c.cleanupLoop()
	return c
}

// CheckAndAdd returns true if the key has been seen within the TTL window
// (replay detected). If the key is new or expired, it is recorded and
// false is returned.
func (c *TTLCache) CheckAndAdd(key [32]byte) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.nowFunc()

	if firstSeen, exists := c.entries[key]; exists {
		if now.Sub(firstSeen) < c.ttl {
			log.WithFields(logger.Fields{"pkg": "replaycache", "func": "TTLCache.CheckAndAdd"}).Debug("Replay detected in cache")
			return true // replay detected
		}
		// Entry expired — treat as new.
	}

	if len(c.entries) >= c.maxSize {
		c.evictOldestLocked()
	}

	c.entries[key] = now
	return false
}

// Size returns the current number of entries in the cache.
func (c *TTLCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// Close stops the background cleanup goroutine and releases resources.
// Close is idempotent — calling it more than once is safe.
func (c *TTLCache) Close() {
	log.WithFields(logger.Fields{"pkg": "replaycache", "func": "TTLCache.Close"}).Debug("Closing replay cache")
	c.closeOnce.Do(func() { close(c.done) })
}

// Reset removes all entries from the cache.
func (c *TTLCache) Reset() {
	log.WithFields(logger.Fields{"pkg": "replaycache", "func": "TTLCache.Reset"}).Debug("Clearing all replay cache entries")
	c.mu.Lock()
	defer c.mu.Unlock()
	for k := range c.entries {
		delete(c.entries, k)
	}
}

// cleanupLoop periodically evicts expired entries.
func (c *TTLCache) cleanupLoop() {
	ticker := time.NewTicker(c.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-c.done:
			return
		case <-ticker.C:
			c.evictExpired()
		}
	}
}

// evictExpired removes all entries older than the TTL.
func (c *TTLCache) evictExpired() {
	c.mu.Lock()
	defer c.mu.Unlock()

	cutoff := c.nowFunc().Add(-c.ttl)
	for key, firstSeen := range c.entries {
		if firstSeen.Before(cutoff) {
			delete(c.entries, key)
		}
	}
}

// evictOldestLocked removes the oldest 10% of entries when the cache
// is full. It sorts entries by insertion time so that the genuinely oldest
// entries are evicted first. Must be called with c.mu held for writing.
func (c *TTLCache) evictOldestLocked() {
	evictCount := len(c.entries) / 10
	if evictCount < 1 {
		evictCount = 1
	}

	// Collect all entries with their timestamps into a slice so we can sort.
	type kv struct {
		key       [32]byte
		firstSeen time.Time
	}
	all := make([]kv, 0, len(c.entries))
	for k, t := range c.entries {
		all = append(all, kv{k, t})
	}

	// Sort ascending by insertion time — oldest first.
	sort.Slice(all, func(i, j int) bool {
		return all[i].firstSeen.Before(all[j].firstSeen)
	})

	// Delete the evictCount oldest entries.
	for i := 0; i < evictCount && i < len(all); i++ {
		delete(c.entries, all[i].key)
	}
}
