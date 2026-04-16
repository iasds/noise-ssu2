package ssu2

import (
	"sync"
	"time"

	"github.com/go-i2p/logger"
)

// Token admission gates for retry-token issuance.
//
// SSU2 allows unauthenticated peers (off-path UDP spoofers) to trigger a
// Retry/token exchange by sending a TokenRequest. Without per-packet proof
// of reachability (which would be a cookie-based scheme), a naive listener
// that issues one token per distinct source address can be forced to evict
// real peers' tokens by flooding spoofed sources.
//
// Two cheap gates shrink that attack surface:
//
//  1. firstSightTracker: a bounded map of address -> first-seen time. An
//     address that has never been observed is recorded but declined; the
//     peer must retry (SSU2 clients already retry TokenRequests under
//     spec-defined backoff). Entries are timestamps only — much smaller
//     than a full Token struct — and live in an independent bounded
//     structure, so exhausting first-sight does not evict real tokens.
//
//  2. tokenIssuanceLimiter: a single global token bucket that caps total
//     tokens issued per second across all peers. Even if the first-sight
//     gate were bypassed, an attacker cannot amplify issuance beyond the
//     configured rate by fanning across spoofed IPs.

// firstSightTracker records the first time an address was observed so that
// the listener can demand a repeat contact before allocating a full token
// cache entry for it.
type firstSightTracker struct {
	// entries maps address string -> first-seen time.
	entries map[string]time.Time
	// window is the duration a sighting remains "fresh".
	window time.Duration
	// maxEntries bounds memory use. When the tracker is full, the oldest
	// sighting is evicted before a new one is recorded.
	maxEntries int
	// nowFunc returns the current time. Overridden by tests.
	nowFunc func() time.Time
	mutex   sync.Mutex
}

// newFirstSightTracker constructs a firstSightTracker with the given window
// and maximum size. If maxEntries is <= 0 it defaults to 50000. If window
// is <= 0 it defaults to 30 seconds.
func newFirstSightTracker(window time.Duration, maxEntries int) *firstSightTracker {
	if window <= 0 {
		window = 30 * time.Second
	}
	if maxEntries <= 0 {
		maxEntries = 50000
	}
	log.WithFields(logger.Fields{
		"pkg":         "ssu2",
		"func":        "newFirstSightTracker",
		"window":      window,
		"max_entries": maxEntries,
	}).Debug("Creating first-sight tracker")
	return &firstSightTracker{
		entries:    make(map[string]time.Time),
		window:     window,
		maxEntries: maxEntries,
		nowFunc:    time.Now,
	}
}

// ObserveAndAllow records that addr was seen and returns true only if the
// address was already observed within the configured window. On a brand-new
// address it records the sighting and returns false. On re-observation
// within the window it refreshes the timestamp and returns true.
//
// The caller should treat a false return as "drop this token request; the
// peer may retry and succeed on a subsequent request".
func (f *firstSightTracker) ObserveAndAllow(addr string) bool {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	now := f.nowFunc()

	if ts, exists := f.entries[addr]; exists {
		if now.Sub(ts) < f.window {
			f.entries[addr] = now
			return true
		}
		// Stale sighting: treat as brand new.
	}

	if len(f.entries) >= f.maxEntries {
		f.evictOldestLocked()
	}
	f.entries[addr] = now
	return false
}

// Size returns the current number of tracked addresses.
func (f *firstSightTracker) Size() int {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	return len(f.entries)
}

// Cleanup removes entries older than the window. Returns the number of
// entries removed. Intended to be called periodically by the listener.
func (f *firstSightTracker) Cleanup() int {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	cutoff := f.nowFunc().Add(-f.window)
	removed := 0
	for addr, ts := range f.entries {
		if ts.Before(cutoff) {
			delete(f.entries, addr)
			removed++
		}
	}
	return removed
}

// evictOldestLocked drops the single oldest sighting. Caller must hold mu.
func (f *firstSightTracker) evictOldestLocked() {
	var oldestKey string
	var oldestTime time.Time
	first := true
	for k, v := range f.entries {
		if first || v.Before(oldestTime) {
			oldestKey = k
			oldestTime = v
			first = false
		}
	}
	if !first {
		delete(f.entries, oldestKey)
	}
}

// tokenIssuanceLimiter is a single global token bucket that limits the
// listener's total token issuance rate. It backstops firstSightTracker: an
// attacker who somehow bypasses first-sight still cannot issue more than
// rate tokens/second in aggregate.
type tokenIssuanceLimiter struct {
	// rate is the steady-state number of tokens/sec allowed.
	rate float64
	// burst is the maximum bucket capacity (allows short traffic spikes).
	burst float64
	// tokens is the current number of available tokens.
	tokens float64
	// lastRefill is the last time the bucket was refilled.
	lastRefill time.Time
	// nowFunc returns the current time. Overridden by tests.
	nowFunc func() time.Time
	mutex   sync.Mutex
}

// newTokenIssuanceLimiter creates a limiter with the given steady-state
// rate (tokens/sec) and burst capacity. If burst is <= 0 it defaults to
// max(rate, 1).
func newTokenIssuanceLimiter(rate, burst float64) *tokenIssuanceLimiter {
	if rate < 0 {
		rate = 0
	}
	if burst <= 0 {
		burst = rate
		if burst < 1 {
			burst = 1
		}
	}
	log.WithFields(logger.Fields{
		"pkg":   "ssu2",
		"func":  "newTokenIssuanceLimiter",
		"rate":  rate,
		"burst": burst,
	}).Debug("Creating global token issuance limiter")
	return &tokenIssuanceLimiter{
		rate:       rate,
		burst:      burst,
		tokens:     burst,
		lastRefill: time.Now(),
		nowFunc:    time.Now,
	}
}

// Allow consumes one token from the bucket. Returns true if a token was
// available, false if the bucket is empty (in which case no issuance
// should occur). If the limiter was constructed with rate == 0 it always
// returns false.
func (t *tokenIssuanceLimiter) Allow() bool {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	if t.rate == 0 {
		return false
	}

	now := t.nowFunc()
	elapsed := now.Sub(t.lastRefill).Seconds()
	if elapsed > 0 {
		t.tokens += elapsed * t.rate
		if t.tokens > t.burst {
			t.tokens = t.burst
		}
		t.lastRefill = now
	}

	if t.tokens >= 1 {
		t.tokens--
		return true
	}
	return false
}
