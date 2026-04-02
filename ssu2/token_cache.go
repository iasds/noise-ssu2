package ssu2

import (
	"crypto/rand"
	"crypto/subtle"
	"net"
	"sync"
	"time"

	"github.com/samber/oops"
)

// TokenSize is the size of SSU2 retry tokens in bytes.
// Per SSU2 spec, tokens are 8-byte randomly-generated unsigned big-endian integers.
// The NewToken block (Type 17) carries: 4-byte expiration + 8-byte token = 12 bytes of data.
const TokenSize = 8

// MaxTokenCacheSize is the maximum number of tokens that can be stored.
// This prevents unbounded growth from peers rapidly changing addresses.
const MaxTokenCacheSize = 10000

// TokenCache manages tokens for SSU2 retry mechanism.
// Tokens are used to prevent address spoofing attacks during connection establishment.
// Per SSU2 specification, tokens are short-lived (typically 60 seconds) and tied to
// a specific UDP address. The cache enforces a maximum size of MaxTokenCacheSize
// entries; when full, the oldest token is evicted.
type TokenCache struct {
	tokens  map[string]*Token // Key: address string, Value: token data
	ttl     time.Duration     // Token time-to-live
	maxSize int               // Maximum number of cached tokens
	mutex   sync.RWMutex
}

// Token represents a retry token issued to a specific address.
type Token struct {
	Value     []byte       // Token value (8 bytes)
	Address   *net.UDPAddr // UDP address this token was issued to
	CreatedAt time.Time    // When token was created
}

// NewTokenCache creates a new token cache with the specified TTL.
// If ttl is zero or negative, defaults to 60 seconds.
func NewTokenCache(ttl time.Duration) *TokenCache {
	log.WithField("ttl", ttl).Debug("Creating new TokenCache")
	if ttl <= 0 {
		ttl = 60 * time.Second
	}

	return &TokenCache{
		tokens:  make(map[string]*Token),
		ttl:     ttl,
		maxSize: MaxTokenCacheSize,
	}
}

// newTokenCacheFromConfig creates a TokenCache using SSU2Config values.
func newTokenCacheFromConfig(config *SSU2Config) *TokenCache {
	tc := NewTokenCache(60 * time.Second)
	if config != nil && config.TokenCacheMaxSize > 0 {
		tc.maxSize = config.TokenCacheMaxSize
	}
	return tc
}

// GenerateToken creates a new token for the specified address.
// The token is cryptographically random and stored in the cache.
// Returns the token value.
func (tc *TokenCache) GenerateToken(addr *net.UDPAddr) ([]byte, error) {
	log.Debug("Generating new token")
	if addr == nil {
		return nil, oops.
			Code("NIL_ADDRESS").
			In("ssu2").
			Errorf("address cannot be nil")
	}

	// Generate 8-byte random token per SSU2 spec
	tokenValue := make([]byte, TokenSize)
	if _, err := rand.Read(tokenValue); err != nil {
		return nil, oops.
			Code("TOKEN_GENERATION_FAILED").
			In("ssu2").
			With("address", addr.String()).
			Wrapf(err, "failed to generate random token")
	}

	token := &Token{
		Value:     tokenValue,
		Address:   addr,
		CreatedAt: time.Now(),
	}

	tc.mutex.Lock()
	defer tc.mutex.Unlock()

	// Evict oldest token if at capacity
	if len(tc.tokens) >= tc.maxSize {
		tc.evictOldestLocked()
	}

	// Store token keyed by address string
	tc.tokens[addr.String()] = token

	return tokenValue, nil
}

// ValidateToken checks if a token is valid for the specified address.
// Returns true if the token exists, matches the address, and hasn't expired.
func (tc *TokenCache) ValidateToken(tokenValue []byte, addr *net.UDPAddr) bool {
	if addr == nil || len(tokenValue) != TokenSize {
		return false
	}

	tc.mutex.RLock()
	defer tc.mutex.RUnlock()

	token, exists := tc.tokens[addr.String()]
	if !exists {
		return false
	}

	// Check if token has expired
	if time.Since(token.CreatedAt) > tc.ttl {
		return false
	}

	// Compare token values using constant-time comparison
	return subtle.ConstantTimeCompare(token.Value, tokenValue) == 1
}

// ConsumeToken validates and removes a token from the cache.
// This should be called when a valid SessionRequest with token is received.
// Returns true if the token was valid and consumed.
func (tc *TokenCache) ConsumeToken(tokenValue []byte, addr *net.UDPAddr) bool {
	if addr == nil || len(tokenValue) != TokenSize {
		return false
	}

	tc.mutex.Lock()
	defer tc.mutex.Unlock()

	addrStr := addr.String()
	token, exists := tc.tokens[addrStr]
	if !exists {
		return false
	}

	// Check if token has expired
	if time.Since(token.CreatedAt) > tc.ttl {
		delete(tc.tokens, addrStr)
		return false
	}

	// Compare token values
	if subtle.ConstantTimeCompare(token.Value, tokenValue) != 1 {
		return false
	}

	// Token is valid, consume it (remove from cache)
	delete(tc.tokens, addrStr)
	return true
}

// Cleanup removes expired tokens from the cache.
// This should be called periodically to prevent memory leaks.
func (tc *TokenCache) Cleanup() int {
	tc.mutex.Lock()
	defer tc.mutex.Unlock()

	now := time.Now()
	removed := 0

	for addrStr, token := range tc.tokens {
		if now.Sub(token.CreatedAt) > tc.ttl {
			delete(tc.tokens, addrStr)
			removed++
		}
	}

	return removed
}

// Size returns the number of tokens currently in the cache.
func (tc *TokenCache) Size() int {
	tc.mutex.RLock()
	defer tc.mutex.RUnlock()
	return len(tc.tokens)
}

// Clear removes all tokens from the cache.
func (tc *TokenCache) Clear() {
	tc.mutex.Lock()
	defer tc.mutex.Unlock()
	tc.tokens = make(map[string]*Token)
}

// InvalidateAddress removes any token associated with the given address.
// Per spec, tokens are bound to an IP:port pair and must be invalidated
// when a connection migrates to a new address.
func (tc *TokenCache) InvalidateAddress(addr *net.UDPAddr) {
	if addr == nil {
		return
	}
	key := addr.String()
	tc.mutex.Lock()
	defer tc.mutex.Unlock()
	delete(tc.tokens, key)
}

// evictOldestLocked removes the oldest token from the cache.
// Caller must hold tc.mutex.
func (tc *TokenCache) evictOldestLocked() {
	var oldestKey string
	var oldestTime time.Time
	first := true

	for key, token := range tc.tokens {
		if first || token.CreatedAt.Before(oldestTime) {
			oldestKey = key
			oldestTime = token.CreatedAt
			first = false
		}
	}

	if !first {
		delete(tc.tokens, oldestKey)
	}
}

// GetTTL returns the token time-to-live duration.
func (tc *TokenCache) GetTTL() time.Duration {
	return tc.ttl
}
