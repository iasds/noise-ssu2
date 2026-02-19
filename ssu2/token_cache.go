package ssu2

import (
	"crypto/rand"
	"net"
	"sync"
	"time"

	"github.com/samber/oops"
)

// TokenCache manages tokens for SSU2 retry mechanism.
// Tokens are used to prevent address spoofing attacks during connection establishment.
// Per SSU2 specification, tokens are short-lived (typically 60 seconds) and tied to
// a specific UDP address.
type TokenCache struct {
	tokens map[string]*Token // Key: address string, Value: token data
	ttl    time.Duration     // Token time-to-live
	mutex  sync.RWMutex
}

// Token represents a retry token issued to a specific address.
type Token struct {
	Value     []byte       // Token value (32 bytes)
	Address   *net.UDPAddr // UDP address this token was issued to
	CreatedAt time.Time    // When token was created
}

// NewTokenCache creates a new token cache with the specified TTL.
// If ttl is zero or negative, defaults to 60 seconds.
func NewTokenCache(ttl time.Duration) *TokenCache {
	if ttl <= 0 {
		ttl = 60 * time.Second
	}

	return &TokenCache{
		tokens: make(map[string]*Token),
		ttl:    ttl,
	}
}

// GenerateToken creates a new token for the specified address.
// The token is cryptographically random and stored in the cache.
// Returns the token value.
func (tc *TokenCache) GenerateToken(addr *net.UDPAddr) ([]byte, error) {
	if addr == nil {
		return nil, oops.
			Code("NIL_ADDRESS").
			In("ssu2").
			Errorf("address cannot be nil")
	}

	// Generate 32 bytes of cryptographically random data
	tokenValue := make([]byte, 32)
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

	// Store token keyed by address string
	tc.tokens[addr.String()] = token

	return tokenValue, nil
}

// ValidateToken checks if a token is valid for the specified address.
// Returns true if the token exists, matches the address, and hasn't expired.
func (tc *TokenCache) ValidateToken(tokenValue []byte, addr *net.UDPAddr) bool {
	if addr == nil || len(tokenValue) != 32 {
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
	return bytesEqual(token.Value, tokenValue)
}

// ConsumeToken validates and removes a token from the cache.
// This should be called when a valid SessionRequest with token is received.
// Returns true if the token was valid and consumed.
func (tc *TokenCache) ConsumeToken(tokenValue []byte, addr *net.UDPAddr) bool {
	if addr == nil || len(tokenValue) != 32 {
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
	if !bytesEqual(token.Value, tokenValue) {
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

// GetTTL returns the token time-to-live duration.
func (tc *TokenCache) GetTTL() time.Duration {
	return tc.ttl
}

// bytesEqual performs constant-time comparison of two byte slices.
// This prevents timing attacks when comparing tokens.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}

	// XOR all bytes and check if result is zero
	var result byte
	for i := 0; i < len(a); i++ {
		result |= a[i] ^ b[i]
	}

	return result == 0
}
