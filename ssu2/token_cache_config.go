package ssu2

import (
	"time"

	"github.com/go-i2p/logger"
)

// newTokenCacheFromConfig creates a TokenCache using SSU2Config values.
func newTokenCacheFromConfig(config *SSU2Config) *TokenCache {
	log.WithFields(logger.Fields{"pkg": "ssu2", "func": "newTokenCacheFromConfig"}).Debug("Creating token cache from config")
	maxSize := MaxTokenCacheSize
	if config != nil && config.TokenCacheMaxSize > 0 {
		maxSize = config.TokenCacheMaxSize
	}
	return NewTokenCacheWithMaxSize(60*time.Second, maxSize)
}
