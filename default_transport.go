package noise

import (
	"sync"
	"time"

	"github.com/go-i2p/logger"
	"github.com/go-i2p/pool"
)

var (
	defaultOnce sync.Once
	defaultInst *Transport
)

// Default is the package-level Transport used by DialNoise, ListenNoise, etc.
// It is lazily initialised on first use via getDefault().
//
// Deprecated: Package-level convenience only. Callers that share the Default instance
// across goroutines or tests affect shared state (pool, shutdown manager).
// Prefer constructing a Transport directly for production use:
//
//	newTransport := noise.NewTransport(myPool, myShutdown)
//
// For test isolation, call ResetDefault() in your TestMain or test teardown.
var Default *Transport

// ResetDefault resets the package-level Default Transport and its initialisation
// state so that the next call to getDefault() creates a fresh instance.
//
// Intended for test isolation only. Do not call in production code; concurrent
// callers that hold a reference to the previous Default will observe a stale
// pointer.
//
// If a Default Transport exists, ResetDefault calls GracefulShutdown on it to
// clean up pool resources and shutdown manager goroutines before dropping the
// reference. This prevents goroutine leaks in test suites that call ResetDefault
// multiple times.
func ResetDefault() {
	if defaultInst != nil {
		_ = defaultInst.GracefulShutdown()
	}
	defaultOnce = sync.Once{}
	defaultInst = nil
	Default = nil
}

// getDefault lazily creates the singleton Transport and exposes it as Default.
func getDefault() *Transport {
	defaultOnce.Do(func() {
		defaultInst = NewTransport(
			pool.NewConnPool(&pool.PoolConfig{
				MaxSize: 10,
				MaxAge:  30 * time.Minute,
				MaxIdle: 5 * time.Minute,
			}),
			NewShutdownManager(30*time.Second),
		)
		Default = defaultInst
	})
	return defaultInst
}

// SetGlobalConnPool sets a custom connection pool on the Default Transport.
// p may be any implementation of pool.Pool, including *pool.ConnPool.
//
// Deprecated: Use Transport.DialWithPool or Transport.DialWithPoolAndHandshake
// on a dedicated Transport instance instead of mutating global state.
func SetGlobalConnPool(p pool.Pool) {
	dt := getDefault()
	dt.mu.Lock()
	defer dt.mu.Unlock()
	if dt.pool != nil {
		dt.pool.Close()
	}
	dt.pool = p
}

// GetGlobalConnPool returns the Default Transport's connection pool.
//
// Deprecated: Use a dedicated Transport instance instead of accessing global state.
func GetGlobalConnPool() pool.Pool {
	dt := getDefault()
	dt.mu.RLock()
	defer dt.mu.RUnlock()
	return dt.pool
}

// SetGlobalShutdownManager sets a custom shutdown manager on the Default Transport.
// The previous shutdown manager is shut down gracefully before being replaced.
//
// Deprecated: Use a dedicated Transport instance instead of mutating global state.
func SetGlobalShutdownManager(sm Shutdowner) {
	dt := getDefault()
	dt.mu.Lock()
	defer dt.mu.Unlock()
	if dt.sm != nil {
		dt.sm.Shutdown()
	}
	dt.sm = sm
}

// GetGlobalShutdownManager returns the Default Transport's shutdown manager.
//
// Deprecated: Use a dedicated Transport instance instead of accessing global state.
func GetGlobalShutdownManager() Shutdowner {
	dt := getDefault()
	dt.mu.RLock()
	defer dt.mu.RUnlock()
	return dt.sm
}

// GracefulShutdown initiates graceful shutdown of all Default Transport components.
//
// Deprecated: Use Transport.GracefulShutdown on a dedicated Transport instance instead.
func GracefulShutdown() error {
	log.WithFields(logger.Fields{"pkg": "noise", "func": "GracefulShutdown"}).Debug("Initiating graceful shutdown of global components")
	return getDefault().GracefulShutdown()
}
