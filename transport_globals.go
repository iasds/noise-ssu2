package noise

import (
	"context"
	"net"
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

// # Dial function selection matrix
//
// The package exposes six DialNoise variants that differ along two axes:
//
//   - Pool: reuse idle TCP connections from the Default Transport pool?
//   - Handshake: perform the Noise handshake (with retry) as part of the call?
//
// Use this matrix to pick the right entry-point:
//
//	                        │ No handshake │ Handshake (retry) │
//	────────────────────────┼──────────────┼───────────────────┤
//	No pool (fresh TCP)     │ DialNoise    │ DialNoiseWithHandshake
//	                        │              │ DialNoiseWithHandshakeContext
//	────────────────────────┼──────────────┼───────────────────┤
//	Pool (reuse TCP)        │ DialNoiseWithPool │ DialNoiseWithPoolAndHandshake
//	                        │              │ DialNoiseWithPoolAndHandshakeContext
//
// Guidance:
//   - For most applications, use [DialNoiseWithHandshakeContext] (fresh TCP +
//     handshake + context) — it provides cancellation and retry support.
//   - Use the *WithPool* variants only if you share long-lived TCP connections
//     and have already configured the Default Transport pool.
//   - Use the bare [DialNoise] only when you will perform the handshake yourself
//     on the returned *NoiseConn.
//   - Prefer constructing a [Transport] directly for production workloads to
//     avoid coupling to the package-level Default singleton.

// DialNoise creates a connection to the given address and wraps it with NoiseConn.
// This is a convenience function that delegates to the Default Transport.
//
// Deprecated: Use Transport.Dial on a dedicated Transport instance instead of
// depending on package-level global state.
func DialNoise(network, addr string, config *ConnConfig) (*NoiseConn, error) {
	return getDefault().Dial(network, addr, config)
}

// ListenNoise creates a listener on the given address and wraps it with NoiseListener.
// This is a convenience function that delegates to the Default Transport.
//
// Deprecated: Use Transport.Listen on a dedicated Transport instance instead of
// depending on package-level global state.
func ListenNoise(network, addr string, config *ListenerConfig) (*NoiseListener, error) {
	return getDefault().Listen(network, addr, config)
}

// WrapConn wraps an existing net.Conn with NoiseConn.
// This is an alias for NewNoiseConn for consistency with the transport API.
func WrapConn(conn net.Conn, config *ConnConfig) (*NoiseConn, error) {
	return NewNoiseConn(conn, config)
}

// WrapListener wraps an existing net.Listener with NoiseListener.
// This is an alias for NewNoiseListener for consistency with the transport API.
func WrapListener(listener net.Listener, config *ListenerConfig) (*NoiseListener, error) {
	return NewNoiseListener(listener, config)
}

// DialNoiseWithPool creates a connection to the given address, checking the pool first.
// If a suitable connection is available in the pool, it will be reused.
// Otherwise, a new connection is created. The connection will be automatically
// returned to the pool when the NoiseConn is closed.
//
// Deprecated: Use Transport.DialWithPool on a dedicated Transport instance instead of
// depending on package-level global state.
func DialNoiseWithPool(network, addr string, config *ConnConfig) (*NoiseConn, error) {
	return getDefault().DialWithPool(network, addr, config)
}

// DialNoiseWithHandshake creates a connection to the given address, wraps it with NoiseConn,
// and performs the handshake with retry logic. This is the recommended high-level function
// for establishing Noise connections with automatic retry capabilities.
//
// Deprecated: Use Transport.DialWithHandshake on a dedicated Transport instance instead of
// depending on package-level global state.
func DialNoiseWithHandshake(network, addr string, config *ConnConfig) (*NoiseConn, error) {
	return getDefault().DialWithHandshake(network, addr, config)
}

// DialNoiseWithHandshakeContext creates a connection with context support for cancellation.
// It combines dialing, NoiseConn creation, and handshake with retry in a single operation.
//
// Deprecated: Use Transport.DialWithHandshakeContext on a dedicated Transport instance instead of
// depending on package-level global state.
func DialNoiseWithHandshakeContext(ctx context.Context, network, addr string, config *ConnConfig) (*NoiseConn, error) {
	return getDefault().DialWithHandshakeContext(ctx, network, addr, config)
}

// DialNoiseWithPoolAndHandshake creates a connection with pool support and handshake retry.
// It checks the pool first, creates new if needed, and performs handshake with retry logic.
//
// Deprecated: Use Transport.DialWithPoolAndHandshake on a dedicated Transport instance instead of
// depending on package-level global state.
func DialNoiseWithPoolAndHandshake(network, addr string, config *ConnConfig) (*NoiseConn, error) {
	return getDefault().DialWithPoolAndHandshake(network, addr, config)
}

// DialNoiseWithPoolAndHandshakeContext combines pool checking, dialing, and handshake with context.
// It reuses a pooled raw TCP connection when available (the pool keys by
// conn.RemoteAddr().String(), which equals addr), wraps it in a new NoiseConn,
// and performs the Noise handshake. Falls back to a fresh dial if the pool is
// empty or the pooled connection fails the handshake.
//
// Deprecated: Use Transport.DialWithPoolAndHandshakeContext on a dedicated Transport instance instead of
// depending on package-level global state.
func DialNoiseWithPoolAndHandshakeContext(ctx context.Context, network, addr string, config *ConnConfig) (*NoiseConn, error) {
	return getDefault().DialWithPoolAndHandshakeContext(ctx, network, addr, config)
}
