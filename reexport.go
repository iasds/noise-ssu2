// Package noise provides a high-level net.Conn/net.Listener/net.Addr wrapper
// around the Noise Protocol Framework. This file re-exports the public API
// from the noise/conn, noise/listener, and noise/shutdown sub-packages so
// that callers continue to use the root import path unchanged.
package noise

import (
	"net"
	"time"

	"github.com/go-i2p/go-noise/conn"
	"github.com/go-i2p/go-noise/listener"
	"github.com/go-i2p/go-noise/shutdown"
)

// ─── Type aliases (zero-cost: no wrapping, full method set preserved) ────────

// NoiseConn is an alias for conn.Conn.
type NoiseConn = conn.Conn

// NoiseAddr is an alias for conn.Addr.
type NoiseAddr = conn.Addr

// ConnConfig is an alias for conn.ConnConfig.
type ConnConfig = conn.ConnConfig

// ConnState is an alias for conn.ConnState.
type ConnState = conn.ConnState

// NoiseListener is an alias for listener.Listener.
type NoiseListener = listener.Listener

// ListenerConfig is an alias for listener.ListenerConfig.
type ListenerConfig = listener.ListenerConfig

// ShutdownManager is an alias for shutdown.ShutdownManager.
type ShutdownManager = shutdown.ShutdownManager

// ShutdownConn is an alias for shutdown.ShutdownConn.
type ShutdownConn = shutdown.ShutdownConn

// ShutdownListener is an alias for shutdown.ShutdownListener.
type ShutdownListener = shutdown.ShutdownListener

// Shutdowner is an alias for shutdown.Shutdowner.
// Accept Shutdowner instead of *ShutdownManager to allow substitution of test
// doubles or alternative shutdown coordinators.
type Shutdowner = shutdown.Shutdowner

// ─── Constant re-exports ─────────────────────────────────────────────────────

// Connection state constants forwarded from noise/conn for backwards compatibility.
const (
	StateInit        = conn.StateInit
	StateHandshaking = conn.StateHandshaking
	StateEstablished = conn.StateEstablished
	StateClosed      = conn.StateClosed
)

// ─── Constructor wrappers ─────────────────────────────────────────────────────

// NewNoiseConn creates a new NoiseConn wrapping the given net.Conn.
func NewNoiseConn(underlying net.Conn, config *ConnConfig) (*NoiseConn, error) {
	return conn.NewNoiseConn(underlying, config)
}

// NewNoiseAddr creates a new NoiseAddr from an underlying net.Addr.
func NewNoiseAddr(underlying net.Addr, pattern, role string) *NoiseAddr {
	return conn.NewNoiseAddr(underlying, pattern, role)
}

// NewConnConfig creates a ConnConfig with sensible defaults.
func NewConnConfig(pattern string, initiator bool) *ConnConfig {
	return conn.NewConnConfig(pattern, initiator)
}

// NewNoiseListener wraps an existing net.Listener with Noise Protocol encryption.
func NewNoiseListener(underlying net.Listener, config *ListenerConfig) (*NoiseListener, error) {
	return listener.NewNoiseListener(underlying, config)
}

// NewListenerConfig creates a ListenerConfig with sensible defaults.
func NewListenerConfig(pattern string) *ListenerConfig {
	return listener.NewListenerConfig(pattern)
}

// NewShutdownManager creates a ShutdownManager with the given graceful-shutdown timeout.
func NewShutdownManager(timeout time.Duration) *ShutdownManager {
	return shutdown.NewShutdownManager(timeout)
}

// ValidateHandshakePattern reports whether pattern is a known Noise handshake
// pattern name, accepting short ("XX") and full protocol names.
func ValidateHandshakePattern(pattern string) error {
	return conn.ValidateHandshakePattern(pattern)
}
