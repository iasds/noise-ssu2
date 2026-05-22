package noise

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/go-i2p/go-noise/pool"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

var (
	defaultOnce sync.Once
	defaultInst *Transport
)

// Default is the package-level Transport used by DialNoise, ListenNoise, etc.
// It is lazily initialised on first use via getDefault().
var Default *Transport

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
func GetGlobalConnPool() pool.Pool {
	dt := getDefault()
	dt.mu.RLock()
	defer dt.mu.RUnlock()
	return dt.pool
}

// SetGlobalShutdownManager sets a custom shutdown manager on the Default Transport.
// The previous shutdown manager is shut down gracefully before being replaced.
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
func GetGlobalShutdownManager() Shutdowner {
	dt := getDefault()
	dt.mu.RLock()
	defer dt.mu.RUnlock()
	return dt.sm
}

// GracefulShutdown initiates graceful shutdown of all Default Transport components.
func GracefulShutdown() error {
	log.WithFields(logger.Fields{"pkg": "noise", "func": "GracefulShutdown"}).Debug("Initiating graceful shutdown of global components")
	return getDefault().GracefulShutdown()
}

// DialNoise creates a connection to the given address and wraps it with NoiseConn.
// This is a convenience function that delegates to the Default Transport.
func DialNoise(network, addr string, config *ConnConfig) (*NoiseConn, error) {
	return getDefault().Dial(network, addr, config)
}

// ListenNoise creates a listener on the given address and wraps it with NoiseListener.
// This is a convenience function that delegates to the Default Transport.
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
func DialNoiseWithPool(network, addr string, config *ConnConfig) (*NoiseConn, error) {
	log.WithFields(logger.Fields{"pkg": "noise", "func": "DialNoiseWithPool", "network": network, "address": addr}).Debug("starting")
	if err := validateDialParams(network, addr, config); err != nil {
		return nil, err
	}

	conn, fromPool := tryGetPooledConn(addr)
	if conn == nil {
		var err error
		conn, err = createNewConn(network, addr)
		if err != nil {
			return nil, err
		}
		// Wrap the freshly-dialed conn so that NoiseConn.Close() returns it to
		// the pool instead of closing it to the OS.  Pool-retrieved conns are
		// already wrapped in PoolConnWrapper by ConnPool.Get(), which handles
		// the release path; this wrapper covers only the new-connection case.
		dt := getDefault()
		dt.mu.RLock()
		p := dt.pool
		dt.mu.RUnlock()
		if p != nil {
			conn = newPutOnCloseWrapper(conn, p)
		}
	}
	_ = fromPool // pool-retrieved path is handled by PoolConnWrapper

	noiseConn, err := createNoiseConn(conn, config, network, addr)
	if err != nil {
		conn.Close()
		return nil, err
	}

	return noiseConn, nil
}

// DialNoiseWithHandshake creates a connection to the given address, wraps it with NoiseConn,
// and performs the handshake with retry logic. This is the recommended high-level function
// for establishing Noise connections with automatic retry capabilities.
func DialNoiseWithHandshake(network, addr string, config *ConnConfig) (*NoiseConn, error) {
	return DialNoiseWithHandshakeContext(context.Background(), network, addr, config)
}

// DialNoiseWithHandshakeContext creates a connection with context support for cancellation.
// It combines dialing, NoiseConn creation, and handshake with retry in a single operation.
func DialNoiseWithHandshakeContext(ctx context.Context, network, addr string, config *ConnConfig) (*NoiseConn, error) {
	if err := validateDialParams(network, addr, config); err != nil {
		return nil, err
	}

	conn, err := net.Dial(network, addr)
	if err != nil {
		return nil, oops.
			Code("DIAL_FAILED").
			In("transport").
			With("network", network).
			With("address", addr).
			Wrapf(err, "failed to dial %s://%s", network, addr)
	}

	// createAndHandshakeConn takes ownership of conn on error (closes it
	// and zeros key material), so we must not close conn here.
	noiseConn, err := createAndHandshakeConn(ctx, conn, config, network, addr)
	if err != nil {
		return nil, err
	}

	return noiseConn, nil
}

// DialNoiseWithPoolAndHandshake creates a connection with pool support and handshake retry.
// It checks the pool first, creates new if needed, and performs handshake with retry logic.
func DialNoiseWithPoolAndHandshake(network, addr string, config *ConnConfig) (*NoiseConn, error) {
	return DialNoiseWithPoolAndHandshakeContext(context.Background(), network, addr, config)
}

// DialNoiseWithPoolAndHandshakeContext combines pool checking, dialing, and handshake with context.
// It reuses a pooled raw TCP connection when available (the pool keys by
// conn.RemoteAddr().String(), which equals addr), wraps it in a new NoiseConn,
// and performs the Noise handshake. Falls back to a fresh dial if the pool is
// empty or the pooled connection fails the handshake.
func DialNoiseWithPoolAndHandshakeContext(ctx context.Context, network, addr string, config *ConnConfig) (*NoiseConn, error) {
	if err := validateDialParams(network, addr, config); err != nil {
		return nil, err
	}

	// pool.Put stores entries under conn.RemoteAddr().String(), which is the
	// plain "host:port" string — use addr directly so the keys match.
	dt := getDefault()
	dt.mu.RLock()
	p := dt.pool
	dt.mu.RUnlock()
	if p != nil {
		if rawConn := p.Get(addr); rawConn != nil {
			noiseConn, err := createAndHandshakeConn(ctx, rawConn, config, network, addr)
			if err == nil {
				return noiseConn, nil
			}
			// createAndHandshakeConn takes ownership of rawConn on error
			// (closes it to release the PoolConnWrapper and zero keys).
			// Fall through to fresh dial.
		}
	}

	// Create new connection with handshake
	return DialNoiseWithHandshakeContext(ctx, network, addr, config)
}
