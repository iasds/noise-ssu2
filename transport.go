package noise

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/go-i2p/go-noise/pool"
	"github.com/samber/oops"
)

// globalConnPool is the default connection pool used by transport functions
var globalConnPool *pool.ConnPool

// globalShutdownManager is the default shutdown manager for coordinated shutdown
var globalShutdownManager *ShutdownManager

// init initializes the global connection pool and shutdown manager with default settings
func init() {
	globalConnPool = pool.NewConnPool(&pool.PoolConfig{
		MaxSize: 10,
		MaxAge:  30 * time.Minute,
		MaxIdle: 5 * time.Minute,
	})
	globalShutdownManager = NewShutdownManager(30 * time.Second)
}

// SetGlobalConnPool sets a custom connection pool for transport functions
func SetGlobalConnPool(p *pool.ConnPool) {
	if globalConnPool != nil {
		globalConnPool.Close()
	}
	globalConnPool = p
}

// GetGlobalConnPool returns the current global connection pool
func GetGlobalConnPool() *pool.ConnPool {
	return globalConnPool
}

// SetGlobalShutdownManager sets a custom shutdown manager for transport functions.
// The previous shutdown manager will be shut down gracefully.
func SetGlobalShutdownManager(sm *ShutdownManager) {
	if globalShutdownManager != nil {
		globalShutdownManager.Shutdown()
	}
	globalShutdownManager = sm
}

// GetGlobalShutdownManager returns the current global shutdown manager.
func GetGlobalShutdownManager() *ShutdownManager {
	return globalShutdownManager
}

// GracefulShutdown initiates graceful shutdown of all global components.
// This includes the global connection pool and all registered connections/listeners.
func GracefulShutdown() error {
	if globalShutdownManager != nil {
		return globalShutdownManager.Shutdown()
	}
	return nil
}

// DialNoise creates a connection to the given address and wraps it with NoiseConn.
// This is a convenience function that combines net.Dial and NewNoiseConn.
// For more control over the underlying connection, use net.Dial followed by NewNoiseConn.
func DialNoise(network, addr string, config *ConnConfig) (*NoiseConn, error) {
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

	noiseConn, err := NewNoiseConn(conn, config)
	if err != nil {
		// Close the underlying connection if NoiseConn creation fails
		conn.Close()
		return nil, oops.
			Code("NOISE_CONN_FAILED").
			In("transport").
			With("network", network).
			With("address", addr).
			Wrapf(err, "failed to create noise connection")
	}

	// Register with global shutdown manager
	if globalShutdownManager != nil {
		noiseConn.SetShutdownManager(globalShutdownManager)
	}

	return noiseConn, nil
}

// ListenNoise creates a listener on the given address and wraps it with NoiseListener.
// This is a convenience function that combines net.Listen and NewNoiseListener.
// For more control over the underlying listener, use net.Listen followed by NewNoiseListener.
func ListenNoise(network, addr string, config *ListenerConfig) (*NoiseListener, error) {
	if err := validateListenParams(network, addr, config); err != nil {
		return nil, err
	}

	listener, err := net.Listen(network, addr)
	if err != nil {
		return nil, oops.
			Code("LISTEN_FAILED").
			In("transport").
			With("network", network).
			With("address", addr).
			Wrapf(err, "failed to listen on %s://%s", network, addr)
	}

	noiseListener, err := NewNoiseListener(listener, config)
	if err != nil {
		// Close the underlying listener if NoiseListener creation fails
		listener.Close()
		return nil, oops.
			Code("NOISE_LISTENER_FAILED").
			In("transport").
			With("network", network).
			With("address", addr).
			Wrapf(err, "failed to create noise listener")
	}

	// Register with global shutdown manager
	if globalShutdownManager != nil {
		noiseListener.SetShutdownManager(globalShutdownManager)
	}

	return noiseListener, nil
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

// validateDialParams validates parameters for DialNoise function.
func validateDialParams(network, addr string, config *ConnConfig) error {
	if network == "" {
		return oops.
			Code("INVALID_NETWORK").
			Errorf("network cannot be empty")
	}

	if addr == "" {
		return oops.
			Code("INVALID_ADDRESS").
			Errorf("address cannot be empty")
	}

	if config == nil {
		return oops.
			Code("INVALID_CONFIG").
			Errorf("config cannot be nil")
	}

	return config.Validate()
}

// validateListenParams validates parameters for ListenNoise function.
func validateListenParams(network, addr string, config *ListenerConfig) error {
	if network == "" {
		return oops.
			Code("INVALID_NETWORK").
			Errorf("network cannot be empty")
	}

	if addr == "" {
		return oops.
			Code("INVALID_ADDRESS").
			Errorf("address cannot be empty")
	}

	if config == nil {
		return oops.
			Code("INVALID_CONFIG").
			Errorf("config cannot be nil")
	}

	return config.Validate()
}

// DialNoiseWithPool creates a connection to the given address, checking the pool first.
// If a suitable connection is available in the pool, it will be reused.
// Otherwise, a new connection is created. The connection will be automatically
// returned to the pool when the NoiseConn is closed.
func DialNoiseWithPool(network, addr string, config *ConnConfig) (*NoiseConn, error) {
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
		if globalConnPool != nil {
			conn = newPutOnCloseWrapper(conn, globalConnPool)
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

// tryGetPooledConn attempts to retrieve a connection from the global pool.
// Returns the connection and a boolean indicating if it came from the pool.
func tryGetPooledConn(addr string) (net.Conn, bool) {
	if globalConnPool != nil {
		conn := globalConnPool.Get(addr)
		if conn != nil {
			return conn, true
		}
	}
	return nil, false
}

// createNewConn establishes a new network connection to the specified address.
// Returns an error with detailed context if the connection fails.
func createNewConn(network, addr string) (net.Conn, error) {
	conn, err := net.Dial(network, addr)
	if err != nil {
		return nil, oops.
			Code("DIAL_FAILED").
			In("transport").
			With("network", network).
			With("address", addr).
			Wrapf(err, "failed to dial %s://%s", network, addr)
	}
	return conn, nil
}

// createNoiseConn wraps a network connection with NoiseConn configuration.
// Returns an error with detailed context if NoiseConn creation fails.
func createNoiseConn(conn net.Conn, config *ConnConfig, network, addr string) (*NoiseConn, error) {
	noiseConn, err := NewNoiseConn(conn, config)
	if err != nil {
		return nil, oops.
			Code("NOISE_CONN_FAILED").
			In("transport").
			With("network", network).
			With("address", addr).
			Wrapf(err, "failed to create noise connection")
	}
	return noiseConn, nil
}

// putOnCloseWrapper wraps a freshly-dialed net.Conn so that its Close() call
// returns the connection to the pool for reuse rather than closing it to the OS.
// This is used by DialNoiseWithPool for new (non-pool-retrieved) connections.
type putOnCloseWrapper struct {
	net.Conn
	p    *pool.ConnPool
	mu   sync.Mutex
	done bool
}

// newPutOnCloseWrapper creates a putOnCloseWrapper for the given connection.
func newPutOnCloseWrapper(conn net.Conn, p *pool.ConnPool) net.Conn {
	return &putOnCloseWrapper{Conn: conn, p: p}
}

// Close puts the underlying connection back into the pool instead of closing it.
// The pool will close the connection itself if it is over capacity or already closed.
func (w *putOnCloseWrapper) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.done {
		return nil
	}
	w.done = true
	// pool.Put unwraps any PoolConnWrapper nesting and keys by RemoteAddr.
	return w.p.Put(w.Conn)
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

	noiseConn, err := createAndHandshakeConn(ctx, conn, config, network, addr)
	if err != nil {
		conn.Close()
		return nil, err
	}

	return noiseConn, nil
}

// createAndHandshakeConn creates a NoiseConn and performs handshake with retry logic.
func createAndHandshakeConn(ctx context.Context, conn net.Conn, config *ConnConfig, network, addr string) (*NoiseConn, error) {
	noiseConn, err := NewNoiseConn(conn, config)
	if err != nil {
		return nil, oops.
			Code("NOISE_CONN_FAILED").
			In("transport").
			With("network", network).
			With("address", addr).
			Wrapf(err, "failed to create noise connection")
	}

	// Register with global shutdown manager
	if globalShutdownManager != nil {
		noiseConn.SetShutdownManager(globalShutdownManager)
	}

	// Perform handshake with retry logic
	if err := noiseConn.HandshakeWithRetry(ctx); err != nil {
		return nil, oops.
			Code("HANDSHAKE_FAILED").
			In("transport").
			With("network", network).
			With("address", addr).
			Wrapf(err, "handshake failed")
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
	if globalConnPool != nil {
		if rawConn := globalConnPool.Get(addr); rawConn != nil {
			noiseConn, err := createAndHandshakeConn(ctx, rawConn, config, network, addr)
			if err == nil {
				return noiseConn, nil
			}
			// Pooled conn failed handshake (e.g. peer reset); fall through to fresh dial.
		}
	}

	// Create new connection with handshake
	return DialNoiseWithHandshakeContext(ctx, network, addr, config)
}
