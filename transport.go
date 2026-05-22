package noise

import (
	"context"
	"io"
	"net"
	"sync"
	"time"

	"github.com/go-i2p/go-noise/pool"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// Transport owns a Pool and ShutdownManager and provides Dial/Listen methods.
// Construct one with NewTransport; use the package-level Default for the
// conventional singleton.
type Transport struct {
	mu   sync.RWMutex
	pool pool.Pool
	sm   Shutdowner
}

// NewTransport creates a Transport backed by the given pool and shutdown
// manager. Either may be nil: a nil pool disables connection reuse; a nil
// ShutdownManager disables shutdown registration.
func NewTransport(p pool.Pool, sm Shutdowner) *Transport {
	return &Transport{pool: p, sm: sm}
}

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

// GracefulShutdown shuts down this Transport's ShutdownManager and Pool.
func (t *Transport) GracefulShutdown() error {
	t.mu.RLock()
	sm := t.sm
	cp := t.pool
	t.mu.RUnlock()
	var shutdownErr error
	if sm != nil {
		shutdownErr = sm.Shutdown()
	}
	if cp != nil {
		if err := cp.Close(); err != nil && shutdownErr == nil {
			shutdownErr = err
		}
	}
	return shutdownErr
}

// Dial creates a Noise-wrapped connection to the given address using this Transport's
// ShutdownManager and Pool. It is the Transport-scoped equivalent of DialNoise.
func (t *Transport) Dial(network, addr string, config *ConnConfig) (*NoiseConn, error) {
	log.WithFields(logger.Fields{"pkg": "noise", "func": "Transport.Dial", "network": network, "address": addr}).Debug("starting")
	nc, err := openAndWrapTransport(
		func() error { return validateDialParams(network, addr, config) },
		func() (io.Closer, error) { return createNewConn(network, addr) },
		func(c io.Closer) (*NoiseConn, error) {
			return createNoiseConn(c.(net.Conn), config, network, addr)
		},
	)
	if err != nil {
		return nil, err
	}
	t.mu.RLock()
	sm := t.sm
	t.mu.RUnlock()
	if sm != nil {
		nc.SetShutdownManager(sm)
	}
	return nc, nil
}

// Listen creates a Noise-wrapped listener on the given address using this Transport's
// ShutdownManager. It is the Transport-scoped equivalent of ListenNoise.
func (t *Transport) Listen(network, addr string, config *ListenerConfig) (*NoiseListener, error) {
	log.WithFields(logger.Fields{"pkg": "noise", "func": "Transport.Listen", "network": network, "address": addr}).Debug("starting")
	nl, err := openAndWrapTransport(
		func() error { return validateListenParams(network, addr, config) },
		func() (io.Closer, error) { return createNewListener(network, addr) },
		func(c io.Closer) (*NoiseListener, error) {
			return createNoiseListener(c.(net.Listener), config, network, addr)
		},
	)
	if err != nil {
		return nil, err
	}
	t.mu.RLock()
	sm := t.sm
	t.mu.RUnlock()
	if sm != nil {
		nl.SetShutdownManager(sm)
	}
	return nl, nil
}

// shutdownRegisterer is implemented by types that support global shutdown management.
type shutdownRegisterer interface {
	SetShutdownManager(Shutdowner)
}

// wrapTransportError creates a contextual error with transport metadata.
// This consolidates the repeated oops error wrapping pattern used by
// DialNoise and ListenNoise.
func wrapTransportError(code, network, addr, msg string, err error, args ...interface{}) error {
	return oops.
		Code(code).
		In("transport").
		With("network", network).
		With("address", addr).
		Wrapf(err, msg, args...)
}

// registerShutdownWith registers a shutdownRegisterer with the given shutdown
// manager if it is non-nil. This is a helper for openAndWrapTransport.
func registerShutdownWith(target shutdownRegisterer, sm *ShutdownManager) {
	if sm != nil {
		target.SetShutdownManager(sm)
	}
}

// openAndWrapTransport validates parameters, opens a network resource, wraps it
// in a Noise layer, and registers it for global shutdown. It consolidates the
// shared validate-open-wrap-cleanup-register pattern used by DialNoise and
// ListenNoise, eliminating the structural duplication between them.
func openAndWrapTransport[R shutdownRegisterer](
	validate func() error,
	open func() (io.Closer, error),
	wrap func(io.Closer) (R, error),
) (R, error) {
	var zero R
	if err := validate(); err != nil {
		return zero, err
	}
	resource, err := open()
	if err != nil {
		return zero, err
	}
	result, err := wrap(resource)
	if err != nil {
		resource.Close()
		return zero, err
	}
	return result, nil
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

// validateNetworkAddr validates the network and address parameters shared
// by validateDialParams and validateListenParams.
func validateNetworkAddr(network, addr string) error {
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

	return nil
}

// validateDialParams validates parameters for DialNoise function.
func validateDialParams(network, addr string, config *ConnConfig) error {
	if err := validateNetworkAddr(network, addr); err != nil {
		return err
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
	if err := validateNetworkAddr(network, addr); err != nil {
		return err
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

// tryGetPooledConn attempts to retrieve a connection from the Default Transport's pool.
// Returns the connection and a boolean indicating if it came from the pool.
func tryGetPooledConn(addr string) (net.Conn, bool) {
	dt := getDefault()
	dt.mu.RLock()
	p := dt.pool
	dt.mu.RUnlock()
	if p != nil {
		conn := p.Get(addr)
		if conn != nil {
			return conn, true
		}
	}
	return nil, false
}

// createNewConn establishes a new network connection to the specified address.
// Returns an error with detailed context if the connection fails.
func createNewConn(network, addr string) (net.Conn, error) {
	log.WithFields(logger.Fields{"pkg": "noise", "func": "createNewConn", "network": network, "address": addr}).Debug("Dialing new connection")
	conn, err := net.Dial(network, addr)
	if err != nil {
		log.WithFields(logger.Fields{"pkg": "noise", "func": "createNewConn", "network": network, "address": addr}).WithError(err).Error("Dial failed")
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
	log.WithFields(logger.Fields{"pkg": "noise", "func": "createNoiseConn", "network": network, "address": addr}).Debug("Creating NoiseConn wrapper")
	noiseConn, err := NewNoiseConn(conn, config)
	if err != nil {
		log.WithFields(logger.Fields{"pkg": "noise", "func": "createNoiseConn"}).WithError(err).Error("Failed to create NoiseConn")
		return nil, oops.
			Code("NOISE_CONN_FAILED").
			In("transport").
			With("network", network).
			With("address", addr).
			Wrapf(err, "failed to create noise connection")
	}
	return noiseConn, nil
}

// createNewListener establishes a new network listener on the specified address.
// Returns an error with detailed context if the listen call fails.
func createNewListener(network, addr string) (net.Listener, error) {
	log.WithFields(logger.Fields{"pkg": "noise", "func": "createNewListener", "network": network, "address": addr}).Debug("Creating new listener")
	listener, err := net.Listen(network, addr)
	if err != nil {
		log.WithFields(logger.Fields{"pkg": "noise", "func": "createNewListener", "network": network, "address": addr}).WithError(err).Error("Listen failed")
		return nil, wrapTransportError("LISTEN_FAILED", network, addr,
			"failed to listen on %s://%s", err, network, addr)
	}
	return listener, nil
}

// createNoiseListener wraps a network listener with NoiseListener configuration.
// Returns an error with detailed context if NoiseListener creation fails.
func createNoiseListener(listener net.Listener, config *ListenerConfig, network, addr string) (*NoiseListener, error) {
	noiseListener, err := NewNoiseListener(listener, config)
	if err != nil {
		return nil, wrapTransportError("NOISE_LISTENER_FAILED", network, addr,
			"failed to create noise listener", err)
	}
	return noiseListener, nil
}

// putOnCloseWrapper wraps a freshly-dialed net.Conn so that its Close() call
// returns the connection to the pool for reuse rather than closing it to the OS.
// This is used by DialNoiseWithPool for new (non-pool-retrieved) connections.
type putOnCloseWrapper struct {
	net.Conn
	p    pool.Pool
	mu   sync.Mutex
	done bool
}

// newPutOnCloseWrapper creates a putOnCloseWrapper for the given connection.
func newPutOnCloseWrapper(conn net.Conn, p pool.Pool) net.Conn {
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

	// createAndHandshakeConn takes ownership of conn on error (closes it
	// and zeros key material), so we must not close conn here.
	noiseConn, err := createAndHandshakeConn(ctx, conn, config, network, addr)
	if err != nil {
		return nil, err
	}

	return noiseConn, nil
}

// createAndHandshakeConn creates a NoiseConn and performs handshake with retry logic.
// On error, the function closes conn (directly or via noiseConn.Close) so the
// caller must NOT close conn when an error is returned.
func createAndHandshakeConn(ctx context.Context, conn net.Conn, config *ConnConfig, network, addr string) (*NoiseConn, error) {
	noiseConn, err := NewNoiseConn(conn, config)
	if err != nil {
		conn.Close()
		return nil, oops.
			Code("NOISE_CONN_FAILED").
			In("transport").
			With("network", network).
			With("address", addr).
			Wrapf(err, "failed to create noise connection")
	}

	// Register with Default Transport's shutdown manager
	if sm := GetGlobalShutdownManager(); sm != nil {
		noiseConn.SetShutdownManager(sm)
	}

	// Perform handshake with retry logic
	if err := noiseConn.HandshakeWithRetry(ctx); err != nil {
		// Close noiseConn to zero key material and close underlying conn
		noiseConn.Close()
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
