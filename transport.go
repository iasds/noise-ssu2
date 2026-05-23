package noise

import (
	"io"
	"net"
	"sync"

	"github.com/go-i2p/logger"
	"github.com/go-i2p/pool"
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
	t.mu.RLock()
	sm := t.sm
	t.mu.RUnlock()
	return openAndWrapTransport(
		sm,
		func() error { return validateDialParams(network, addr, config) },
		func() (io.Closer, error) { return createNewConn(network, addr) },
		func(c io.Closer) (*NoiseConn, error) {
			return createNoiseConn(c.(net.Conn), config, network, addr)
		},
	)
}

// Listen creates a Noise-wrapped listener on the given address using this Transport's
// ShutdownManager. It is the Transport-scoped equivalent of ListenNoise.
func (t *Transport) Listen(network, addr string, config *ListenerConfig) (*NoiseListener, error) {
	log.WithFields(logger.Fields{"pkg": "noise", "func": "Transport.Listen", "network": network, "address": addr}).Debug("starting")
	t.mu.RLock()
	sm := t.sm
	t.mu.RUnlock()
	return openAndWrapTransport(
		sm,
		func() error { return validateListenParams(network, addr, config) },
		func() (io.Closer, error) { return createNewListener(network, addr) },
		func(c io.Closer) (*NoiseListener, error) {
			return createNoiseListener(c.(net.Listener), config, network, addr)
		},
	)
}
