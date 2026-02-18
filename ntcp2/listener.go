package ntcp2

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"

	noise "github.com/go-i2p/go-noise"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// NTCP2Listener implements net.Listener for accepting NTCP2 transport connections.
// It accepts raw TCP connections from the underlying listener, wraps each in a
// NoiseConn created via NTCP2Config.ToConnConfig() (which sets the correct
// CipherSuite, ProtocolName, and Modifiers), and then wraps that in an NTCP2Conn.
type NTCP2Listener struct {
	// underlying is the raw TCP listener
	underlying net.Listener

	// config contains the NTCP2-specific configuration
	config *NTCP2Config

	// addr is the NTCP2 address for this listener
	addr *NTCP2Addr

	// logger for listener events
	logger logger.Logger

	// closed indicates if the listener has been closed (atomic for lock-free reads)
	closed atomic.Bool

	// acceptMutex protects accept operations
	acceptMutex sync.Mutex
}

// NewNTCP2Listener creates a new NTCP2Listener that wraps the underlying TCP listener.
// The listener will accept connections and wrap them in NTCP2Conn instances
// configured as responders with NTCP2-specific addressing and protocol handling.
func NewNTCP2Listener(underlying net.Listener, config *NTCP2Config) (*NTCP2Listener, error) {
	if err := validateListenerInput(underlying, config); err != nil {
		return nil, err
	}

	ntcp2Addr, err := createNTCP2Address(underlying, config)
	if err != nil {
		return nil, err
	}

	return initializeListener(underlying, config, ntcp2Addr), nil
}

// validateListenerInput checks if the underlying listener and config parameters are valid
func validateListenerInput(underlying net.Listener, config *NTCP2Config) error {
	if underlying == nil {
		return oops.
			Code("INVALID_UNDERLYING_LISTENER").
			In("ntcp2").
			Errorf("underlying listener cannot be nil")
	}

	if config == nil {
		return oops.
			Code("INVALID_CONFIG").
			In("ntcp2").
			Errorf("ntcp2 config cannot be nil")
	}

	if err := config.Validate(); err != nil {
		return oops.
			Code("INVALID_CONFIG").
			In("ntcp2").
			With("listener_addr", underlying.Addr().String()).
			Wrapf(err, "invalid ntcp2 listener configuration")
	}

	return nil
}

// createNTCP2Address creates the NTCP2 address for the listener from the underlying address and config
func createNTCP2Address(underlying net.Listener, config *NTCP2Config) (*NTCP2Addr, error) {
	ntcp2Addr, err := NewNTCP2Addr(underlying.Addr(), config.RouterHash, "responder")
	if err != nil {
		return nil, oops.
			Code("ADDR_CREATION_FAILED").
			In("ntcp2").
			With("listener_addr", underlying.Addr().String()).
			Wrapf(err, "failed to create ntcp2 address")
	}

	return ntcp2Addr, nil
}

// initializeListener creates and configures the final NTCP2Listener with logging
func initializeListener(underlying net.Listener, config *NTCP2Config, ntcp2Addr *NTCP2Addr) *NTCP2Listener {
	nl := &NTCP2Listener{
		underlying: underlying,
		config:     config,
		addr:       ntcp2Addr,
		logger:     *log,
	}

	nl.logger.Info("NTCP2 listener created",
		"pattern", config.Pattern,
		"listener_address", underlying.Addr().String(),
		"router_hash", formatRouterHash(config.RouterHash))

	return nl
}

// createResponderConnConfig creates a ConnConfig for an accepted (responder)
// connection via the full NTCP2Config.ToConnConfig() path, ensuring the
// CipherSuite, ProtocolName, and Modifiers are all correctly set.
// It also returns the per-connection NTCP2Config so the PostHandshakeHook's
// SipHash keys can be propagated to the NTCP2Conn after handshake.
func (nl *NTCP2Listener) createResponderConnConfig() (*noise.ConnConfig, *NTCP2Config, error) {
	// Clone the listener's config to get an independent per-connection config.
	// Clone() avoids copying the atomic.Pointer and is resilient to new fields.
	responderCfg := nl.config.Clone()
	responderCfg.Initiator = false
	connConfig, err := responderCfg.ToConnConfig()
	if err != nil {
		return nil, nil, oops.
			Code("CONN_CONFIG_FAILED").
			In("ntcp2").
			With("listener_addr", nl.addr.String()).
			Wrapf(err, "failed to create responder ConnConfig")
	}
	return connConfig, responderCfg, nil
}

// createRemoteNTCP2Addr creates the remote NTCP2 address for the accepted connection.
// Note: PeerStatic() returns the remote peer's Noise static public key (32 bytes),
// which is used here as a placeholder router hash. The NTCP2 spec defines the
// router hash as SHA-256(RouterIdentity), where the static key is only part of
// the full RouterIdentity. The router transport layer
// (github.com/go-i2p/go-i2p/lib/transport/ntcp) should use PeerStaticKey() and
// HandshakeHash() from NTCP2Conn, parse the full RouterIdentity from message 3
// part 2 via github.com/go-i2p/common/router_identity, and compute the proper
// hash via github.com/go-i2p/common/data.HashData().
func (nl *NTCP2Listener) createRemoteNTCP2Addr(noiseConn *noise.NoiseConn) (*NTCP2Addr, error) {
	remoteRouterHash := noiseConn.PeerStatic()
	if len(remoteRouterHash) == 0 {
		// Fall back to config if handshake didn't provide the peer's static key
		remoteRouterHash = make([]byte, RouterHashSize)
		if nl.config.RemoteRouterHash != nil {
			copy(remoteRouterHash, nl.config.RemoteRouterHash)
		}
	}
	remoteAddr, err := NewNTCP2Addr(noiseConn.RemoteAddr(), remoteRouterHash, "initiator")
	if err != nil {
		return nil, oops.
			Code("REMOTE_ADDR_FAILED").
			In("ntcp2").
			With("listener_addr", nl.addr.String()).
			With("remote_addr", noiseConn.RemoteAddr().String()).
			Wrapf(err, "failed to create remote ntcp2 address")
	}
	return remoteAddr, nil
}

// wrapInNTCP2Conn wraps the noise connection in an NTCP2Conn.
// perConnConfig is the per-connection NTCP2Config whose PostHandshakeHook
// will store derived SipHash keys; it is saved on the conn so that
// PropagateSipHash() can copy them after the handshake completes.
func (nl *NTCP2Listener) wrapInNTCP2Conn(noiseConn *noise.NoiseConn, remoteAddr *NTCP2Addr, perConnConfig *NTCP2Config) (*NTCP2Conn, error) {
	ntcp2Conn, err := NewNTCP2Conn(noiseConn, nl.addr, remoteAddr)
	if err != nil {
		return nil, oops.
			Code("NTCP2_WRAP_FAILED").
			In("ntcp2").
			With("listener_addr", nl.addr.String()).
			With("remote_addr", noiseConn.RemoteAddr().String()).
			Wrapf(err, "failed to create ntcp2 connection")
	}

	// Store the per-connection config so PropagateSipHash can read derived keys.
	ntcp2Conn.SetNTCP2Config(perConnConfig)

	return ntcp2Conn, nil
}

// Accept waits for and returns the next connection to the listener.
// The returned connection is wrapped in an NTCP2Conn configured as a responder
// with the full NTCP2 cipher suite, protocol name, and modifiers.
func (nl *NTCP2Listener) Accept() (net.Conn, error) {
	// Only hold acceptMutex for the state check and raw TCP accept.
	// Release it before the Noise handshake wrapping so that multiple
	// connections can handshake concurrently.
	nl.acceptMutex.Lock()
	if err := nl.validateAcceptState(); err != nil {
		nl.acceptMutex.Unlock()
		return nil, err
	}

	// Accept raw TCP connection from the underlying listener.
	underlying, err := nl.underlying.Accept()
	nl.acceptMutex.Unlock() // Release before expensive handshake wrapping
	if err != nil {
		return nil, oops.
			Code("ACCEPT_FAILED").
			In("ntcp2").
			With("listener_addr", nl.addr.String()).
			Wrapf(err, "failed to accept connection")
	}

	// Create ConnConfig with full NTCP2 settings (CipherSuite, ProtocolName, Modifiers).
	connConfig, perConnConfig, err := nl.createResponderConnConfig()
	if err != nil {
		underlying.Close()
		return nil, err
	}

	// Wrap in NoiseConn using the properly configured ConnConfig.
	noiseConn, err := noise.NewNoiseConn(underlying, connConfig)
	if err != nil {
		underlying.Close()
		return nil, oops.
			Code("NOISE_CONN_FAILED").
			In("ntcp2").
			With("listener_addr", nl.addr.String()).
			With("remote_addr", underlying.RemoteAddr().String()).
			Wrapf(err, "failed to create noise connection")
	}

	remoteAddr, err := nl.createRemoteNTCP2Addr(noiseConn)
	if err != nil {
		noiseConn.Close()
		return nil, err
	}

	ntcp2Conn, err := nl.wrapInNTCP2Conn(noiseConn, remoteAddr, perConnConfig)
	if err != nil {
		noiseConn.Close()
		return nil, err
	}

	nl.logAcceptedConnection(ntcp2Conn)
	return ntcp2Conn, nil
}

// validateAcceptState checks if the listener is in a valid state for accepting connections.
func (nl *NTCP2Listener) validateAcceptState() error {
	if nl.isClosed() {
		return oops.
			Code("LISTENER_CLOSED").
			In("ntcp2").
			With("listener_addr", nl.addr.String()).
			Errorf("ntcp2 listener is closed")
	}
	return nil
}

// logAcceptedConnection logs details about the newly accepted connection.
func (nl *NTCP2Listener) logAcceptedConnection(ntcp2Conn *NTCP2Conn) {
	nl.logger.Debug("accepted new NTCP2 connection",
		"listener_addr", nl.addr.String(),
		"remote_addr", ntcp2Conn.RemoteAddr().String())
}

// Close closes the listener and prevents new connections from being accepted.
// Any blocked Accept operations will be unblocked and return errors.
func (nl *NTCP2Listener) Close() error {
	if !nl.closed.CompareAndSwap(false, true) {
		return nil // Already closed
	}

	err := nl.underlying.Close()
	if err != nil {
		nl.logger.Error("error closing underlying listener",
			"listener_addr", nl.addr.String(),
			"error", err.Error())

		return oops.
			Code("CLOSE_FAILED").
			In("ntcp2").
			With("listener_addr", nl.addr.String()).
			Wrapf(err, "failed to close underlying listener")
	}

	nl.logger.Info("NTCP2 listener closed",
		"listener_addr", nl.addr.String())

	return nil
}

// Addr returns the listener's network address.
// This is an NTCP2Addr that wraps the underlying listener's address.
func (nl *NTCP2Listener) Addr() net.Addr {
	return nl.addr
}

// isClosed returns true if the listener has been closed.
// Thread-safe: uses atomic.Bool.Load().
func (nl *NTCP2Listener) isClosed() bool {
	return nl.closed.Load()
}

// formatRouterHash formats a router hash for logging (first 8 bytes as hex).
func formatRouterHash(hash []byte) string {
	if len(hash) < 8 {
		return "invalid"
	}
	return fmt.Sprintf("%x...", hash[:8])
}

// AcceptWithHandshake waits for the next connection and automatically
// performs the NTCP2 handshake. This mirrors DialNTCP2WithHandshakeContext
// for the responder side.
func (nl *NTCP2Listener) AcceptWithHandshake(ctx context.Context) (*NTCP2Conn, error) {
	conn, err := nl.Accept()
	if err != nil {
		return nil, err
	}
	ntcp2Conn := conn.(*NTCP2Conn)
	if err := ntcp2Conn.UnderlyingConn().Handshake(ctx); err != nil {
		ntcp2Conn.Close()
		return nil, oops.
			Code("HANDSHAKE_FAILED").
			In("ntcp2").
			With("listener_addr", nl.addr.String()).
			Wrapf(err, "NTCP2 handshake failed during accept")
	}
	// Propagate SipHash keys derived by the PostHandshakeHook to the conn.
	ntcp2Conn.PropagateSipHash()
	return ntcp2Conn, nil
}
