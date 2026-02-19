package ssu2

import (
	"context"
	"net"

	"github.com/samber/oops"
)

// DialSSU2 creates an SSU2 connection to the remote address without performing handshake.
// Use DialSSU2WithHandshake for automatic handshake completion.
//
// Design rationale:
// - Follows standard library pattern (net.Dial)
// - Uses UDP for connectionless transport
// - Creates minimal viable connection wrapper
// - Handshake is separate for flexibility (manual control)
//
// Parameters:
//   - localAddr: Local UDP address to bind to (use nil for automatic)
//   - remoteAddr: Remote UDP address to connect to
//   - config: SSU2 configuration for the connection
//
// Returns an SSU2Conn ready for handshake, or an error if creation fails.
func DialSSU2(localAddr, remoteAddr *net.UDPAddr, config *SSU2Config) (*SSU2Conn, error) {
	if err := validateDialParams(localAddr, remoteAddr, config); err != nil {
		return nil, err
	}

	// Create UDP connection
	packetConn, err := createUDPConnection(localAddr)
	if err != nil {
		return nil, err
	}

	// Create SSU2 connection wrapper
	conn, err := createSSU2Connection(packetConn, remoteAddr, config)
	if err != nil {
		packetConn.Close()
		return nil, err
	}

	return conn, nil
}

// DialSSU2WithHandshake creates an SSU2 connection and performs the handshake automatically.
// This is the recommended function for most use cases.
func DialSSU2WithHandshake(localAddr, remoteAddr *net.UDPAddr, config *SSU2Config) (*SSU2Conn, error) {
	return DialSSU2WithHandshakeContext(context.Background(), localAddr, remoteAddr, config)
}

// DialSSU2WithHandshakeContext creates an SSU2 connection and performs the handshake with context.
// The context can be used to cancel the dial or handshake operations.
//
// Design rationale:
// - Context enables timeout and cancellation
// - Follows Go standard patterns (context.Context for cancellable operations)
// - Automatic cleanup on handshake failure
//
// Parameters:
//   - ctx: Context for cancellation and timeout
//   - localAddr: Local UDP address to bind to (use nil for automatic)
//   - remoteAddr: Remote UDP address to connect to
//   - config: SSU2 configuration for the connection
//
// Returns an established SSU2Conn, or an error if dial or handshake fails.
func DialSSU2WithHandshakeContext(ctx context.Context, localAddr, remoteAddr *net.UDPAddr, config *SSU2Config) (*SSU2Conn, error) {
	conn, err := DialSSU2(localAddr, remoteAddr, config)
	if err != nil {
		return nil, err
	}

	// Perform handshake with context
	if err := conn.Handshake(ctx); err != nil {
		conn.Close()
		return nil, oops.
			Code("HANDSHAKE_FAILED").
			In("ssu2_transport").
			With("local_address", localAddr).
			With("remote_address", remoteAddr).
			Wrapf(err, "SSU2 handshake failed")
	}

	return conn, nil
}

// ListenSSU2 creates an SSU2 listener on the specified address.
// The listener is ready to accept incoming connections immediately after creation.
//
// Design rationale:
// - Follows standard library pattern (net.Listen)
// - Creates UDP socket for connectionless transport
// - Starts packet routing automatically
// - Single socket multiplexed across all connections
//
// Parameters:
//   - addr: Local UDP address to listen on
//   - config: SSU2 configuration for accepted connections
//
// Returns an SSU2Listener ready to accept, or an error if creation fails.
func ListenSSU2(addr *net.UDPAddr, config *SSU2Config) (*SSU2Listener, error) {
	if err := validateListenParams(addr, config); err != nil {
		return nil, err
	}

	// Create UDP listener
	packetConn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, oops.
			Code("LISTEN_FAILED").
			In("ssu2_transport").
			With("address", addr).
			Wrapf(err, "failed to listen on UDP address")
	}

	// Create SSU2 listener wrapper
	listener, err := NewSSU2Listener(packetConn, config)
	if err != nil {
		packetConn.Close()
		return nil, oops.
			Code("SSU2_LISTENER_FAILED").
			In("ssu2_transport").
			With("address", addr).
			Wrapf(err, "failed to create SSU2 listener")
	}

	// Start packet routing
	if err := listener.Start(); err != nil {
		listener.Close()
		return nil, oops.
			Code("LISTENER_START_FAILED").
			In("ssu2_transport").
			With("address", addr).
			Wrapf(err, "failed to start SSU2 listener")
	}

	return listener, nil
}

// WrapSSU2Conn wraps an existing net.PacketConn with SSU2Conn.
// This function provides manual control over the underlying connection.
//
// Design rationale:
// - Allows reuse of existing PacketConn (e.g., with custom options)
// - Does NOT perform handshake (caller controls timing)
// - Validates connection type for safety
//
// Parameters:
//   - underlying: Existing PacketConn to wrap
//   - remoteAddr: Remote UDP address for the connection
//   - config: SSU2 configuration for the connection
//
// Returns an SSU2Conn wrapper, or an error if wrapping fails.
func WrapSSU2Conn(underlying net.PacketConn, remoteAddr *net.UDPAddr, config *SSU2Config) (*SSU2Conn, error) {
	if err := validateWrapConnParams(underlying, remoteAddr, config); err != nil {
		return nil, err
	}

	return createSSU2Connection(underlying, remoteAddr, config)
}

// WrapSSU2Listener wraps an existing net.PacketConn with SSU2Listener.
// This function provides manual control over the underlying connection.
//
// Design rationale:
// - Allows reuse of existing PacketConn (e.g., with custom socket options)
// - Does NOT start packet routing (caller controls timing)
// - Validates connection type for safety
//
// Parameters:
//   - underlying: Existing PacketConn to wrap
//   - config: SSU2 configuration for accepted connections
//
// Returns an SSU2Listener wrapper ready to start, or an error if wrapping fails.
func WrapSSU2Listener(underlying net.PacketConn, config *SSU2Config) (*SSU2Listener, error) {
	if err := validateWrapListenerParams(underlying, config); err != nil {
		return nil, err
	}

	return NewSSU2Listener(underlying, config)
}

// validateDialParams validates parameters for DialSSU2.
func validateDialParams(localAddr, remoteAddr *net.UDPAddr, config *SSU2Config) error {
	if remoteAddr == nil {
		return oops.
			Code("INVALID_REMOTE_ADDRESS").
			In("ssu2_transport").
			Errorf("remote address cannot be nil")
	}

	if config == nil {
		return oops.
			Code("INVALID_CONFIG").
			In("ssu2_transport").
			Errorf("config cannot be nil")
	}

	// Validate configuration
	if err := config.Validate(); err != nil {
		return oops.
			Code("CONFIG_VALIDATION_FAILED").
			In("ssu2_transport").
			Wrapf(err, "SSU2 config validation failed")
	}

	// Dial operations should use initiator role
	if !config.Initiator {
		return oops.
			Code("INVALID_INITIATOR_FLAG").
			In("ssu2_transport").
			Errorf("dial operations require initiator=true in config")
	}

	return nil
}

// validateListenParams validates parameters for ListenSSU2.
func validateListenParams(addr *net.UDPAddr, config *SSU2Config) error {
	if addr == nil {
		return oops.
			Code("INVALID_ADDRESS").
			In("ssu2_transport").
			Errorf("listen address cannot be nil")
	}

	if config == nil {
		return oops.
			Code("INVALID_CONFIG").
			In("ssu2_transport").
			Errorf("config cannot be nil")
	}

	// Validate configuration
	if err := config.Validate(); err != nil {
		return oops.
			Code("CONFIG_VALIDATION_FAILED").
			In("ssu2_transport").
			Wrapf(err, "SSU2 config validation failed")
	}

	// Listen operations should use responder role
	if config.Initiator {
		return oops.
			Code("INVALID_INITIATOR_FLAG").
			In("ssu2_transport").
			Errorf("listen operations require initiator=false in config")
	}

	return nil
}

// validateWrapConnParams validates parameters for WrapSSU2Conn.
func validateWrapConnParams(underlying net.PacketConn, remoteAddr *net.UDPAddr, config *SSU2Config) error {
	if underlying == nil {
		return oops.
			Code("INVALID_PACKET_CONN").
			In("ssu2_transport").
			Errorf("underlying packet connection cannot be nil")
	}

	if remoteAddr == nil {
		return oops.
			Code("INVALID_REMOTE_ADDRESS").
			In("ssu2_transport").
			Errorf("remote address cannot be nil")
	}

	if config == nil {
		return oops.
			Code("INVALID_CONFIG").
			In("ssu2_transport").
			Errorf("config cannot be nil")
	}

	// Validate configuration
	if err := config.Validate(); err != nil {
		return oops.
			Code("CONFIG_VALIDATION_FAILED").
			In("ssu2_transport").
			Wrapf(err, "SSU2 config validation failed")
	}

	return nil
}

// validateWrapListenerParams validates parameters for WrapSSU2Listener.
func validateWrapListenerParams(underlying net.PacketConn, config *SSU2Config) error {
	if underlying == nil {
		return oops.
			Code("INVALID_PACKET_CONN").
			In("ssu2_transport").
			Errorf("underlying packet connection cannot be nil")
	}

	if config == nil {
		return oops.
			Code("INVALID_CONFIG").
			In("ssu2_transport").
			Errorf("config cannot be nil")
	}

	// Validate configuration
	if err := config.Validate(); err != nil {
		return oops.
			Code("CONFIG_VALIDATION_FAILED").
			In("ssu2_transport").
			Wrapf(err, "SSU2 config validation failed")
	}

	return nil
}

// createUDPConnection creates a UDP PacketConn bound to the specified local address.
func createUDPConnection(localAddr *net.UDPAddr) (net.PacketConn, error) {
	packetConn, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		return nil, oops.
			Code("UDP_DIAL_FAILED").
			In("ssu2_transport").
			With("local_address", localAddr).
			Wrapf(err, "failed to create UDP connection")
	}
	return packetConn, nil
}

// createSSU2Connection creates an SSU2Conn from a PacketConn and configuration.
func createSSU2Connection(packetConn net.PacketConn, remoteAddr *net.UDPAddr, config *SSU2Config) (*SSU2Conn, error) {
	// Generate connection ID if not set
	if config.ConnectionID == 0 {
		connID, err := GenerateConnectionID()
		if err != nil {
			return nil, oops.
				Code("CONNECTION_ID_GENERATION_FAILED").
				In("ssu2_transport").
				Wrapf(err, "failed to generate connection ID")
		}
		config.ConnectionID = connID
	}

	// For initiator connections, we need static keys
	// These should be provided in the config
	staticKey := config.StaticKey
	// Remote static key should be in RemoteRouterHash for responder's key
	remoteStaticKey := config.RemoteRouterHash

	conn, err := NewSSU2Conn(
		packetConn,
		remoteAddr,
		config,
		config.Initiator,
		staticKey,
		remoteStaticKey,
	)
	if err != nil {
		return nil, oops.
			Code("SSU2_CONN_FAILED").
			In("ssu2_transport").
			With("remote_address", remoteAddr).
			Wrapf(err, "failed to create SSU2 connection")
	}

	return conn, nil
}
