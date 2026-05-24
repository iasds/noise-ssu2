package noise

import (
	"net"
)

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
