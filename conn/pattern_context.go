package conn

import (
	"net"

	"github.com/go-i2p/go-noise/handshake"
	i2plogger "github.com/go-i2p/logger"
)

// PatternContext provides the interface that custom Noise pattern handlers
// need to execute a handshake. It exposes only the operations required for
// pattern implementation, hiding internal connection state.
//
// This interface allows third parties to implement custom Noise patterns
// without depending on internal *Conn fields. Pattern handlers registered
// via RegisterPattern should accept a PatternContext rather than *Conn.
type PatternContext interface {
	// Config returns the connection's Noise configuration.
	Config() *ConnConfig

	// Logger returns the connection's logger instance.
	Logger() *i2plogger.Logger

	// Underlying returns the wrapped network connection.
	Underlying() net.Conn

	// LocalAddr returns the local address.
	LocalAddr() net.Addr

	// RemoteAddr returns the remote address.
	RemoteAddr() net.Addr

	// SendHandshakeMessage writes a Noise handshake message with the specified
	// phase and label. It creates the message via the handshake state, applies
	// handshake modifiers, writes it to the underlying connection, and updates
	// cipher states.
	SendHandshakeMessage(phase handshake.HandshakePhase, label string) error

	// ReceiveHandshakeMessage reads a Noise handshake message with the specified
	// phase and label. It reads from the underlying connection, applies handshake
	// modifiers, processes the message via the handshake state, and updates
	// cipher states.
	ReceiveHandshakeMessage(phase handshake.HandshakePhase, label string) error
}

// Ensure *Conn implements PatternContext at compile time.
var _ PatternContext = (*Conn)(nil)

// Logger returns the connection's logger instance.
func (nc *Conn) Logger() *i2plogger.Logger {
	return nc.logger
}

// SendHandshakeMessage writes a Noise handshake message with the specified
// phase and label. This is a public wrapper around sendNoiseHandshakeMsg
// that satisfies the PatternContext interface.
func (nc *Conn) SendHandshakeMessage(phase handshake.HandshakePhase, label string) error {
	return nc.sendNoiseHandshakeMsg(phase, label)
}

// ReceiveHandshakeMessage reads a Noise handshake message with the specified
// phase and label. This is a public wrapper around receiveNoiseHandshakeMsg
// that satisfies the PatternContext interface.
func (nc *Conn) ReceiveHandshakeMessage(phase handshake.HandshakePhase, label string) error {
	return nc.receiveNoiseHandshakeMsg(phase, label)
}
