package session

import (
	"net"

	"github.com/go-i2p/go-noise/ssu2/wire"
)

// Router abstracts routing SSU2 packets to established sessions.
// *PacketRouter satisfies this interface.
//
// Callers that dispatch incoming packets can depend on Router rather than
// on the concrete *PacketRouter, enabling easier testing and alternative
// routing strategies.
type Router interface {
	// AddSession registers a connection so it can receive routed packets.
	AddSession(conn *SSU2Conn) error

	// RemoveSession unregisters a connection by its connection ID.
	RemoveSession(connID uint64)

	// GetSession retrieves a registered connection by its connection ID.
	// Returns nil if no session with that ID exists.
	GetSession(connID uint64) *SSU2Conn

	// RoutePacket dispatches a received packet to its owning session.
	RoutePacket(packet *wire.SSU2Packet, remoteAddr *net.UDPAddr) error

	// SessionCount returns the number of active sessions.
	SessionCount() int
}

// Compile-time check: *PacketRouter satisfies Router.
var _ Router = (*PacketRouter)(nil)
