package server

import (
	"net"
)

// Acceptor abstracts accepting inbound SSU2 connections.
// *SSU2Listener satisfies this interface.
//
// Callers that only need to accept connections can depend on Acceptor
// rather than on the concrete *SSU2Listener, making mocking and testing
// straightforward.
type Acceptor interface {
	// net.Listener embeds Accept, Close, and Addr.
	net.Listener

	// Start begins processing incoming packets. Call Start before Accept.
	Start() error

	// SessionCount returns the number of active sessions.
	SessionCount() int
}

// Compile-time check: *SSU2Listener satisfies Acceptor.
var _ Acceptor = (*SSU2Listener)(nil)
