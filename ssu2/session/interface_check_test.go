package session

import (
	"net"
	"time"
)

// Compile-time interface checks to verify SSU2Conn satisfies expected contracts.
// These will fail at build time if the interface contract is broken.

// SSU2Conn implements core net.Addr methods but not full net.Conn
// due to its callback-based message-oriented architecture (DataHandler.MessageChan).
// This is documented in AUDIT.md M-9: SSU2Conn missing Read/Write methods.
//
// Uncomment the following line to see the compilation error:
// var _ net.Conn = (*SSU2Conn)(nil)

// SSU2Conn does implement the methods it shares with net.Conn:
var _ interface {
	Close() error
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	SetDeadline(time.Time) error
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
} = (*SSU2Conn)(nil)
