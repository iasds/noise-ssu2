// Package ssu2 consumer-facing interfaces.
//
// This file declares the top-level behavioral contracts that external callers
// should use when working with SSU2. Depending on interfaces rather than
// concrete types (*SSU2Listener, *PacketRouter, *SSU2Conn) makes it possible
// to unit-test components in isolation without an active network.
//
// Acceptor and Router are re-exported from their sub-packages; Dialer is
// defined here because the dialing functionality is implemented as free
// functions rather than a struct.
package ssu2

import (
	"context"
	"net"
)

// Dialer establishes outbound SSU2 connections with handshake.
// Use NewDialer to obtain the default implementation.
type Dialer interface {
	// DialContext establishes a new SSU2 session from localAddr to remoteAddr.
	// The context controls connection and handshake timeouts.
	DialContext(ctx context.Context, localAddr, remoteAddr *net.UDPAddr, config *SSU2Config) (*SSU2Conn, error)
}

// dialerImpl wraps DialSSU2WithHandshakeContext as a Dialer.
type dialerImpl struct{}

// NewDialer returns a Dialer backed by DialSSU2WithHandshakeContext.
func NewDialer() Dialer { return &dialerImpl{} }

func (d *dialerImpl) DialContext(ctx context.Context, localAddr, remoteAddr *net.UDPAddr, config *SSU2Config) (*SSU2Conn, error) {
	return DialSSU2WithHandshakeContext(ctx, localAddr, remoteAddr, config)
}

// Compile-time interface satisfaction checks.
var (
	_ Acceptor = (*SSU2Listener)(nil)
	_ Router   = (*PacketRouter)(nil)
	_ Dialer   = (*dialerImpl)(nil)
)
