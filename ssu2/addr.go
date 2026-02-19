// Package ssu2 provides SSU2-specific implementations for the Noise Protocol Framework
// supporting I2P's SSU2 transport protocol with UDP-based connections and NAT traversal.
package ssu2

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"

	"github.com/samber/oops"
)

// SSU2Addr implements net.Addr for SSU2 transport connections.
// It provides I2P-specific addressing information including router identity,
// connection ID, and optional introducer support for NAT traversal.
type SSU2Addr struct {
	// underlying is the UDP network address
	underlying net.Addr
	// routerHash is the 32-byte I2P router identity hash
	routerHash []byte
	// connectionID is the 8-byte SSU2 connection identifier
	connectionID uint64
	// role indicates if this is an initiator or responder address
	role string
	// destHash is the 32-byte destination hash (optional, nil for router-to-router)
	destHash []byte
	// introducerAddr is the UDP address of an introducer for NAT traversal (optional)
	introducerAddr net.Addr
}

// NewSSU2Addr creates a new SSU2Addr with the specified UDP address, router hash, connection ID, and role.
// routerHash must be exactly 32 bytes representing the I2P router identity.
// connID should be a cryptographically secure random 8-byte value (use GenerateConnectionID).
// role should be either "initiator" or "responder".
func NewSSU2Addr(underlying net.Addr, routerHash []byte, connID uint64, role string) (*SSU2Addr, error) {
	if underlying == nil {
		return nil, oops.
			Code("INVALID_UNDERLYING_ADDR").
			In("ssu2").
			Errorf("underlying address cannot be nil")
	}

	if len(routerHash) != 32 {
		return nil, oops.
			Code("INVALID_ROUTER_HASH").
			In("ssu2").
			With("hash_length", len(routerHash)).
			Errorf("router hash must be exactly 32 bytes")
	}

	if connID == 0 {
		return nil, oops.
			Code("INVALID_CONNECTION_ID").
			In("ssu2").
			Errorf("connection ID cannot be zero (reserved for handshake)")
	}

	if role != "initiator" && role != "responder" {
		return nil, oops.
			Code("INVALID_ROLE").
			In("ssu2").
			With("role", role).
			Errorf("role must be 'initiator' or 'responder'")
	}

	// Make defensive copy of router hash
	hash := make([]byte, 32)
	copy(hash, routerHash)

	return &SSU2Addr{
		underlying:   underlying,
		routerHash:   hash,
		connectionID: connID,
		role:         role,
	}, nil
}

// WithDestinationHash sets the destination hash for tunnel connections.
// destHash must be exactly 32 bytes or nil for router-to-router connections.
// Returns a new SSU2Addr instance (immutable pattern).
func (sa *SSU2Addr) WithDestinationHash(destHash []byte) (*SSU2Addr, error) {
	if destHash != nil && len(destHash) != 32 {
		return nil, oops.
			Code("INVALID_DEST_HASH").
			In("ssu2").
			With("hash_length", len(destHash)).
			Errorf("destination hash must be exactly 32 bytes or nil")
	}

	return sa.copyWithModifications(func(newAddr *SSU2Addr) {
		if destHash != nil {
			newAddr.destHash = make([]byte, 32)
			copy(newAddr.destHash, destHash)
		}
	}), nil
}

// WithIntroducer sets the introducer address for NAT traversal.
// introducerAddr is the UDP address of the introducer service.
// Returns a new SSU2Addr instance (immutable pattern).
func (sa *SSU2Addr) WithIntroducer(introducerAddr net.Addr) (*SSU2Addr, error) {
	if introducerAddr == nil {
		return nil, oops.
			Code("INVALID_INTRODUCER_ADDR").
			In("ssu2").
			Errorf("introducer address cannot be nil")
	}

	return sa.copyWithModifications(func(newAddr *SSU2Addr) {
		newAddr.introducerAddr = introducerAddr
	}), nil
}

// copyWithModifications creates a defensive copy and applies modifications.
// Helper function to maintain immutability pattern while reducing code duplication.
func (sa *SSU2Addr) copyWithModifications(modify func(*SSU2Addr)) *SSU2Addr {
	newAddr := &SSU2Addr{
		underlying:   sa.underlying,
		connectionID: sa.connectionID,
		role:         sa.role,
		routerHash:   make([]byte, 32),
	}
	copy(newAddr.routerHash, sa.routerHash)

	if sa.destHash != nil {
		newAddr.destHash = make([]byte, 32)
		copy(newAddr.destHash, sa.destHash)
	}

	if sa.introducerAddr != nil {
		newAddr.introducerAddr = sa.introducerAddr
	}

	modify(newAddr)
	return newAddr
}

// Network returns "ssu2" to identify this as an SSU2 transport address.
// This implements the net.Addr interface requirement.
func (sa *SSU2Addr) Network() string {
	return "ssu2"
}

// String returns a string representation of the SSU2 address.
// Format: "ssu2://[router_hash]:[conn_id]/[role]/[udp_address][?dest=dest_hash][&introducer=introducer_addr]"
// Router hash is base64 encoded for readability.
func (sa *SSU2Addr) String() string {
	if sa.underlying == nil {
		return "ssu2://invalid"
	}

	// Base64 encode router hash for readability
	routerB64 := base64.URLEncoding.EncodeToString(sa.routerHash)

	// Build base address with connection ID
	addr := fmt.Sprintf("ssu2://%s:%d/%s/%s",
		routerB64, sa.connectionID, sa.role, sa.underlying.String())

	// Add optional destination hash
	if sa.destHash != nil {
		destB64 := base64.URLEncoding.EncodeToString(sa.destHash)
		addr += "?dest=" + destB64
	}

	// Add optional introducer address
	if sa.introducerAddr != nil {
		separator := "?"
		if sa.destHash != nil {
			separator = "&"
		}
		addr += separator + "introducer=" + sa.introducerAddr.String()
	}

	return addr
}

// RouterHash returns a copy of the router identity hash.
// The returned slice is a defensive copy to prevent external modification.
func (sa *SSU2Addr) RouterHash() []byte {
	if sa.routerHash == nil {
		return nil
	}
	hash := make([]byte, 32)
	copy(hash, sa.routerHash)
	return hash
}

// ConnectionID returns the SSU2 connection identifier.
func (sa *SSU2Addr) ConnectionID() uint64 {
	return sa.connectionID
}

// Role returns the connection role ("initiator" or "responder").
func (sa *SSU2Addr) Role() string {
	return sa.role
}

// UnderlyingAddr returns the underlying UDP network address.
func (sa *SSU2Addr) UnderlyingAddr() net.Addr {
	return sa.underlying
}

// DestinationHash returns a copy of the destination hash, or nil for router-to-router connections.
// The returned slice is a defensive copy to prevent external modification.
func (sa *SSU2Addr) DestinationHash() []byte {
	if sa.destHash == nil {
		return nil
	}
	hash := make([]byte, 32)
	copy(hash, sa.destHash)
	return hash
}

// IntroducerAddr returns the introducer address, or nil if no introducer is used.
func (sa *SSU2Addr) IntroducerAddr() net.Addr {
	return sa.introducerAddr
}

// IsDirectConnection returns true if this is a direct connection (no introducer).
func (sa *SSU2Addr) IsDirectConnection() bool {
	return sa.introducerAddr == nil
}

// IsIntroducedConnection returns true if this connection uses an introducer for NAT traversal.
func (sa *SSU2Addr) IsIntroducedConnection() bool {
	return sa.introducerAddr != nil
}

// IsRouterToRouter returns true if this is a router-to-router connection (no destination hash).
func (sa *SSU2Addr) IsRouterToRouter() bool {
	return sa.destHash == nil
}

// IsTunnelConnection returns true if this is a tunnel connection (has destination hash).
func (sa *SSU2Addr) IsTunnelConnection() bool {
	return sa.destHash != nil
}

// GenerateConnectionID generates a cryptographically secure random connection ID.
// The ID is guaranteed to be non-zero (zero is reserved for handshake).
// This is a convenience function for creating SSU2 addresses.
func GenerateConnectionID() (uint64, error) {
	var id uint64
	buf := make([]byte, 8)

	// Loop until we get a non-zero ID (probability of zero is negligible)
	for id == 0 {
		if _, err := rand.Read(buf); err != nil {
			return 0, oops.
				Code("RANDOM_GENERATION_FAILED").
				In("ssu2").
				Wrap(err)
		}

		// Convert bytes to uint64 (big-endian)
		id = uint64(buf[0])<<56 | uint64(buf[1])<<48 |
			uint64(buf[2])<<40 | uint64(buf[3])<<32 |
			uint64(buf[4])<<24 | uint64(buf[5])<<16 |
			uint64(buf[6])<<8 | uint64(buf[7])
	}

	return id, nil
}
