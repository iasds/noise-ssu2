// Package ssu2: handshake re-exports from ssu2/handshake.
// Implementations live in ssu2/handshake; this file provides
// backward-compatible access from the flat ssu2 package.
package ssu2

import "github.com/go-i2p/go-noise/ssu2/handshake"

// ─── Type aliases ─────────────────────────────────────────────────────────────

type HandshakeHandler = handshake.HandshakeHandler
type OptionsParams = handshake.OptionsParams

// ─── Constants ────────────────────────────────────────────────────────────────

const SSU2ProtocolName = handshake.SSU2ProtocolName

// ─── Function re-exports ───────────────────────────────────────────────────────

var (
	NewHandshakeHandler         = handshake.NewHandshakeHandler
	NewHandshakeHandlerWithKeys = handshake.NewHandshakeHandlerWithKeys
	ParseOptionsBlock           = handshake.ParseOptionsBlock
)
