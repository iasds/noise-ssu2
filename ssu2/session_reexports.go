// Package ssu2: session re-exports from ssu2/session.
// Implementations live in ssu2/session; this file provides
// backward-compatible access from the flat ssu2 package.
package ssu2

import "github.com/go-i2p/go-noise/ssu2/session"

// ─── Type aliases ─────────────────────────────────────────────────────────────

type SSU2Conn = session.SSU2Conn
type PendingPacket = session.PendingPacket
type ConnState = session.ConnState
type DataHandler = session.DataHandler
type DataHandlerCallbacks = session.DataHandlerCallbacks
type DataHandlerStats = session.DataHandlerStats
type PacketRouter = session.PacketRouter
type FragmentSet = session.FragmentSet

// ─── Function re-exports ──────────────────────────────────────────────────────

var (
	NewSSU2Conn    = session.NewSSU2Conn
	NewDataHandler = session.NewDataHandler
	NewPacketRouter = session.NewPacketRouter
)

// ─── State constant re-exports ────────────────────────────────────────────────

const (
	StateInit        = session.StateInit
	StateHandshaking = session.StateHandshaking
	StateEstablished = session.StateEstablished
	StateClosing     = session.StateClosing
	StateClosed      = session.StateClosed
)
