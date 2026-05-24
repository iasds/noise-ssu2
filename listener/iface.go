package listener

import (
	"net"

	shutdown "github.com/go-i2p/go-noise/shutdown"
)

// ListenerIface defines the public interface for Noise protocol listeners.
// It embeds net.Listener and adds shutdown management.
//
// This interface allows consumers to substitute test doubles or alternative
// implementations without depending on the concrete *Listener type.
type ListenerIface interface {
	net.Listener

	// SetShutdownManager registers a shutdown manager for coordinated shutdown.
	// The listener will unregister itself when closed.
	SetShutdownManager(sm shutdown.Shutdowner)
}

// Compile-time assertion that *Listener implements ListenerIface.
var _ ListenerIface = (*Listener)(nil)
