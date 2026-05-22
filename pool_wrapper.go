package noise

import (
	"net"
	"sync"

	"github.com/go-i2p/pool"
)

// putOnCloseWrapper wraps a freshly-dialed net.Conn so that its Close() call
// returns the connection to the pool for reuse rather than closing it to the OS.
// This is used by DialNoiseWithPool for new (non-pool-retrieved) connections.
type putOnCloseWrapper struct {
	net.Conn
	p    pool.Pool
	mu   sync.Mutex
	done bool
}

// newPutOnCloseWrapper creates a putOnCloseWrapper for the given connection.
func newPutOnCloseWrapper(conn net.Conn, p pool.Pool) net.Conn {
	return &putOnCloseWrapper{Conn: conn, p: p}
}

// Close puts the underlying connection back into the pool instead of closing it.
// The pool will close the connection itself if it is over capacity or already closed.
func (w *putOnCloseWrapper) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.done {
		return nil
	}
	w.done = true
	// pool.Put unwraps any PoolConnWrapper nesting and keys by RemoteAddr.
	return w.p.Put(w.Conn)
}
