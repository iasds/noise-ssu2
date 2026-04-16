package pool

import (
	"net"
	"time"
)

// PoolConfig configures a connection pool
type PoolConfig struct {
	// MaxSize is the maximum number of connections per remote address.
	// A zero or negative value is treated as "apply the default limit"
	// (see DefaultMaxSize). To deliberately disable the per-address limit
	// (NOT recommended — it is a file-descriptor exhaustion vector), set
	// Unbounded to true.
	MaxSize int
	// MaxTotal is the maximum total number of connections across all addresses.
	// A zero value means no global limit is enforced.
	MaxTotal int
	// MaxAge is the maximum age of a connection before it is closed.
	MaxAge time.Duration
	// MaxIdle is the maximum idle time before a connection is closed.
	MaxIdle time.Duration
	// Unbounded, when true, disables the safe default for MaxSize. Callers
	// must opt in explicitly to unbounded per-address pools so that a
	// forgotten MaxSize does not silently allow FD exhaustion (AUDIT L-1).
	Unbounded bool
	// HealthCheck is an optional callback to probe connection liveness
	// before returning it from Get(). Return true if healthy.
	HealthCheck func(net.Conn) bool
	// ReadyCheck is an optional callback invoked by Put() to verify that a
	// connection is ready for reuse (e.g., that a Noise handshake has been
	// completed). Return true if the connection is ready to be pooled.
	// When nil, all connections are accepted by Put().
	//
	// For NTCP2 connections, the recommended check is:
	//   func(c net.Conn) bool {
	//       if nc, ok := c.(*noise.NoiseConn); ok {
	//           return nc.GetConnectionState() == internal.StateEstablished
	//       }
	//       return true
	//   }
	ReadyCheck func(net.Conn) bool
}

// DefaultMaxSize is the default per-address connection limit applied when a
// caller supplies a PoolConfig without MaxSize and without setting Unbounded.
const DefaultMaxSize = 10
