package pool

import (
	"net"
	"time"
)

// PoolConfig configures a connection pool
type PoolConfig struct {
	// MaxSize is the maximum number of connections per remote address.
	MaxSize int
	// MaxTotal is the maximum total number of connections across all addresses.
	// A zero value means no global limit is enforced.
	MaxTotal int
	// MaxAge is the maximum age of a connection before it is closed.
	MaxAge time.Duration
	// MaxIdle is the maximum idle time before a connection is closed.
	MaxIdle time.Duration
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
