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
}
