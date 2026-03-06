package pool

import "time"

// newTestPool creates a ConnPool with standard test defaults
// (MaxAge=1h, MaxIdle=1h) and the given maximum size.
func newTestPool(maxSize int) *ConnPool {
	return NewConnPool(&PoolConfig{
		MaxSize: maxSize,
		MaxAge:  time.Hour,
		MaxIdle: time.Hour,
	})
}
