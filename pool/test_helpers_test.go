package pool

import (
	"net"
	"testing"
	"time"
)

// newTestPool creates a ConnPool with standard test defaults
// (MaxAge=1h, MaxIdle=1h) and the given maximum size.
func newTestPool(maxSize int) *ConnPool {
	return NewConnPool(&PoolConfig{
		MaxSize: maxSize,
		MaxAge:  time.Hour,
		MaxIdle: time.Hour,
	})
}

// poolConnFixture holds a pool with a single mock connection already Put.
type poolConnFixture struct {
	pool *ConnPool
	conn *mockConn
	addr string
}

// setupPoolWithConn creates a size-5 pool, puts a mock connection with addr,
// and registers pool.Close via t.Cleanup. The returned fixture provides
// access to the pool, mock conn, and address.
func setupPoolWithConn(t *testing.T, addr string) poolConnFixture {
	t.Helper()
	p := newTestPool(5)
	t.Cleanup(func() { p.Close() })
	c := newMockConn(addr)
	if err := p.Put(c); err != nil {
		t.Fatalf("Put(%s): %v", addr, err)
	}
	return poolConnFixture{pool: p, conn: c, addr: addr}
}

// checkout calls Get on the fixture's address and fatals if nil.
func (f poolConnFixture) checkout(t *testing.T) net.Conn {
	t.Helper()
	w := f.pool.Get(f.addr)
	if w == nil {
		t.Fatalf("Get(%q) returned nil", f.addr)
	}
	return w
}
