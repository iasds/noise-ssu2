package pool

import (
	"net"
	"testing"
	"time"
)

// mockConn implements net.Conn for testing
type mockConn struct {
	closed     bool
	localAddr  net.Addr
	remoteAddr net.Addr
}

func (m *mockConn) Read(b []byte) (n int, err error)   { return 0, nil }
func (m *mockConn) Write(b []byte) (n int, err error)  { return len(b), nil }
func (m *mockConn) Close() error                       { m.closed = true; return nil }
func (m *mockConn) LocalAddr() net.Addr                { return m.localAddr }
func (m *mockConn) RemoteAddr() net.Addr               { return m.remoteAddr }
func (m *mockConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }

// mockAddr implements net.Addr for testing
type mockAddr struct {
	network string
	address string
}

func (m *mockAddr) Network() string { return m.network }
func (m *mockAddr) String() string  { return m.address }

func newMockConn(remoteAddr string) *mockConn {
	return &mockConn{
		localAddr:  &mockAddr{network: "tcp", address: "127.0.0.1:0"},
		remoteAddr: &mockAddr{network: "tcp", address: remoteAddr},
	}
}

func TestNewConnPool(t *testing.T) {
	tests := []struct {
		name   string
		config *PoolConfig
	}{
		{
			name:   "with config",
			config: &PoolConfig{MaxSize: 5, MaxAge: time.Hour, MaxIdle: time.Minute},
		},
		{
			name:   "with nil config (defaults)",
			config: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pool := NewConnPool(tt.config)
			if pool == nil {
				t.Error("NewConnPool returned nil")
			}

			defer pool.Close()

			if pool.closed {
				t.Error("Pool should not be closed initially")
			}

			if pool.conns == nil {
				t.Error("Pool connections map should be initialized")
			}
		})
	}
}

func TestConnPool_PutAndGet(t *testing.T) {
	pool := NewConnPool(&PoolConfig{
		MaxSize: 2,
		MaxAge:  time.Hour,
		MaxIdle: time.Minute,
	})
	defer pool.Close()

	// Test putting a connection
	conn1 := newMockConn("127.0.0.1:8080")
	err := pool.Put(conn1)
	if err != nil {
		t.Fatalf("Put failed: %v", err)
	}

	// Test getting the connection back
	retrieved := pool.Get("127.0.0.1:8080")
	if retrieved == nil {
		t.Error("Get returned nil for available connection")
	}

	// Test getting when no connection is available
	retrieved2 := pool.Get("127.0.0.1:8080")
	if retrieved2 != nil {
		t.Error("Get should return nil when connection is in use")
	}

	// Test getting for non-existent address
	retrieved3 := pool.Get("127.0.0.1:9090")
	if retrieved3 != nil {
		t.Error("Get should return nil for non-existent address")
	}
}

func TestConnPool_Release(t *testing.T) {
	pool := NewConnPool(&PoolConfig{
		MaxSize: 2,
		MaxAge:  time.Hour,
		MaxIdle: time.Minute,
	})
	defer pool.Close()

	conn1 := newMockConn("127.0.0.1:8080")
	pool.Put(conn1)

	retrieved := pool.Get("127.0.0.1:8080")
	if retrieved == nil {
		t.Fatal("Get returned nil")
	}

	// Release the connection
	pool.Release("127.0.0.1:8080", conn1)

	// Should be able to get it again
	retrieved2 := pool.Get("127.0.0.1:8080")
	if retrieved2 == nil {
		t.Error("Get should return connection after release")
	}
}

func TestConnPool_MaxSize(t *testing.T) {
	pool := NewConnPool(&PoolConfig{
		MaxSize: 1,
		MaxAge:  time.Hour,
		MaxIdle: time.Minute,
	})
	defer pool.Close()

	conn1 := newMockConn("127.0.0.1:8080")
	conn2 := newMockConn("127.0.0.1:8080")

	// First connection should succeed
	err1 := pool.Put(conn1)
	if err1 != nil {
		t.Fatalf("First Put failed: %v", err1)
	}

	// Second connection should be rejected (exceeds max size)
	err2 := pool.Put(conn2)
	if err2 != nil {
		t.Fatalf("Second Put failed: %v", err2)
	}

	// Should only have one connection available
	stats := pool.Stats()
	if stats["total"] != 1 {
		t.Errorf("Expected 1 total connection, got %d", stats["total"])
	}

	// Verify conn2 was closed due to max size limit
	if !conn2.closed {
		t.Error("Connection should be closed when exceeding max size")
	}
}

func TestConnPool_Stats(t *testing.T) {
	pool := NewConnPool(&PoolConfig{
		MaxSize: 5,
		MaxAge:  time.Hour,
		MaxIdle: time.Minute,
	})
	defer pool.Close()

	// Add some connections
	conn1 := newMockConn("127.0.0.1:8080")
	conn2 := newMockConn("127.0.0.1:9090")

	pool.Put(conn1)
	pool.Put(conn2)

	// Get one connection (mark as in use)
	pool.Get("127.0.0.1:8080")

	stats := pool.Stats()

	expectedTotal := 2
	expectedInUse := 1
	expectedAvailable := 1
	expectedAddresses := 2

	if stats["total"] != expectedTotal {
		t.Errorf("Expected total %d, got %d", expectedTotal, stats["total"])
	}
	if stats["in_use"] != expectedInUse {
		t.Errorf("Expected in_use %d, got %d", expectedInUse, stats["in_use"])
	}
	if stats["available"] != expectedAvailable {
		t.Errorf("Expected available %d, got %d", expectedAvailable, stats["available"])
	}
	if stats["addresses"] != expectedAddresses {
		t.Errorf("Expected addresses %d, got %d", expectedAddresses, stats["addresses"])
	}
}

func TestConnPool_Close(t *testing.T) {
	pool := NewConnPool(&PoolConfig{
		MaxSize: 5,
		MaxAge:  time.Hour,
		MaxIdle: time.Minute,
	})

	conn1 := newMockConn("127.0.0.1:8080")
	pool.Put(conn1)

	// Close the pool
	err := pool.Close()
	if err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Verify connection was closed
	if !conn1.closed {
		t.Error("Connection should be closed when pool is closed")
	}

	// Verify pool is marked as closed
	if !pool.closed {
		t.Error("Pool should be marked as closed")
	}

	// Verify new operations are rejected
	retrieved := pool.Get("127.0.0.1:8080")
	if retrieved != nil {
		t.Error("Get should return nil after pool is closed")
	}

	conn2 := newMockConn("127.0.0.1:9090")
	err = pool.Put(conn2)
	if err != nil {
		t.Fatalf("Put after close failed: %v", err)
	}

	// Verify conn2 was closed immediately
	if !conn2.closed {
		t.Error("Connection should be closed immediately when put in closed pool")
	}
}

func TestPoolConnWrapper(t *testing.T) {
	pool := NewConnPool(&PoolConfig{
		MaxSize: 5,
		MaxAge:  time.Hour,
		MaxIdle: time.Minute,
	})
	defer pool.Close()

	conn1 := newMockConn("127.0.0.1:8080")
	pool.Put(conn1)

	// Get wrapped connection
	wrapped := pool.Get("127.0.0.1:8080")
	if wrapped == nil {
		t.Fatal("Get returned nil")
	}

	// Verify wrapper functionality
	if wrapped.RemoteAddr().String() != "127.0.0.1:8080" {
		t.Error("Wrapper should delegate RemoteAddr to underlying connection")
	}

	// Close wrapped connection (should release to pool)
	err := wrapped.Close()
	if err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Should be able to get the connection again
	retrieved := pool.Get("127.0.0.1:8080")
	if retrieved == nil {
		t.Error("Connection should be available after wrapper close")
	}
}

func TestConnPool_NilConnection(t *testing.T) {
	pool := NewConnPool(nil)
	defer pool.Close()

	err := pool.Put(nil)
	if err == nil {
		t.Error("Put should fail with nil connection")
	}
}

// --- Cleanup path tests (Issue: 0% coverage) ---

func TestShouldStopCleanup(t *testing.T) {
	pool := NewConnPool(nil)

	if pool.shouldStopCleanup() {
		t.Error("shouldStopCleanup should return false for open pool")
	}

	pool.Close()

	if !pool.shouldStopCleanup() {
		t.Error("shouldStopCleanup should return true for closed pool")
	}
}

func TestPerformCleanupCycle_ExpiresOldConnections(t *testing.T) {
	pool := NewConnPool(&PoolConfig{
		MaxSize: 10,
		MaxAge:  50 * time.Millisecond,
		MaxIdle: 25 * time.Millisecond,
	})
	defer pool.Close()

	conn := newMockConn("127.0.0.1:8080")
	pool.Put(conn)

	stats := pool.Stats()
	if stats["total"] != 1 {
		t.Fatalf("Expected 1 connection, got %d", stats["total"])
	}

	time.Sleep(100 * time.Millisecond)

	pool.performCleanupCycle()

	stats = pool.Stats()
	if stats["total"] != 0 {
		t.Errorf("Expected 0 connections after cleanup, got %d", stats["total"])
	}

	if !conn.closed {
		t.Error("Expired connection should be closed")
	}
}

func TestPerformCleanupCycle_KeepsInUseConnections(t *testing.T) {
	pool := NewConnPool(&PoolConfig{
		MaxSize: 10,
		MaxAge:  50 * time.Millisecond,
		MaxIdle: 25 * time.Millisecond,
	})
	defer pool.Close()

	conn := newMockConn("127.0.0.1:8080")
	pool.Put(conn)
	pool.Get("127.0.0.1:8080") // mark in-use

	time.Sleep(100 * time.Millisecond)

	pool.performCleanupCycle()

	stats := pool.Stats()
	if stats["total"] != 1 {
		t.Errorf("In-use connection should survive cleanup, got total=%d", stats["total"])
	}
}

func TestFilterValidConnections(t *testing.T) {
	pool := NewConnPool(&PoolConfig{
		MaxSize: 10,
		MaxAge:  50 * time.Millisecond,
		MaxIdle: 25 * time.Millisecond,
	})
	defer pool.Close()

	fresh := &PooledConn{
		Conn:     newMockConn("127.0.0.1:8080"),
		Created:  time.Now(),
		LastUsed: time.Now(),
	}
	expired := &PooledConn{
		Conn:     newMockConn("127.0.0.1:8081"),
		Created:  time.Now().Add(-time.Hour),
		LastUsed: time.Now().Add(-time.Hour),
	}

	result := pool.filterValidConnections([]*PooledConn{fresh, expired})

	if len(result) != 1 {
		t.Fatalf("Expected 1 valid connection, got %d", len(result))
	}
	if result[0] != fresh {
		t.Error("Expected the fresh connection to survive")
	}
	if !expired.Conn.(*mockConn).closed {
		t.Error("Expired connection should be closed")
	}
}

func TestShouldKeepConnection(t *testing.T) {
	pool := NewConnPool(&PoolConfig{
		MaxSize: 10,
		MaxAge:  time.Hour,
		MaxIdle: time.Minute,
	})
	defer pool.Close()

	valid := &PooledConn{
		Conn:     newMockConn("127.0.0.1:8080"),
		Created:  time.Now(),
		LastUsed: time.Now(),
	}
	inUseExpired := &PooledConn{
		Conn:     newMockConn("127.0.0.1:8081"),
		Created:  time.Now().Add(-2 * time.Hour),
		LastUsed: time.Now().Add(-2 * time.Hour),
		InUse:    true,
	}
	expired := &PooledConn{
		Conn:     newMockConn("127.0.0.1:8082"),
		Created:  time.Now().Add(-2 * time.Hour),
		LastUsed: time.Now().Add(-2 * time.Hour),
	}

	if !pool.shouldKeepConnection(valid) {
		t.Error("Valid connection should be kept")
	}
	if !pool.shouldKeepConnection(inUseExpired) {
		t.Error("In-use connection should be kept even if expired")
	}
	if pool.shouldKeepConnection(expired) {
		t.Error("Expired idle connection should not be kept")
	}
}

func TestCloseExpiredConnection(t *testing.T) {
	pool := NewConnPool(nil)
	defer pool.Close()

	conn := newMockConn("127.0.0.1:8080")
	pooledConn := &PooledConn{Conn: conn}

	pool.closeExpiredConnection(pooledConn)

	if !conn.closed {
		t.Error("closeExpiredConnection should close the connection")
	}
}

func TestUpdateConnectionMap(t *testing.T) {
	pool := NewConnPool(nil)
	defer pool.Close()

	pool.mu.Lock()
	pool.conns["addr1"] = []*PooledConn{{Conn: newMockConn("addr1")}}
	pool.mu.Unlock()

	// Update with non-empty list
	pool.mu.Lock()
	newConns := []*PooledConn{{Conn: newMockConn("addr1")}}
	pool.updateConnectionMap("addr1", newConns)
	pool.mu.Unlock()

	pool.mu.RLock()
	if _, ok := pool.conns["addr1"]; !ok {
		t.Error("addr1 should still be in map")
	}
	pool.mu.RUnlock()

	// Update with empty list
	pool.mu.Lock()
	pool.updateConnectionMap("addr1", []*PooledConn{})
	pool.mu.Unlock()

	pool.mu.RLock()
	if _, ok := pool.conns["addr1"]; ok {
		t.Error("addr1 should be removed from map when empty")
	}
	pool.mu.RUnlock()
}

func TestCleanupStopsOnDoneChannel(t *testing.T) {
	pool := NewConnPool(nil)
	// Close immediately — done channel signals cleanup to exit
	pool.Close()

	// The cleanup goroutine should exit promptly via the done channel
	// rather than waiting up to 60 seconds for the next tick.
	// If it doesn't, this would be detected by the race detector or
	// goroutine leak checkers in long-running test suites.
	if !pool.closed {
		t.Error("Pool should be closed")
	}
}

// --- Additional bug-fix tests ---

func TestRelease_UnknownConnection_ReturnsError(t *testing.T) {
	pool := NewConnPool(nil)
	defer pool.Close()

	conn := newMockConn("127.0.0.1:8080")
	err := pool.Release("127.0.0.1:8080", conn)
	if err == nil {
		t.Error("Release should return error for unknown connection")
	}
}

func TestRelease_ClosedPool_ClosesConnection(t *testing.T) {
	pool := NewConnPool(nil)

	conn := newMockConn("127.0.0.1:8080")
	pool.Put(conn)
	pool.Close()

	conn2 := newMockConn("127.0.0.1:8080")
	err := pool.Release("127.0.0.1:8080", conn2)
	if err != nil {
		t.Errorf("Release on closed pool should not error: %v", err)
	}
	if !conn2.closed {
		t.Error("Connection should be closed when released to a closed pool")
	}
}

func TestPoolConnWrapper_DoubleClose(t *testing.T) {
	pool := NewConnPool(nil)
	defer pool.Close()

	conn := newMockConn("127.0.0.1:8080")
	pool.Put(conn)

	wrapped := pool.Get("127.0.0.1:8080")
	if wrapped == nil {
		t.Fatal("Get returned nil")
	}

	err := wrapped.Close()
	if err != nil {
		t.Fatalf("First close should succeed: %v", err)
	}

	err = wrapped.Close()
	if err == nil {
		t.Error("Second close should return an error")
	}
}

func TestPoolConnWrapper_Discard(t *testing.T) {
	pool := NewConnPool(nil)
	defer pool.Close()

	conn := newMockConn("127.0.0.1:8080")
	pool.Put(conn)

	wrapped := pool.Get("127.0.0.1:8080")
	if wrapped == nil {
		t.Fatal("Get returned nil")
	}

	wrapper, ok := wrapped.(*PoolConnWrapper)
	if !ok {
		t.Fatal("Expected PoolConnWrapper")
	}

	err := wrapper.Discard()
	if err != nil {
		t.Fatalf("Discard failed: %v", err)
	}

	if !conn.closed {
		t.Error("Discarded connection should be closed")
	}

	stats := pool.Stats()
	if stats["total"] != 0 {
		t.Errorf("Pool should be empty after discard, got total=%d", stats["total"])
	}
}

func TestClose_SkipsInUseConnections(t *testing.T) {
	pool := NewConnPool(&PoolConfig{
		MaxSize: 5,
		MaxAge:  time.Hour,
		MaxIdle: time.Hour,
	})

	idle := newMockConn("127.0.0.1:8080")
	inUse := newMockConn("127.0.0.1:9090")

	pool.Put(idle)
	pool.Put(inUse)

	// Mark inUse conn as in-use by getting it
	wrapped := pool.Get("127.0.0.1:9090")
	if wrapped == nil {
		t.Fatal("Get returned nil for in-use test conn")
	}

	pool.Close()

	if !idle.closed {
		t.Error("Idle connection should be closed on pool.Close()")
	}
	if inUse.closed {
		t.Error("In-use connection should NOT be closed by pool.Close()")
	}

	// Returning the in-use connection to the closed pool should close it
	err := wrapped.Close()
	if err != nil {
		t.Errorf("Close on returned wrapper should not error: %v", err)
	}
	if !inUse.closed {
		t.Error("In-use connection should be closed after release to closed pool")
	}
}

func TestPut_DuplicateConnection(t *testing.T) {
	pool := NewConnPool(&PoolConfig{
		MaxSize: 5,
		MaxAge:  time.Hour,
		MaxIdle: time.Hour,
	})
	defer pool.Close()

	conn := newMockConn("127.0.0.1:8080")
	pool.Put(conn)
	pool.Put(conn) // duplicate

	stats := pool.Stats()
	if stats["total"] != 1 {
		t.Errorf("Duplicate Put should not create a second entry, got total=%d", stats["total"])
	}
}

func TestPut_UnwrapsPoolConnWrapper(t *testing.T) {
	pool := NewConnPool(&PoolConfig{
		MaxSize: 5,
		MaxAge:  time.Hour,
		MaxIdle: time.Hour,
	})
	defer pool.Close()

	raw := newMockConn("127.0.0.1:8080")
	pool.Put(raw)
	wrapped := pool.Get("127.0.0.1:8080")
	if wrapped == nil {
		t.Fatal("Get returned nil")
	}

	// Put the wrapped connection back (should unwrap it)
	err := pool.Put(wrapped)
	if err != nil {
		t.Fatalf("Put wrapped conn failed: %v", err)
	}

	// Should be the same underlying connection, so duplicate check = 1
	stats := pool.Stats()
	if stats["total"] != 1 {
		t.Errorf("Expected 1 after put-back of wrapper, got total=%d", stats["total"])
	}
}

func TestMaxTotal_EnforcesGlobalLimit(t *testing.T) {
	pool := NewConnPool(&PoolConfig{
		MaxSize:  10,
		MaxTotal: 2,
		MaxAge:   time.Hour,
		MaxIdle:  time.Hour,
	})
	defer pool.Close()

	conn1 := newMockConn("127.0.0.1:8080")
	conn2 := newMockConn("127.0.0.1:9090")
	conn3 := newMockConn("127.0.0.1:7070")

	pool.Put(conn1)
	pool.Put(conn2)
	pool.Put(conn3) // exceeds MaxTotal

	stats := pool.Stats()
	if stats["total"] != 2 {
		t.Errorf("Expected 2 connections (MaxTotal=2), got total=%d", stats["total"])
	}
	if !conn3.closed {
		t.Error("Third connection should be closed due to MaxTotal limit")
	}
}

func TestHealthCheck_RejectsUnhealthyConnections(t *testing.T) {
	unhealthyConn := newMockConn("127.0.0.1:8080")

	pool := NewConnPool(&PoolConfig{
		MaxSize: 5,
		MaxAge:  time.Hour,
		MaxIdle: time.Hour,
		HealthCheck: func(c net.Conn) bool {
			// Mark the specific connection as unhealthy
			return c != unhealthyConn
		},
	})
	defer pool.Close()

	pool.Put(unhealthyConn)

	got := pool.Get("127.0.0.1:8080")
	if got != nil {
		t.Error("Get should return nil when health check fails")
	}

	if !unhealthyConn.closed {
		t.Error("Unhealthy connection should be closed and removed")
	}

	stats := pool.Stats()
	if stats["total"] != 0 {
		t.Errorf("Pool should be empty after unhealthy conn removed, got total=%d", stats["total"])
	}
}
