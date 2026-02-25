package pool

import (
	"net"
	"sync"
	"time"

	"github.com/samber/oops"
)

// ConnPool manages a pool of reusable connections for performance optimization.
// It only uses interface types (net.Conn, net.Addr) for maximum compatibility.
type ConnPool struct {
	mu          sync.RWMutex
	conns       map[string][]*PooledConn // keyed by remote address
	maxSize     int
	maxTotal    int
	maxAge      time.Duration
	maxIdle     time.Duration
	healthCheck func(net.Conn) bool
	closed      bool
	done        chan struct{}
}

// NewConnPool creates a new connection pool with the given configuration
func NewConnPool(config *PoolConfig) *ConnPool {
	if config == nil {
		config = &PoolConfig{
			MaxSize: 10,
			MaxAge:  30 * time.Minute,
			MaxIdle: 5 * time.Minute,
		}
	}

	pool := &ConnPool{
		conns:       make(map[string][]*PooledConn),
		maxSize:     config.MaxSize,
		maxTotal:    config.MaxTotal,
		maxAge:      config.MaxAge,
		maxIdle:     config.MaxIdle,
		healthCheck: config.HealthCheck,
		done:        make(chan struct{}),
	}

	// Start cleanup goroutine
	go pool.cleanup()

	return pool
}

// Get retrieves a connection from the pool for the given remote address.
// Returns nil if no suitable connection is available.
func (p *ConnPool) Get(remoteAddr string) net.Conn {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return nil
	}

	connList, exists := p.conns[remoteAddr]
	if !exists || len(connList) == 0 {
		return nil
	}

	// Find an available, valid, and healthy connection.
	// Expired connections are closed and removed here to prevent them from
	// accumulating and inflating the count against maxSize (starvation fix).
	for i := 0; i < len(connList); i++ {
		pooledConn := connList[i]
		if pooledConn.InUse {
			continue
		}
		if !p.isValid(pooledConn) {
			// Remove expired connection immediately so it does not count against capacity.
			pooledConn.Conn.Close()
			connList = append(connList[:i], connList[i+1:]...)
			i--
			p.updateConnectionMap(remoteAddr, connList)
			continue
		}
		if p.healthCheck != nil && !p.healthCheck(pooledConn.Conn) {
			pooledConn.Conn.Close()
			connList = append(connList[:i], connList[i+1:]...)
			i--
			p.updateConnectionMap(remoteAddr, connList)
			continue
		}
		pooledConn.InUse = true
		pooledConn.LastUsed = time.Now()
		return &PoolConnWrapper{
			Conn: pooledConn.Conn,
			pool: p,
			addr: remoteAddr,
		}
	}

	return nil
}

// Put adds a connection to the pool for reuse
func (p *ConnPool) Put(conn net.Conn) error {
	if conn == nil {
		return oops.
			Code("INVALID_CONNECTION").
			In("pool").
			Errorf("cannot put nil connection in pool")
	}

	conn = unwrapPoolConn(conn)
	remoteAddr := conn.RemoteAddr().String()

	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return conn.Close()
	}

	connList := p.conns[remoteAddr]

	if p.exceedsCapacity(connList) {
		return conn.Close()
	}

	if p.isDuplicateConn(connList, conn) {
		return nil
	}

	p.conns[remoteAddr] = append(connList, newPooledConn(conn, remoteAddr))
	return nil
}

// unwrapPoolConn extracts the underlying net.Conn from a PoolConnWrapper to avoid
// wrapper-inside-wrapper nesting.
func unwrapPoolConn(conn net.Conn) net.Conn {
	if wrapper, ok := conn.(*PoolConnWrapper); ok {
		return wrapper.Conn
	}
	return conn
}

// exceedsCapacity returns true if the pool has no room for a new connection,
// considering both per-address and global limits.
// A maxSize of 0 is treated as "no per-address limit" to avoid silently
// closing every connection when the caller explicitly sets MaxSize to zero.
func (p *ConnPool) exceedsCapacity(connList []*PooledConn) bool {
	if p.maxSize > 0 && len(connList) >= p.maxSize {
		return true
	}
	if p.maxTotal > 0 && p.totalConnsLocked() >= p.maxTotal {
		return true
	}
	return false
}

// isDuplicateConn checks whether the connection is already present in the pool.
func (p *ConnPool) isDuplicateConn(connList []*PooledConn, conn net.Conn) bool {
	for _, existing := range connList {
		if existing.Conn == conn {
			return true
		}
	}
	return false
}

// newPooledConn creates a new PooledConn entry with current timestamps.
func newPooledConn(conn net.Conn, remoteAddr string) *PooledConn {
	return &PooledConn{
		Conn:       conn,
		Created:    time.Now(),
		LastUsed:   time.Now(),
		InUse:      false,
		RemoteAddr: remoteAddr,
	}
}

// Release marks a connection as no longer in use, making it available for reuse.
// Returns an error if the pool is closed or the connection is not found.
func (p *ConnPool) Release(remoteAddr string, conn net.Conn) error {
	// Unwrap PoolConnWrapper for correct identity comparison
	if wrapper, ok := conn.(*PoolConnWrapper); ok {
		conn = wrapper.Conn
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return conn.Close()
	}

	connList, exists := p.conns[remoteAddr]
	if !exists {
		return oops.Code("CONNECTION_NOT_FOUND").In("pool").
			Errorf("connection not found for address %s", remoteAddr)
	}

	for _, pooledConn := range connList {
		if pooledConn.Conn == conn {
			pooledConn.InUse = false
			pooledConn.LastUsed = time.Now()
			return nil
		}
	}

	return oops.Code("CONNECTION_NOT_FOUND").In("pool").
		Errorf("connection not found in pool for address %s", remoteAddr)
}

// Remove closes a connection and permanently removes it from the pool.
// Use this when a connection is known to be broken.
func (p *ConnPool) Remove(remoteAddr string, conn net.Conn) error {
	if wrapper, ok := conn.(*PoolConnWrapper); ok {
		conn = wrapper.Conn
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	// Honour the closed state consistently with Get(), Put(), and Release().
	if p.closed {
		return conn.Close()
	}

	connList, exists := p.conns[remoteAddr]
	if !exists {
		return conn.Close()
	}

	for i, pooledConn := range connList {
		if pooledConn.Conn == conn {
			connList = append(connList[:i], connList[i+1:]...)
			p.updateConnectionMap(remoteAddr, connList)
			return conn.Close()
		}
	}

	return conn.Close()
}

// Close closes idle connections and prevents new connections from being added.
// In-use connections are closed when returned via Release() or Discard().
func (p *ConnPool) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return nil
	}

	p.closed = true
	close(p.done)

	// Close only idle connections; in-use connections will be
	// closed when returned via Release() or Discard().
	for _, connList := range p.conns {
		for _, pooledConn := range connList {
			if !pooledConn.InUse {
				pooledConn.Conn.Close()
			}
		}
	}

	p.conns = make(map[string][]*PooledConn)

	return nil
}

// Stats returns pool statistics
func (p *ConnPool) Stats() map[string]int {
	p.mu.RLock()
	defer p.mu.RUnlock()

	total := 0
	inUse := 0

	for _, connList := range p.conns {
		total += len(connList)
		for _, pooledConn := range connList {
			if pooledConn.InUse {
				inUse++
			}
		}
	}

	return map[string]int{
		"total":     total,
		"in_use":    inUse,
		"available": total - inUse,
		"addresses": len(p.conns),
	}
}

// isValid checks if a pooled connection is still valid for use
func (p *ConnPool) isValid(pooledConn *PooledConn) bool {
	now := time.Now()

	// Check age limit
	if p.maxAge > 0 && now.Sub(pooledConn.Created) > p.maxAge {
		return false
	}

	// Check idle time limit
	if p.maxIdle > 0 && now.Sub(pooledConn.LastUsed) > p.maxIdle {
		return false
	}

	return true
}

// totalConnsLocked returns the total connection count. Must hold mu.
func (p *ConnPool) totalConnsLocked() int {
	total := 0
	for _, list := range p.conns {
		total += len(list)
	}
	return total
}

// cleanupInterval returns the ticker period for the cleanup goroutine.
// It uses half the configured MaxIdle or MaxAge (whichever is smaller and
// non-zero) so that expired connections are evicted promptly for short-lived
// pool configurations rather than waiting the hardcoded 1-minute default.
func (p *ConnPool) cleanupInterval() time.Duration {
	const defaultInterval = time.Minute
	const minInterval = time.Second
	interval := defaultInterval
	if p.maxIdle > 0 && p.maxIdle/2 < interval {
		interval = p.maxIdle / 2
	}
	if p.maxAge > 0 && p.maxAge/2 < interval {
		interval = p.maxAge / 2
	}
	if interval < minInterval {
		interval = minInterval
	}
	return interval
}

// cleanup runs periodically to remove expired connections
func (p *ConnPool) cleanup() {
	ticker := time.NewTicker(p.cleanupInterval())
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if p.shouldStopCleanup() {
				return
			}
			p.performCleanupCycle()
		case <-p.done:
			return
		}
	}
}

// shouldStopCleanup checks if the cleanup process should be terminated.
// Uses RLock because it only reads the closed boolean.
func (p *ConnPool) shouldStopCleanup() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.closed
}

// performCleanupCycle executes a single cleanup cycle for all connections
func (p *ConnPool) performCleanupCycle() {
	p.mu.Lock()
	defer p.mu.Unlock()

	for addr, connList := range p.conns {
		validConns := p.filterValidConnections(connList)
		p.updateConnectionMap(addr, validConns)
	}
}

// filterValidConnections separates valid connections from expired ones
func (p *ConnPool) filterValidConnections(connList []*PooledConn) []*PooledConn {
	validConns := make([]*PooledConn, 0, len(connList))

	for _, pooledConn := range connList {
		if p.shouldKeepConnection(pooledConn) {
			validConns = append(validConns, pooledConn)
		} else {
			p.closeExpiredConnection(pooledConn)
		}
	}

	return validConns
}

// shouldKeepConnection determines if a connection should be retained
func (p *ConnPool) shouldKeepConnection(pooledConn *PooledConn) bool {
	return pooledConn.InUse || p.isValid(pooledConn)
}

// closeExpiredConnection properly closes an expired connection
func (p *ConnPool) closeExpiredConnection(pooledConn *PooledConn) {
	pooledConn.Conn.Close()
}

// updateConnectionMap updates the pool map with valid connections
func (p *ConnPool) updateConnectionMap(addr string, validConns []*PooledConn) {
	if len(validConns) == 0 {
		delete(p.conns, addr)
	} else {
		p.conns[addr] = validConns
	}
}
