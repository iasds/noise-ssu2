# pool
--
    import "github.com/go-i2p/go-noise/pool"



## Usage

#### type ConnPool

```go
type ConnPool struct {
}
```

ConnPool manages a pool of reusable connections for performance optimization. It
only uses interface types (net.Conn, net.Addr) for maximum compatibility.

#### func  NewConnPool

```go
func NewConnPool(config *PoolConfig) *ConnPool
```
NewConnPool creates a new connection pool with the given configuration

#### func (*ConnPool) Close

```go
func (p *ConnPool) Close() error
```
Close closes idle connections and prevents new connections from being added.
In-use connections are closed when returned via Release() or Discard().

#### func (*ConnPool) Get

```go
func (p *ConnPool) Get(remoteAddr string) net.Conn
```
Get retrieves a connection from the pool for the given remote address. Returns
nil if no suitable connection is available.

#### func (*ConnPool) Put

```go
func (p *ConnPool) Put(conn net.Conn) error
```
Put adds a connection to the pool for reuse

#### func (*ConnPool) Release

```go
func (p *ConnPool) Release(remoteAddr string, conn net.Conn) error
```
Release marks a connection as no longer in use, making it available for reuse.
Returns an error if the pool is closed or the connection is not found.

#### func (*ConnPool) Remove

```go
func (p *ConnPool) Remove(remoteAddr string, conn net.Conn) error
```
Remove closes a connection and permanently removes it from the pool.
Use this when a connection is known to be broken.

#### func (*ConnPool) Stats

```go
func (p *ConnPool) Stats() map[string]int
```
Stats returns pool statistics

#### type PoolConfig

```go
type PoolConfig struct {
        MaxSize     int              // Maximum number of connections per remote address.
        MaxTotal    int              // Maximum total connections across all addresses (0 = unlimited).
        MaxAge      time.Duration    // Maximum age of a connection before it is closed.
        MaxIdle     time.Duration    // Maximum idle time before a connection is closed.
        HealthCheck func(net.Conn) bool // Optional liveness probe; return true if healthy.
}
```

PoolConfig configures a connection pool

#### type PoolConnWrapper

```go
type PoolConnWrapper struct {
        net.Conn
        // contains filtered or unexported fields
}
```

PoolConnWrapper wraps a pooled connection to handle automatic release.
Calling Close() returns the connection to the pool; calling Discard() removes it
permanently.

#### func (*PoolConnWrapper) Close

```go
func (w *PoolConnWrapper) Close() error
```
Close returns the connection to the pool instead of closing it.
Returns an error on double-close or if the pool rejects the connection.

#### func (*PoolConnWrapper) Discard

```go
func (w *PoolConnWrapper) Discard() error
```
Discard closes the underlying connection and permanently removes it from the
pool. Use this when the connection is known to be broken.

#### type PooledConn

```go
type PooledConn struct {
        // contains unexported fields
}
```

PooledConn represents a connection in the pool with metadata. All fields are
unexported to prevent callers from mutating pool state without holding the pool
mutex. Use the accessor methods for read access.

#### func (*PooledConn) NetConn

```go
func (p *PooledConn) NetConn() net.Conn
```
NetConn returns the underlying network connection.

#### func (*PooledConn) CreatedAt

```go
func (p *PooledConn) CreatedAt() time.Time
```
CreatedAt returns the time the connection was added to the pool.

#### func (*PooledConn) LastUsedAt

```go
func (p *PooledConn) LastUsedAt() time.Time
```
LastUsedAt returns the time the connection was last returned from Get().

#### func (*PooledConn) IsInUse

```go
func (p *PooledConn) IsInUse() bool
```
IsInUse reports whether the connection is currently checked out of the pool.

#### func (*PooledConn) Address

```go
func (p *PooledConn) Address() string
```
Address returns the remote address string used as the pool key.



pool
