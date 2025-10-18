# SSU2 Address Module Documentation

## Overview

The SSU2 address module (`addr.go`) provides a complete implementation of the `net.Addr` interface for SSU2 transport connections. It encapsulates UDP addressing along with I2P-specific metadata required for the SSU2 protocol, including router identities, connection IDs, and NAT traversal support.

## Architecture

### Core Types

#### `SSU2Addr`
Implements `net.Addr` for SSU2 UDP-based connections with I2P protocol extensions.

**Fields:**
- `underlying net.Addr` - The UDP network address
- `routerHash []byte` - 32-byte I2P router identity hash
- `connectionID uint64` - 8-byte SSU2 connection identifier (non-zero, cryptographically random)
- `role string` - Connection role ("initiator" or "responder")
- `destHash []byte` - Optional 32-byte destination hash for tunnel connections
- `introducerAddr net.Addr` - Optional introducer UDP address for NAT traversal

### Design Patterns

#### Immutability Pattern
All modification methods (`WithDestinationHash`, `WithIntroducer`) return new instances rather than modifying the original, ensuring thread-safety and preventing unexpected mutations.

```go
// Original address remains unchanged
baseAddr, _ := NewSSU2Addr(udpAddr, routerHash, connID, "initiator")
addrWithDest, _ := baseAddr.WithDestinationHash(destHash)
// baseAddr.destHash == nil (still true)
// addrWithDest.destHash != nil (new instance)
```

#### Defensive Copying
All byte slices are defensively copied on input and output to prevent external modification of internal state.

```go
// Input: defensive copy prevents external modification
hash := make([]byte, 32)
addr, _ := NewSSU2Addr(udpAddr, hash, connID, "initiator")
hash[0] = 0xFF // Does not affect addr.routerHash

// Output: defensive copy protects internal state
returned := addr.RouterHash()
returned[0] = 0xFF // Does not affect addr.routerHash
```

#### Builder Pattern
Methods chain fluently for constructing complex addresses:

```go
addr, _ := NewSSU2Addr(udpAddr, routerHash, connID, "initiator")
fullAddr, _ := addr.
    WithDestinationHash(destHash).
    WithIntroducer(introducerAddr)
```

## API Reference

### Constructor

#### `NewSSU2Addr(underlying net.Addr, routerHash []byte, connID uint64, role string) (*SSU2Addr, error)`

Creates a new SSU2 address with required parameters.

**Parameters:**
- `underlying` - UDP address (must not be nil)
- `routerHash` - 32-byte router identity (exact length required)
- `connID` - Connection ID (must be non-zero; use `GenerateConnectionID()`)
- `role` - "initiator" or "responder"

**Returns:**
- `*SSU2Addr` on success
- Error if validation fails

**Errors:**
- `INVALID_UNDERLYING_ADDR` - nil underlying address
- `INVALID_ROUTER_HASH` - routerHash is not exactly 32 bytes
- `INVALID_CONNECTION_ID` - connID is zero (reserved for handshake)
- `INVALID_ROLE` - role is not "initiator" or "responder"

**Example:**
```go
udpAddr, _ := net.ResolveUDPAddr("udp", "192.168.1.1:8080")
routerHash := make([]byte, 32) // Your router's identity
connID, _ := GenerateConnectionID()

addr, err := NewSSU2Addr(udpAddr, routerHash, connID, "initiator")
if err != nil {
    log.Fatalf("Failed to create address: %v", err)
}
```

### Modification Methods

#### `WithDestinationHash(destHash []byte) (*SSU2Addr, error)`

Returns a new address with destination hash set for tunnel connections.

**Parameters:**
- `destHash` - 32-byte destination hash or nil for router-to-router

**Returns:**
- New `*SSU2Addr` instance with destination hash
- Error if destHash is non-nil and not exactly 32 bytes

**Example:**
```go
destHash := make([]byte, 32) // Destination identity
tunnelAddr, err := addr.WithDestinationHash(destHash)
```

#### `WithIntroducer(introducerAddr net.Addr) (*SSU2Addr, error)`

Returns a new address with introducer set for NAT traversal.

**Parameters:**
- `introducerAddr` - UDP address of introducer service (must not be nil)

**Returns:**
- New `*SSU2Addr` instance with introducer
- Error if introducerAddr is nil

**Example:**
```go
introducerUDP, _ := net.ResolveUDPAddr("udp", "10.0.0.2:9999")
introducedAddr, err := addr.WithIntroducer(introducerUDP)
```

### net.Addr Interface Methods

#### `Network() string`
Returns `"ssu2"` to identify the transport protocol.

#### `String() string`
Returns formatted address string:
```
ssu2://[base64_router_hash]:[conn_id]/[role]/[udp_address][?dest=base64_dest][&introducer=udp_addr]
```

**Example outputs:**
```
ssu2://AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:12345/initiator/192.168.1.1:8080
ssu2://AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:12345/initiator/192.168.1.1:8080?dest=BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
ssu2://AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:12345/initiator/192.168.1.1:8080?dest=BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=&introducer=10.0.0.2:9999
```

### Accessor Methods

#### `RouterHash() []byte`
Returns defensive copy of router identity hash (32 bytes).

#### `ConnectionID() uint64`
Returns the SSU2 connection identifier.

#### `Role() string`
Returns connection role ("initiator" or "responder").

#### `UnderlyingAddr() net.Addr`
Returns the underlying UDP network address.

#### `DestinationHash() []byte`
Returns defensive copy of destination hash or nil for router-to-router connections.

#### `IntroducerAddr() net.Addr`
Returns introducer address or nil for direct connections.

### Connection Type Queries

#### `IsDirectConnection() bool`
Returns true if no introducer is used (direct UDP connection).

#### `IsIntroducedConnection() bool`
Returns true if connection uses introducer for NAT traversal.

#### `IsRouterToRouter() bool`
Returns true if destination hash is nil (router-to-router connection).

#### `IsTunnelConnection() bool`
Returns true if destination hash is set (tunnel connection).

**Example:**
```go
if addr.IsDirectConnection() && addr.IsRouterToRouter() {
    log.Println("Direct router-to-router connection")
} else if addr.IsIntroducedConnection() && addr.IsTunnelConnection() {
    log.Println("NAT-traversed tunnel connection")
}
```

## Utility Functions

### `GenerateConnectionID() (uint64, error)`

Generates a cryptographically secure random connection ID.

**Returns:**
- Non-zero `uint64` connection ID
- Error if random generation fails

**Implementation:**
- Uses `crypto/rand` for secure randomness
- Guaranteed non-zero (zero is reserved for handshake)
- 8-byte random value converted to uint64

**Example:**
```go
connID, err := GenerateConnectionID()
if err != nil {
    log.Fatalf("Failed to generate connection ID: %v", err)
}
// connID is guaranteed to be non-zero and cryptographically random
```

**Usage Note:** Always use this function to generate connection IDs rather than creating them manually. This ensures cryptographic strength and uniqueness.

## Design Decisions

### Connection ID vs Session Tag

SSU2 uses `connectionID` (8-byte uint64) instead of NTCP2's `sessionTag` (8-byte array). This reflects protocol differences:

- **NTCP2 Session Tag**: Opaque 8-byte identifier for session management
- **SSU2 Connection ID**: Numeric identifier for packet demultiplexing

Both are 8 bytes but serve different purposes in their respective protocols.

### Introducer Support

SSU2Addr includes native introducer support for NAT traversal, unlike NTCP2Addr. This is protocol-specific:

- **NTCP2**: TCP-based, relies on OS-level NAT traversal
- **SSU2**: UDP-based, requires application-level hole punching with introducers

### Zero Connection ID Restriction

Connection ID zero is reserved for handshake packets in SSU2 protocol. This restriction is enforced at address creation to prevent protocol violations.

### String Format Differences from NTCP2

SSU2Addr string format includes connection ID:
```
ssu2://[hash]:[conn_id]/[role]/[addr]
```

NTCP2Addr omits session tag from main format:
```
ntcp2://[hash]/[role]/[addr]
```

This reflects the different roles these identifiers play in their protocols.

## Performance Characteristics

Based on benchmarks (Intel i7-10710U @ 1.10GHz):

| Operation | Time | Allocations |
|-----------|------|-------------|
| `NewSSU2Addr()` | ~300 ns | 144 B (2 allocs) |
| `String()` | ~1.3 µs | 288 B (10 allocs) |
| `GenerateConnectionID()` | ~97 ns | 0 B (0 allocs) |

**Optimization Notes:**
- Address creation involves 2 allocations: struct + defensive router hash copy
- String formatting allocates for base64 encoding and string building
- Connection ID generation is allocation-free (uses stack buffer)

## Thread Safety

**Thread-Safe Operations:**
- All accessor methods (read-only)
- `GenerateConnectionID()` (uses `crypto/rand` which is thread-safe)

**Not Thread-Safe:**
- Concurrent modification of the same address instance (but addresses are immutable, so this is not a concern)

**Immutability Guarantee:**
Once created, an `SSU2Addr` cannot be modified. All modification methods return new instances, making concurrent reads completely safe without synchronization.

## Error Handling

All errors use `samber/oops` for rich context:

```go
addr, err := NewSSU2Addr(nil, routerHash, connID, "initiator")
// Error includes:
// - Code: "INVALID_UNDERLYING_ADDR"
// - Context: "ssu2"
// - Message: "underlying address cannot be nil"
```

**Error Codes:**
- `INVALID_UNDERLYING_ADDR` - nil underlying address
- `INVALID_ROUTER_HASH` - incorrect routerHash length
- `INVALID_CONNECTION_ID` - zero connection ID
- `INVALID_ROLE` - invalid role string
- `INVALID_DEST_HASH` - incorrect destHash length
- `INVALID_INTRODUCER_ADDR` - nil introducer address
- `RANDOM_GENERATION_FAILED` - crypto/rand failure

## Usage Examples

### Basic Router-to-Router Connection

```go
package main

import (
    "fmt"
    "net"
    "github.com/go-i2p/go-noise/ssu2"
)

func main() {
    // Create UDP address
    udpAddr, _ := net.ResolveUDPAddr("udp", "192.168.1.100:8080")
    
    // Router identity (normally from I2P key material)
    routerHash := make([]byte, 32)
    // ... populate with actual router identity hash
    
    // Generate connection ID
    connID, _ := ssu2.GenerateConnectionID()
    
    // Create SSU2 address
    addr, err := ssu2.NewSSU2Addr(udpAddr, routerHash, connID, "initiator")
    if err != nil {
        panic(err)
    }
    
    fmt.Printf("SSU2 Address: %s\n", addr)
    fmt.Printf("Connection ID: %d\n", addr.ConnectionID())
    fmt.Printf("Direct connection: %v\n", addr.IsDirectConnection())
}
```

### Tunnel Connection with Introducer

```go
// Create base address
baseAddr, _ := ssu2.NewSSU2Addr(udpAddr, routerHash, connID, "initiator")

// Set destination for tunnel
destHash := make([]byte, 32)
// ... populate with destination identity
tunnelAddr, _ := baseAddr.WithDestinationHash(destHash)

// Add introducer for NAT traversal
introducerUDP, _ := net.ResolveUDPAddr("udp", "10.0.0.2:9999")
finalAddr, _ := tunnelAddr.WithIntroducer(introducerUDP)

// Now have a fully-configured tunnel address with NAT traversal
fmt.Printf("Tunnel via introducer: %s\n", finalAddr)
fmt.Printf("Is tunnel: %v\n", finalAddr.IsTunnelConnection())
fmt.Printf("Is introduced: %v\n", finalAddr.IsIntroducedConnection())
```

### Connection Type Detection

```go
func describeConnection(addr *ssu2.SSU2Addr) string {
    connType := "Unknown"
    
    if addr.IsRouterToRouter() {
        connType = "Router-to-Router"
    } else if addr.IsTunnelConnection() {
        connType = "Tunnel"
    }
    
    natType := "Direct"
    if addr.IsIntroducedConnection() {
        natType = "Introduced (NAT traversal)"
    }
    
    return fmt.Sprintf("%s connection (%s)", connType, natType)
}
```

## Testing

The address module has comprehensive test coverage (100% for addr.go):

- **Unit tests**: Constructor validation, builder pattern, defensive copying
- **Interface tests**: `net.Addr` compliance verification
- **Error path tests**: All validation error conditions
- **Concurrency tests**: Immutability guarantees
- **Benchmark tests**: Performance characteristics

Run tests:
```bash
cd ssu2/
go test -v -run "TestSSU2Addr|TestGenerate"
go test -bench="BenchmarkSSU2Addr|BenchmarkGenerate" -benchmem
```

## Future Enhancements

Potential additions in later phases:

1. **Connection Statistics**: Track connection metrics (bytes sent/received, packet loss)
2. **Introducer Selection**: Helper for selecting optimal introducer from multiple options
3. **Address Serialization**: Binary format for network transmission
4. **IPv6 Support**: Enhanced handling for IPv6-specific addressing
5. **Multi-path Addressing**: Support for simultaneous multiple UDP paths

## See Also

- [NTCP2 Address Documentation](../ntcp2/addr.go) - TCP-based addressing for comparison
- [SSU2 README](README.md) - Protocol overview and implementation status
- [PLAN.md](../PLAN.md) - Full SSU2 implementation roadmap
