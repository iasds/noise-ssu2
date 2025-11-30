# go-noise

A wrapper library around the go-i2p/noise package that provides `net.Conn`, `net.Listener`, and `net.Addr` interfaces for the Noise Protocol Framework. Designed for implementing I2P's NTCP2 and SSU2 transport protocols with extensible handshake modification capabilities.

## Features

- **Configurable Noise Patterns**: Support for all standard Noise Protocol patterns  
- **net.Conn Interface**: Compatible with Go's standard network interfaces  
- **Error Handling**: Contextual error information using samber/oops  
- **Thread-Safe**: Concurrent connection handling with synchronization - Read/Write operations can be called concurrently, Close() is idempotent, and state access is atomic  
- **Memory Management**: Structured buffer management  

## Supported Noise Patterns

The library supports all standard Noise Protocol patterns with both short names and full specification:

- **One-way patterns**: `N`, `K`, `X`
- **Interactive patterns**: `NN`, `NK`, `NX`, `XN`, `XK`, `XX`, `KN`, `KK`, `KX`, `IN`, `IK`, `IX`
- **Full pattern names**: `Noise_XX_25519_AESGCM_SHA256`, etc.

## Quick Start

```go
package main

import (
    "context"
    "fmt"
    "net"
    "time"
    
    "github.com/go-i2p/go-noise"
)

func main() {
    // Create configuration for XX pattern
    config := noise.NewConnConfig("XX", true).
        WithHandshakeTimeout(10 * time.Second).
        WithReadTimeout(5 * time.Second)
    
    // Wrap an existing connection
    tcpConn, err := net.Dial("tcp", "localhost:8080")
    if err != nil {
        panic(err)
    }
    defer tcpConn.Close()
    
    // Create Noise connection
    noiseConn, err := noise.NewNoiseConn(tcpConn, config)
    if err != nil {
        panic(err)
    }
    defer noiseConn.Close()
    
    // Perform handshake
    ctx := context.Background()
    if err := noiseConn.Handshake(ctx); err != nil {
        panic(err)
    }
    
    // Use as regular net.Conn
    _, err = noiseConn.Write([]byte("Hello, Noise!"))
    if err != nil {
        panic(err)
    }
    
    buffer := make([]byte, 1024)
    n, err := noiseConn.Read(buffer)
    if err != nil {
        panic(err)
    }
    
    fmt.Printf("Received: %s\n", buffer[:n])
}
```

## Configuration

### ConnConfig Options

```go
config := noise.NewConnConfig("XX", true).
    WithStaticKey(staticKey).              // 32-byte Curve25519 private key
    WithHandshakeTimeout(30*time.Second).  // Handshake timeout
    WithReadTimeout(5*time.Second).        // Read operation timeout
    WithWriteTimeout(5*time.Second)        // Write operation timeout
```

### Pattern Selection

Choose the appropriate pattern based on your security requirements:

- **XX**: Mutual authentication with ephemeral keys
- **IK**: Initiator knows responder's static key
- **NK**: Responder has known static key, one-way authentication
- **NN**: No authentication, only encryption (not recommended for production)

## Connection State Management

The library provides connection state tracking and metrics:

```go
// Check connection state
state := noiseConn.GetConnectionState()
switch state {
case noise.StateInit:
    fmt.Println("Connection created, handshake not started")
case noise.StateHandshaking:
    fmt.Println("Handshake in progress")
case noise.StateEstablished:
    fmt.Println("Handshake complete, ready for secure communication")
case noise.StateClosed:
    fmt.Println("Connection closed")
}

// Get connection metrics
bytesRead, bytesWritten, handshakeDuration := noiseConn.GetConnectionMetrics()
fmt.Printf("Transferred %d bytes read, %d bytes written\n", bytesRead, bytesWritten)
fmt.Printf("Handshake completed in %v\n", handshakeDuration)
```

### State Transitions

Connections follow this lifecycle:
1. **Init** → Created with `NewNoiseConn()`
2. **Handshaking** → `Handshake()` called
3. **Established** → Handshake completed successfully
4. **Closed** → `Close()` called or connection failed

### Monitoring

The library tracks:
- **Handshake Duration**: Time taken to complete the Noise handshake
- **Bytes Read/Written**: Total data transferred (plaintext, not encrypted)
- **Connection Lifecycle**: Creation time and state transitions

## Implementation Status

### Core Components ✅
- **Noise Protocol Wrapper**: Complete with net.Conn interface
- **NTCP2 Transport**: Complete with AES obfuscation, padding, and SipHash modifiers
- **Connection Pooling**: Complete with configurable pool management
- **Listener Support**: Complete for NTCP2 connections

### SSU2 Transport 🚧 (In Progress)
- **Phase 1.1**: ChaCha20 Obfuscation Modifier ✅ (91.1% test coverage)
  - ChaCha20 stream cipher for ephemeral key obfuscation
  - 8-byte IV support for SSU2 protocol
  - Automatic state derivation between handshake messages
  - See [ssu2/README.md](ssu2/README.md) for details
- **Phase 1.2**: SSU2 Padding Modifier ✅ (82.7% test coverage)
  - MTU-aware padding with I2P ratios (0.0-15.9375)
  - Dynamic MTU adjustment during connection
  - Thread-safe parameter updates
- **Phase 1.3**: SipHash Length Modifier ✅ (100% test coverage)
  - Frame length obfuscation using SipHash-2-4
  - Wraps NTCP2 implementation for protocol-agnostic use
- **Phase 2.1**: SSU2 Address Implementation ✅ (100% test coverage)
  - Complete `net.Addr` interface for UDP-based SSU2 connections
  - Connection ID generation with cryptographic security
  - NAT traversal support via introducer addresses
  - Immutable builder pattern with defensive copying
- **Phase 2.2**: SSU2 Configuration Builder (Next)
- **Phase 3+**: Connection layer, transport functions, utilities (See [PLAN.md](PLAN.md))

## Architecture

```
NoiseConn (net.Conn)
├── Config (pattern, keys, timeouts)
├── HandshakeState (go-i2p/noise)
├── CipherState (post-handshake encryption)
├── NoiseAddr (net.Addr with pattern info)
└── Underlying net.Conn (TCP, UDP, etc.)
```

## Logging

The library uses structured logging via `github.com/go-i2p/logger` for enhanced observability and debugging.

### Enabling Debug Logging

Enable verbose debug output by setting the `DEBUG_I2P` environment variable:

```bash
# Enable debug logging
export DEBUG_I2P=debug

# Run your application
go run main.go

# Or run tests with debug logging
DEBUG_I2P=debug go test -v ./...
```

### Fast-Fail Mode (Testing Only)

For testing and development, enable fast-fail mode to catch warnings and errors immediately:

```bash
# Enable fast-fail mode (warnings become fatal)
export WARNFAIL_I2P=true
export DEBUG_I2P=debug

# Run tests in strict mode
WARNFAIL_I2P=true DEBUG_I2P=debug go test -v ./...
```

⚠️ **Warning**: Fast-fail mode should only be used in testing/development environments. Do not enable in production.

### What Gets Logged

The library logs structured information at various levels:

- **Debug**: Connection creation, handshake progress, state transitions, cipher state updates
- **Info**: Handshake completion, listener events, connection metrics
- **Warn**: Retry attempts, timeout warnings, recoverable issues
- **Error**: Handshake failures, connection errors, validation failures

All log entries include structured fields such as:

- `pattern`: Noise protocol pattern (e.g., "XX", "IK")
- `initiator`: Connection role (true/false)
- `local_addr`: Local connection address
- `remote_addr`: Remote connection address
- `state`: Connection state (Init, Handshaking, Established, Closed)

### Zero-Impact by Default

When `DEBUG_I2P` is not set, logging is completely disabled with zero performance overhead. This ensures production deployments have no logging costs unless explicitly enabled for troubleshooting.

### Example Debug Output

```bash
$ DEBUG_I2P=debug go run examples/basic/main.go
[DEBUG] NoiseConn created pattern=XX initiator=true local_addr=127.0.0.1:54321 remote_addr=127.0.0.1:8080
[INFO] Starting Noise handshake pattern=XX initiator=true local_addr=127.0.0.1:54321 remote_addr=127.0.0.1:8080
[DEBUG] Starting initiator handshake pattern=XX role=initiator remote_addr=127.0.0.1:8080
[DEBUG] Cipher state updated - handshake progressing pattern=XX state=cipher_updated
[INFO] Handshake completed successfully pattern=XX duration=2.3ms
```

## Dependencies

- **go-i2p/noise** v1.1.0: Core Noise Protocol implementation
- **go-i2p/logger**: Structured logging support with environment-based control
- **samber/oops** v1.19.0: Rich error context

## Testing

```bash
go test -v ./...
```

Current test coverage includes unit and integration tests for core functionality across all components:

- Handshake pattern parsing and validation
- Configuration validation  
- NoiseAddr interface compliance
- NoiseConn read/write operations and error handling
- NTCP2Addr I2P-specific addressing functionality
- NTCP2Conn net.Conn interface compliance and error wrapping
- Handshake modifier chaining and transformations
- Error handling scenarios across all components

## Contributing

This library follows Go best practices:

- Functions under 30 lines with single responsibility
- Explicit error handling (no ignored returns)
- Self-documenting code with clear naming
- Unit and integration testing with coverage monitoring

## License

MIT License

## Status

**Development Status**: Core functionality and handshake modification system implemented. Connection pooling and listener features in development.
