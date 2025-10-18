# SSU2 Transport Implementation

I2P SSU2 (Secure Semi-reliable UDP version 2) transport protocol implementation using the Noise Protocol Framework.

## Overview

This package provides handshake modifiers and utilities for implementing the SSU2 transport protocol, which is I2P's UDP-based encrypted transport. SSU2 uses the Noise Protocol Framework with ChaCha20-Poly1305 for encryption and ChaCha20 stream cipher for ephemeral key obfuscation.

## Features

### Implemented (Phase 1)

1. **ChaCha20 Obfuscation Modifier**: Stream cipher-based ephemeral key obfuscation for handshake messages 1-2
   - 8-byte IV (vs NTCP2's 16-byte)
   - XOR-based stream cipher (vs block cipher)
   - Automatic state derivation for message 2

2. **SSU2 Padding Modifier**: MTU-aware padding for UDP packet size optimization
   - MTU range: 1280-1500 bytes (IPv6 minimum to Ethernet maximum)
   - I2P padding ratios: 0.0-15.9375
   - Thread-safe dynamic parameter updates
   - AEAD and cleartext padding modes

## Protocol Compliance

- **Pattern**: `Noise_XKchaobfse+hs1+hs2+hs3_25519_ChaChaPoly_SHA256`
- **DH**: Curve25519
- **Cipher**: ChaCha20-Poly1305 AEAD
- **Hash**: SHA-256
- **Obfuscation**: ChaCha20 stream cipher

## Quick Start

### ChaCha20 Obfuscation Modifier

```go
package main

import (
    "crypto/rand"
    "github.com/go-i2p/go-noise/ssu2"
    "github.com/go-i2p/go-noise/handshake"
)

func main() {
    // Generate 32-byte router hash and 8-byte IV
    routerHash := make([]byte, 32)
    iv := make([]byte, 8)
    rand.Read(routerHash)
    rand.Read(iv)
    
    // Create ChaCha20 obfuscation modifier
    modifier, err := ssu2.NewChaChaObfuscationModifier(
        "ssu2-chacha-obfs",
        routerHash,
        iv,
    )
    if err != nil {
        panic(err)
    }
    
    // Use in handshake (initiator)
    ephemeralKey := make([]byte, 32) // X or Y ephemeral key
    rand.Read(ephemeralKey)
    
    // Encrypt outbound message 1
    encrypted, err := modifier.ModifyOutbound(handshake.PhaseInitial, ephemeralKey)
    if err != nil {
        panic(err)
    }
    
    // ... send encrypted data over network ...
    
    // Decrypt inbound message 2 (responder's ephemeral key)
    // Note: Receiver must create their own modifier with same routerHash and IV
    decrypted, err := modifier.ModifyInbound(handshake.PhaseExchange, encrypted)
    if err != nil {
        panic(err)
    }
}
```

## Architecture

### ChaCha20 Obfuscation

The ChaCha20 obfuscation modifier implements SSU2's ephemeral key obfuscation:

- **Message 1 (Initial)**: XOR X ephemeral key with ChaCha20(routerHash, IV)
  - Derives state from last 8 bytes of encrypted output for message 2
- **Message 2 (Exchange)**: XOR Y ephemeral key with ChaCha20(routerHash, derived_IV)
- **Message 3+ (Final)**: No obfuscation (Noise protocol handles encryption)

Key differences from NTCP2's AES obfuscation:
- **IV Size**: 8 bytes (SSU2) vs 16 bytes (NTCP2)
- **Cipher Type**: Stream cipher (ChaCha20) vs block cipher (AES-CBC)
- **Operation**: XOR-based vs block encryption
- **State Derivation**: From encrypted data (sender and receiver must coordinate)

## Security Properties

### Obfuscation

ChaCha20 obfuscation provides:
- **DPI Resistance**: Encrypted ephemeral keys prevent deep packet inspection fingerprinting
- **Pattern Hiding**: Noise handshake pattern is obscured from network observers
- **Performance**: ChaCha20 is faster than AES on non-AES-NI hardware

### Key Management

- **Router Hash**: 32-byte I2P router identity (must match peer's public router info)
- **IV**: 8-byte initialization vector from network database (public, non-secret)
- **Derived State**: Automatically derived for message 2 from message 1 output

### Thread Safety

All modifiers are thread-safe for concurrent use:
- Defensive copying of input parameters
- Safe for use in concurrent handshakes
- State management is modifier-instance-specific

## Performance

Based on benchmarks on Intel Core i7-10710U @ 1.10GHz:

```text
BenchmarkChaChaObfuscation-12     1396284    855.2 ns/op    40 B/op     2 allocs/op
BenchmarkSSU2Padding-12           1000000   1170 ns/op     140 B/op     0 allocs/op
BenchmarkSSU2PaddingRemoval-12   13712234     73.52 ns/op    0 B/op     0 allocs/op
```

- **ChaCha20 Throughput**: ~1.4 million operations/second
- **Padding Overhead**: ~1.2 microseconds per operation
- **Padding Removal**: ~73 nanoseconds (extremely fast)
- **Memory**: Minimal allocations (0-140 bytes per operation)

## Testing

```bash
# Run all SSU2 tests
go test -v ./ssu2/...

# Run with coverage
go test -cover ./ssu2/...

# Run benchmarks
go test -bench=. -benchmem ./ssu2/...
```

Current test coverage: **82.7%**

### Test Scenarios

- ✅ Constructor validation (router hash, IV sizes)
- ✅ Defensive copying of parameters
- ✅ Roundtrip encryption/decryption
- ✅ Phase-specific behavior (Initial, Exchange, Final)
- ✅ State management across messages
- ✅ Non-32-byte data pass-through
- ✅ Different keys/IVs produce different output
- ✅ Symmetric XOR operation

## Implementation Status

### Phase 1: Core Cryptographic Foundation ✅

- [x] **ChaCha20 Obfuscation Modifier**: Complete with 91.1% test coverage
- [x] **SSU2 Padding Modifier**: Complete with 82.7% test coverage (MTU-aware padding)
- [ ] **SipHash Length Modifier**: Planned (reuse NTCP2 implementation)

### Phase 2: Address and Configuration Layer (Planned)

- [ ] SSU2 Address Implementation
- [ ] SSU2 Configuration Builder

### Future Phases

See [PLAN.md](../PLAN.md) for complete implementation roadmap.

## Dependencies

- **golang.org/x/crypto/chacha20**: ChaCha20 stream cipher implementation
- **github.com/samber/oops**: Rich error context and wrapping
- **github.com/go-i2p/go-noise/handshake**: Handshake modifier interface

## Contributing

This library follows Go best practices:

- Functions under 30 lines with single responsibility
- Explicit error handling (no ignored returns)
- Self-documenting code with clear naming
- Comprehensive testing (>80% coverage requirement)
- GoDoc comments for all exported types/functions

## License

MIT License

## Status

**Development Status**: Phase 1 in progress - Core cryptographic modifiers being implemented.

**Production Ready**: ChaCha20 obfuscation modifier is complete and well-tested, suitable for use in SSU2 implementations.
