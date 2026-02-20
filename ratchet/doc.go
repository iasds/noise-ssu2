// Package ratchet defines interfaces for the ECIES-X25519-AEAD-Ratchet
// cryptographic engine used by the I2P network.
//
// This package provides the contract between go-i2p (routing layer) and
// go-noise (crypto layer). All interfaces use primitive types ([32]byte,
// [8]byte, []byte) instead of I2P-specific types, ensuring that go-noise
// has no dependency on go-i2p/common or go-i2p/go-i2p.
//
// The primary interfaces are:
//
//   - [GarlicSessionManager]: Full encrypt/decrypt/lifecycle for garlic sessions.
//   - [GarlicEncryptor]: Encrypt-only subset for producers (e.g., I2CP message router).
//   - [GarlicDecryptor]: Decrypt-only subset for consumers (e.g., message processor).
//   - [BuildRecordEncryptor]: ECIES encrypt/decrypt for tunnel build request records.
//   - [BuildReplyEncryptor]: ChaCha20-Poly1305/AES encrypt/decrypt for build reply records.
//   - [TagResolver]: O(1) session tag lookup for incoming messages.
//
// Callers in go-i2p convert I2P types to raw bytes before calling these interfaces:
//
// common.Hash          → [32]byte
// session_key.SessionKey → [32]byte
// session_tag.ECIESSessionTag → [8]byte
// router_info.RouterInfo → extracted [32]byte keys via adapter functions
//
// Reference: https://geti2p.net/spec/ecies
package ratchet
