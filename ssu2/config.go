package ssu2

import (
	"time"

	noise "github.com/go-i2p/go-noise"
	"github.com/go-i2p/go-noise/handshake"
	"github.com/samber/oops"
)

// SSU2Config contains configuration for creating SSU2 connections and listeners.
// SSU2 (Secure Semi-reliable UDP version 2) is I2P's UDP-based transport protocol.
// It follows the builder pattern for optional configuration and validation.
type SSU2Config struct {
	// Pattern is the Noise protocol pattern for SSU2
	// Default: "XK" (standard SSU2 pattern)
	Pattern string

	// Initiator indicates if this connection is the handshake initiator
	// For listeners, this is always false
	Initiator bool

	// RouterHash is the local router identity (32 bytes)
	// Required for SSU2 addressing and session establishment
	RouterHash []byte

	// StaticKey is the long-term static key for this peer (32 bytes for Curve25519)
	StaticKey []byte

	// RemoteRouterHash is the remote peer's router identity (32 bytes)
	// Required for outbound connections, optional for listeners
	RemoteRouterHash []byte

	// HandshakeTimeout is the maximum time to wait for handshake completion
	// Default: 30 seconds
	HandshakeTimeout time.Duration

	// ReadTimeout is the timeout for read operations after handshake
	// Default: no timeout (0)
	ReadTimeout time.Duration

	// WriteTimeout is the timeout for write operations after handshake
	// Default: no timeout (0)
	WriteTimeout time.Duration

	// HandshakeRetries is the number of handshake retry attempts
	// Default: 3 attempts (0 = no retries, -1 = infinite retries)
	HandshakeRetries int

	// RetryBackoff is the base delay between retry attempts
	// Actual delay uses exponential backoff: delay = RetryBackoff * (2^attempt)
	// Default: 1 second
	RetryBackoff time.Duration

	// EnableChaChaObfuscation enables ChaCha20-based ephemeral key obfuscation
	// Default: true (recommended for production)
	EnableChaChaObfuscation bool

	// ObfuscationIV is the 8-byte IV for ChaCha20 obfuscation
	// If nil, will be derived from router hash (recommended)
	ObfuscationIV []byte

	// EnableSipHashLength enables SipHash-based frame length obfuscation
	// Default: true (recommended for production)
	EnableSipHashLength bool

	// SipHashKeys are the k1, k2 keys for SipHash length obfuscation
	// If empty, will be derived during handshake
	SipHashKeys [2]uint64

	// MTU is the Maximum Transmission Unit for UDP packets
	// Default: 1280 bytes (IPv6 minimum MTU)
	// Range: 1280-1500 bytes
	MTU int

	// MaxPacketSize is the maximum UDP packet size to send/receive
	// Default: 1500 bytes (typical Ethernet MTU)
	MaxPacketSize int

	// EnableFragmentation allows splitting large messages across multiple packets
	// Default: false (handle at SSU2 layer)
	EnableFragmentation bool

	// PaddingEnabled enables random padding in SSU2 frames
	// Default: true (recommended for traffic analysis resistance)
	PaddingEnabled bool

	// MinPaddingSize is the minimum padding size for frames
	// Default: 0 bytes
	MinPaddingSize int

	// MaxPaddingSize is the maximum padding size for frames
	// Default: 64 bytes
	MaxPaddingSize int

	// PaddingRatio is the padding amount as ratio of data size
	// Valid range: 0.0 to 15.9375 (I2P specification)
	// Default: 1.0 (100% of data size)
	PaddingRatio float64

	// ConnectionID is the 8-byte SSU2 connection identifier
	// If 0, will be generated randomly
	ConnectionID uint64

	// KeepaliveInterval is the time between keepalive packets
	// UDP requires active keepalive to maintain connection state
	// Default: 15 seconds
	KeepaliveInterval time.Duration

	// Modifiers is a list of additional handshake modifiers for custom obfuscation
	// These are applied in addition to SSU2's standard modifiers
	// Default: empty (no additional modifiers)
	Modifiers []handshake.HandshakeModifier
}

// NewSSU2Config creates a new SSU2Config with sensible defaults.
// routerHash must be exactly 32 bytes representing the local router identity.
// initiator indicates whether this connection will initiate the handshake.
func NewSSU2Config(routerHash []byte, initiator bool) (*SSU2Config, error) {
	if len(routerHash) != 32 {
		return nil, oops.
			Code("INVALID_ROUTER_HASH").
			In("ssu2").
			With("hash_length", len(routerHash)).
			Errorf("router hash must be exactly 32 bytes")
	}

	// Make defensive copy of router hash
	hash := make([]byte, 32)
	copy(hash, routerHash)

	return &SSU2Config{
		Pattern:                 "XK",
		Initiator:               initiator,
		RouterHash:              hash,
		HandshakeTimeout:        30 * time.Second,
		ReadTimeout:             0, // No timeout by default
		WriteTimeout:            0, // No timeout by default
		HandshakeRetries:        3,
		RetryBackoff:            1 * time.Second,
		EnableChaChaObfuscation: true,
		EnableSipHashLength:     true,
		MTU:                     1280, // IPv6 minimum
		MaxPacketSize:           1500, // Standard Ethernet
		EnableFragmentation:     false,
		PaddingEnabled:          true,
		MinPaddingSize:          0,
		MaxPaddingSize:          64,
		PaddingRatio:            1.0, // 100%
		ConnectionID:            0,   // Will be generated
		KeepaliveInterval:       15 * time.Second,
	}, nil
}

// WithPattern sets the Noise protocol pattern.
// For SSU2, this should typically remain "XK".
func (sc *SSU2Config) WithPattern(pattern string) *SSU2Config {
	sc.Pattern = pattern
	return sc
}

// WithStaticKey sets the static key for this connection.
// key must be 32 bytes for Curve25519.
func (sc *SSU2Config) WithStaticKey(key []byte) *SSU2Config {
	if len(key) == 32 {
		sc.StaticKey = make([]byte, 32)
		copy(sc.StaticKey, key)
	}
	return sc
}

// WithRemoteRouterHash sets the remote peer's router identity.
// hash must be 32 bytes. Required for outbound connections.
func (sc *SSU2Config) WithRemoteRouterHash(hash []byte) *SSU2Config {
	if len(hash) == 32 {
		sc.RemoteRouterHash = make([]byte, 32)
		copy(sc.RemoteRouterHash, hash)
	}
	return sc
}

// WithHandshakeTimeout sets the handshake timeout.
func (sc *SSU2Config) WithHandshakeTimeout(timeout time.Duration) *SSU2Config {
	sc.HandshakeTimeout = timeout
	return sc
}

// WithReadTimeout sets the read timeout for post-handshake operations.
func (sc *SSU2Config) WithReadTimeout(timeout time.Duration) *SSU2Config {
	sc.ReadTimeout = timeout
	return sc
}

// WithWriteTimeout sets the write timeout for post-handshake operations.
func (sc *SSU2Config) WithWriteTimeout(timeout time.Duration) *SSU2Config {
	sc.WriteTimeout = timeout
	return sc
}

// WithHandshakeRetries sets the number of handshake retry attempts.
// Use 0 for no retries, -1 for infinite retries.
func (sc *SSU2Config) WithHandshakeRetries(retries int) *SSU2Config {
	sc.HandshakeRetries = retries
	return sc
}

// WithRetryBackoff sets the base delay between retry attempts.
func (sc *SSU2Config) WithRetryBackoff(backoff time.Duration) *SSU2Config {
	sc.RetryBackoff = backoff
	return sc
}

// WithChaChaObfuscation enables or disables ChaCha20-based ephemeral key obfuscation.
// When enabled with a custom IV, the IV must be exactly 8 bytes.
func (sc *SSU2Config) WithChaChaObfuscation(enabled bool, customIV []byte) *SSU2Config {
	sc.EnableChaChaObfuscation = enabled
	if len(customIV) == 8 {
		sc.ObfuscationIV = make([]byte, 8)
		copy(sc.ObfuscationIV, customIV)
	}
	return sc
}

// WithSipHashLength enables or disables SipHash-based frame length obfuscation.
// When enabled with custom keys, both k1 and k2 must be provided.
func (sc *SSU2Config) WithSipHashLength(enabled bool, k1, k2 uint64) *SSU2Config {
	sc.EnableSipHashLength = enabled
	if enabled && (k1 != 0 || k2 != 0) {
		sc.SipHashKeys[0] = k1
		sc.SipHashKeys[1] = k2
	}
	return sc
}

// WithMTU sets the Maximum Transmission Unit for UDP packets.
// Valid range: 1280-1500 bytes. Default is 1280 (IPv6 minimum).
func (sc *SSU2Config) WithMTU(mtu int) *SSU2Config {
	if mtu >= 1280 && mtu <= 1500 {
		sc.MTU = mtu
	}
	return sc
}

// WithPacketSettings configures UDP packet handling parameters.
// maxSize sets the maximum packet size (default: 1500 bytes).
// fragmentation enables splitting large messages (default: false).
func (sc *SSU2Config) WithPacketSettings(maxSize int, fragmentation bool) *SSU2Config {
	if maxSize > 0 {
		sc.MaxPacketSize = maxSize
	}
	sc.EnableFragmentation = fragmentation
	return sc
}

// WithPaddingSettings configures SSU2 frame padding parameters.
// enabled enables random padding (default: true).
// minPad and maxPad set the padding size range (default: 0-64 bytes).
// ratio sets the padding amount as ratio of data size (0.0-15.9375).
func (sc *SSU2Config) WithPaddingSettings(enabled bool, minPad, maxPad int, ratio float64) *SSU2Config {
	sc.PaddingEnabled = enabled
	if minPad >= 0 {
		sc.MinPaddingSize = minPad
	}
	if maxPad >= minPad {
		sc.MaxPaddingSize = maxPad
	}
	if ratio >= 0.0 && ratio <= 15.9375 {
		sc.PaddingRatio = ratio
	}
	return sc
}

// WithConnectionID sets the SSU2 connection identifier.
// If connID is 0, a random ID will be generated during connection creation.
func (sc *SSU2Config) WithConnectionID(connID uint64) *SSU2Config {
	sc.ConnectionID = connID
	return sc
}

// WithKeepalive sets the interval between keepalive packets.
// UDP connections require active keepalive to maintain state.
func (sc *SSU2Config) WithKeepalive(interval time.Duration) *SSU2Config {
	sc.KeepaliveInterval = interval
	return sc
}

// WithModifiers sets additional handshake modifiers for custom obfuscation.
// These are applied in addition to SSU2's standard modifiers.
func (sc *SSU2Config) WithModifiers(modifiers ...handshake.HandshakeModifier) *SSU2Config {
	// Make defensive copy
	sc.Modifiers = make([]handshake.HandshakeModifier, len(modifiers))
	copy(sc.Modifiers, modifiers)
	return sc
}

// Validate checks if the configuration is valid for SSU2.
func (sc *SSU2Config) Validate() error {
	if err := sc.validateBasicConfiguration(); err != nil {
		return err
	}

	if err := sc.validateCryptographicParameters(); err != nil {
		return err
	}

	if err := sc.validateTimeoutConfiguration(); err != nil {
		return err
	}

	if err := sc.validateUDPConfiguration(); err != nil {
		return err
	}

	if err := sc.validatePaddingConfiguration(); err != nil {
		return err
	}

	return nil
}

// validateBasicConfiguration checks pattern and router hash requirements.
func (sc *SSU2Config) validateBasicConfiguration() error {
	// Validate pattern (SSU2 typically uses XK)
	if sc.Pattern == "" {
		return oops.
			Code("MISSING_PATTERN").
			In("ssu2").
			Errorf("noise pattern is required")
	}

	// Validate router hash
	if len(sc.RouterHash) != 32 {
		return oops.
			Code("INVALID_ROUTER_HASH").
			In("ssu2").
			With("hash_length", len(sc.RouterHash)).
			Errorf("router hash must be exactly 32 bytes")
	}

	return nil
}

// validateCryptographicParameters checks keys, hashes, and obfuscation settings.
func (sc *SSU2Config) validateCryptographicParameters() error {
	// Validate static key if provided
	if len(sc.StaticKey) > 0 && len(sc.StaticKey) != 32 {
		return oops.
			Code("INVALID_STATIC_KEY").
			In("ssu2").
			With("key_length", len(sc.StaticKey)).
			Errorf("static key must be 32 bytes")
	}

	// Validate remote router hash if provided
	if len(sc.RemoteRouterHash) > 0 && len(sc.RemoteRouterHash) != 32 {
		return oops.
			Code("INVALID_REMOTE_ROUTER_HASH").
			In("ssu2").
			With("hash_length", len(sc.RemoteRouterHash)).
			Errorf("remote router hash must be 32 bytes")
	}

	// For initiator connections, remote router hash is required
	if sc.Initiator && len(sc.RemoteRouterHash) == 0 {
		return oops.
			Code("MISSING_REMOTE_ROUTER_HASH").
			In("ssu2").
			Errorf("remote router hash is required for initiator connections")
	}

	// Validate ChaCha20 obfuscation IV if provided (8 bytes for SSU2)
	if sc.ObfuscationIV != nil && len(sc.ObfuscationIV) != 8 {
		return oops.
			Code("INVALID_OBFUSCATION_IV").
			In("ssu2").
			With("iv_length", len(sc.ObfuscationIV)).
			Errorf("obfuscation IV must be 8 bytes")
	}

	return nil
}

// validateTimeoutConfiguration checks handshake timeouts and retry settings.
func (sc *SSU2Config) validateTimeoutConfiguration() error {
	// Validate handshake timeout
	if sc.HandshakeTimeout <= 0 {
		return oops.
			Code("INVALID_HANDSHAKE_TIMEOUT").
			In("ssu2").
			With("timeout", sc.HandshakeTimeout).
			Errorf("handshake timeout must be positive")
	}

	// Validate retry configuration
	if sc.HandshakeRetries < -1 {
		return oops.
			Code("INVALID_RETRY_COUNT").
			In("ssu2").
			With("retries", sc.HandshakeRetries).
			Errorf("handshake retries must be >= -1")
	}

	if sc.RetryBackoff < 0 {
		return oops.
			Code("INVALID_RETRY_BACKOFF").
			In("ssu2").
			With("backoff", sc.RetryBackoff).
			Errorf("retry backoff must be non-negative")
	}

	// Validate keepalive interval
	if sc.KeepaliveInterval <= 0 {
		return oops.
			Code("INVALID_KEEPALIVE_INTERVAL").
			In("ssu2").
			With("interval", sc.KeepaliveInterval).
			Errorf("keepalive interval must be positive")
	}

	return nil
}

// validateUDPConfiguration checks MTU, packet size, and fragmentation settings.
func (sc *SSU2Config) validateUDPConfiguration() error {
	// Validate MTU (IPv6 minimum is 1280, typical Ethernet is 1500)
	if sc.MTU < 1280 || sc.MTU > 1500 {
		return oops.
			Code("INVALID_MTU").
			In("ssu2").
			With("mtu", sc.MTU).
			Errorf("MTU must be between 1280 and 1500 bytes")
	}

	// Validate max packet size
	if sc.MaxPacketSize <= 0 {
		return oops.
			Code("INVALID_MAX_PACKET_SIZE").
			In("ssu2").
			With("max_size", sc.MaxPacketSize).
			Errorf("max packet size must be positive")
	}

	// Max packet size should be >= MTU for proper operation
	if sc.MaxPacketSize < sc.MTU {
		return oops.
			Code("PACKET_SIZE_LESS_THAN_MTU").
			In("ssu2").
			With("max_packet_size", sc.MaxPacketSize).
			With("mtu", sc.MTU).
			Errorf("max packet size must be >= MTU")
	}

	return nil
}

// validatePaddingConfiguration checks padding ranges and ratios.
func (sc *SSU2Config) validatePaddingConfiguration() error {
	// Validate padding sizes
	if sc.MinPaddingSize < 0 {
		return oops.
			Code("INVALID_MIN_PADDING").
			In("ssu2").
			With("min_padding", sc.MinPaddingSize).
			Errorf("min padding size must be non-negative")
	}

	if sc.MaxPaddingSize < sc.MinPaddingSize {
		return oops.
			Code("INVALID_PADDING_RANGE").
			In("ssu2").
			With("min_padding", sc.MinPaddingSize).
			With("max_padding", sc.MaxPaddingSize).
			Errorf("max padding size must be >= min padding size")
	}

	// Validate padding ratio (I2P spec allows 0.0 to 15.9375)
	if sc.PaddingRatio < 0.0 || sc.PaddingRatio > 15.9375 {
		return oops.
			Code("INVALID_PADDING_RATIO").
			In("ssu2").
			With("ratio", sc.PaddingRatio).
			Errorf("padding ratio must be between 0.0 and 15.9375")
	}

	return nil
}

// ToConnConfig converts SSU2Config to a standard ConnConfig for use with NoiseConn.
// This includes setting up SSU2-specific modifiers based on the configuration.
func (sc *SSU2Config) ToConnConfig() (*noise.ConnConfig, error) {
	if err := sc.Validate(); err != nil {
		return nil, oops.
			Code("INVALID_CONFIG").
			In("ssu2").
			Wrap(err)
	}

	config := sc.createBaseConnConfig()
	sc.copyStaticKeyIfProvided(config)

	modifiers, err := sc.setupSSU2Modifiers()
	if err != nil {
		return nil, err
	}

	config.Modifiers = modifiers
	return config, nil
}

// createBaseConnConfig creates a base ConnConfig with core SSU2 settings.
func (sc *SSU2Config) createBaseConnConfig() *noise.ConnConfig {
	return &noise.ConnConfig{
		Pattern:          sc.Pattern,
		Initiator:        sc.Initiator,
		StaticKey:        make([]byte, len(sc.StaticKey)),
		HandshakeTimeout: sc.HandshakeTimeout,
		ReadTimeout:      sc.ReadTimeout,
		WriteTimeout:     sc.WriteTimeout,
		HandshakeRetries: sc.HandshakeRetries,
		RetryBackoff:     sc.RetryBackoff,
	}
}

// copyStaticKeyIfProvided copies the static key to the config if one is provided.
func (sc *SSU2Config) copyStaticKeyIfProvided(config *noise.ConnConfig) {
	if len(sc.StaticKey) > 0 {
		copy(config.StaticKey, sc.StaticKey)
	}
}

// setupSSU2Modifiers creates and configures all SSU2-specific handshake modifiers.
func (sc *SSU2Config) setupSSU2Modifiers() ([]handshake.HandshakeModifier, error) {
	var modifiers []handshake.HandshakeModifier

	chachaModifier, err := sc.createChaChaModifierIfEnabled()
	if err != nil {
		return nil, err
	}
	if chachaModifier != nil {
		modifiers = append(modifiers, chachaModifier)
	}

	paddingModifier, err := sc.createPaddingModifierIfEnabled()
	if err != nil {
		return nil, err
	}
	if paddingModifier != nil {
		modifiers = append(modifiers, paddingModifier)
	}

	sipModifier := sc.createSipHashModifierIfEnabled()
	if sipModifier != nil {
		modifiers = append(modifiers, sipModifier)
	}

	modifiers = append(modifiers, sc.Modifiers...)
	return modifiers, nil
}

// createChaChaModifierIfEnabled creates a ChaCha20 obfuscation modifier if enabled.
func (sc *SSU2Config) createChaChaModifierIfEnabled() (handshake.HandshakeModifier, error) {
	if !sc.EnableChaChaObfuscation {
		return nil, nil
	}

	iv := sc.ObfuscationIV
	if iv == nil {
		// Derive IV from router hash (last 8 bytes)
		iv = sc.RouterHash[24:]
	}

	chachaModifier, err := NewChaChaObfuscationModifier("ssu2-chacha", sc.RouterHash, iv)
	if err != nil {
		return nil, oops.
			Code("CHACHA_MODIFIER_FAILED").
			In("ssu2").
			Wrap(err)
	}
	return chachaModifier, nil
}

// createPaddingModifierIfEnabled creates an SSU2 padding modifier if enabled.
func (sc *SSU2Config) createPaddingModifierIfEnabled() (handshake.HandshakeModifier, error) {
	if !sc.PaddingEnabled {
		return nil, nil
	}

	paddingModifier, err := NewSSU2PaddingModifierWithMTU(
		"ssu2-padding",
		sc.MinPaddingSize,
		sc.MaxPaddingSize,
		sc.MTU,
		true, // AEAD mode for SSU2
		sc.PaddingRatio,
	)
	if err != nil {
		return nil, oops.
			Code("PADDING_MODIFIER_FAILED").
			In("ssu2").
			Wrap(err)
	}
	return paddingModifier, nil
}

// createSipHashModifierIfEnabled creates a SipHash length modifier if enabled.
func (sc *SSU2Config) createSipHashModifierIfEnabled() handshake.HandshakeModifier {
	if !sc.EnableSipHashLength {
		return nil
	}
	// SipHash keys will be set up during handshake if not provided
	return NewSSU2LengthModifier("ssu2-siphash", sc.SipHashKeys, 0)
}
