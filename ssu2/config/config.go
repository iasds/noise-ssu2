package config

import (
	"crypto/subtle"
	"time"

	"github.com/go-i2p/common/data"
	"github.com/go-i2p/common/router_info"
	noise "github.com/go-i2p/go-noise"
	"github.com/go-i2p/go-noise/handshake"
	"github.com/go-i2p/go-noise/internal"
	ssu2hs "github.com/go-i2p/go-noise/ssu2/handshake"
	"github.com/go-i2p/go-noise/ssu2/wire"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// Default timeout values per SSU2 specification (ssu2.rst)
const (
	// DefaultHandshakeTimeout is the spec-defined handshake timeout of 15 seconds.
	// Per ssu2.rst: "Handshake timeout: 15 seconds"
	DefaultHandshakeTimeout = 15 * time.Second
)

// DefaultRouterInfoValidator validates that the Noise-authenticated static
// key matches the "s" option in an SSU2 address within the RouterInfo.
//
// It parses the RouterInfo binary payload, locates SSU2 router addresses,
// and compares the static key from the "s" option against the
// Noise-authenticated static key using constant-time comparison.
//
// Per SSU2 spec §SessionConfirmed Notes, the responder must verify that
// the static key authenticated by the Noise handshake corresponds to the
// key published in the peer's RouterInfo.
func DefaultRouterInfoValidator(routerInfo, authenticatedStaticKey []byte) error {
	log.WithFields(logger.Fields{"pkg": "config", "func": "DefaultRouterInfoValidator", "router_info_len": len(routerInfo), "static_key_len": len(authenticatedStaticKey)}).Debug("Validating router info against authenticated static key")
	if len(routerInfo) == 0 {
		return oops.
			Code("EMPTY_ROUTER_INFO").
			In("ssu2").
			Errorf("RouterInfo is empty")
	}
	if len(authenticatedStaticKey) == 0 {
		return oops.
			Code("EMPTY_STATIC_KEY").
			In("ssu2").
			Errorf("authenticated static key is empty")
	}

	ri, _, err := router_info.ReadRouterInfo(routerInfo)
	if err != nil {
		return oops.
			Code("ROUTER_INFO_PARSE_FAILED").
			In("ssu2").
			Wrapf(err, "failed to parse RouterInfo")
	}

	for _, addr := range ri.RouterAddresses() {
		if addr == nil || !addr.IsSSU2() {
			continue
		}
		staticKey, err := addr.StaticKey()
		if err != nil {
			continue
		}
		if subtle.ConstantTimeCompare(staticKey[:], authenticatedStaticKey) == 1 {
			return nil
		}
	}

	return oops.
		Code("ROUTER_INFO_KEY_MISMATCH").
		In("ssu2").
		Errorf("no SSU2 address in RouterInfo contains the Noise-authenticated static key")
}

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

	// RouterHash is the local router identity hash
	// Required for SSU2 addressing and session establishment
	RouterHash data.Hash

	// StaticKey is the long-term static key for this peer (32 bytes for Curve25519)
	StaticKey []byte

	// RemoteRouterHash is the remote peer's router identity hash
	// Used for identity verification, optional for listeners
	RemoteRouterHash *data.Hash

	// RemoteStaticKey is the remote peer's X25519 static public key (32 bytes).
	// Required for initiator connections (XK pattern requires pre-knowledge of
	// the responder's static key). This is NOT the router hash — it is the "s"
	// parameter from the peer's RouterAddress options.
	RemoteStaticKey []byte

	// HandshakeTimeout is the maximum time to wait for handshake completion
	// Default: 15 seconds (per SSU2 specification)
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

	// IntroKey is the local router's intro key for header protection (32 bytes).
	// If nil, header protection is disabled (headers sent in plaintext).
	IntroKey []byte

	// RemoteIntroKey is the remote peer's intro key for header protection (32 bytes).
	// Required for initiator when IntroKey is set; optional for responder.
	RemoteIntroKey []byte

	// InitiatorConnectionID is the initiator's source connection ID, used by
	// the responder to construct the Noise prologue for handshake binding.
	// Set by the listener when creating a responder connection.
	InitiatorConnectionID uint64

	// RequireRetry, when true, causes the listener to send a Retry message
	// in response to SessionRequest packets that do not carry a valid token.
	// This implements SSU2 source-address validation: the responder sends
	// Retry with a token, and the initiator must resend SessionRequest
	// including that token before the handshake proceeds.
	// Default: false (accept SessionRequest without token)
	RequireRetry bool

	// IdleTimeout is the maximum duration without activity before the
	// connection is closed. The spec does not mandate a specific value.
	// Default: 5 minutes.
	IdleTimeout time.Duration

	// FragmentTimeout is the duration after which incomplete fragment sets
	// are discarded by the DataHandler. The SSU2 spec does not prescribe
	// a specific value; 10 seconds matches the Java I2P default (M-4).
	// Default: 10 seconds.
	FragmentTimeout time.Duration

	// TokenCacheMaxSize is the maximum number of retry tokens the listener
	// will cache. Under high connection rates, a small cache can evict
	// legitimate tokens before use.
	// Default: 10000.
	TokenCacheMaxSize int

	// GlobalTokenIssuanceRate caps the total number of retry tokens the
	// listener will issue per second across ALL source addresses. This
	// backstops the per-IP rate limiter so that a UDP-spoofing attacker
	// who fans out across many source addresses still cannot amplify
	// issuance beyond the configured rate.
	// Default: 40 tokens/sec.
	// Set to 0 to disable token issuance entirely (listener will refuse
	// all Retry/TokenRequest flows). Set to a very large value to
	// effectively disable the cap.
	GlobalTokenIssuanceRate float64

	// GlobalTokenIssuanceBurst is the burst capacity of the global token
	// issuance bucket. Short spikes up to this many tokens can be issued
	// instantaneously before rate limiting applies.
	// Default: max(GlobalTokenIssuanceRate, 80). Ignored when
	// GlobalTokenIssuanceRate == 0.
	GlobalTokenIssuanceBurst float64

	// FirstSightRequired, when true, causes the listener to decline the
	// first TokenRequest from a previously-unseen source address and
	// record the sighting in a cheap, bounded tracker. A token is only
	// issued on the second (or subsequent) TokenRequest from the same
	// address within FirstSightWindow. SSU2 clients already retry
	// TokenRequests with backoff per spec, so legitimate peers recover
	// transparently on the next retry.
	// This defends against off-path spoofed-source token-cache
	// exhaustion: an attacker pays two packets per spoofed address
	// instead of one, and the first-sight tracker entries are smaller
	// than full Token cache entries and live in a separate bounded map.
	// Default: true.
	FirstSightRequired bool

	// FirstSightWindow is the time a first-sight record stays fresh. A
	// peer that re-contacts within this window will be granted a token
	// (subject to other limits). Older entries are treated as first evicted.
	// Default: 30 seconds.
	FirstSightWindow time.Duration

	// FirstSightMaxEntries bounds the memory held by the first-sight
	// tracker. When full, the oldest sighting is evicted.
	// Default: 50000.
	FirstSightMaxEntries int

	// DestroyTimeout is the time to wait after sending a Termination block
	// before releasing session resources. Per spec §Termination, this gives
	// the remote peer time to receive and acknowledge the close.
	// Default: 11 seconds (max RTO per spec). Set to 0 to skip the wait (e.g. in tests).
	DestroyTimeout time.Duration

	// EnableNextNonce enables the NextNonce rekey mechanism (block type 11).
	// WARNING: The SSU2 spec has NOT finalized this block's format or
	// semantics (marked "TODO" with size "TBD"). Enabling this risks
	// breaking interoperability with peers that implement a different
	// (or no) rekey protocol.
	// Default: false (disabled until spec is finalized) (G-1).
	EnableNextNonce bool

	// ReplayCacheTTL is the time-to-live for entries in the handshake replay
	// cache. The spec does not mandate a specific value; 4 minutes is a
	// reasonable default for the handshake window.
	// Default: 4 minutes (M-2).
	ReplayCacheTTL time.Duration

	// MaxClockSkew is the maximum allowed difference between local and
	// remote clocks for handshake timestamp validation (G-1). Per the SSU2
	// spec, the receiver should verify that the DateTime block timestamp is
	// within a certain window of local time.
	// Default: 120 seconds. Set to 0 to disable skew validation.
	MaxClockSkew time.Duration

	// ReceiveWindowSize is the maximum number of out-of-order packets
	// buffered by the receive window. Larger values improve throughput
	// on lossy links at the cost of memory (M-3).
	// Default: 256. Use 0 for DefaultMaxWindowSize (512).
	ReceiveWindowSize int

	// RouterInfoValidator is a callback invoked after the handshake
	// completes on the responder side. It receives the raw RouterInfo block
	// from SessionConfirmed and the Noise-authenticated static public key.
	// The validator MUST verify that the RouterInfo's identity key corresponds
	// to the static key authenticated by the Noise handshake (C-2).
	// Required for responder configs (Initiator=false); use
	// DefaultRouterInfoValidator or provide a custom implementation.
	RouterInfoValidator func(routerInfo, authenticatedStaticKey []byte) error
}

// NewSSU2Config creates a new SSU2Config with sensible defaults.
// routerHash is the local router identity hash.
// initiator indicates whether this connection will initiate the handshake.
func NewSSU2Config(routerHash data.Hash, initiator bool) (*SSU2Config, error) {
	log.WithFields(logger.Fields{"pkg": "config", "func": "NewSSU2Config", "initiator": initiator}).Debug("Creating new SSU2Config")
	return &SSU2Config{
		Pattern:                  "XK",
		Initiator:                initiator,
		RouterHash:               routerHash,
		HandshakeTimeout:         DefaultHandshakeTimeout,
		ReadTimeout:              0, // No timeout by default
		WriteTimeout:             0, // No timeout by default
		HandshakeRetries:         3,
		RetryBackoff:             1250 * time.Millisecond,
		EnableChaChaObfuscation:  true,
		MTU:                      1280, // IPv6 minimum
		MaxPacketSize:            1500, // Standard Ethernet
		EnableFragmentation:      false,
		PaddingEnabled:           true,
		MinPaddingSize:           0,
		MaxPaddingSize:           64,
		PaddingRatio:             1.0, // 100%
		ConnectionID:             0,   // Will be generated
		KeepaliveInterval:        15 * time.Second,
		IdleTimeout:              5 * time.Minute,
		FragmentTimeout:          10 * time.Second,
		TokenCacheMaxSize:        10000,
		GlobalTokenIssuanceRate:  40,
		GlobalTokenIssuanceBurst: 80,
		FirstSightRequired:       true,
		FirstSightWindow:         30 * time.Second,
		FirstSightMaxEntries:     50000,
		DestroyTimeout:           11 * time.Second,  // Per spec §Termination: 11s (max RTO)
		MaxClockSkew:             120 * time.Second, // Per spec: ±120s skew tolerance (G-1)
		ReplayCacheTTL:           4 * time.Minute,
		ReceiveWindowSize:        256, // Configurable via WithReceiveWindowSize (M-3)
		RouterInfoValidator:      nil, // C-1: no default; callers must explicitly set via WithRouterInfoValidator
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

// WithRemoteRouterHash sets the remote peer's router identity hash.
// Used for identity verification.
func (sc *SSU2Config) WithRemoteRouterHash(hash data.Hash) *SSU2Config {
	h := hash
	sc.RemoteRouterHash = &h
	return sc
}

// WithRemoteStaticKey sets the remote peer's X25519 static public key.
// Required for initiator connections. The key must be 32 bytes (Curve25519).
// This is the "s" parameter from the peer's RouterAddress options, NOT the
// router hash.
func (sc *SSU2Config) WithRemoteStaticKey(key []byte) *SSU2Config {
	if len(key) == 32 {
		sc.RemoteStaticKey = make([]byte, 32)
		copy(sc.RemoteStaticKey, key)
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

// WithIdleTimeout sets the idle timeout after which the connection is closed.
func (sc *SSU2Config) WithIdleTimeout(timeout time.Duration) *SSU2Config {
	sc.IdleTimeout = timeout
	return sc
}

// WithFragmentTimeout sets the duration after which incomplete fragment sets are discarded.
func (sc *SSU2Config) WithFragmentTimeout(timeout time.Duration) *SSU2Config {
	sc.FragmentTimeout = timeout
	return sc
}

// WithDestroyTimeout sets the time to wait after sending a Termination block
// before releasing session resources. Set to 0 to skip the wait (e.g. in tests).
func (sc *SSU2Config) WithDestroyTimeout(timeout time.Duration) *SSU2Config {
	sc.DestroyTimeout = timeout
	return sc
}

// WithMaxClockSkew sets the maximum allowed clock skew for handshake timestamp
// validation. Set to 0 to disable skew checking.
func (sc *SSU2Config) WithMaxClockSkew(skew time.Duration) *SSU2Config {
	sc.MaxClockSkew = skew
	return sc
}

// WithReceiveWindowSize sets the maximum number of out-of-order packets
// the receive window will buffer. Use 0 for DefaultMaxWindowSize.
func (sc *SSU2Config) WithReceiveWindowSize(size int) *SSU2Config {
	if size >= 0 {
		sc.ReceiveWindowSize = size
	}
	return sc
}

// WithTokenCacheMaxSize sets the maximum number of retry tokens cached by the listener.
func (sc *SSU2Config) WithTokenCacheMaxSize(maxSize int) *SSU2Config {
	if maxSize > 0 {
		sc.TokenCacheMaxSize = maxSize
	}
	return sc
}

// WithGlobalTokenIssuanceRate sets the global cap on retry-token issuance
// across all source addresses (tokens/sec). Pass 0 to disable issuance
// entirely. Negative values are clamped to 0.
func (sc *SSU2Config) WithGlobalTokenIssuanceRate(rate float64) *SSU2Config {
	if rate < 0 {
		rate = 0
	}
	sc.GlobalTokenIssuanceRate = rate
	return sc
}

// WithGlobalTokenIssuanceBurst sets the burst capacity of the global
// token-issuance bucket. Values <= 0 are ignored (the default is preserved).
func (sc *SSU2Config) WithGlobalTokenIssuanceBurst(burst float64) *SSU2Config {
	if burst > 0 {
		sc.GlobalTokenIssuanceBurst = burst
	}
	return sc
}

// WithFirstSightRequired controls whether the listener requires a previously
// observed sighting before issuing a token. When true (the default), a
// brand-new source address must re-request to receive a token. Setting this
// to false disables the gate entirely.
func (sc *SSU2Config) WithFirstSightRequired(required bool) *SSU2Config {
	sc.FirstSightRequired = required
	return sc
}

// WithFirstSightWindow sets how long a first-sight record stays fresh.
// Values <= 0 are ignored.
func (sc *SSU2Config) WithFirstSightWindow(window time.Duration) *SSU2Config {
	if window > 0 {
		sc.FirstSightWindow = window
	}
	return sc
}

// WithFirstSightMaxEntries bounds the memory held by the first-sight
// tracker. Values <= 0 are ignored.
func (sc *SSU2Config) WithFirstSightMaxEntries(maxEntries int) *SSU2Config {
	if maxEntries > 0 {
		sc.FirstSightMaxEntries = maxEntries
	}
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

// WithRouterInfoValidator sets the RouterInfo validation callback.
// The validator is invoked on the responder after handshake completion to verify
// that the peer's RouterInfo contains the Noise-authenticated static key.
func (sc *SSU2Config) WithRouterInfoValidator(validator func(routerInfo, authenticatedStaticKey []byte) error) *SSU2Config {
	sc.RouterInfoValidator = validator
	return sc
}

// Validate checks if the configuration is valid for SSU2.
func (sc *SSU2Config) Validate() error {
	log.WithFields(logger.Fields{"pkg": "config", "func": "Validate"}).Debug("Validating SSU2Config")
	return internal.RunValidators(
		sc.validateBasicConfiguration,
		sc.validateCryptographicParameters,
		sc.validateTimeoutConfiguration,
		sc.validateUDPConfiguration,
		sc.validatePaddingConfiguration,
	)
}

// validateBasicConfiguration checks pattern and router hash requirements.
func (sc *SSU2Config) validateBasicConfiguration() error {
	log.WithFields(logger.Fields{"pkg": "config", "func": "validateBasicConfiguration", "pattern": sc.Pattern}).Debug("Checking pattern and router hash")
	// Validate pattern (SSU2 typically uses XK)
	if err := internal.ValidatePattern(sc.Pattern, "ssu2"); err != nil {
		return err
	}

	return nil
}

// validateCryptographicParameters checks keys, hashes, and obfuscation settings.
func (sc *SSU2Config) validateCryptographicParameters() error {
	log.WithFields(logger.Fields{"pkg": "config", "func": "validateCryptographicParameters", "initiator": sc.Initiator, "has_static_key": len(sc.StaticKey) > 0}).Debug("Checking keys and obfuscation settings")
	// Validate static key if provided
	if err := internal.ValidateKeyLength(sc.StaticKey, "static key", "ssu2"); err != nil {
		return err
	}

	// For initiator connections, the remote static key is required for the
	// Noise XK handshake (C-1). The router hash is used separately for
	// identity verification.
	if sc.Initiator && len(sc.RemoteStaticKey) == 0 {
		return oops.
			Code("MISSING_REMOTE_STATIC_KEY").
			In("ssu2").
			Errorf("remote static key is required for initiator connections (use WithRemoteStaticKey)")
	}

	if sc.Initiator && len(sc.RemoteStaticKey) != 0 && len(sc.RemoteStaticKey) != 32 {
		return oops.
			Code("INVALID_REMOTE_STATIC_KEY").
			In("ssu2").
			With("key_length", len(sc.RemoteStaticKey)).
			Errorf("remote static key must be 32 bytes")
	}

	// Validate ChaCha20 obfuscation IV if provided (8 bytes for SSU2)
	if sc.ObfuscationIV != nil && len(sc.ObfuscationIV) != 8 {
		return oops.
			Code("INVALID_OBFUSCATION_IV").
			In("ssu2").
			With("iv_length", len(sc.ObfuscationIV)).
			Errorf("obfuscation IV must be 8 bytes")
	}

	// Per SSU2 spec §Session Confirmed (C-2): responders must validate
	// that the Noise-authenticated static key matches the RouterInfo.
	if !sc.Initiator && sc.RouterInfoValidator == nil {
		return oops.
			Code("MISSING_ROUTER_INFO_VALIDATOR").
			In("ssu2").
			Errorf("RouterInfoValidator is required for responder configs per SSU2 spec")
	}

	return nil
}

// validateTimeoutConfiguration checks handshake timeouts and retry settings.
func (sc *SSU2Config) validateTimeoutConfiguration() error {
	log.WithFields(logger.Fields{"pkg": "config", "func": "validateTimeoutConfiguration", "handshake_timeout": sc.HandshakeTimeout, "keepalive_interval": sc.KeepaliveInterval}).Debug("Checking timeout and retry settings")
	// Validate handshake timeout
	if err := internal.ValidateHandshakeTimeout(sc.HandshakeTimeout, "ssu2"); err != nil {
		return err
	}

	// Validate retry configuration
	if err := internal.ValidateRetryConfig(sc.HandshakeRetries, sc.RetryBackoff, "ssu2"); err != nil {
		return err
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
	log.WithFields(logger.Fields{"pkg": "config", "func": "validateUDPConfiguration", "mtu": sc.MTU, "max_packet_size": sc.MaxPacketSize}).Debug("Checking MTU and packet size settings")
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
	log.WithFields(logger.Fields{"pkg": "config", "func": "validatePaddingConfiguration", "enabled": sc.PaddingEnabled, "min": sc.MinPaddingSize, "max": sc.MaxPaddingSize, "ratio": sc.PaddingRatio}).Debug("Checking padding ranges and ratios")
	if err := handshake.ValidatePaddingRange("ssu2", sc.MinPaddingSize, sc.MaxPaddingSize); err != nil {
		return err
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
	log.WithFields(logger.Fields{"pkg": "config", "func": "ToConnConfig"}).Debug("Converting SSU2Config to ConnConfig")
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
		ProtocolName:     []byte(ssu2hs.SSU2ProtocolName),
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

	modifiers = append(modifiers, sc.Modifiers...)
	return modifiers, nil
}

// createChaChaModifierIfEnabled creates a ChaCha20 obfuscation modifier if enabled.
// Per SSU2 spec, the ChaCha20 key is Bob's intro key:
//   - Initiator uses RemoteIntroKey (Bob's intro key)
//   - Responder uses IntroKey (own intro key, which IS Bob's intro key)
func (sc *SSU2Config) createChaChaModifierIfEnabled() (handshake.HandshakeModifier, error) {
	if !sc.EnableChaChaObfuscation {
		return nil, nil
	}

	// Select the correct intro key based on role
	var introKey []byte
	if sc.Initiator && len(sc.RemoteIntroKey) == 32 {
		introKey = sc.RemoteIntroKey
	} else if !sc.Initiator && len(sc.IntroKey) == 32 {
		introKey = sc.IntroKey
	} else {
		// Fallback to router hash for backward compatibility
		introKey = sc.RouterHash[:]
	}

	chachaModifier, err := wire.NewChaChaObfuscationModifier("ssu2-chacha", introKey)
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

	paddingModifier, err := wire.NewSSU2PaddingModifierWithMTU(
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
