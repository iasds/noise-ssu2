package ntcp2

import (
	"sync/atomic"
	"time"

	noise "github.com/go-i2p/go-noise"
	"github.com/go-i2p/go-noise/handshake"
	upstreamnoise "github.com/go-i2p/noise"
	"github.com/samber/oops"
)

// NTCP2Config contains configuration for creating NTCP2 connections and listeners.
// It follows the builder pattern for optional configuration and validation,
// similar to the main ConnConfig but with NTCP2-specific parameters.
type NTCP2Config struct {
	// Pattern is the Noise protocol pattern for NTCP2
	// Default: "XK" (standard NTCP2 pattern)
	Pattern string

	// Initiator indicates if this connection is the handshake initiator
	// For listeners, this is always false
	Initiator bool

	// RouterHash is the local router identity (32 bytes)
	// Required for NTCP2 addressing and session establishment
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

	// EnableAESObfuscation enables AES-based ephemeral key obfuscation
	// Default: true (recommended for production)
	EnableAESObfuscation bool

	// ObfuscationIV is the 16-byte IV for AES obfuscation
	// If nil, will be derived from router hash (recommended)
	ObfuscationIV []byte

	// EnableSipHashLength enables SipHash-based frame length obfuscation
	// Default: true (recommended for production)
	EnableSipHashLength bool

	// SipHashKeys are the k1, k2 keys for SipHash length obfuscation
	// If empty, will be derived during handshake
	SipHashKeys [2]uint64

	// Modifiers is a list of additional handshake modifiers for custom obfuscation
	// These are applied in addition to NTCP2's standard modifiers
	// Default: empty (no additional modifiers)
	Modifiers []handshake.HandshakeModifier

	// MaxFrameSize is the maximum size of NTCP2 data frames
	// Default: 16384 bytes (16KB)
	MaxFrameSize int

	// FramePaddingEnabled enables random padding in NTCP2 frames
	// Default: true (recommended for traffic analysis resistance)
	FramePaddingEnabled bool

	// MinPaddingSize is the minimum padding size for frames
	// Default: 0 bytes
	MinPaddingSize int

	// MaxPaddingSize is the maximum padding size for frames
	// Default: 64 bytes
	MaxPaddingSize int

	// sipHashModifier stores the SipHash modifier created during ToConnConfig()
	// so it can be passed to NTCP2Conn for data-phase framing.
	// Access is via atomic.Pointer to avoid data races between the
	// PostHandshakeHook goroutine and SipHashModifier() callers.
	sipHashModifier atomic.Pointer[SipHashLengthModifier]
}

// NewNTCP2Config creates a new NTCP2Config with sensible defaults.
// routerHash must be exactly 32 bytes representing the local router identity.
// initiator indicates whether this connection will initiate the handshake.
func NewNTCP2Config(routerHash []byte, initiator bool) (*NTCP2Config, error) {
	if len(routerHash) != RouterHashSize {
		return nil, oops.
			Code("INVALID_ROUTER_HASH").
			In("ntcp2").
			With("hash_length", len(routerHash)).
			Errorf("router hash must be exactly %d bytes", RouterHashSize)
	}

	// Make defensive copy of router hash
	hash := make([]byte, RouterHashSize)
	copy(hash, routerHash)

	return &NTCP2Config{
		Pattern:              NTCP2Pattern,
		Initiator:            initiator,
		RouterHash:           hash,
		HandshakeTimeout:     DefaultHandshakeTimeoutSeconds * time.Second,
		ReadTimeout:          0,
		WriteTimeout:         0,
		HandshakeRetries:     DefaultHandshakeRetries,
		RetryBackoff:         1 * time.Second,
		EnableAESObfuscation: true,
		EnableSipHashLength:  true,
		MaxFrameSize:         DefaultMaxFrameSize,
		FramePaddingEnabled:  true,
		MinPaddingSize:       0,
		MaxPaddingSize:       DefaultMaxPaddingSize,
	}, nil
}

// WithPattern sets the Noise protocol pattern.
// For NTCP2, this should typically remain "XK".
func (nc *NTCP2Config) WithPattern(pattern string) *NTCP2Config {
	nc.Pattern = pattern
	return nc
}

// WithStaticKey sets the static key for this connection.
// key must be 32 bytes for Curve25519. Returns an error if the key length is invalid.
func (nc *NTCP2Config) WithStaticKey(key []byte) (*NTCP2Config, error) {
	if len(key) != StaticKeySize {
		return nc, oops.
			Code("INVALID_STATIC_KEY").
			In("ntcp2").
			With("expected", StaticKeySize).
			With("got", len(key)).
			Errorf("static key must be exactly %d bytes", StaticKeySize)
	}
	nc.StaticKey = make([]byte, StaticKeySize)
	copy(nc.StaticKey, key)
	return nc, nil
}

// WithRemoteRouterHash sets the remote peer's router identity.
// hash must be 32 bytes. Required for outbound connections.
// Returns an error if the hash length is invalid.
func (nc *NTCP2Config) WithRemoteRouterHash(hash []byte) (*NTCP2Config, error) {
	if len(hash) != RouterHashSize {
		return nc, oops.
			Code("INVALID_REMOTE_ROUTER_HASH").
			In("ntcp2").
			With("expected", RouterHashSize).
			With("got", len(hash)).
			Errorf("remote router hash must be exactly %d bytes", RouterHashSize)
	}
	nc.RemoteRouterHash = make([]byte, RouterHashSize)
	copy(nc.RemoteRouterHash, hash)
	return nc, nil
}

// WithHandshakeTimeout sets the handshake timeout.
func (nc *NTCP2Config) WithHandshakeTimeout(timeout time.Duration) *NTCP2Config {
	nc.HandshakeTimeout = timeout
	return nc
}

// WithReadTimeout sets the read timeout for post-handshake operations.
func (nc *NTCP2Config) WithReadTimeout(timeout time.Duration) *NTCP2Config {
	nc.ReadTimeout = timeout
	return nc
}

// WithWriteTimeout sets the write timeout for post-handshake operations.
func (nc *NTCP2Config) WithWriteTimeout(timeout time.Duration) *NTCP2Config {
	nc.WriteTimeout = timeout
	return nc
}

// WithHandshakeRetries sets the number of handshake retry attempts.
// Use 0 for no retries, -1 for infinite retries.
func (nc *NTCP2Config) WithHandshakeRetries(retries int) *NTCP2Config {
	nc.HandshakeRetries = retries
	return nc
}

// WithRetryBackoff sets the base delay between retry attempts.
func (nc *NTCP2Config) WithRetryBackoff(backoff time.Duration) *NTCP2Config {
	nc.RetryBackoff = backoff
	return nc
}

// WithAESObfuscation enables or disables AES-based ephemeral key obfuscation.
// When enabled with a custom IV, the IV must be exactly 16 bytes.
// Returns an error if the custom IV has an invalid (non-zero, non-16) length.
// Note: Options negotiation (padding limits as 4.4 fixed-point, dummy traffic,
// delay parameters) is the responsibility of the higher-level router transport.
func (nc *NTCP2Config) WithAESObfuscation(enabled bool, customIV []byte) (*NTCP2Config, error) {
	nc.EnableAESObfuscation = enabled
	if len(customIV) == IVSize {
		nc.ObfuscationIV = make([]byte, IVSize)
		copy(nc.ObfuscationIV, customIV)
	} else if len(customIV) > 0 {
		return nil, oops.
			Code("INVALID_IV_LENGTH").
			In("ntcp2").
			With("expected", IVSize).
			With("got", len(customIV)).
			Errorf("WithAESObfuscation: custom IV must be exactly %d bytes, got %d", IVSize, len(customIV))
	}
	return nc, nil
}

// WithSipHashLength enables or disables SipHash-based frame length obfuscation.
// When enabled with custom keys, both k1 and k2 must be provided.
func (nc *NTCP2Config) WithSipHashLength(enabled bool, k1, k2 uint64) *NTCP2Config {
	nc.EnableSipHashLength = enabled
	if enabled && (k1 != 0 || k2 != 0) {
		nc.SipHashKeys[0] = k1
		nc.SipHashKeys[1] = k2
	}
	return nc
}

// WithModifiers sets additional handshake modifiers for custom obfuscation.
// These are applied in addition to NTCP2's standard modifiers.
func (nc *NTCP2Config) WithModifiers(modifiers ...handshake.HandshakeModifier) *NTCP2Config {
	// Make defensive copy
	nc.Modifiers = make([]handshake.HandshakeModifier, len(modifiers))
	copy(nc.Modifiers, modifiers)
	return nc
}

// WithFrameSettings configures NTCP2 frame handling parameters.
// maxSize sets the maximum frame size (default: 16384 bytes).
// paddingEnabled enables random padding (default: true).
// minPadding and maxPadding set the padding size range (default: 0-64 bytes).
func (nc *NTCP2Config) WithFrameSettings(maxSize int, paddingEnabled bool, minPadding, maxPadding int) *NTCP2Config {
	if maxSize > 0 {
		nc.MaxFrameSize = maxSize
	}
	nc.FramePaddingEnabled = paddingEnabled
	if minPadding >= 0 {
		nc.MinPaddingSize = minPadding
	}
	if maxPadding >= minPadding {
		nc.MaxPaddingSize = maxPadding
	}
	return nc
}

// Validate checks if the configuration is valid for NTCP2.
func (nc *NTCP2Config) Validate() error {
	if err := nc.validateBasicConfiguration(); err != nil {
		return err
	}

	if err := nc.validateCryptographicParameters(); err != nil {
		return err
	}

	if err := nc.validateTimeoutConfiguration(); err != nil {
		return err
	}

	if err := nc.validateFrameConfiguration(); err != nil {
		return err
	}

	return nil
}

// validateBasicConfiguration checks pattern and router hash requirements.
func (nc *NTCP2Config) validateBasicConfiguration() error {
	// Validate pattern (NTCP2 typically uses XK)
	if nc.Pattern == "" {
		return oops.
			Code("MISSING_PATTERN").
			In("ntcp2").
			Errorf("noise pattern is required")
	}

	// Validate router hash
	if len(nc.RouterHash) != RouterHashSize {
		return oops.
			Code("INVALID_ROUTER_HASH").
			In("ntcp2").
			With("hash_length", len(nc.RouterHash)).
			Errorf("router hash must be exactly %d bytes", RouterHashSize)
	}

	return nil
}

// validateCryptographicParameters checks static keys, remote hashes, and obfuscation settings.
func (nc *NTCP2Config) validateCryptographicParameters() error {
	// Validate static key if provided
	if len(nc.StaticKey) > 0 && len(nc.StaticKey) != StaticKeySize {
		return oops.
			Code("INVALID_STATIC_KEY").
			In("ntcp2").
			With("key_length", len(nc.StaticKey)).
			Errorf("static key must be %d bytes", StaticKeySize)
	}

	// Validate remote router hash if provided
	if len(nc.RemoteRouterHash) > 0 && len(nc.RemoteRouterHash) != RouterHashSize {
		return oops.
			Code("INVALID_REMOTE_ROUTER_HASH").
			In("ntcp2").
			With("hash_length", len(nc.RemoteRouterHash)).
			Errorf("remote router hash must be %d bytes", RouterHashSize)
	}

	// For initiator connections, remote router hash is required
	if nc.Initiator && len(nc.RemoteRouterHash) == 0 {
		return oops.
			Code("MISSING_REMOTE_ROUTER_HASH").
			In("ntcp2").
			Errorf("remote router hash is required for initiator connections")
	}

	// Validate AES obfuscation IV if provided
	if nc.ObfuscationIV != nil && len(nc.ObfuscationIV) != IVSize {
		return oops.
			Code("INVALID_OBFUSCATION_IV").
			In("ntcp2").
			With("iv_length", len(nc.ObfuscationIV)).
			Errorf("obfuscation IV must be %d bytes", IVSize)
	}

	return nil
}

// validateTimeoutConfiguration checks handshake timeouts and retry settings.
func (nc *NTCP2Config) validateTimeoutConfiguration() error {
	// Validate handshake timeout
	if nc.HandshakeTimeout <= 0 {
		return oops.
			Code("INVALID_HANDSHAKE_TIMEOUT").
			In("ntcp2").
			With("timeout", nc.HandshakeTimeout).
			Errorf("handshake timeout must be positive")
	}

	// Validate retry configuration
	if nc.HandshakeRetries < -1 {
		return oops.
			Code("INVALID_RETRY_COUNT").
			In("ntcp2").
			With("retries", nc.HandshakeRetries).
			Errorf("handshake retries must be >= -1")
	}

	if nc.RetryBackoff < 0 {
		return oops.
			Code("INVALID_RETRY_BACKOFF").
			In("ntcp2").
			With("backoff", nc.RetryBackoff).
			Errorf("retry backoff must be non-negative")
	}

	return nil
}

// validateFrameConfiguration checks frame size and padding settings.
func (nc *NTCP2Config) validateFrameConfiguration() error {
	// Validate frame settings
	if nc.MaxFrameSize <= 0 {
		return oops.
			Code("INVALID_MAX_FRAME_SIZE").
			In("ntcp2").
			With("max_size", nc.MaxFrameSize).
			Errorf("max frame size must be positive")
	}

	if nc.MaxFrameSize > SpecMaxFrameSize {
		return oops.
			Code("INVALID_MAX_FRAME_SIZE").
			In("ntcp2").
			With("max_size", nc.MaxFrameSize).
			With("spec_max", SpecMaxFrameSize).
			Errorf("max frame size %d exceeds spec maximum %d", nc.MaxFrameSize, SpecMaxFrameSize)
	}

	if nc.MinPaddingSize < 0 {
		return oops.
			Code("INVALID_MIN_PADDING").
			In("ntcp2").
			With("min_padding", nc.MinPaddingSize).
			Errorf("min padding size must be non-negative")
	}

	if nc.MaxPaddingSize < nc.MinPaddingSize {
		return oops.
			Code("INVALID_PADDING_RANGE").
			In("ntcp2").
			With("min_padding", nc.MinPaddingSize).
			With("max_padding", nc.MaxPaddingSize).
			Errorf("max padding size must be >= min padding size")
	}

	return nil
}

// ToConnConfig converts NTCP2Config to a standard ConnConfig for use with NoiseConn.
// This includes setting up NTCP2-specific modifiers based on the configuration.
// A PostHandshakeHook is automatically registered when SipHash length obfuscation
// is enabled — the hook captures the handshake hash for future SipHash key derivation.
func (nc *NTCP2Config) ToConnConfig() (*noise.ConnConfig, error) {
	if err := nc.Validate(); err != nil {
		return nil, oops.
			Code("INVALID_CONFIG").
			In("ntcp2").
			Wrap(err)
	}

	config := nc.createBaseConnConfig()

	modifiers, err := nc.setupNTCP2Modifiers()
	if err != nil {
		return nil, err
	}

	config.Modifiers = modifiers

	// Wire PostHandshakeHook for SipHash key derivation.
	// Configure the ASK label so the upstream noise library derives
	// ask_master via SplitWithASK() during the handshake.
	if nc.EnableSipHashLength {
		config.AdditionalSymmetricKeyLabels = [][]byte{[]byte("ask")}
		config.PostHandshakeHook = nc.createPostHandshakeHook()
	}

	return config, nil
}

// createPostHandshakeHook returns a PostHandshakeHook that derives
// per-direction SipHash keys from the ASK master and handshake hash
// after the Noise XK handshake completes.
//
// The upstream go-i2p/noise library's SplitWithASK() derives the
// ask_master via Config.AdditionalSymmetricKeyLabels = {"ask"}.
// This hook retrieves it via AdditionalSymmetricKeys()[0], then calls
// DeriveSipHashKeys(askMaster, h) to produce directional SipHash keys
// and stores them in the NTCP2Config for later use by NTCP2Conn.
func (nc *NTCP2Config) createPostHandshakeHook() func(*noise.NoiseConn) error {
	return func(conn *noise.NoiseConn) error {
		h := conn.ChannelBinding()
		if h == nil {
			return oops.
				Code("NO_HANDSHAKE_HASH").
				In("ntcp2").
				Errorf("handshake hash not available after handshake")
		}

		askKeys := conn.AdditionalSymmetricKeys()
		if len(askKeys) == 0 || len(askKeys[0]) == 0 {
			return oops.
				Code("NO_ASK_MASTER").
				In("ntcp2").
				Errorf("ask_master not available after handshake (no ASK labels configured?)")
		}
		askMaster := askKeys[0]

		sipKeysAB, sipIVAB, sipKeysBA, sipIVBA, err := DeriveSipHashKeys(askMaster, h)
		if err != nil {
			return oops.
				Code("SIPHASH_DERIVATION_FAILED").
				In("ntcp2").
				Wrapf(err, "failed to derive SipHash keys from ask_master")
		}

		// Create a directional SipHash modifier with proper key assignment:
		//   Initiator: outbound = AB, inbound = BA
		//   Responder: outbound = BA, inbound = AB
		var modifier *SipHashLengthModifier
		if nc.Initiator {
			modifier = NewSipHashLengthModifierDirectional("ntcp2-siphash",
				sipKeysAB, sipKeysBA, sipIVAB, sipIVBA)
		} else {
			modifier = NewSipHashLengthModifierDirectional("ntcp2-siphash",
				sipKeysBA, sipKeysAB, sipIVBA, sipIVAB)
		}

		// Store the directional modifier for NTCP2Conn to use.
		nc.sipHashModifier.Store(modifier)

		log.WithField("handshake_hash_len", len(h)).
			WithField("ask_master_len", len(askMaster)).
			Debug("PostHandshakeHook: derived per-direction SipHash keys")

		return nil
	}
}

// createBaseConnConfig creates a base ConnConfig with core NTCP2 settings.
func (nc *NTCP2Config) createBaseConnConfig() *noise.ConnConfig {
	// When no static key is provided, use nil (not a zero-length slice)
	// so the upstream library can distinguish "no key" from "empty key".
	var staticKey []byte
	if len(nc.StaticKey) > 0 {
		staticKey = make([]byte, len(nc.StaticKey))
		copy(staticKey, nc.StaticKey)
	}

	return &noise.ConnConfig{
		Pattern:          nc.Pattern,
		Initiator:        nc.Initiator,
		StaticKey:        staticKey,
		HandshakeTimeout: nc.HandshakeTimeout,
		ReadTimeout:      nc.ReadTimeout,
		WriteTimeout:     nc.WriteTimeout,
		HandshakeRetries: nc.HandshakeRetries,
		RetryBackoff:     nc.RetryBackoff,
		// NTCP2 mandates ChaChaPoly (ChaCha20-Poly1305 per RFC 7539)
		CipherSuite: upstreamnoise.NewCipherSuite(
			upstreamnoise.DH25519,
			upstreamnoise.CipherChaChaPoly,
			upstreamnoise.HashSHA256,
		),
		// NTCP2 uses a non-standard protocol name for InitializeSymmetric()
		ProtocolName: []byte(NTCP2ProtocolName),
	}
}

// setupNTCP2Modifiers creates and configures all NTCP2-specific handshake modifiers.
func (nc *NTCP2Config) setupNTCP2Modifiers() ([]handshake.HandshakeModifier, error) {
	var modifiers []handshake.HandshakeModifier

	aesModifier, err := nc.createAESModifierIfEnabled()
	if err != nil {
		return nil, err
	}
	if aesModifier != nil {
		modifiers = append(modifiers, aesModifier)
	}

	sipModifier := nc.createSipHashModifierIfEnabled()
	if sipModifier != nil {
		// Add placeholder to the handshake modifier list (no-op for non-PhaseFinal).
		// Do NOT store as nc.sipHashModifier — that is set by the post-handshake
		// hook with proper per-direction keys. Storing the zero-key placeholder
		// would expose a predictable modifier via SipHashModifier() before the
		// handshake completes.
		modifiers = append(modifiers, sipModifier)
	}

	modifiers = append(modifiers, nc.Modifiers...)
	return modifiers, nil
}

// createAESModifierIfEnabled creates an AES obfuscation modifier if enabled.
func (nc *NTCP2Config) createAESModifierIfEnabled() (handshake.HandshakeModifier, error) {
	if !nc.EnableAESObfuscation {
		return nil, nil
	}

	iv := nc.ObfuscationIV
	if iv == nil {
		// The IV must be provided explicitly from the remote peer's published
		// network database entry ("i=" option). There is no valid fallback.
		return nil, oops.
			Code("MISSING_OBFUSCATION_IV").
			In("ntcp2").
			Errorf("AES obfuscation IV is required (published in peer's network database entry)")
	}

	aesModifier, err := NewAESObfuscationModifier("ntcp2-aes", nc.RouterHash, iv)
	if err != nil {
		return nil, oops.
			Code("AES_MODIFIER_FAILED").
			In("ntcp2").
			Wrap(err)
	}
	return aesModifier, nil
}

// createSipHashModifierIfEnabled creates a new SipHash length modifier if enabled.
// A fresh instance is created on every call to prevent shared state between connections.
//
// TODO(ntcp2-spec): After the Noise XK handshake completes, the router
// transport layer must call DeriveSipHashKeys() to obtain per-direction keys
// and then create a directional modifier via NewSipHashLengthModifierDirectional().
// The placeholder modifier returned here uses shared zero keys and is only
// suitable as a handshake-phase pass-through (SipHash is a no-op before PhaseFinal).
func (nc *NTCP2Config) createSipHashModifierIfEnabled() *SipHashLengthModifier {
	if !nc.EnableSipHashLength {
		return nil
	}
	// SipHash keys (sipk1, sipk2) and initial IV should be derived from the
	// data-phase KDF after the Noise XK handshake completes. Use DeriveSipHashKeys()
	// with the ask_master secret and the handshake hash (from NTCP2Conn.HandshakeHash())
	// to obtain proper keys. The router transport layer should call DeriveSipHashKeys()
	// and then inject the result via SetLengthObfuscator() on the NTCP2Conn.
	return NewSipHashLengthModifier("ntcp2-siphash", nc.SipHashKeys, 0)
}

// SipHashModifier returns the SipHash length modifier created during ToConnConfig().
// Returns nil if SipHash length obfuscation is disabled or ToConnConfig() hasn't been called.
// Each call to ToConnConfig() creates a fresh modifier instance, so configs can be safely
// reused for multiple connections without sharing IV state.
func (nc *NTCP2Config) SipHashModifier() *SipHashLengthModifier {
	return nc.sipHashModifier.Load()
}

// Clone creates a deep copy of this NTCP2Config that is safe to use
// independently (e.g., for per-connection configs on the listener path).
// The atomic.Pointer[SipHashLengthModifier] field is NOT copied — the
// returned config has a fresh zero-value atomic, which is correct
// because the PostHandshakeHook will populate it after the handshake.
func (nc *NTCP2Config) Clone() *NTCP2Config {
	clone := &NTCP2Config{
		Pattern:              nc.Pattern,
		Initiator:            nc.Initiator,
		HandshakeTimeout:     nc.HandshakeTimeout,
		ReadTimeout:          nc.ReadTimeout,
		WriteTimeout:         nc.WriteTimeout,
		HandshakeRetries:     nc.HandshakeRetries,
		RetryBackoff:         nc.RetryBackoff,
		EnableAESObfuscation: nc.EnableAESObfuscation,
		EnableSipHashLength:  nc.EnableSipHashLength,
		SipHashKeys:          nc.SipHashKeys,
		MaxFrameSize:         nc.MaxFrameSize,
		FramePaddingEnabled:  nc.FramePaddingEnabled,
		MinPaddingSize:       nc.MinPaddingSize,
		MaxPaddingSize:       nc.MaxPaddingSize,
	}
	if nc.RouterHash != nil {
		clone.RouterHash = make([]byte, len(nc.RouterHash))
		copy(clone.RouterHash, nc.RouterHash)
	}
	if nc.StaticKey != nil {
		clone.StaticKey = make([]byte, len(nc.StaticKey))
		copy(clone.StaticKey, nc.StaticKey)
	}
	if nc.RemoteRouterHash != nil {
		clone.RemoteRouterHash = make([]byte, len(nc.RemoteRouterHash))
		copy(clone.RemoteRouterHash, nc.RemoteRouterHash)
	}
	if nc.ObfuscationIV != nil {
		clone.ObfuscationIV = make([]byte, len(nc.ObfuscationIV))
		copy(clone.ObfuscationIV, nc.ObfuscationIV)
	}
	if nc.Modifiers != nil {
		clone.Modifiers = make([]handshake.HandshakeModifier, len(nc.Modifiers))
		copy(clone.Modifiers, nc.Modifiers)
	}
	return clone
}
