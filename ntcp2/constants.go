package ntcp2

// NTCP2 protocol constants per the I2P NTCP2 specification.
// Reference: https://i2p.net/en/docs/specs/ntcp2

const (
	// RouterHashSize is the size of the I2P router identity hash in bytes.
	RouterHashSize = 32

	// StaticKeySize is the size of a Curve25519 static key in bytes.
	StaticKeySize = 32

	// IVSize is the size of the AES-CBC initialization vector in bytes.
	IVSize = 16

	// PaddingBlockType is the I2P NTCP2 padding block type identifier.
	PaddingBlockType = 254

	// MaxBlockDataSize is the maximum data size for a single I2P NTCP2 block (bytes).
	MaxBlockDataSize = 65516

	// MaxFrameSize is the maximum size of an NTCP2 data frame (bytes).
	MaxFrameSize = 65535

	// BlockHeaderSize is the size of an I2P block header: [type:1][size:2].
	BlockHeaderSize = 3

	// SipHashIVSize is the size of the SipHash IV in bytes (uint64 = 8 bytes).
	SipHashIVSize = 8

	// FrameLengthFieldSize is the size of the SipHash-obfuscated length field.
	FrameLengthFieldSize = 2

	// NTCP2ProtocolName is the full Noise protocol name for NTCP2 as defined by the I2P spec.
	// TODO(ntcp2-spec): The upstream go-i2p/noise library does not yet support custom
	// protocol names for InitializeSymmetric(). It constructs the name from the pattern
	// and cipher suite. Until upstream adds a ProtocolName override to noise.Config,
	// the KDF will produce different outputs than other I2P implementations.
	NTCP2ProtocolName = "Noise_XKaesobfse+hs2+hs3_25519_ChaChaPoly_SHA256"

	// NTCP2Pattern is the base Noise pattern used by NTCP2.
	NTCP2Pattern = "XK"

	// DefaultHandshakeTimeoutSeconds is the default handshake timeout in seconds.
	DefaultHandshakeTimeoutSeconds = 30

	// DefaultMaxFrameSize is the default maximum frame size (16KB).
	DefaultMaxFrameSize = 16384

	// DefaultMaxPaddingSize is the default maximum padding size in bytes.
	DefaultMaxPaddingSize = 64

	// DefaultHandshakeRetries is the default number of handshake retry attempts.
	DefaultHandshakeRetries = 3

	// MaxPaddingRatio is the maximum padding ratio per I2P NTCP2 spec (4.4 fixed-point).
	MaxPaddingRatio = 15.9375
)
