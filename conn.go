package noise

import (
	"net"
	"sync"
	"time"

	"github.com/go-i2p/go-noise/handshake"
	"github.com/go-i2p/go-noise/internal"
	i2plogger "github.com/go-i2p/logger"
	"github.com/go-i2p/noise"
	"github.com/samber/oops"
)

// maxNoiseMessageSize is the maximum Noise message size per the Noise spec (§12.3).
// Each message on the wire is preceded by a 2-byte big-endian length prefix.
const maxNoiseMessageSize = 65535

// Connection state constants for public API
const (
	// StateInit represents a newly created connection
	StateInit = internal.StateInit
	// StateHandshaking represents a connection performing handshake
	StateHandshaking = internal.StateHandshaking
	// StateEstablished represents a connection with completed handshake
	StateEstablished = internal.StateEstablished
	// StateClosed represents a closed connection
	StateClosed = internal.StateClosed
)

// ConnState represents the state of a NoiseConn
type ConnState = internal.ConnState

// NoiseConn implements net.Conn with Noise Protocol encryption.
// It wraps an underlying net.Conn and provides encrypted communication
// following the Noise Protocol Framework specification.
//
// Thread Safety:
// NoiseConn is safe for concurrent use by multiple goroutines with the following guarantees:
//   - Read() and Write() can be called concurrently from different goroutines
//   - Close() can be called concurrently with other operations and will be idempotent
//   - GetConnectionState() and GetConnectionMetrics() are safe for concurrent access
//   - Handshake() operations are serialized - only one handshake can occur at a time
//   - All operations that check connection state are atomic and consistent
//
// Synchronization is achieved through multiple mutexes:
//   - stateMutex: Protects connection state transitions (RWMutex for read-heavy access)
//   - handshakeMutex: Serializes handshake operations
//   - closeMutex: Protects close operations from concurrent execution
//   - Internal metrics mutex: Protects connection metrics updates
type NoiseConn struct {
	// underlying is the wrapped network connection
	underlying net.Conn

	// config contains the Noise protocol configuration
	config *ConnConfig

	// sendCipherState handles encryption for outgoing data after handshake.
	// For interactive patterns: initiator uses cs1, responder uses cs2.
	sendCipherState *noise.CipherState

	// recvCipherState handles decryption for incoming data after handshake.
	// For interactive patterns: initiator uses cs2, responder uses cs1.
	recvCipherState *noise.CipherState

	// handshakeState handles the handshake process
	handshakeState *noise.HandshakeState

	// localAddr is the local Noise address
	localAddr *NoiseAddr

	// remoteAddr is the remote Noise address
	remoteAddr *NoiseAddr

	// state tracks the connection lifecycle and metrics
	state internal.ConnState

	// metrics tracks connection performance data
	metrics *internal.ConnectionMetrics

	// stateMutex protects state transitions
	stateMutex sync.RWMutex

	// handshakeMutex protects handshake operations
	handshakeMutex sync.Mutex

	// logger for connection events
	logger *i2plogger.Logger

	// shutdownManager for coordinated shutdown (optional)
	shutdownManager *ShutdownManager

	// closeMutex protects close operations
	closeMutex sync.Mutex

	// readMutex serializes Read calls to protect recvCipherState nonce
	readMutex sync.Mutex

	// writeMutex serializes Write calls to protect sendCipherState nonce
	writeMutex sync.Mutex
}

// NewNoiseConn creates a new NoiseConn wrapping the underlying connection.
// The handshake must be completed before using Read/Write operations.
func NewNoiseConn(underlying net.Conn, config *ConnConfig) (*NoiseConn, error) {
	if err := validateNewConnParams(underlying, config); err != nil {
		return nil, err
	}

	hs, err := createHandshakeState(config)
	if err != nil {
		return nil, err
	}

	localAddr, remoteAddr := createNoiseAddresses(underlying, config)

	nc := &NoiseConn{
		underlying:     underlying,
		config:         config,
		handshakeState: hs,
		localAddr:      localAddr,
		remoteAddr:     remoteAddr,
		logger:         log,
		metrics:        internal.NewConnectionMetrics(),
		state:          internal.StateInit,
	}

	nc.logger.WithFields(i2plogger.Fields{
		"pattern":     nc.config.Pattern,
		"role":        map[bool]string{true: "initiator", false: "responder"}[nc.config.Initiator],
		"local_addr":  nc.localAddr.String(),
		"remote_addr": nc.remoteAddr.String(),
	}).Debug("noise connection created")
	return nc, nil
}

// Read reads data from the connection.
// If the handshake is not complete, it will return an error.
//
// Thread Safety: This method is safe for concurrent use. Multiple goroutines
// can call Read simultaneously; calls are serialized via readMutex to protect
// the receive cipher state nonce counter.
func (nc *NoiseConn) Read(b []byte) (int, error) {
	if err := nc.validateReadState(); err != nil {
		return 0, err
	}

	if err := nc.configureReadTimeout(); err != nil {
		return 0, err
	}

	nc.readMutex.Lock()
	defer nc.readMutex.Unlock()

	encrypted, n, err := nc.readEncryptedData(b)
	if err != nil {
		return 0, err
	}

	decrypted, err := nc.decryptData(encrypted[:n], n)
	if err != nil {
		return 0, err
	}

	// Apply PhaseData modifier chain on decrypted plaintext (e.g., strip padding).
	decrypted, err = nc.applyInboundModifier(decrypted)
	if err != nil {
		return 0, err
	}

	return nc.copyDecryptedData(b, decrypted, n, len(decrypted))
}

// Write writes data to the connection.
// If the handshake is not complete, it will return an error.
//
// Thread Safety: This method is safe for concurrent use. Multiple goroutines
// can call Write simultaneously; calls are serialized via writeMutex to protect
// the send cipher state nonce counter.
func (nc *NoiseConn) Write(b []byte) (int, error) {
	if err := nc.validateWriteState(); err != nil {
		return 0, err
	}

	nc.writeMutex.Lock()
	defer nc.writeMutex.Unlock()

	if err := nc.configureWriteTimeout(); err != nil {
		return 0, err
	}

	// Apply PhaseData modifier chain before encryption (e.g., add padding).
	// toEncrypt may be larger than b if a modifier adds padding; we still report
	// len(b) as the number of caller bytes consumed.
	toEncrypt, err := nc.applyOutboundModifier(b)
	if err != nil {
		return 0, err
	}

	encrypted, err := nc.encryptData(toEncrypt)
	if err != nil {
		return 0, err
	}

	return nc.writeEncryptedData(b, encrypted)
}

// Encrypt encrypts plaintext data using the connection's cipher state
// without writing to the underlying connection. This allows callers to
// separate encryption from wire-level framing (e.g., for NTCP2's
// SipHash-obfuscated length prefix).
//
// The connection must have completed the Noise handshake.
// Thread Safety: Same guarantees as Write().
func (nc *NoiseConn) Encrypt(data []byte) ([]byte, error) {
	if err := nc.validateWriteState(); err != nil {
		return nil, err
	}
	return nc.encryptData(data)
}

// Decrypt decrypts ciphertext data using the connection's cipher state
// without reading from the underlying connection. This allows callers to
// separate decryption from wire-level framing (e.g., for NTCP2's
// SipHash-obfuscated length prefix).
//
// The connection must have completed the Noise handshake.
// Thread Safety: Same guarantees as Read().
func (nc *NoiseConn) Decrypt(encrypted []byte) ([]byte, error) {
	if err := nc.validateReadState(); err != nil {
		return nil, err
	}
	return nc.decryptData(encrypted, len(encrypted))
}

// Underlying returns the underlying net.Conn for direct wire access.
// This is needed for protocols like NTCP2 that add framing (e.g.,
// SipHash-obfuscated length prefixes) between the TCP connection and
// the encrypted Noise frames.
//
// Callers should use Encrypt/Decrypt for crypto and write/read the
// resulting bytes to/from this connection with their own framing.
func (nc *NoiseConn) Underlying() net.Conn {
	return nc.underlying
}

// GetModifierChain returns the HandshakeModifier chain from the config.
// Returns nil if no modifiers are configured. NTCP2 framed I/O uses this
// to apply PhaseData transforms (padding, obfuscation) around Encrypt/Decrypt.
func (nc *NoiseConn) GetModifierChain() *handshake.ModifierChain {
	return nc.config.GetModifierChain()
}

// Close closes the connection.
//
// Thread Safety: This method is safe for concurrent use and is idempotent.
// Multiple goroutines can call Close simultaneously - only the first call
// will perform the actual close operation, subsequent calls will return nil.
// The close mutex ensures atomic close operations.
func (nc *NoiseConn) Close() error {
	nc.closeMutex.Lock()
	defer nc.closeMutex.Unlock()

	// Check and set state atomically to prevent race conditions
	nc.stateMutex.Lock()
	if nc.state == internal.StateClosed {
		nc.stateMutex.Unlock()
		return nil // Already closed
	}

	oldState := nc.state
	nc.state = internal.StateClosed
	nc.stateMutex.Unlock()

	nc.logger.WithFields(i2plogger.Fields{
		"old_state": oldState.String(),
		"new_state": internal.StateClosed.String(),
	}).Debug("Connection state changed")

	nc.logger.Debug("Closing NoiseConn")

	// Zero cipher state key material before closing
	nc.ZeroKeys()

	// Zero static key material from config to prevent lingering in memory
	if nc.config != nil && len(nc.config.StaticKey) > 0 {
		internal.SecureZero(nc.config.StaticKey)
	}

	// Unregister from shutdown manager if set
	if nc.shutdownManager != nil {
		nc.shutdownManager.UnregisterConnection(nc)
	}

	err := nc.underlying.Close()
	if err != nil {
		return oops.
			Code("UNDERLYING_CLOSE_FAILED").
			In("noise").
			With("state", nc.getState().String()).
			Wrapf(err, "failed to close underlying connection")
	}

	return nil
}

// LocalAddr returns the local network address.
func (nc *NoiseConn) LocalAddr() net.Addr {
	return nc.localAddr
}

// RemoteAddr returns the remote network address.
func (nc *NoiseConn) RemoteAddr() net.Addr {
	return nc.remoteAddr
}

// SetDeadline sets the read and write deadlines.
func (nc *NoiseConn) SetDeadline(t time.Time) error {
	if err := nc.underlying.SetDeadline(t); err != nil {
		return oops.
			Code("SET_DEADLINE_FAILED").
			In("noise").
			With("deadline", t).
			Wrapf(err, "failed to set deadline on underlying connection")
	}
	return nil
}

// SetReadDeadline sets the read deadline.
func (nc *NoiseConn) SetReadDeadline(t time.Time) error {
	if err := nc.underlying.SetReadDeadline(t); err != nil {
		return oops.
			Code("SET_READ_DEADLINE_FAILED").
			In("noise").
			With("deadline", t).
			Wrapf(err, "failed to set read deadline on underlying connection")
	}
	return nil
}

// SetWriteDeadline sets the write deadline.
func (nc *NoiseConn) SetWriteDeadline(t time.Time) error {
	if err := nc.underlying.SetWriteDeadline(t); err != nil {
		return oops.
			Code("SET_WRITE_DEADLINE_FAILED").
			In("noise").
			With("deadline", t).
			Wrapf(err, "failed to set write deadline on underlying connection")
	}
	return nil
}
