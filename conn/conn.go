package conn

import (
	"net"
	"sync"
	"time"

	"github.com/go-i2p/go-noise/internal"
	shutdown "github.com/go-i2p/go-noise/shutdown"
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

// Conn implements net.Conn with Noise Protocol encryption.
// It wraps an underlying net.Conn and provides encrypted communication
// following the Noise Protocol Framework specification.
//
// Thread Safety:
// Conn is safe for concurrent use by multiple goroutines with the following guarantees:
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
type Conn struct {
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
	localAddr *Addr

	// remoteAddr is the remote Noise address
	remoteAddr *Addr

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
	shutdownManager shutdown.Shutdowner

	// closeMutex protects close operations
	closeMutex sync.Mutex

	// readMutex serializes Read calls to protect recvCipherState nonce
	readMutex sync.Mutex

	// writeMutex serializes Write calls to protect sendCipherState nonce
	writeMutex sync.Mutex
}

// NewNoiseConn creates a new NoiseConn wrapping the underlying connection.
// The handshake must be completed before using Read/Write operations.
func NewNoiseConn(underlying net.Conn, config *ConnConfig) (*Conn, error) {
	if err := validateNewConnParams(underlying, config); err != nil {
		return nil, err
	}

	hs, err := createHandshakeState(config)
	if err != nil {
		return nil, err
	}

	localAddr, remoteAddr := createNoiseAddresses(underlying, config)

	nc := &Conn{
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
		"pkg":         "noise",
		"func":        "NewNoiseConn",
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
func (nc *Conn) Read(b []byte) (int, error) {
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
func (nc *Conn) Write(b []byte) (int, error) {
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

// Close closes the connection.
//
// Thread Safety: This method is safe for concurrent use and is idempotent.
// Multiple goroutines can call Close simultaneously - only the first call
// will perform the actual close operation, subsequent calls will return nil.
// The close mutex ensures atomic close operations.
func (nc *Conn) Close() error {
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
		"pkg":       "noise",
		"func":      "NoiseConn.Close",
		"old_state": oldState.String(),
		"new_state": internal.StateClosed.String(),
	}).Debug("Connection state changed")

	nc.logger.WithFields(i2plogger.Fields{"pkg": "noise", "func": "NoiseConn.Close"}).Debug("Closing NoiseConn")

	// Zero cipher state key material before closing
	nc.ZeroKeys()

	// Close modifier chain to release any resources held by modifiers
	if chain := nc.config.GetModifierChain(); chain != nil {
		chain.Close()
	}

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
func (nc *Conn) LocalAddr() net.Addr {
	return nc.localAddr
}

// RemoteAddr returns the remote network address.
func (nc *Conn) RemoteAddr() net.Addr {
	return nc.remoteAddr
}

// SetDeadline sets the read and write deadlines.
func (nc *Conn) SetDeadline(t time.Time) error {
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
func (nc *Conn) SetReadDeadline(t time.Time) error {
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
func (nc *Conn) SetWriteDeadline(t time.Time) error {
	if err := nc.underlying.SetWriteDeadline(t); err != nil {
		return oops.
			Code("SET_WRITE_DEADLINE_FAILED").
			In("noise").
			With("deadline", t).
			Wrapf(err, "failed to set write deadline on underlying connection")
	}
	return nil
}
