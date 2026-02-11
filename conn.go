package noise

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/go-i2p/go-noise/internal"
	"github.com/go-i2p/logger"
	i2plogger "github.com/go-i2p/logger"
	"github.com/go-i2p/noise"
	"github.com/samber/oops"
)

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

	// cipherState handles encryption/decryption after handshake
	cipherState *noise.CipherState

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
	logger *logger.Logger

	// shutdownManager for coordinated shutdown (optional)
	shutdownManager *ShutdownManager

	// closeMutex protects close operations
	closeMutex sync.Mutex
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
// can call Read simultaneously. State validation is atomic and encryption
// operations are protected by the underlying cipher state synchronization.
func (nc *NoiseConn) Read(b []byte) (int, error) {
	if err := nc.validateReadState(); err != nil {
		return 0, err
	}

	if err := nc.configureReadTimeout(); err != nil {
		return 0, err
	}

	encrypted, n, err := nc.readEncryptedData(b)
	if err != nil {
		return 0, err
	}

	decrypted, err := nc.decryptData(encrypted[:n], n)
	if err != nil {
		return 0, err
	}

	return nc.copyDecryptedData(b, decrypted, n, len(decrypted))
}

// Write writes data to the connection.
// If the handshake is not complete, it will return an error.
//
// Thread Safety: This method is safe for concurrent use. Multiple goroutines
// can call Write simultaneously. State validation is atomic and encryption
// operations are protected by the underlying cipher state synchronization.
func (nc *NoiseConn) Write(b []byte) (int, error) {
	if err := nc.validateWriteState(); err != nil {
		return 0, err
	}

	if err := nc.configureWriteTimeout(); err != nil {
		return 0, err
	}

	encrypted, err := nc.encryptData(b)
	if err != nil {
		return 0, err
	}

	return nc.writeEncryptedData(b, encrypted)
}

// validateWriteState validates the connection state before writing.
func (nc *NoiseConn) validateWriteState() error {
	if nc.isClosed() {
		return oops.
			Code("CONN_CLOSED").
			In("noise").
			With("state", nc.getState().String()).
			Errorf("connection is closed")
	}

	if !nc.isHandshakeDone() {
		return oops.
			Code("HANDSHAKE_NOT_DONE").
			In("noise").
			With("state", nc.getState().String()).
			Errorf("handshake not completed")
	}

	if nc.cipherState == nil {
		return oops.
			Code("NO_CIPHER_STATE").
			In("noise").
			Errorf("cipher state not initialized")
	}

	return nil
}

// configureWriteTimeout sets the write timeout if configured.
func (nc *NoiseConn) configureWriteTimeout() error {
	if nc.config.WriteTimeout > 0 {
		if err := nc.underlying.SetWriteDeadline(time.Now().Add(nc.config.WriteTimeout)); err != nil {
			return oops.
				Code("SET_DEADLINE_FAILED").
				In("noise").
				With("timeout", nc.config.WriteTimeout).
				Wrapf(err, "failed to set write deadline")
		}
	}
	return nil
}

// encryptData encrypts the provided data using the cipher state.
func (nc *NoiseConn) encryptData(data []byte) ([]byte, error) {
	encrypted, err := nc.cipherState.Encrypt(nil, nil, data)
	// encrypted, err := nc.cipherState.Encrypt(nil, nil, data)
	if err != nil {
		return nil, oops.
			Code("ENCRYPT_FAILED").
			In("noise").
			With("plaintext_len", len(data)).
			Wrapf(err, "failed to encrypt data")
	}
	return encrypted, nil
}

// writeEncryptedData writes encrypted data to the underlying connection and handles the response.
func (nc *NoiseConn) writeEncryptedData(originalData, encryptedData []byte) (int, error) {
	n, err := nc.underlying.Write(encryptedData)
	if err != nil {
		return 0, oops.
			Code("UNDERLYING_WRITE_FAILED").
			In("noise").
			With("local_addr", nc.LocalAddr().String()).
			With("remote_addr", nc.RemoteAddr().String()).
			With("encrypted_len", len(encryptedData)).
			Wrapf(err, "underlying connection write failed")
	}

	// Track metrics for written data
	nc.metrics.AddBytesWritten(int64(len(originalData)))

	nc.logger.WithFields(i2plogger.Fields{
		"plaintext_bytes": len(originalData),
		"encrypted_bytes": len(encryptedData),
		"written_bytes":   n,
	}).Trace("encrypted data written to wire")

	if n == len(encryptedData) {
		return len(originalData), nil
	}

	return 0, oops.
		Code("PARTIAL_WRITE").
		In("noise").
		With("expected", len(encryptedData)).
		With("written", n).
		Errorf("partial write not supported with encryption")
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

// GetConnectionMetrics returns the current connection statistics
func (nc *NoiseConn) GetConnectionMetrics() (bytesRead, bytesWritten int64, handshakeDuration time.Duration) {
	return nc.metrics.GetStats()
}

// GetConnectionState returns the current connection state
//
// Thread Safety: This method is safe for concurrent use. It uses a read lock
// on the state mutex, allowing multiple goroutines to read the state simultaneously
// while preventing inconsistent reads during state transitions.
func (nc *NoiseConn) GetConnectionState() ConnState {
	return nc.getState()
}

// Rekey triggers a rekey operation on the underlying cipher state.
// This advances the encryption key material per the Noise Protocol specification
// (encrypts 32 zero bytes with nonce 2^64-1, takes first 32 bytes as new key).
//
// Rekey requires the handshake to be complete (connection in Established state).
// It is safe for concurrent use; the underlying CipherState.Rekey() is mutex-protected.
func (nc *NoiseConn) Rekey() error {
	if nc.getState() != internal.StateEstablished {
		return oops.
			Code("REKEY_INVALID_STATE").
			In("noise").
			With("state", nc.getState().String()).
			Errorf("cannot rekey: connection is not in established state")
	}
	if nc.cipherState == nil {
		return oops.
			Code("REKEY_NO_CIPHER").
			In("noise").
			Errorf("no cipher state available for rekeying")
	}
	nc.cipherState.Rekey()
	nc.logger.WithFields(logger.Fields{
		"pattern":     nc.config.Pattern,
		"local_addr":  nc.localAddr.String(),
		"remote_addr": nc.remoteAddr.String(),
	}).Info("Rekey completed")
	return nil
}

// SetShutdownManager sets the shutdown manager for this connection.
// If a shutdown manager is set, the connection will be automatically
// registered for graceful shutdown coordination.
func (nc *NoiseConn) SetShutdownManager(sm *ShutdownManager) {
	nc.shutdownManager = sm
	if sm != nil {
		sm.RegisterConnection(nc)
	}
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

// Handshake performs the Noise Protocol handshake.
// This must be called before using Read/Write operations.
//
// Thread Safety: This method is safe for concurrent use but handshake operations
// are serialized. Only one handshake can be in progress at a time per connection.
// If multiple goroutines call Handshake concurrently, they will be queued and
// execute sequentially. If the handshake is already complete, subsequent calls
// will return immediately without error.
func (nc *NoiseConn) Handshake(ctx context.Context) error {
	nc.handshakeMutex.Lock()
	defer nc.handshakeMutex.Unlock()

	if nc.isHandshakeDone() {
		return nil // Already completed
	}

	nc.setState(internal.StateHandshaking)
	nc.metrics.SetHandshakeStart()
	nc.logger.WithFields(i2plogger.Fields{
		"pattern":           nc.config.Pattern,
		"role":              map[bool]string{true: "initiator", false: "responder"}[nc.config.Initiator],
		"local_addr":        nc.LocalAddr().String(),
		"remote_addr":       nc.RemoteAddr().String(),
		"handshake_timeout": nc.config.HandshakeTimeout,
		"retry_enabled":     nc.config.HandshakeRetries > 0,
		"max_retries":       nc.config.HandshakeRetries,
	}).Info("starting noise protocol handshake")

	handshakeCtx := nc.createHandshakeContext(ctx)
	defer handshakeCtx.cancel()

	if err := nc.executeRoleBasedHandshake(handshakeCtx.ctx); err != nil {
		// On failure, return to init state for potential retry
		nc.setState(internal.StateInit)
		return err
	}

	nc.markHandshakeComplete()
	return nil
}

// performInitiatorHandshake handles the initiator side of the handshake.
func (nc *NoiseConn) performInitiatorHandshake(ctx context.Context) error {
	pattern := nc.config.Pattern
	nc.logger.WithFields(i2plogger.Fields{
		"pattern":     pattern,
		"role":        "initiator",
		"local_addr":  nc.LocalAddr().String(),
		"remote_addr": nc.RemoteAddr().String(),
	}).Debug("performing handshake as initiator")

	switch pattern {
	// One-way patterns (1 message)
	case "N", "Noise_N_25519_AESGCM_SHA256":
		return nc.performNInitiator(ctx)
	case "K", "Noise_K_25519_AESGCM_SHA256":
		return nc.performKInitiator(ctx)
	case "X", "Noise_X_25519_AESGCM_SHA256":
		return nc.performXInitiator(ctx)

	// Two-message interactive patterns
	case "NN", "Noise_NN_25519_AESGCM_SHA256":
		return nc.performNNInitiator(ctx)
	case "NK", "Noise_NK_25519_AESGCM_SHA256":
		return nc.performNKInitiator(ctx)
	case "NX", "Noise_NX_25519_AESGCM_SHA256":
		return nc.performNXInitiator(ctx)
	case "XN", "Noise_XN_25519_AESGCM_SHA256":
		return nc.performXNInitiator(ctx)
	case "XK", "Noise_XK_25519_AESGCM_SHA256":
		return nc.performXKInitiator(ctx)
	case "KN", "Noise_KN_25519_AESGCM_SHA256":
		return nc.performKNInitiator(ctx)
	case "KK", "Noise_KK_25519_AESGCM_SHA256":
		return nc.performKKInitiator(ctx)
	case "IN", "Noise_IN_25519_AESGCM_SHA256":
		return nc.performINInitiator(ctx)
	case "IK", "Noise_IK_25519_AESGCM_SHA256":
		return nc.performIKInitiator(ctx)
	case "IX", "Noise_IX_25519_AESGCM_SHA256":
		return nc.performIXInitiator(ctx)

	// Three-message patterns
	case "XX", "Noise_XX_25519_AESGCM_SHA256":
		return nc.performXXInitiator(ctx)
	case "KX", "Noise_KX_25519_AESGCM_SHA256":
		return nc.performKXInitiator(ctx)

	default:
		return oops.
			Code("UNSUPPORTED_PATTERN").
			In("noise").
			Errorf("unsupported handshake pattern: %s", pattern)
	}
}

// performOneWayInitiator handles one-way patterns (N, K, X)
func (nc *NoiseConn) performOneWayInitiator(ctx context.Context) error {
	// Send single message
	msg, cs1, cs2, err := nc.handshakeState.WriteMessage(nil, nil)
	if err != nil {
		return oops.
			Code("WRITE_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to create handshake message")
	}

	if _, err := nc.underlying.Write(msg); err != nil {
		return oops.
			Code("SEND_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to send handshake message")
	}

	// Store cipher state
	nc.updateCipherStates(cs1, cs2)
	return nil
}

// performNNInitiator handles NN pattern as initiator
func (nc *NoiseConn) performNNInitiator(ctx context.Context) error {
	// Message 1: → e (send ephemeral)
	msg, cs1, cs2, err := nc.handshakeState.WriteMessage(nil, nil)
	if err != nil {
		return oops.
			Code("WRITE_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to create first handshake message")
	}

	if _, err := nc.underlying.Write(msg); err != nil {
		return oops.
			Code("SEND_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to send first handshake message")
	}

	// Store cipher states if available
	nc.updateCipherStates(cs1, cs2)

	// Message 2: ← e, ee (receive ephemeral and compute shared secret)
	buffer := make([]byte, 2048)
	n, err := nc.underlying.Read(buffer)
	if err != nil {
		return oops.
			Code("READ_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to read second handshake message")
	}

	_, cs1, cs2, err = nc.handshakeState.ReadMessage(nil, buffer[:n])
	if err != nil {
		return oops.
			Code("PROCESS_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to process second handshake message")
	}

	// Update cipher states
	nc.updateCipherStates(cs1, cs2)
	return nil
}

// performXXInitiator handles XX pattern as initiator
func (nc *NoiseConn) performXXInitiator(ctx context.Context) error {
	// Message 1: → e
	msg, cs1, cs2, err := nc.handshakeState.WriteMessage(nil, nil)
	if err != nil {
		return oops.
			Code("WRITE_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to create first handshake message")
	}

	if _, err := nc.underlying.Write(msg); err != nil {
		return oops.
			Code("SEND_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to send first handshake message")
	}

	nc.updateCipherStates(cs1, cs2)

	// Message 2: ← e, ee, s, es (receive)
	buffer := make([]byte, 2048)
	n, err := nc.underlying.Read(buffer)
	if err != nil {
		return oops.
			Code("READ_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to read second handshake message")
	}

	_, cs1, cs2, err = nc.handshakeState.ReadMessage(nil, buffer[:n])
	if err != nil {
		return oops.
			Code("PROCESS_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to process second handshake message")
	}

	nc.updateCipherStates(cs1, cs2)

	// Message 3: → s, se (send)
	msg, cs1, cs2, err = nc.handshakeState.WriteMessage(nil, nil)
	if err != nil {
		return oops.
			Code("WRITE_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to create third handshake message")
	}

	if _, err := nc.underlying.Write(msg); err != nil {
		return oops.
			Code("SEND_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to send third handshake message")
	}

	nc.updateCipherStates(cs1, cs2)
	return nil
}

// getPatternMessageCount returns the expected number of handshake messages for each pattern.
// Returns an error for unknown patterns instead of defaulting, preventing configuration errors.
func (nc *NoiseConn) getPatternMessageCount() (int, error) {
	pattern := nc.config.Pattern

	switch pattern {
	// One-way patterns (1 message)
	case "N", "K", "X":
		nc.logger.WithFields(i2plogger.Fields{
			"pattern":           pattern,
			"expected_messages": 1,
			"pattern_type":      "one-way",
		}).Debug("detected one-way handshake pattern")
		return 1, nil
	// Two-message interactive patterns
	case "NN", "NK", "NX", "XN", "XK", "KN", "KK", "IN", "IK", "IX":
		nc.logger.WithFields(i2plogger.Fields{
			"pattern":           pattern,
			"expected_messages": 2,
			"pattern_type":      "two-message-interactive",
		}).Debug("detected two-message interactive handshake pattern")
		return 2, nil
	// Three-message patterns
	case "XX", "KX":
		nc.logger.WithFields(i2plogger.Fields{
			"pattern":           pattern,
			"expected_messages": 3,
			"pattern_type":      "three-message",
		}).Debug("detected three-message handshake pattern")
		return 3, nil
	default:
		// Check for full pattern names
		if strings.Contains(pattern, "_N_") || strings.Contains(pattern, "_K_") || strings.Contains(pattern, "_X_") {
			// One-way patterns
			nc.logger.WithFields(i2plogger.Fields{
				"pattern":           pattern,
				"expected_messages": 1,
				"pattern_type":      "one-way",
				"pattern_format":    "full",
			}).Debug("detected full-form one-way handshake pattern")
			return 1, nil
		} else if strings.Contains(pattern, "_NN_") || strings.Contains(pattern, "_NK_") ||
			strings.Contains(pattern, "_NX_") || strings.Contains(pattern, "_XN_") ||
			strings.Contains(pattern, "_XK_") || strings.Contains(pattern, "_KN_") ||
			strings.Contains(pattern, "_KK_") || strings.Contains(pattern, "_IN_") ||
			strings.Contains(pattern, "_IK_") || strings.Contains(pattern, "_IX_") {
			// Two-message patterns
			nc.logger.WithFields(i2plogger.Fields{
				"pattern":           pattern,
				"expected_messages": 2,
				"pattern_type":      "two-message-interactive",
				"pattern_format":    "full",
			}).Debug("detected full-form two-message handshake pattern")
			return 2, nil
		} else if strings.Contains(pattern, "_XX_") || strings.Contains(pattern, "_KX_") {
			// Three-message patterns
			nc.logger.WithFields(i2plogger.Fields{
				"pattern":           pattern,
				"expected_messages": 3,
				"pattern_type":      "three-message",
				"pattern_format":    "full",
			}).Debug("detected full-form three-message handshake pattern")
			return 3, nil
		}
		// Return error for unknown patterns instead of defaulting
		return 0, oops.
			Code("UNKNOWN_PATTERN").
			In("noise").
			With("pattern", pattern).
			Errorf("unknown handshake pattern: %s", pattern)
	}
}

// sendHandshakeMessage sends a handshake message
func (nc *NoiseConn) sendHandshakeMessage(ctx context.Context) error {
	// Write handshake message using the handshake state
	msg, cs1, cs2, err := nc.handshakeState.WriteMessage(nil, nil)
	if err != nil {
		return oops.
			Code("WRITE_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to create handshake message")
	}

	// Send message over underlying connection
	if _, err := nc.underlying.Write(msg); err != nil {
		return oops.
			Code("SEND_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to send handshake message")
	}

	// Store cipher states if handshake is complete
	nc.updateCipherStates(cs1, cs2)
	return nil
}

// receiveHandshakeMessage receives and processes a handshake message
func (nc *NoiseConn) receiveHandshakeMessage(ctx context.Context) error {
	// Read message from underlying connection
	buffer := make([]byte, 2048) // Increased buffer size for larger handshake messages
	n, err := nc.underlying.Read(buffer)
	if err != nil {
		return oops.
			Code("READ_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to read handshake message")
	}

	// Process message using handshake state
	_, cs1, cs2, err := nc.handshakeState.ReadMessage(nil, buffer[:n])
	if err != nil {
		return oops.
			Code("PROCESS_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to process handshake message")
	}

	// Store cipher states if handshake is complete
	nc.updateCipherStates(cs1, cs2)
	return nil
}

// updateCipherStates updates the cipher states when they become available
func (nc *NoiseConn) updateCipherStates(cs1, cs2 *noise.CipherState) {
	// Store the appropriate cipher state based on role
	// For most patterns, initiator uses cs1 for sending, cs2 for receiving
	// Responder uses cs2 for sending, cs1 for receiving
	// We'll use cs1 as the primary cipher state for simplicity
	if cs1 != nil {
		nc.cipherState = cs1
		nc.logger.WithFields(i2plogger.Fields{
			"pattern":            nc.config.Pattern,
			"role":               map[bool]string{true: "initiator", false: "responder"}[nc.config.Initiator],
			"cipher_state":       "cs1",
			"handshake_complete": nc.cipherState != nil,
		}).Debug("cipher state updated during handshake")
	} else if cs2 != nil {
		nc.cipherState = cs2
		nc.logger.WithFields(i2plogger.Fields{
			"pattern":            nc.config.Pattern,
			"role":               map[bool]string{true: "initiator", false: "responder"}[nc.config.Initiator],
			"cipher_state":       "cs2",
			"handshake_complete": nc.cipherState != nil,
		}).Debug("cipher state updated during handshake")
	}
}

// performResponderHandshake handles the responder side of the handshake.
func (nc *NoiseConn) performResponderHandshake(ctx context.Context) error {
	pattern := nc.config.Pattern
	nc.logger.WithFields(i2plogger.Fields{
		"pattern":     pattern,
		"role":        "responder",
		"local_addr":  nc.LocalAddr().String(),
		"remote_addr": nc.RemoteAddr().String(),
	}).Debug("performing handshake as responder")

	switch pattern {
	// One-way patterns (1 message)
	case "N", "Noise_N_25519_AESGCM_SHA256":
		return nc.performNResponder(ctx)
	case "K", "Noise_K_25519_AESGCM_SHA256":
		return nc.performKResponder(ctx)
	case "X", "Noise_X_25519_AESGCM_SHA256":
		return nc.performXResponder(ctx)

	// Two-message interactive patterns
	case "NN", "Noise_NN_25519_AESGCM_SHA256":
		return nc.performNNResponder(ctx)
	case "NK", "Noise_NK_25519_AESGCM_SHA256":
		return nc.performNKResponder(ctx)
	case "NX", "Noise_NX_25519_AESGCM_SHA256":
		return nc.performNXResponder(ctx)
	case "XN", "Noise_XN_25519_AESGCM_SHA256":
		return nc.performXNResponder(ctx)
	case "XK", "Noise_XK_25519_AESGCM_SHA256":
		return nc.performXKResponder(ctx)
	case "KN", "Noise_KN_25519_AESGCM_SHA256":
		return nc.performKNResponder(ctx)
	case "KK", "Noise_KK_25519_AESGCM_SHA256":
		return nc.performKKResponder(ctx)
	case "IN", "Noise_IN_25519_AESGCM_SHA256":
		return nc.performINResponder(ctx)
	case "IK", "Noise_IK_25519_AESGCM_SHA256":
		return nc.performIKResponder(ctx)
	case "IX", "Noise_IX_25519_AESGCM_SHA256":
		return nc.performIXResponder(ctx)

	// Three-message patterns
	case "XX", "Noise_XX_25519_AESGCM_SHA256":
		return nc.performXXResponder(ctx)
	case "KX", "Noise_KX_25519_AESGCM_SHA256":
		return nc.performKXResponder(ctx)

	default:
		return oops.
			Code("UNSUPPORTED_PATTERN").
			In("noise").
			Errorf("unsupported handshake pattern: %s", pattern)
	}
}

// performOneWayResponder handles one-way patterns (N, K, X)
func (nc *NoiseConn) performOneWayResponder(ctx context.Context) error {
	// Receive single message
	buffer := make([]byte, 2048)
	n, err := nc.underlying.Read(buffer)
	if err != nil {
		return oops.
			Code("READ_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to read handshake message")
	}

	_, cs1, cs2, err := nc.handshakeState.ReadMessage(nil, buffer[:n])
	if err != nil {
		return oops.
			Code("PROCESS_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to process handshake message")
	}

	// Store cipher state
	nc.updateCipherStates(cs1, cs2)
	return nil
}

// performNNResponder handles NN pattern as responder
func (nc *NoiseConn) performNNResponder(ctx context.Context) error {
	// Message 1: → e (receive ephemeral)
	buffer := make([]byte, 2048)
	n, err := nc.underlying.Read(buffer)
	if err != nil {
		return oops.
			Code("READ_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to read first handshake message")
	}

	_, cs1, cs2, err := nc.handshakeState.ReadMessage(nil, buffer[:n])
	if err != nil {
		return oops.
			Code("PROCESS_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to process first handshake message")
	}

	// Store cipher states if available
	nc.updateCipherStates(cs1, cs2)

	// Message 2: ← e, ee (send ephemeral and compute shared secret)
	msg, cs1, cs2, err := nc.handshakeState.WriteMessage(nil, nil)
	if err != nil {
		return oops.
			Code("WRITE_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to create second handshake message")
	}

	if _, err := nc.underlying.Write(msg); err != nil {
		return oops.
			Code("SEND_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to send second handshake message")
	}

	// Update cipher states
	nc.updateCipherStates(cs1, cs2)
	return nil
}

// performXXResponder handles XX pattern as responder
func (nc *NoiseConn) performXXResponder(ctx context.Context) error {
	// Message 1: → e (receive)
	buffer := make([]byte, 2048)
	n, err := nc.underlying.Read(buffer)
	if err != nil {
		return oops.
			Code("READ_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to read first handshake message")
	}

	_, cs1, cs2, err := nc.handshakeState.ReadMessage(nil, buffer[:n])
	if err != nil {
		return oops.
			Code("PROCESS_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to process first handshake message")
	}

	nc.updateCipherStates(cs1, cs2)

	// Message 2: ← e, ee, s, es (send)
	msg, cs1, cs2, err := nc.handshakeState.WriteMessage(nil, nil)
	if err != nil {
		return oops.
			Code("WRITE_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to create second handshake message")
	}

	if _, err := nc.underlying.Write(msg); err != nil {
		return oops.
			Code("SEND_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to send second handshake message")
	}

	nc.updateCipherStates(cs1, cs2)

	// Message 3: → s, se (receive)
	n, err = nc.underlying.Read(buffer)
	if err != nil {
		return oops.
			Code("READ_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to read third handshake message")
	}

	_, cs1, cs2, err = nc.handshakeState.ReadMessage(nil, buffer[:n])
	if err != nil {
		return oops.
			Code("PROCESS_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to process third handshake message")
	}

	nc.updateCipherStates(cs1, cs2)
	return nil
}

// ============================================================================
// ONE-WAY PATTERNS (1 message)
// ============================================================================

// performNInitiator handles N pattern as initiator: → e, es
func (nc *NoiseConn) performNInitiator(ctx context.Context) error {
	// Message 1: → e, es (send ephemeral, encrypt with responder's static)
	msg, cs1, cs2, err := nc.handshakeState.WriteMessage(nil, nil)
	if err != nil {
		return oops.
			Code("WRITE_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to create N handshake message")
	}

	if _, err := nc.underlying.Write(msg); err != nil {
		return oops.
			Code("SEND_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to send N handshake message")
	}

	nc.updateCipherStates(cs1, cs2)
	return nil
}

// performKInitiator handles K pattern as initiator: → e, es, ss
func (nc *NoiseConn) performKInitiator(ctx context.Context) error {
	// Message 1: → e, es, ss (send ephemeral, encrypt with both static keys)
	msg, cs1, cs2, err := nc.handshakeState.WriteMessage(nil, nil)
	if err != nil {
		return oops.
			Code("WRITE_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to create K handshake message")
	}

	if _, err := nc.underlying.Write(msg); err != nil {
		return oops.
			Code("SEND_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to send K handshake message")
	}

	nc.updateCipherStates(cs1, cs2)
	return nil
}

// performXInitiator handles X pattern as initiator: → e, es, s, ss
func (nc *NoiseConn) performXInitiator(ctx context.Context) error {
	// Message 1: → e, es, s, ss (send ephemeral and static, encrypt with responder's static)
	msg, cs1, cs2, err := nc.handshakeState.WriteMessage(nil, nil)
	if err != nil {
		return oops.
			Code("WRITE_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to create X handshake message")
	}

	if _, err := nc.underlying.Write(msg); err != nil {
		return oops.
			Code("SEND_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to send X handshake message")
	}

	nc.updateCipherStates(cs1, cs2)
	return nil
}

// ============================================================================
// TWO-MESSAGE INTERACTIVE PATTERNS
// ============================================================================

// performNKInitiator handles NK pattern as initiator: → e, es, ← e, ee
func (nc *NoiseConn) performNKInitiator(ctx context.Context) error {
	// Message 1: → e, es (send ephemeral, encrypt with responder's static)
	msg, cs1, cs2, err := nc.handshakeState.WriteMessage(nil, nil)
	if err != nil {
		return oops.
			Code("WRITE_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to create first NK handshake message")
	}

	if _, err := nc.underlying.Write(msg); err != nil {
		return oops.
			Code("SEND_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to send first NK handshake message")
	}

	nc.updateCipherStates(cs1, cs2)

	// Message 2: ← e, ee (receive ephemeral and compute DH)
	buffer := make([]byte, 2048)
	n, err := nc.underlying.Read(buffer)
	if err != nil {
		return oops.
			Code("READ_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to read second NK handshake message")
	}

	_, cs1, cs2, err = nc.handshakeState.ReadMessage(nil, buffer[:n])
	if err != nil {
		return oops.
			Code("PROCESS_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to process second NK handshake message")
	}

	nc.updateCipherStates(cs1, cs2)
	return nil
}

// performNXInitiator handles NX pattern as initiator: → e, ← e, ee, s, es
func (nc *NoiseConn) performNXInitiator(ctx context.Context) error {
	// Message 1: → e (send ephemeral)
	msg, cs1, cs2, err := nc.handshakeState.WriteMessage(nil, nil)
	if err != nil {
		return oops.
			Code("WRITE_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to create first NX handshake message")
	}

	if _, err := nc.underlying.Write(msg); err != nil {
		return oops.
			Code("SEND_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to send first NX handshake message")
	}

	nc.updateCipherStates(cs1, cs2)

	// Message 2: ← e, ee, s, es (receive ephemeral and static, compute DH)
	buffer := make([]byte, 2048)
	n, err := nc.underlying.Read(buffer)
	if err != nil {
		return oops.
			Code("READ_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to read second NX handshake message")
	}

	_, cs1, cs2, err = nc.handshakeState.ReadMessage(nil, buffer[:n])
	if err != nil {
		return oops.
			Code("PROCESS_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to process second NX handshake message")
	}

	nc.updateCipherStates(cs1, cs2)
	return nil
}

// performXNInitiator handles XN pattern as initiator: → e, s, ← e, ee, se
func (nc *NoiseConn) performXNInitiator(ctx context.Context) error {
	// Message 1: → e, s (send ephemeral and static)
	msg, cs1, cs2, err := nc.handshakeState.WriteMessage(nil, nil)
	if err != nil {
		return oops.
			Code("WRITE_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to create first XN handshake message")
	}

	if _, err := nc.underlying.Write(msg); err != nil {
		return oops.
			Code("SEND_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to send first XN handshake message")
	}

	nc.updateCipherStates(cs1, cs2)

	// Message 2: ← e, ee, se (receive ephemeral, compute DH)
	buffer := make([]byte, 2048)
	n, err := nc.underlying.Read(buffer)
	if err != nil {
		return oops.
			Code("READ_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to read second XN handshake message")
	}

	_, cs1, cs2, err = nc.handshakeState.ReadMessage(nil, buffer[:n])
	if err != nil {
		return oops.
			Code("PROCESS_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to process second XN handshake message")
	}

	nc.updateCipherStates(cs1, cs2)
	return nil
}

// performXKInitiator handles XK pattern as initiator: → e, es, s, ss, ← e, ee, se
func (nc *NoiseConn) performXKInitiator(ctx context.Context) error {
	// Message 1: → e, es, s, ss (send ephemeral and static, encrypt with responder's static)
	msg, cs1, cs2, err := nc.handshakeState.WriteMessage(nil, nil)
	if err != nil {
		return oops.
			Code("WRITE_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to create first XK handshake message")
	}

	if _, err := nc.underlying.Write(msg); err != nil {
		return oops.
			Code("SEND_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to send first XK handshake message")
	}

	nc.updateCipherStates(cs1, cs2)

	// Message 2: ← e, ee, se (receive ephemeral, compute DH)
	buffer := make([]byte, 2048)
	n, err := nc.underlying.Read(buffer)
	if err != nil {
		return oops.
			Code("READ_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to read second XK handshake message")
	}

	_, cs1, cs2, err = nc.handshakeState.ReadMessage(nil, buffer[:n])
	if err != nil {
		return oops.
			Code("PROCESS_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to process second XK handshake message")
	}

	nc.updateCipherStates(cs1, cs2)
	return nil
}

// performKNInitiator handles KN pattern as initiator: → e, ← e, ee, se, es
func (nc *NoiseConn) performKNInitiator(ctx context.Context) error {
	// Message 1: → e (send ephemeral)
	msg, cs1, cs2, err := nc.handshakeState.WriteMessage(nil, nil)
	if err != nil {
		return oops.
			Code("WRITE_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to create first KN handshake message")
	}

	if _, err := nc.underlying.Write(msg); err != nil {
		return oops.
			Code("SEND_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to send first KN handshake message")
	}

	nc.updateCipherStates(cs1, cs2)

	// Message 2: ← e, ee, se, es (receive ephemeral and static, compute DH)
	buffer := make([]byte, 2048)
	n, err := nc.underlying.Read(buffer)
	if err != nil {
		return oops.
			Code("READ_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to read second KN handshake message")
	}

	_, cs1, cs2, err = nc.handshakeState.ReadMessage(nil, buffer[:n])
	if err != nil {
		return oops.
			Code("PROCESS_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to process second KN handshake message")
	}

	nc.updateCipherStates(cs1, cs2)
	return nil
}

// performKKInitiator handles KK pattern as initiator: → e, es, ss, ← e, ee, se
func (nc *NoiseConn) performKKInitiator(ctx context.Context) error {
	// Message 1: → e, es, ss (send ephemeral, encrypt with responder's static and our static)
	msg, cs1, cs2, err := nc.handshakeState.WriteMessage(nil, nil)
	if err != nil {
		return oops.
			Code("WRITE_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to create first KK handshake message")
	}

	if _, err := nc.underlying.Write(msg); err != nil {
		return oops.
			Code("SEND_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to send first KK handshake message")
	}

	nc.updateCipherStates(cs1, cs2)

	// Message 2: ← e, ee, se (receive ephemeral, compute DH)
	buffer := make([]byte, 2048)
	n, err := nc.underlying.Read(buffer)
	if err != nil {
		return oops.
			Code("READ_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to read second KK handshake message")
	}

	_, cs1, cs2, err = nc.handshakeState.ReadMessage(nil, buffer[:n])
	if err != nil {
		return oops.
			Code("PROCESS_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to process second KK handshake message")
	}

	nc.updateCipherStates(cs1, cs2)
	return nil
}

// performINInitiator handles IN pattern as initiator: → e, s, ← e, ee, se, es
func (nc *NoiseConn) performINInitiator(ctx context.Context) error {
	// Message 1: → e, s (send ephemeral and static)
	msg, cs1, cs2, err := nc.handshakeState.WriteMessage(nil, nil)
	if err != nil {
		return oops.
			Code("WRITE_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to create first IN handshake message")
	}

	if _, err := nc.underlying.Write(msg); err != nil {
		return oops.
			Code("SEND_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to send first IN handshake message")
	}

	nc.updateCipherStates(cs1, cs2)

	// Message 2: ← e, ee, se, es (receive ephemeral and static, compute DH)
	buffer := make([]byte, 2048)
	n, err := nc.underlying.Read(buffer)
	if err != nil {
		return oops.
			Code("READ_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to read second IN handshake message")
	}

	_, cs1, cs2, err = nc.handshakeState.ReadMessage(nil, buffer[:n])
	if err != nil {
		return oops.
			Code("PROCESS_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to process second IN handshake message")
	}

	nc.updateCipherStates(cs1, cs2)
	return nil
}

// performIKInitiator handles IK pattern as initiator: → e, es, s, ss, ← e, ee, se
func (nc *NoiseConn) performIKInitiator(ctx context.Context) error {
	// Message 1: → e, es, s, ss (send ephemeral and static, encrypt with responder's static)
	msg, cs1, cs2, err := nc.handshakeState.WriteMessage(nil, nil)
	if err != nil {
		return oops.
			Code("WRITE_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to create first IK handshake message")
	}

	if _, err := nc.underlying.Write(msg); err != nil {
		return oops.
			Code("SEND_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to send first IK handshake message")
	}

	nc.updateCipherStates(cs1, cs2)

	// Message 2: ← e, ee, se (receive ephemeral, compute DH)
	buffer := make([]byte, 2048)
	n, err := nc.underlying.Read(buffer)
	if err != nil {
		return oops.
			Code("READ_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to read second IK handshake message")
	}

	_, cs1, cs2, err = nc.handshakeState.ReadMessage(nil, buffer[:n])
	if err != nil {
		return oops.
			Code("PROCESS_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to process second IK handshake message")
	}

	nc.updateCipherStates(cs1, cs2)
	return nil
}

// performIXInitiator handles IX pattern as initiator: → e, s, ← e, ee, se, s, es
func (nc *NoiseConn) performIXInitiator(ctx context.Context) error {
	// Message 1: → e, s (send ephemeral and static)
	msg, cs1, cs2, err := nc.handshakeState.WriteMessage(nil, nil)
	if err != nil {
		return oops.
			Code("WRITE_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to create first IX handshake message")
	}

	if _, err := nc.underlying.Write(msg); err != nil {
		return oops.
			Code("SEND_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to send first IX handshake message")
	}

	nc.updateCipherStates(cs1, cs2)

	// Message 2: ← e, ee, se, s, es (receive ephemeral and static, compute DH)
	buffer := make([]byte, 2048)
	n, err := nc.underlying.Read(buffer)
	if err != nil {
		return oops.
			Code("READ_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to read second IX handshake message")
	}

	_, cs1, cs2, err = nc.handshakeState.ReadMessage(nil, buffer[:n])
	if err != nil {
		return oops.
			Code("PROCESS_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to process second IX handshake message")
	}

	nc.updateCipherStates(cs1, cs2)
	return nil
}

// ============================================================================
// THREE-MESSAGE PATTERNS
// ============================================================================

// performKXInitiator handles KX pattern as initiator: → e, ← e, ee, se, s, es, → s, se
func (nc *NoiseConn) performKXInitiator(ctx context.Context) error {
	// Message 1: → e (send ephemeral)
	msg, cs1, cs2, err := nc.handshakeState.WriteMessage(nil, nil)
	if err != nil {
		return oops.
			Code("WRITE_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to create first KX handshake message")
	}

	if _, err := nc.underlying.Write(msg); err != nil {
		return oops.
			Code("SEND_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to send first KX handshake message")
	}

	nc.updateCipherStates(cs1, cs2)

	// Message 2: ← e, ee, se, s, es (receive ephemeral and static, compute DH)
	buffer := make([]byte, 2048)
	n, err := nc.underlying.Read(buffer)
	if err != nil {
		return oops.
			Code("READ_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to read second KX handshake message")
	}

	_, cs1, cs2, err = nc.handshakeState.ReadMessage(nil, buffer[:n])
	if err != nil {
		return oops.
			Code("PROCESS_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to process second KX handshake message")
	}

	nc.updateCipherStates(cs1, cs2)

	// Message 3: → s, se (send static, compute final DH)
	msg, cs1, cs2, err = nc.handshakeState.WriteMessage(nil, nil)
	if err != nil {
		return oops.
			Code("WRITE_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to create third KX handshake message")
	}

	if _, err := nc.underlying.Write(msg); err != nil {
		return oops.
			Code("SEND_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to send third KX handshake message")
	}

	nc.updateCipherStates(cs1, cs2)
	return nil
}

// ============================================================================
// ONE-WAY PATTERN RESPONDERS
// ============================================================================

// performNResponder handles N pattern as responder: → e, es
func (nc *NoiseConn) performNResponder(ctx context.Context) error {
	// Message 1: → e, es (receive ephemeral encrypted with our static)
	buffer := make([]byte, 2048)
	n, err := nc.underlying.Read(buffer)
	if err != nil {
		return oops.
			Code("READ_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to read N handshake message")
	}

	_, cs1, cs2, err := nc.handshakeState.ReadMessage(nil, buffer[:n])
	if err != nil {
		return oops.
			Code("PROCESS_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to process N handshake message")
	}

	nc.updateCipherStates(cs1, cs2)
	return nil
}

// performKResponder handles K pattern as responder: → e, es, ss
func (nc *NoiseConn) performKResponder(ctx context.Context) error {
	// Message 1: → e, es, ss (receive ephemeral encrypted with both static keys)
	buffer := make([]byte, 2048)
	n, err := nc.underlying.Read(buffer)
	if err != nil {
		return oops.
			Code("READ_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to read K handshake message")
	}

	_, cs1, cs2, err := nc.handshakeState.ReadMessage(nil, buffer[:n])
	if err != nil {
		return oops.
			Code("PROCESS_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to process K handshake message")
	}

	nc.updateCipherStates(cs1, cs2)
	return nil
}

// performXResponder handles X pattern as responder: → e, es, s, ss
func (nc *NoiseConn) performXResponder(ctx context.Context) error {
	// Message 1: → e, es, s, ss (receive ephemeral and static encrypted with our static)
	buffer := make([]byte, 2048)
	n, err := nc.underlying.Read(buffer)
	if err != nil {
		return oops.
			Code("READ_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to read X handshake message")
	}

	_, cs1, cs2, err := nc.handshakeState.ReadMessage(nil, buffer[:n])
	if err != nil {
		return oops.
			Code("PROCESS_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to process X handshake message")
	}

	nc.updateCipherStates(cs1, cs2)
	return nil
}

// ============================================================================
// TWO-MESSAGE INTERACTIVE PATTERN RESPONDERS
// ============================================================================

// performNKResponder handles NK pattern as responder: → e, es, ← e, ee
func (nc *NoiseConn) performNKResponder(ctx context.Context) error {
	// Message 1: → e, es (receive ephemeral encrypted with our static)
	buffer := make([]byte, 2048)
	n, err := nc.underlying.Read(buffer)
	if err != nil {
		return oops.
			Code("READ_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to read first NK handshake message")
	}

	_, cs1, cs2, err := nc.handshakeState.ReadMessage(nil, buffer[:n])
	if err != nil {
		return oops.
			Code("PROCESS_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to process first NK handshake message")
	}

	nc.updateCipherStates(cs1, cs2)

	// Message 2: ← e, ee (send ephemeral and compute DH)
	msg, cs1, cs2, err := nc.handshakeState.WriteMessage(nil, nil)
	if err != nil {
		return oops.
			Code("WRITE_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to create second NK handshake message")
	}

	if _, err := nc.underlying.Write(msg); err != nil {
		return oops.
			Code("SEND_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to send second NK handshake message")
	}

	nc.updateCipherStates(cs1, cs2)
	return nil
}

// performNXResponder handles NX pattern as responder: → e, ← e, ee, s, es
func (nc *NoiseConn) performNXResponder(ctx context.Context) error {
	// Message 1: → e (receive ephemeral)
	buffer := make([]byte, 2048)
	n, err := nc.underlying.Read(buffer)
	if err != nil {
		return oops.
			Code("READ_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to read first NX handshake message")
	}

	_, cs1, cs2, err := nc.handshakeState.ReadMessage(nil, buffer[:n])
	if err != nil {
		return oops.
			Code("PROCESS_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to process first NX handshake message")
	}

	nc.updateCipherStates(cs1, cs2)

	// Message 2: ← e, ee, s, es (send ephemeral and static, compute DH)
	msg, cs1, cs2, err := nc.handshakeState.WriteMessage(nil, nil)
	if err != nil {
		return oops.
			Code("WRITE_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to create second NX handshake message")
	}

	if _, err := nc.underlying.Write(msg); err != nil {
		return oops.
			Code("SEND_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to send second NX handshake message")
	}

	nc.updateCipherStates(cs1, cs2)
	return nil
}

// performXNResponder handles XN pattern as responder: → e, s, ← e, ee, se
func (nc *NoiseConn) performXNResponder(ctx context.Context) error {
	// Message 1: → e, s (receive ephemeral and static)
	buffer := make([]byte, 2048)
	n, err := nc.underlying.Read(buffer)
	if err != nil {
		return oops.
			Code("READ_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to read first XN handshake message")
	}

	_, cs1, cs2, err := nc.handshakeState.ReadMessage(nil, buffer[:n])
	if err != nil {
		return oops.
			Code("PROCESS_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to process first XN handshake message")
	}

	nc.updateCipherStates(cs1, cs2)

	// Message 2: ← e, ee, se (send ephemeral, compute DH)
	msg, cs1, cs2, err := nc.handshakeState.WriteMessage(nil, nil)
	if err != nil {
		return oops.
			Code("WRITE_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to create second XN handshake message")
	}

	if _, err := nc.underlying.Write(msg); err != nil {
		return oops.
			Code("SEND_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to send second XN handshake message")
	}

	nc.updateCipherStates(cs1, cs2)
	return nil
}

// performXKResponder handles XK pattern as responder: → e, es, s, ss, ← e, ee, se
func (nc *NoiseConn) performXKResponder(ctx context.Context) error {
	// Message 1: → e, es, s, ss (receive ephemeral and static encrypted with our static)
	buffer := make([]byte, 2048)
	n, err := nc.underlying.Read(buffer)
	if err != nil {
		return oops.
			Code("READ_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to read first XK handshake message")
	}

	_, cs1, cs2, err := nc.handshakeState.ReadMessage(nil, buffer[:n])
	if err != nil {
		return oops.
			Code("PROCESS_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to process first XK handshake message")
	}

	nc.updateCipherStates(cs1, cs2)

	// Message 2: ← e, ee, se (send ephemeral, compute DH)
	msg, cs1, cs2, err := nc.handshakeState.WriteMessage(nil, nil)
	if err != nil {
		return oops.
			Code("WRITE_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to create second XK handshake message")
	}

	if _, err := nc.underlying.Write(msg); err != nil {
		return oops.
			Code("SEND_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to send second XK handshake message")
	}

	nc.updateCipherStates(cs1, cs2)
	return nil
}

// performKNResponder handles KN pattern as responder: → e, ← e, ee, se, es
func (nc *NoiseConn) performKNResponder(ctx context.Context) error {
	// Message 1: → e (receive ephemeral)
	buffer := make([]byte, 2048)
	n, err := nc.underlying.Read(buffer)
	if err != nil {
		return oops.
			Code("READ_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to read first KN handshake message")
	}

	_, cs1, cs2, err := nc.handshakeState.ReadMessage(nil, buffer[:n])
	if err != nil {
		return oops.
			Code("PROCESS_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to process first KN handshake message")
	}

	nc.updateCipherStates(cs1, cs2)

	// Message 2: ← e, ee, se, es (send ephemeral and static, compute DH)
	msg, cs1, cs2, err := nc.handshakeState.WriteMessage(nil, nil)
	if err != nil {
		return oops.
			Code("WRITE_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to create second KN handshake message")
	}

	if _, err := nc.underlying.Write(msg); err != nil {
		return oops.
			Code("SEND_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to send second KN handshake message")
	}

	nc.updateCipherStates(cs1, cs2)
	return nil
}

// performKKResponder handles KK pattern as responder: → e, es, ss, ← e, ee, se
func (nc *NoiseConn) performKKResponder(ctx context.Context) error {
	// Message 1: → e, es, ss (receive ephemeral encrypted with both static keys)
	buffer := make([]byte, 2048)
	n, err := nc.underlying.Read(buffer)
	if err != nil {
		return oops.
			Code("READ_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to read first KK handshake message")
	}

	_, cs1, cs2, err := nc.handshakeState.ReadMessage(nil, buffer[:n])
	if err != nil {
		return oops.
			Code("PROCESS_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to process first KK handshake message")
	}

	nc.updateCipherStates(cs1, cs2)

	// Message 2: ← e, ee, se (send ephemeral, compute DH)
	msg, cs1, cs2, err := nc.handshakeState.WriteMessage(nil, nil)
	if err != nil {
		return oops.
			Code("WRITE_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to create second KK handshake message")
	}

	if _, err := nc.underlying.Write(msg); err != nil {
		return oops.
			Code("SEND_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to send second KK handshake message")
	}

	nc.updateCipherStates(cs1, cs2)
	return nil
}

// performINResponder handles IN pattern as responder: → e, s, ← e, ee, se, es
func (nc *NoiseConn) performINResponder(ctx context.Context) error {
	// Message 1: → e, s (receive ephemeral and static)
	buffer := make([]byte, 2048)
	n, err := nc.underlying.Read(buffer)
	if err != nil {
		return oops.
			Code("READ_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to read first IN handshake message")
	}

	_, cs1, cs2, err := nc.handshakeState.ReadMessage(nil, buffer[:n])
	if err != nil {
		return oops.
			Code("PROCESS_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to process first IN handshake message")
	}

	nc.updateCipherStates(cs1, cs2)

	// Message 2: ← e, ee, se, es (send ephemeral and static, compute DH)
	msg, cs1, cs2, err := nc.handshakeState.WriteMessage(nil, nil)
	if err != nil {
		return oops.
			Code("WRITE_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to create second IN handshake message")
	}

	if _, err := nc.underlying.Write(msg); err != nil {
		return oops.
			Code("SEND_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to send second IN handshake message")
	}

	nc.updateCipherStates(cs1, cs2)
	return nil
}

// performIKResponder handles IK pattern as responder: → e, es, s, ss, ← e, ee, se
func (nc *NoiseConn) performIKResponder(ctx context.Context) error {
	// Message 1: → e, es, s, ss (receive ephemeral and static encrypted with our static)
	buffer := make([]byte, 2048)
	n, err := nc.underlying.Read(buffer)
	if err != nil {
		return oops.
			Code("READ_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to read first IK handshake message")
	}

	_, cs1, cs2, err := nc.handshakeState.ReadMessage(nil, buffer[:n])
	if err != nil {
		return oops.
			Code("PROCESS_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to process first IK handshake message")
	}

	nc.updateCipherStates(cs1, cs2)

	// Message 2: ← e, ee, se (send ephemeral, compute DH)
	msg, cs1, cs2, err := nc.handshakeState.WriteMessage(nil, nil)
	if err != nil {
		return oops.
			Code("WRITE_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to create second IK handshake message")
	}

	if _, err := nc.underlying.Write(msg); err != nil {
		return oops.
			Code("SEND_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to send second IK handshake message")
	}

	nc.updateCipherStates(cs1, cs2)
	return nil
}

// performIXResponder handles IX pattern as responder: → e, s, ← e, ee, se, s, es
func (nc *NoiseConn) performIXResponder(ctx context.Context) error {
	// Message 1: → e, s (receive ephemeral and static)
	buffer := make([]byte, 2048)
	n, err := nc.underlying.Read(buffer)
	if err != nil {
		return oops.
			Code("READ_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to read first IX handshake message")
	}

	_, cs1, cs2, err := nc.handshakeState.ReadMessage(nil, buffer[:n])
	if err != nil {
		return oops.
			Code("PROCESS_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to process first IX handshake message")
	}

	nc.updateCipherStates(cs1, cs2)

	// Message 2: ← e, ee, se, s, es (send ephemeral and static, compute DH)
	msg, cs1, cs2, err := nc.handshakeState.WriteMessage(nil, nil)
	if err != nil {
		return oops.
			Code("WRITE_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to create second IX handshake message")
	}

	if _, err := nc.underlying.Write(msg); err != nil {
		return oops.
			Code("SEND_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to send second IX handshake message")
	}

	nc.updateCipherStates(cs1, cs2)
	return nil
}

// ============================================================================
// THREE-MESSAGE PATTERN RESPONDERS
// ============================================================================

// performKXResponder handles KX pattern as responder: → e, ← e, ee, se, s, es, → s, se
func (nc *NoiseConn) performKXResponder(ctx context.Context) error {
	// Message 1: → e (receive ephemeral)
	buffer := make([]byte, 2048)
	n, err := nc.underlying.Read(buffer)
	if err != nil {
		return oops.
			Code("READ_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to read first KX handshake message")
	}

	_, cs1, cs2, err := nc.handshakeState.ReadMessage(nil, buffer[:n])
	if err != nil {
		return oops.
			Code("PROCESS_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to process first KX handshake message")
	}

	nc.updateCipherStates(cs1, cs2)

	// Message 2: ← e, ee, se, s, es (send ephemeral and static, compute DH)
	msg, cs1, cs2, err := nc.handshakeState.WriteMessage(nil, nil)
	if err != nil {
		return oops.
			Code("WRITE_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to create second KX handshake message")
	}

	if _, err := nc.underlying.Write(msg); err != nil {
		return oops.
			Code("SEND_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to send second KX handshake message")
	}

	nc.updateCipherStates(cs1, cs2)

	// Message 3: → s, se (receive static and final DH)
	n, err = nc.underlying.Read(buffer)
	if err != nil {
		return oops.
			Code("READ_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to read third KX handshake message")
	}

	_, cs1, cs2, err = nc.handshakeState.ReadMessage(nil, buffer[:n])
	if err != nil {
		return oops.
			Code("PROCESS_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to process third KX handshake message")
	}

	nc.updateCipherStates(cs1, cs2)
	return nil
}

// parseHandshakePattern maps pattern name strings to go-i2p/noise HandshakePattern types.
// This enables configurable pattern selection from string-based configuration.
func parseHandshakePattern(patternName string) (noise.HandshakePattern, error) {
	switch patternName {
	case "Noise_NN_25519_AESGCM_SHA256", "NN":
		return noise.HandshakeNN, nil
	case "Noise_NK_25519_AESGCM_SHA256", "NK":
		return noise.HandshakeNK, nil
	case "Noise_NX_25519_AESGCM_SHA256", "NX":
		return noise.HandshakeNX, nil
	case "Noise_XN_25519_AESGCM_SHA256", "XN":
		return noise.HandshakeXN, nil
	case "Noise_XK_25519_AESGCM_SHA256", "XK":
		return noise.HandshakeXK, nil
	case "Noise_XX_25519_AESGCM_SHA256", "XX":
		return noise.HandshakeXX, nil
	case "Noise_KN_25519_AESGCM_SHA256", "KN":
		return noise.HandshakeKN, nil
	case "Noise_KK_25519_AESGCM_SHA256", "KK":
		return noise.HandshakeKK, nil
	case "Noise_KX_25519_AESGCM_SHA256", "KX":
		return noise.HandshakeKX, nil
	case "Noise_IN_25519_AESGCM_SHA256", "IN":
		return noise.HandshakeIN, nil
	case "Noise_IK_25519_AESGCM_SHA256", "IK":
		return noise.HandshakeIK, nil
	case "Noise_IX_25519_AESGCM_SHA256", "IX":
		return noise.HandshakeIX, nil
	case "Noise_N_25519_AESGCM_SHA256", "N":
		return noise.HandshakeN, nil
	case "Noise_K_25519_AESGCM_SHA256", "K":
		return noise.HandshakeK, nil
	case "Noise_X_25519_AESGCM_SHA256", "X":
		return noise.HandshakeX, nil
	default:
		return noise.HandshakePattern{}, oops.
			Code("UNSUPPORTED_PATTERN").
			In("noise").
			With("pattern", patternName).
			Errorf("unsupported handshake pattern: %s", patternName)
	}
}

// validateReadState validates the connection state before reading.
func (nc *NoiseConn) validateReadState() error {
	if nc.isClosed() {
		return oops.
			Code("CONN_CLOSED").
			In("noise").
			With("state", nc.getState().String()).
			Errorf("connection is closed")
	}

	if !nc.isHandshakeDone() {
		return oops.
			Code("HANDSHAKE_NOT_DONE").
			In("noise").
			With("state", nc.getState().String()).
			Errorf("handshake not completed")
	}

	if nc.cipherState == nil {
		return oops.
			Code("NO_CIPHER_STATE").
			In("noise").
			With("state", nc.getState().String()).
			Errorf("cipher state not initialized")
	}

	return nil
}

// configureReadTimeout sets the read timeout if configured.
func (nc *NoiseConn) configureReadTimeout() error {
	if nc.config.ReadTimeout > 0 {
		if err := nc.underlying.SetReadDeadline(time.Now().Add(nc.config.ReadTimeout)); err != nil {
			return oops.
				Code("SET_DEADLINE_FAILED").
				In("noise").
				With("timeout", nc.config.ReadTimeout).
				Wrapf(err, "failed to set read deadline")
		}
	}
	return nil
}

// readEncryptedData reads encrypted data from the underlying connection.
func (nc *NoiseConn) readEncryptedData(b []byte) ([]byte, int, error) {
	encrypted := make([]byte, len(b)+16) // Additional space for auth tag
	n, err := nc.underlying.Read(encrypted)
	if err != nil {
		return nil, 0, oops.
			Code("UNDERLYING_READ_FAILED").
			In("noise").
			With("local_addr", nc.LocalAddr().String()).
			With("remote_addr", nc.RemoteAddr().String()).
			Wrapf(err, "underlying connection read failed")
	}
	return encrypted, n, nil
}

// decryptData decrypts the provided encrypted data.
func (nc *NoiseConn) decryptData(encrypted []byte, encryptedLen int) ([]byte, error) {
	decrypted, err := nc.cipherState.Decrypt(nil, nil, encrypted)
	if err != nil {
		return nil, oops.
			Code("DECRYPT_FAILED").
			In("noise").
			With("encrypted_len", encryptedLen).
			Wrapf(err, "failed to decrypt received data")
	}
	return decrypted, nil
}

// copyDecryptedData copies decrypted data to the user buffer and logs the operation.
func (nc *NoiseConn) copyDecryptedData(b, decrypted []byte, encryptedLen, decryptedLen int) (int, error) {
	copied := copy(b, decrypted)

	// Track metrics for read data
	nc.metrics.AddBytesRead(int64(copied))

	nc.logger.Trace("Data read", i2plogger.Fields{
		"encrypted_len": encryptedLen,
		"decrypted_len": decryptedLen,
		"copied_len":    copied,
	})

	return copied, nil
}

// validateNewConnParams validates the parameters for creating a new NoiseConn.
func validateNewConnParams(underlying net.Conn, config *ConnConfig) error {
	if underlying == nil {
		return oops.
			Code("INVALID_CONN").
			In("noise").
			Errorf("underlying connection cannot be nil")
	}

	if config == nil {
		return oops.
			Code("INVALID_CONFIG").
			In("noise").
			Errorf("config cannot be nil")
	}

	if err := config.Validate(); err != nil {
		return oops.
			Code("INVALID_CONFIG").
			In("noise").
			Wrapf(err, "config validation failed")
	}

	return nil
}

// createHandshakeState creates and initializes the Noise handshake state.
func createHandshakeState(config *ConnConfig) (*noise.HandshakeState, error) {
	cs := noise.NewCipherSuite(noise.DH25519, noise.CipherAESGCM, noise.HashSHA256)

	pattern, err := parseHandshakePattern(config.Pattern)
	if err != nil {
		return nil, oops.
			Code("INVALID_PATTERN").
			In("noise").
			With("pattern", config.Pattern).
			Wrapf(err, "invalid handshake pattern")
	}

	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite: cs,
		Random:      nil, // Use crypto/rand
		Pattern:     pattern,
		Initiator:   config.Initiator,
		StaticKeypair: noise.DHKey{
			Private: config.StaticKey,
			Public:  nil, // Will be computed
		},
	})
	if err != nil {
		return nil, oops.
			Code("HANDSHAKE_INIT_FAILED").
			In("noise").
			With("pattern", config.Pattern).
			With("initiator", config.Initiator).
			Wrapf(err, "failed to create handshake state")
	}

	return hs, nil
}

// createNoiseAddresses creates local and remote Noise addresses.
func createNoiseAddresses(underlying net.Conn, config *ConnConfig) (*NoiseAddr, *NoiseAddr) {
	role := "responder"
	if config.Initiator {
		role = "initiator"
	}

	localAddr := NewNoiseAddr(underlying.LocalAddr(), config.Pattern, role)

	remoteRole := "initiator"
	if config.Initiator {
		remoteRole = "responder"
	}
	remoteAddr := NewNoiseAddr(underlying.RemoteAddr(), config.Pattern, remoteRole)

	return localAddr, remoteAddr
}

// handshakeContext encapsulates context management for handshake operations.
type handshakeContext struct {
	ctx    context.Context
	cancel context.CancelFunc
}

// createHandshakeContext creates a context with timeout for handshake operations.
func (nc *NoiseConn) createHandshakeContext(ctx context.Context) *handshakeContext {
	handshakeCtx, cancel := context.WithTimeout(ctx, nc.config.HandshakeTimeout)
	return &handshakeContext{
		ctx:    handshakeCtx,
		cancel: cancel,
	}
}

// executeRoleBasedHandshake performs handshake based on initiator/responder role.
func (nc *NoiseConn) executeRoleBasedHandshake(ctx context.Context) error {
	if nc.config.Initiator {
		if err := nc.performInitiatorHandshake(ctx); err != nil {
			return oops.
				Code("INITIATOR_HANDSHAKE_FAILED").
				In("noise").
				Wrapf(err, "initiator handshake failed")
		}
	} else {
		if err := nc.performResponderHandshake(ctx); err != nil {
			return oops.
				Code("RESPONDER_HANDSHAKE_FAILED").
				In("noise").
				Wrapf(err, "responder handshake failed")
		}
	}
	return nil
}

// markHandshakeComplete sets the handshake completion state and logs success.
func (nc *NoiseConn) markHandshakeComplete() {
	nc.setState(internal.StateEstablished)
	nc.metrics.SetHandshakeEnd()
	nc.logger.Info("Noise handshake completed successfully")
}

// isClosed returns true if the connection is closed
func (nc *NoiseConn) isClosed() bool {
	return nc.getState() == internal.StateClosed
}

// isHandshakeDone returns true if the handshake is complete
// Only established connections have completed handshakes - closed connections should not pass this check
func (nc *NoiseConn) isHandshakeDone() bool {
	state := nc.getState()
	return state == internal.StateEstablished
}

// getState returns the current connection state in a thread-safe manner
func (nc *NoiseConn) getState() internal.ConnState {
	nc.stateMutex.RLock()
	defer nc.stateMutex.RUnlock()
	return nc.state
}

// setState sets the connection state in a thread-safe manner
func (nc *NoiseConn) setState(newState internal.ConnState) {
	nc.stateMutex.Lock()
	defer nc.stateMutex.Unlock()

	oldState := nc.state
	nc.state = newState

	nc.logger.WithFields(i2plogger.Fields{
		"old_state": oldState.String(),
		"new_state": newState.String(),
	}).Debug("Connection state changed")
}
