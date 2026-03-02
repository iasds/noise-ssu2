package noise

import (
	"context"
	"crypto/ecdh"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/go-i2p/go-noise/handshake"
	"github.com/go-i2p/go-noise/internal"
	"github.com/go-i2p/logger"
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
// can call Write simultaneously. State validation is atomic and encryption
// operations are protected by the underlying cipher state synchronization.
func (nc *NoiseConn) Write(b []byte) (int, error) {
	if err := nc.validateWriteState(); err != nil {
		return 0, err
	}

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

// applyOutboundModifier passes plaintext through the modifier chain for
// PhaseData (post-handshake data transport). Called by Write before encryption.
// Returns data unchanged if no modifier chain is configured.
func (nc *NoiseConn) applyOutboundModifier(data []byte) ([]byte, error) {
	chain := nc.config.GetModifierChain()
	if chain == nil {
		return data, nil
	}
	return chain.ModifyOutbound(handshake.PhaseData, data)
}

// applyInboundModifier passes decrypted plaintext through the modifier chain
// for PhaseData (post-handshake data transport). Called by Read after decryption.
// Returns data unchanged if no modifier chain is configured.
func (nc *NoiseConn) applyInboundModifier(data []byte) ([]byte, error) {
	chain := nc.config.GetModifierChain()
	if chain == nil {
		return data, nil
	}
	return chain.ModifyInbound(handshake.PhaseData, data)
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

	if nc.sendCipherState == nil {
		return oops.
			Code("NO_CIPHER_STATE").
			In("noise").
			Errorf("send cipher state not initialized")
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

// encryptData encrypts the provided data using the send cipher state.
func (nc *NoiseConn) encryptData(data []byte) ([]byte, error) {
	encrypted, err := nc.sendCipherState.Encrypt(nil, nil, data)
	if err != nil {
		return nil, oops.
			Code("ENCRYPT_FAILED").
			In("noise").
			With("plaintext_len", len(data)).
			Wrapf(err, "failed to encrypt data")
	}
	return encrypted, nil
}

// writeEncryptedData writes a length-prefixed encrypted frame to the
// underlying connection and handles the response. Per Noise spec §12.3,
// each message is preceded by a 2-byte big-endian length prefix.
func (nc *NoiseConn) writeEncryptedData(originalData, encryptedData []byte) (int, error) {
	if err := nc.writeFramedMessage(encryptedData); err != nil {
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
	}).Trace("encrypted data written to wire")

	return len(originalData), nil
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

// GetConnectionMetrics returns the current connection statistics
func (nc *NoiseConn) GetConnectionMetrics() (bytesRead, bytesWritten int64, handshakeDuration time.Duration) {
	return nc.metrics.GetStats()
}

// metricsForTest returns the underlying ConnectionMetrics for test access.
// This decouples tests from the internal field name, so only this accessor
// needs updating if the field is renamed or restructured.
func (nc *NoiseConn) metricsForTest() *internal.ConnectionMetrics {
	return nc.metrics
}

// GetConnectionState returns the current connection state
//
// Thread Safety: This method is safe for concurrent use. It uses a read lock
// on the state mutex, allowing multiple goroutines to read the state simultaneously
// while preventing inconsistent reads during state transitions.
func (nc *NoiseConn) GetConnectionState() ConnState {
	return nc.getState()
}

// PeerStatic returns the static public key provided by the remote peer
// during the Noise handshake. Returns nil if the handshake has not completed
// or if the handshake pattern does not transmit a static key.
//
// Thread Safety: This method is safe for concurrent use. The underlying
// HandshakeState.PeerStatic() is mutex-protected.
func (nc *NoiseConn) PeerStatic() []byte {
	if nc.handshakeState == nil {
		return nil
	}
	return nc.handshakeState.PeerStatic()
}

// ChannelBinding returns the handshake hash (h) from the completed Noise session.
// This is the hash of all handshake transcript data and can be used for:
//   - Channel binding (tying an application-layer credential to the Noise session)
//   - Deriving additional key material via HKDF (e.g., NTCP2's SipHash keys)
//
// Returns nil if the handshake has not been initiated.
//
// Thread Safety: This method is safe for concurrent use. The underlying
// HandshakeState.ChannelBinding() is mutex-protected.
func (nc *NoiseConn) ChannelBinding() []byte {
	if nc.handshakeState == nil {
		return nil
	}
	return nc.handshakeState.ChannelBinding()
}

// SendCipherState returns the send-direction CipherState for direct access
// by protocol layers (e.g., NTCP2 SipHash key derivation).
// Returns nil before the handshake produces cipher states.
func (nc *NoiseConn) SendCipherState() *noise.CipherState {
	return nc.sendCipherState
}

// RecvCipherState returns the receive-direction CipherState for direct access
// by protocol layers.
// Returns nil before the handshake produces cipher states.
func (nc *NoiseConn) RecvCipherState() *noise.CipherState {
	return nc.recvCipherState
}

// ZeroKeys securely zeroes the send and receive cipher state key material.
// This delegates to the upstream CipherState.ZeroKey() which overwrites the
// key bytes with zeros and marks the cipher states as invalid.
//
// After calling ZeroKeys, the connection can no longer encrypt or decrypt data.
// Any subsequent Read/Write calls will fail.
func (nc *NoiseConn) ZeroKeys() {
	if nc.sendCipherState != nil {
		nc.sendCipherState.ZeroKey()
	}
	if nc.recvCipherState != nil {
		nc.recvCipherState.ZeroKey()
	}
}

// AdditionalSymmetricKeys returns the Additional Symmetric Key (ASK) values
// derived during the handshake Split(), per Noise spec §10.3.
// Returns nil if no labels were configured or the handshake hasn't completed.
// The returned keys correspond 1:1 to the configured AdditionalSymmetricKeyLabels.
func (nc *NoiseConn) AdditionalSymmetricKeys() [][]byte {
	if nc.handshakeState == nil {
		return nil
	}
	return nc.handshakeState.AdditionalSymmetricKeys()
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
	if nc.sendCipherState == nil || nc.recvCipherState == nil {
		return oops.
			Code("REKEY_NO_CIPHER").
			In("noise").
			Errorf("cipher states not available for rekeying")
	}
	nc.sendCipherState.Rekey()
	nc.recvCipherState.Rekey()
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

	// Call post-handshake hook before marking established.
	// This allows protocol layers to derive additional key material
	// (e.g., SipHash keys from the handshake hash for NTCP2).
	if nc.config.PostHandshakeHook != nil {
		if err := nc.config.PostHandshakeHook(nc); err != nil {
			nc.setState(internal.StateInit)
			return oops.
				Code("POST_HANDSHAKE_HOOK_FAILED").
				In("noise").
				Wrapf(err, "post-handshake hook failed")
		}
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
	return nc.sendNoiseHandshakeMsg("one-way")
}

// performNNInitiator handles NN pattern as initiator
func (nc *NoiseConn) performNNInitiator(ctx context.Context) error {
	// Message 1: → e (send ephemeral)
	if err := nc.sendNoiseHandshakeMsg("first NN"); err != nil {
		return err
	}
	// Message 2: ← e, ee (receive ephemeral and compute shared secret)
	return nc.receiveNoiseHandshakeMsg("second NN")
}

// performXXInitiator handles XX pattern as initiator
func (nc *NoiseConn) performXXInitiator(ctx context.Context) error {
	// Message 1: → e
	if err := nc.sendNoiseHandshakeMsg("first XX"); err != nil {
		return err
	}
	// Message 2: ← e, ee, s, es (receive)
	if err := nc.receiveNoiseHandshakeMsg("second XX"); err != nil {
		return err
	}
	// Message 3: → s, se (send)
	return nc.sendNoiseHandshakeMsg("third XX")
}

// getPatternMessageCount returns the expected number of handshake messages for each pattern.
// Returns an error for unknown patterns instead of defaulting, preventing configuration errors.
func (nc *NoiseConn) getPatternMessageCount() (int, error) {
	pattern := nc.config.Pattern

	switch pattern {
	case "N", "K", "X":
		nc.logPatternDetected(pattern, 1, "one-way", "short")
		return 1, nil
	case "NN", "NK", "NX", "KN", "KK", "KX", "IN", "IK", "IX":
		nc.logPatternDetected(pattern, 2, "two-message-interactive", "short")
		return 2, nil
	case "XN", "XK", "XX":
		nc.logPatternDetected(pattern, 3, "three-message", "short")
		return 3, nil
	default:
		return nc.matchFullFormPattern(pattern)
	}
}

// matchFullFormPattern detects full-form Noise protocol pattern names (e.g.
// "Noise_XX_25519_AESGCM_SHA256") and returns the expected message count.
func (nc *NoiseConn) matchFullFormPattern(pattern string) (int, error) {
	oneWay := []string{"_N_", "_K_", "_X_"}
	twoMsg := []string{"_NN_", "_NK_", "_NX_", "_KN_", "_KK_", "_KX_", "_IN_", "_IK_", "_IX_"}
	threeMsg := []string{"_XN_", "_XK_", "_XX_"}

	if containsAny(pattern, oneWay) {
		nc.logPatternDetected(pattern, 1, "one-way", "full")
		return 1, nil
	}
	if containsAny(pattern, twoMsg) {
		nc.logPatternDetected(pattern, 2, "two-message-interactive", "full")
		return 2, nil
	}
	if containsAny(pattern, threeMsg) {
		nc.logPatternDetected(pattern, 3, "three-message", "full")
		return 3, nil
	}

	return 0, oops.
		Code("UNKNOWN_PATTERN").
		In("noise").
		With("pattern", pattern).
		Errorf("unknown handshake pattern: %s", pattern)
}

// logPatternDetected logs the detection of a handshake pattern with its expected message count.
func (nc *NoiseConn) logPatternDetected(pattern string, msgCount int, patternType, patternFormat string) {
	nc.logger.WithFields(i2plogger.Fields{
		"pattern":           pattern,
		"expected_messages": msgCount,
		"pattern_type":      patternType,
		"pattern_format":    patternFormat,
	}).Debug("detected handshake pattern")
}

// containsAny returns true if s contains any of the given substrings.
func containsAny(s string, substrings []string) bool {
	for _, sub := range substrings {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
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

	// Send length-prefixed message over underlying connection
	if err := nc.writeFramedMessage(msg); err != nil {
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
	// Read length-prefixed message from underlying connection
	buffer, err := nc.readFramedMessage()
	if err != nil {
		return oops.
			Code("READ_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to read handshake message")
	}

	// Process message using handshake state
	_, cs1, cs2, err := nc.handshakeState.ReadMessage(nil, buffer)
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

// sendNoiseHandshakeMsg writes a Noise handshake message to the underlying connection
// and updates cipher states. The label parameter identifies the message for error context.
func (nc *NoiseConn) sendNoiseHandshakeMsg(label string) error {
	msg, cs1, cs2, err := nc.handshakeState.WriteMessage(nil, nil)
	if err != nil {
		return oops.
			Code("WRITE_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to create %s handshake message", label)
	}

	if err := nc.writeFramedMessage(msg); err != nil {
		return oops.
			Code("SEND_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to send %s handshake message", label)
	}

	nc.updateCipherStates(cs1, cs2)
	return nil
}

// receiveNoiseHandshakeMsg reads a length-prefixed Noise handshake message from
// the underlying connection, processes it via the handshake state, and updates
// cipher states. The label parameter identifies the message for error context.
func (nc *NoiseConn) receiveNoiseHandshakeMsg(label string) error {
	buffer, err := nc.readFramedMessage()
	if err != nil {
		return oops.
			Code("READ_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to read %s handshake message", label)
	}

	_, cs1, cs2, err := nc.handshakeState.ReadMessage(nil, buffer)
	if err != nil {
		return oops.
			Code("PROCESS_MESSAGE_FAILED").
			In("noise").
			Wrapf(err, "failed to process %s handshake message", label)
	}

	nc.updateCipherStates(cs1, cs2)
	return nil
}

// updateCipherStates updates the cipher states when they become available.
// Per the Noise spec, Split() returns (cs1, cs2) where:
//   - Initiator uses cs1 for sending and cs2 for receiving
//   - Responder uses cs1 for receiving and cs2 for sending
//
// Both cipher states must be non-nil for the handshake to be considered complete.
// During intermediate handshake messages, one or both may still be nil.
func (nc *NoiseConn) updateCipherStates(cs1, cs2 *noise.CipherState) {
	if cs1 == nil && cs2 == nil {
		return
	}

	if nc.config.Initiator {
		// Initiator: cs1 = send, cs2 = receive
		if cs1 != nil {
			nc.sendCipherState = cs1
		}
		if cs2 != nil {
			nc.recvCipherState = cs2
		}
	} else {
		// Responder: cs1 = receive, cs2 = send
		if cs1 != nil {
			nc.recvCipherState = cs1
		}
		if cs2 != nil {
			nc.sendCipherState = cs2
		}
	}

	nc.logger.WithFields(i2plogger.Fields{
		"pattern":         nc.config.Pattern,
		"role":            map[bool]string{true: "initiator", false: "responder"}[nc.config.Initiator],
		"has_send_cs":     nc.sendCipherState != nil,
		"has_recv_cs":     nc.recvCipherState != nil,
		"handshake_ready": nc.sendCipherState != nil && nc.recvCipherState != nil,
	}).Debug("cipher states updated during handshake")
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
	return nc.receiveNoiseHandshakeMsg("OneWay")
}

// performNNResponder handles NN pattern as responder
func (nc *NoiseConn) performNNResponder(ctx context.Context) error {
	// Message 1: → e (receive ephemeral)
	if err := nc.receiveNoiseHandshakeMsg("first NN"); err != nil {
		return err
	}
	// Message 2: ← e, ee (send ephemeral and compute shared secret)
	return nc.sendNoiseHandshakeMsg("second NN")
}

// performXXResponder handles XX pattern as responder
func (nc *NoiseConn) performXXResponder(ctx context.Context) error {
	// Message 1: → e (receive)
	if err := nc.receiveNoiseHandshakeMsg("first XX"); err != nil {
		return err
	}
	// Message 2: ← e, ee, s, es (send)
	if err := nc.sendNoiseHandshakeMsg("second XX"); err != nil {
		return err
	}
	// Message 3: → s, se (receive)
	return nc.receiveNoiseHandshakeMsg("third XX")
}

// ============================================================================
// ONE-WAY PATTERNS (1 message)
// ============================================================================

// performNInitiator handles N pattern as initiator: → e, es
func (nc *NoiseConn) performNInitiator(ctx context.Context) error {
	return nc.sendNoiseHandshakeMsg("N")
}

// performKInitiator handles K pattern as initiator: → e, es, ss
func (nc *NoiseConn) performKInitiator(ctx context.Context) error {
	return nc.sendNoiseHandshakeMsg("K")
}

// performXInitiator handles X pattern as initiator: → e, es, s, ss
func (nc *NoiseConn) performXInitiator(ctx context.Context) error {
	return nc.sendNoiseHandshakeMsg("X")
}

// ============================================================================
// TWO-MESSAGE INTERACTIVE PATTERNS
// ============================================================================

// performNKInitiator handles NK pattern as initiator: → e, es, ← e, ee
func (nc *NoiseConn) performNKInitiator(ctx context.Context) error {
	// Message 1: → e, es (send ephemeral, encrypt with responder's static)
	if err := nc.sendNoiseHandshakeMsg("first NK"); err != nil {
		return err
	}
	// Message 2: ← e, ee (receive ephemeral and compute DH)
	return nc.receiveNoiseHandshakeMsg("second NK")
}

// performNXInitiator handles NX pattern as initiator: → e, ← e, ee, s, es
func (nc *NoiseConn) performNXInitiator(ctx context.Context) error {
	// Message 1: → e (send ephemeral)
	if err := nc.sendNoiseHandshakeMsg("first NX"); err != nil {
		return err
	}
	// Message 2: ← e, ee, s, es (receive ephemeral and static, compute DH)
	return nc.receiveNoiseHandshakeMsg("second NX")
}

// performXNInitiator handles XN pattern as initiator (3 messages):
//
//	→ e
//	← e, ee
//	→ s, se
func (nc *NoiseConn) performXNInitiator(ctx context.Context) error {
	// Message 1: → e (send ephemeral)
	if err := nc.sendNoiseHandshakeMsg("first XN"); err != nil {
		return err
	}
	// Message 2: ← e, ee (receive responder ephemeral, DH ee)
	if err := nc.receiveNoiseHandshakeMsg("second XN"); err != nil {
		return err
	}
	// Message 3: → s, se (send encrypted static, DH se — final message)
	return nc.sendNoiseHandshakeMsg("third XN")
}

// performXKInitiator handles XK pattern as initiator (3 messages):
//
//	pre-message: ← s
//	→ e, es
//	← e, ee
//	→ s, se
func (nc *NoiseConn) performXKInitiator(ctx context.Context) error {
	// Message 1: → e, es (send ephemeral, DH with responder's static)
	if err := nc.sendNoiseHandshakeMsg("first XK"); err != nil {
		return err
	}
	// Message 2: ← e, ee (receive responder ephemeral, DH ee)
	if err := nc.receiveNoiseHandshakeMsg("second XK"); err != nil {
		return err
	}
	// Message 3: → s, se (send encrypted static, DH se — final message)
	return nc.sendNoiseHandshakeMsg("third XK")
}

// performKNInitiator handles KN pattern as initiator: → e, ← e, ee, se, es
func (nc *NoiseConn) performKNInitiator(ctx context.Context) error {
	// Message 1: → e (send ephemeral)
	if err := nc.sendNoiseHandshakeMsg("first KN"); err != nil {
		return err
	}
	// Message 2: ← e, ee, se, es (receive ephemeral and static, compute DH)
	return nc.receiveNoiseHandshakeMsg("second KN")
}

// performKKInitiator handles KK pattern as initiator: → e, es, ss, ← e, ee, se
func (nc *NoiseConn) performKKInitiator(ctx context.Context) error {
	// Message 1: → e, es, ss (send ephemeral, encrypt with responder's static and our static)
	if err := nc.sendNoiseHandshakeMsg("first KK"); err != nil {
		return err
	}
	// Message 2: ← e, ee, se (receive ephemeral, compute DH)
	return nc.receiveNoiseHandshakeMsg("second KK")
}

// performINInitiator handles IN pattern as initiator: → e, s, ← e, ee, se, es
func (nc *NoiseConn) performINInitiator(ctx context.Context) error {
	// Message 1: → e, s (send ephemeral and static)
	if err := nc.sendNoiseHandshakeMsg("first IN"); err != nil {
		return err
	}
	// Message 2: ← e, ee, se, es (receive ephemeral and static, compute DH)
	return nc.receiveNoiseHandshakeMsg("second IN")
}

// performIKInitiator handles IK pattern as initiator: → e, es, s, ss, ← e, ee, se
func (nc *NoiseConn) performIKInitiator(ctx context.Context) error {
	// Message 1: → e, es, s, ss (send ephemeral and static, encrypt with responder's static)
	if err := nc.sendNoiseHandshakeMsg("first IK"); err != nil {
		return err
	}
	// Message 2: ← e, ee, se (receive ephemeral, compute DH)
	return nc.receiveNoiseHandshakeMsg("second IK")
}

// performIXInitiator handles IX pattern as initiator: → e, s, ← e, ee, se, s, es
func (nc *NoiseConn) performIXInitiator(ctx context.Context) error {
	// Message 1: → e, s (send ephemeral and static)
	if err := nc.sendNoiseHandshakeMsg("first IX"); err != nil {
		return err
	}
	// Message 2: ← e, ee, se, s, es (receive ephemeral and static, compute DH)
	return nc.receiveNoiseHandshakeMsg("second IX")
}

// ============================================================================
// THREE-MESSAGE PATTERNS
// ============================================================================

// performKXInitiator handles KX pattern as initiator (2 messages):
//
//	pre-message: → s
//	→ e
//	← e, ee, se, s, es
func (nc *NoiseConn) performKXInitiator(ctx context.Context) error {
	// Message 1: → e (send ephemeral)
	if err := nc.sendNoiseHandshakeMsg("first KX"); err != nil {
		return err
	}
	// Message 2: ← e, ee, se, s, es (receive responder ephemeral + static, compute DH — final message)
	return nc.receiveNoiseHandshakeMsg("second KX")
}

// ============================================================================
// ONE-WAY PATTERN RESPONDERS
// ============================================================================

// performNResponder handles N pattern as responder: → e, es
func (nc *NoiseConn) performNResponder(ctx context.Context) error {
	return nc.receiveNoiseHandshakeMsg("N")
}

// performKResponder handles K pattern as responder: → e, es, ss
func (nc *NoiseConn) performKResponder(ctx context.Context) error {
	return nc.receiveNoiseHandshakeMsg("K")
}

// performXResponder handles X pattern as responder: → e, es, s, ss
func (nc *NoiseConn) performXResponder(ctx context.Context) error {
	return nc.receiveNoiseHandshakeMsg("X")
}

// ============================================================================
// TWO-MESSAGE INTERACTIVE PATTERN RESPONDERS
// ============================================================================

// performNKResponder handles NK pattern as responder: → e, es, ← e, ee
func (nc *NoiseConn) performNKResponder(ctx context.Context) error {
	// Message 1: → e, es (receive ephemeral encrypted with our static)
	if err := nc.receiveNoiseHandshakeMsg("first NK"); err != nil {
		return err
	}
	// Message 2: ← e, ee (send ephemeral and compute DH)
	return nc.sendNoiseHandshakeMsg("second NK")
}

// performNXResponder handles NX pattern as responder: → e, ← e, ee, s, es
func (nc *NoiseConn) performNXResponder(ctx context.Context) error {
	// Message 1: → e (receive ephemeral)
	if err := nc.receiveNoiseHandshakeMsg("first NX"); err != nil {
		return err
	}
	// Message 2: ← e, ee, s, es (send ephemeral and static, compute DH)
	return nc.sendNoiseHandshakeMsg("second NX")
}

// performXNResponder handles XN pattern as responder (3 messages):
//
//	→ e
//	← e, ee
//	→ s, se
func (nc *NoiseConn) performXNResponder(ctx context.Context) error {
	// Message 1: → e (receive initiator ephemeral)
	if err := nc.receiveNoiseHandshakeMsg("first XN"); err != nil {
		return err
	}
	// Message 2: ← e, ee (send our ephemeral, DH ee)
	if err := nc.sendNoiseHandshakeMsg("second XN"); err != nil {
		return err
	}
	// Message 3: → s, se (receive initiator's encrypted static, DH se — final message)
	return nc.receiveNoiseHandshakeMsg("third XN")
}

// performXKResponder handles XK pattern as responder (3 messages):
//
//	pre-message: ← s
//	→ e, es
//	← e, ee
//	→ s, se
func (nc *NoiseConn) performXKResponder(ctx context.Context) error {
	// Message 1: → e, es (receive initiator ephemeral, DH es with our static)
	if err := nc.receiveNoiseHandshakeMsg("first XK"); err != nil {
		return err
	}
	// Message 2: ← e, ee (send our ephemeral, DH ee)
	if err := nc.sendNoiseHandshakeMsg("second XK"); err != nil {
		return err
	}
	// Message 3: → s, se (receive initiator's encrypted static, DH se — final message)
	return nc.receiveNoiseHandshakeMsg("third XK")
}

// performKNResponder handles KN pattern as responder: → e, ← e, ee, se, es
func (nc *NoiseConn) performKNResponder(ctx context.Context) error {
	// Message 1: → e (receive ephemeral)
	if err := nc.receiveNoiseHandshakeMsg("first KN"); err != nil {
		return err
	}
	// Message 2: ← e, ee, se, es (send ephemeral and static, compute DH)
	return nc.sendNoiseHandshakeMsg("second KN")
}

// performKKResponder handles KK pattern as responder: → e, es, ss, ← e, ee, se
func (nc *NoiseConn) performKKResponder(ctx context.Context) error {
	// Message 1: → e, es, ss (receive ephemeral encrypted with both static keys)
	if err := nc.receiveNoiseHandshakeMsg("first KK"); err != nil {
		return err
	}
	// Message 2: ← e, ee, se (send ephemeral, compute DH)
	return nc.sendNoiseHandshakeMsg("second KK")
}

// performINResponder handles IN pattern as responder: → e, s, ← e, ee, se, es
func (nc *NoiseConn) performINResponder(ctx context.Context) error {
	// Message 1: → e, s (receive ephemeral and static)
	if err := nc.receiveNoiseHandshakeMsg("first IN"); err != nil {
		return err
	}
	// Message 2: ← e, ee, se, es (send ephemeral and static, compute DH)
	return nc.sendNoiseHandshakeMsg("second IN")
}

// performIKResponder handles IK pattern as responder: → e, es, s, ss, ← e, ee, se
func (nc *NoiseConn) performIKResponder(ctx context.Context) error {
	// Message 1: → e, es, s, ss (receive ephemeral and static encrypted with our static)
	if err := nc.receiveNoiseHandshakeMsg("first IK"); err != nil {
		return err
	}
	// Message 2: ← e, ee, se (send ephemeral, compute DH)
	return nc.sendNoiseHandshakeMsg("second IK")
}

// performIXResponder handles IX pattern as responder: → e, s, ← e, ee, se, s, es
func (nc *NoiseConn) performIXResponder(ctx context.Context) error {
	// Message 1: → e, s (receive ephemeral and static)
	if err := nc.receiveNoiseHandshakeMsg("first IX"); err != nil {
		return err
	}
	// Message 2: ← e, ee, se, s, es (send ephemeral and static, compute DH)
	return nc.sendNoiseHandshakeMsg("second IX")
}

// ============================================================================
// THREE-MESSAGE PATTERN RESPONDERS
// ============================================================================

// performKXResponder handles KX pattern as responder (2 messages):
//
//	pre-message: → s
//	→ e
//	← e, ee, se, s, es
func (nc *NoiseConn) performKXResponder(ctx context.Context) error {
	// Message 1: → e (receive initiator ephemeral)
	if err := nc.receiveNoiseHandshakeMsg("first KX"); err != nil {
		return err
	}
	// Message 2: ← e, ee, se, s, es (send our ephemeral + static, compute DH — final message)
	return nc.sendNoiseHandshakeMsg("second KX")
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

	if nc.recvCipherState == nil {
		return oops.
			Code("NO_CIPHER_STATE").
			In("noise").
			With("state", nc.getState().String()).
			Errorf("receive cipher state not initialized")
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

// readEncryptedData reads a length-prefixed encrypted frame from the
// underlying connection. Per the Noise spec §12.3, each message is preceded
// by a 2-byte big-endian length field. This method reads the length, then
// reads exactly that many bytes of ciphertext before returning.
func (nc *NoiseConn) readEncryptedData(b []byte) ([]byte, int, error) {
	encrypted, err := nc.readFramedMessage()
	if err != nil {
		return nil, 0, err
	}
	return encrypted, len(encrypted), nil
}

// writeFramedMessage writes a 2-byte big-endian length prefix followed by
// the message data to the underlying connection. Per Noise spec §12.3:
// "Applications should add a length field for each Noise message."
func (nc *NoiseConn) writeFramedMessage(data []byte) error {
	if len(data) > maxNoiseMessageSize {
		return oops.
			Code("MESSAGE_TOO_LARGE").
			In("noise").
			With("message_len", len(data)).
			With("max_len", maxNoiseMessageSize).
			Errorf("message exceeds maximum Noise message size")
	}
	var header [2]byte
	binary.BigEndian.PutUint16(header[:], uint16(len(data)))
	if _, err := nc.underlying.Write(header[:]); err != nil {
		return oops.
			Code("WRITE_LENGTH_FAILED").
			In("noise").
			Wrapf(err, "failed to write message length prefix")
	}
	if _, err := nc.underlying.Write(data); err != nil {
		return oops.
			Code("WRITE_PAYLOAD_FAILED").
			In("noise").
			Wrapf(err, "failed to write message payload")
	}
	return nil
}

// readFramedMessage reads a 2-byte big-endian length prefix from the
// underlying connection, then reads exactly that many bytes. This ensures
// complete Noise messages are received before decryption, preventing
// AES-GCM authentication failures from partial TCP reads.
func (nc *NoiseConn) readFramedMessage() ([]byte, error) {
	var header [2]byte
	if _, err := io.ReadFull(nc.underlying, header[:]); err != nil {
		return nil, oops.
			Code("READ_LENGTH_FAILED").
			In("noise").
			With("local_addr", nc.LocalAddr().String()).
			With("remote_addr", nc.RemoteAddr().String()).
			Wrapf(err, "failed to read message length prefix")
	}
	msgLen := binary.BigEndian.Uint16(header[:])
	if msgLen == 0 {
		return nil, oops.
			Code("EMPTY_MESSAGE").
			In("noise").
			Errorf("received zero-length message")
	}
	buf := make([]byte, msgLen)
	if _, err := io.ReadFull(nc.underlying, buf); err != nil {
		return nil, oops.
			Code("UNDERLYING_READ_FAILED").
			In("noise").
			With("local_addr", nc.LocalAddr().String()).
			With("remote_addr", nc.RemoteAddr().String()).
			With("expected_len", msgLen).
			Wrapf(err, "failed to read complete message")
	}
	return buf, nil
}

// decryptData decrypts the provided encrypted data.
func (nc *NoiseConn) decryptData(encrypted []byte, encryptedLen int) ([]byte, error) {
	decrypted, err := nc.recvCipherState.Decrypt(nil, nil, encrypted)
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
	cs := config.CipherSuite
	if cs == nil {
		cs = noise.NewCipherSuite(noise.DH25519, noise.CipherAESGCM, noise.HashSHA256)
	}

	pattern, err := parseHandshakePattern(config.Pattern)
	if err != nil {
		return nil, oops.
			Code("INVALID_PATTERN").
			In("noise").
			With("pattern", config.Pattern).
			Wrapf(err, "invalid handshake pattern")
	}

	// Derive the public key from the private key so the upstream library
	// can use it in pre-messages and static key transmission patterns.
	// The StaticKeypair requires both Private and Public to be set;
	// the upstream library does NOT compute the public key automatically.
	var staticKeypair noise.DHKey
	if len(config.StaticKey) > 0 {
		privKey, err := ecdh.X25519().NewPrivateKey(config.StaticKey)
		if err != nil {
			return nil, oops.
				Code("INVALID_STATIC_KEY").
				In("noise").
				Wrapf(err, "failed to derive public key from static private key")
		}
		staticKeypair = noise.DHKey{
			Private: config.StaticKey,
			Public:  privKey.PublicKey().Bytes(),
		}
	}

	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:                  cs,
		Random:                       nil, // Use crypto/rand
		Pattern:                      pattern,
		Initiator:                    config.Initiator,
		ProtocolName:                 config.ProtocolName,
		AdditionalSymmetricKeyLabels: config.AdditionalSymmetricKeyLabels,
		StaticKeypair:                staticKeypair,
		PeerStatic:                   config.RemoteKey,
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
// It translates the context deadline into a socket-level deadline so that
// underlying Read/Write calls (which do not observe context) are bounded.
func (nc *NoiseConn) executeRoleBasedHandshake(ctx context.Context) error {
	// Enforce context deadline on the underlying socket so that blocking
	// Read/Write calls respect the handshake timeout.
	if deadline, ok := ctx.Deadline(); ok {
		if err := nc.underlying.SetDeadline(deadline); err != nil {
			return oops.
				Code("SET_DEADLINE_FAILED").
				In("noise").
				Wrapf(err, "failed to set handshake deadline on underlying connection")
		}
		// Clear the deadline once the handshake finishes (or fails) so
		// subsequent data-phase I/O is not accidentally time-limited.
		defer func() {
			_ = nc.underlying.SetDeadline(time.Time{})
		}()
	}

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
