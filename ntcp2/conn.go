package ntcp2

import (
	"encoding/binary"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-i2p/crypto/rand"

	noise "github.com/go-i2p/go-noise"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// NTCP2Conn implements net.Conn for NTCP2 transport connections.
// It wraps a NoiseConn with NTCP2-specific addressing and protocol handling.
//
// This package implements the Noise XK handshake with NTCP2 extensions
// (AES ephemeral key obfuscation, SipHash frame length obfuscation, and
// cleartext padding). It provides framed I/O (SipHash-obfuscated length
// prefix + ChaChaPoly AEAD) and probing resistance on AEAD failures.
//
// Higher-level concerns — I2NP message parsing, block framing (types 0–9),
// termination blocks, options negotiation, timestamp validation, replay
// caches, and version detection — belong in the router transport layer
// (github.com/go-i2p/go-i2p/lib/transport/ntcp).
type NTCP2Conn struct {
	// noiseConn is the underlying encrypted connection
	noiseConn *noise.NoiseConn

	// localAddr is the NTCP2-specific local address
	localAddr *NTCP2Addr

	// remoteAddr is the NTCP2-specific remote address
	remoteAddr *NTCP2Addr

	// lengthObfuscator applies SipHash-2-4 frame length obfuscation
	// in the data phase. When non-nil, Read/Write use framed I/O:
	//   Write: [2-byte SipHash-obfuscated length][ChaChaPoly ciphertext]
	//   Read:  deobfuscate 2-byte length, read exact frame, decrypt
	// When nil, Read/Write delegate directly to NoiseConn (no framing).
	// Access is via atomic.Pointer to avoid data races between
	// SetLengthObfuscator (PostHandshakeHook) and Read/Write.
	lengthObfuscator atomic.Pointer[SipHashLengthModifier]

	// readBuffer holds surplus plaintext from readFramed when the
	// decrypted frame is larger than the caller's Read buffer.
	readBuffer []byte

	// readMu serialises readFramed calls so that SipHash inbound mask
	// generation and the subsequent TCP read are atomic with respect to
	// each other. This mirrors writeMu for the write path.
	readMu sync.Mutex

	// writeMu serialises writeFramed calls so that SipHash mask generation
	// and the subsequent TCP write are atomic with respect to each other.
	writeMu sync.Mutex

	// ntcp2Config is the per-connection NTCP2Config used to create this conn.
	// Retained so that after Handshake() fires the PostHandshakeHook (which
	// stores derived SipHash keys on the config), the caller can call
	// PropagateSipHash() to copy them to lengthObfuscator.
	// Access is via atomic.Pointer for thread safety.
	ntcp2Config atomic.Pointer[NTCP2Config]

	// closeOnce ensures Close is idempotent and key material is zeroed exactly once.
	closeOnce sync.Once

	// broken is set when a framing I/O error occurs after the SipHash mask has
	// been consumed. Once set, the connection's SipHash state is irrecoverably
	// desynchronized and all future Read/Write calls will fail immediately.
	broken atomic.Bool

	// writeNonce tracks the number of frames written (data-phase encrypt operations).
	// The connection MUST be terminated before this reaches MaxNonce (2^64-2).
	// Only accessed under writeMu.
	writeNonce uint64

	// readNonce tracks the number of frames read (data-phase decrypt operations).
	// The connection MUST be terminated before this reaches MaxNonce (2^64-2).
	// Only accessed under readMu.
	readNonce uint64

	// logger for connection events (pointer so runtime log-level changes are visible)
	logger *logger.Logger
}

// NewNTCP2Conn creates a new NTCP2Conn wrapping the provided NoiseConn.
// The NoiseConn must already be configured with appropriate NTCP2 modifiers.
func NewNTCP2Conn(noiseConn *noise.NoiseConn, localAddr, remoteAddr *NTCP2Addr) (*NTCP2Conn, error) {
	if noiseConn == nil {
		return nil, oops.
			Code("INVALID_NOISE_CONN").
			In("ntcp2").
			Errorf("noise connection cannot be nil")
	}

	if localAddr == nil {
		return nil, oops.
			Code("INVALID_LOCAL_ADDR").
			In("ntcp2").
			Errorf("local address cannot be nil")
	}

	if remoteAddr == nil {
		return nil, oops.
			Code("INVALID_REMOTE_ADDR").
			In("ntcp2").
			Errorf("remote address cannot be nil")
	}
	conn := &NTCP2Conn{
		noiseConn:  noiseConn,
		localAddr:  localAddr,
		remoteAddr: remoteAddr,
		logger:     log,
	}

	conn.logger.Debug("NTCP2 connection created",
		"local_addr", localAddr.String(),
		"remote_addr", remoteAddr.String())

	return conn, nil
}

// SetLengthObfuscator sets the SipHash length obfuscator for data-phase framing.
// When set, Read/Write will use framed I/O with SipHash-obfuscated length prefixes.
// This is safe to call concurrently with Read/Write (uses atomic.Pointer).
func (nc *NTCP2Conn) SetLengthObfuscator(slm *SipHashLengthModifier) {
	nc.lengthObfuscator.Store(slm)
}

// SetNTCP2Config stores a reference to the originating NTCP2Config so that
// PropagateSipHash can copy PostHandshakeHook-derived keys after handshake.
// This is safe to call concurrently with PropagateSipHash (uses atomic.Pointer).
func (nc *NTCP2Conn) SetNTCP2Config(cfg *NTCP2Config) {
	nc.ntcp2Config.Store(cfg)
}

// PropagateSipHash copies the SipHash modifier from the stored NTCP2Config
// (populated by the PostHandshakeHook during Handshake) into this connection's
// lengthObfuscator. Call this immediately after a successful Handshake().
func (nc *NTCP2Conn) PropagateSipHash() {
	cfg := nc.ntcp2Config.Load()
	if cfg == nil {
		return
	}
	if slm := cfg.SipHashModifier(); slm != nil {
		nc.lengthObfuscator.Store(slm)
	}
}

// Read implements net.Conn.Read.
// When a length obfuscator is set, reads use NTCP2 framed I/O:
//  1. Return any buffered plaintext from a previous frame first
//  2. Read exactly 2 bytes from the underlying TCP connection
//  3. XOR with SipHash inbound mask to recover the frame length
//  4. Read exactly frameLength bytes of ciphertext from TCP
//  5. Decrypt the ciphertext via the Noise cipher state
//  6. Copy plaintext into the caller's buffer; buffer any remainder
//
// When no length obfuscator is set, delegates directly to NoiseConn.Read.
func (nc *NTCP2Conn) Read(b []byte) (int, error) {
	if nc.broken.Load() {
		return 0, oops.
			Code("CONNECTION_BROKEN").
			In("ntcp2").
			Errorf("connection is broken due to previous framing error (SipHash state desynchronized)")
	}
	if nc.lengthObfuscator.Load() == nil {
		return nc.readDirect(b)
	}
	nc.readMu.Lock()
	defer nc.readMu.Unlock()
	// Drain buffered plaintext from a previous oversized frame first.
	if len(nc.readBuffer) > 0 {
		n := copy(b, nc.readBuffer)
		nc.readBuffer = nc.readBuffer[n:]
		if len(nc.readBuffer) == 0 {
			// Zero accessible backing memory to limit plaintext lingering.
			// After the reslice above, nc.readBuffer has len==0 but cap>0.
			// Reslicing to [:cap] exposes the original backing array so we
			// can zero it before releasing the reference. This is a standard
			// Go idiom for wiping slice-backed memory without allocating.
			if c := cap(nc.readBuffer); c > 0 {
				tail := nc.readBuffer[:c]
				for i := range tail {
					tail[i] = 0
				}
			}
			nc.readBuffer = nil
		}
		return n, nil
	}
	return nc.readFramed(b)
}

// readDirect delegates directly to the underlying NoiseConn for unframed reads.
// Per the io.Reader contract, returns both the bytes read and any error.
// Errors from NoiseConn are returned directly without re-wrapping, since
// NoiseConn already wraps errors with appropriate context.
func (nc *NTCP2Conn) readDirect(b []byte) (int, error) {
	n, err := nc.noiseConn.Read(b)
	if n > 0 {
		nc.logger.Trace("NTCP2 data read (direct)",
			"bytes_read", n,
			"local_addr", nc.localAddr.String(),
			"remote_addr", nc.remoteAddr.String())
	}
	return n, err
}

// readFramed reads an NTCP2 data-phase frame with SipHash length deobfuscation.
func (nc *NTCP2Conn) readFramed(b []byte) (int, error) {
	if err := nc.guardReadNonce(); err != nil {
		return 0, err
	}

	slm := nc.lengthObfuscator.Load()
	underlying := nc.noiseConn.Underlying()

	frameLen, err := nc.readObfuscatedFrameLength(underlying, slm)
	if err != nil {
		return 0, err
	}

	plaintext, err := nc.readAndDecryptFrame(underlying, frameLen)
	if err != nil {
		return 0, err
	}

	n := nc.bufferPlaintext(b, plaintext)
	nc.readNonce++

	nc.logger.Trace("NTCP2 data read (framed)",
		"frame_length", frameLen,
		"plaintext_length", len(plaintext),
		"bytes_copied", n,
		"bytes_buffered", len(plaintext)-n,
		"local_addr", nc.localAddr.String(),
		"remote_addr", nc.remoteAddr.String())

	return n, nil
}

// guardReadNonce rejects read operations when the nonce counter has reached MaxNonce.
// Per the spec: "Connection must be dropped and restarted after it reaches that value."
func (nc *NTCP2Conn) guardReadNonce() error {
	if nc.readNonce >= MaxNonce {
		nc.broken.Store(true)
		return oops.
			Code("NONCE_EXHAUSTED").
			In("ntcp2").
			With("read_nonce", nc.readNonce).
			With("max_nonce", MaxNonce).
			Errorf("read nonce exhausted (reached %d), connection must be terminated", nc.readNonce)
	}
	return nil
}

// readObfuscatedFrameLength reads and deobfuscates the 2-byte SipHash frame length field.
// After this call the SipHash inbound state has advanced; any subsequent error means
// the connection is irrecoverably desynchronized.
func (nc *NTCP2Conn) readObfuscatedFrameLength(underlying net.Conn, slm *SipHashLengthModifier) (uint16, error) {
	lengthBuf := make([]byte, FrameLengthFieldSize)
	if _, err := io.ReadFull(underlying, lengthBuf); err != nil {
		return 0, oops.
			Code("READ_LENGTH_FAILED").
			In("ntcp2").
			With("local_addr", nc.localAddr.String()).
			With("remote_addr", nc.remoteAddr.String()).
			Wrapf(err, "failed to read frame length")
	}

	mask := slm.NextInboundMask()
	obfuscatedLen := binary.BigEndian.Uint16(lengthBuf)
	frameLen := obfuscatedLen ^ mask

	if err := nc.validateFrameLength(frameLen); err != nil {
		nc.broken.Store(true)
		return 0, err
	}
	return frameLen, nil
}

// readAndDecryptFrame reads exactly frameLen bytes of ciphertext from the underlying
// connection and decrypts them via the Noise cipher state. On AEAD failure, applies
// probing-resistance behaviour before returning the error.
func (nc *NTCP2Conn) readAndDecryptFrame(underlying net.Conn, frameLen uint16) ([]byte, error) {
	ciphertext := make([]byte, frameLen)
	if _, err := io.ReadFull(underlying, ciphertext); err != nil {
		nc.broken.Store(true)
		return nil, oops.
			Code("READ_FRAME_FAILED").
			In("ntcp2").
			With("frame_length", frameLen).
			With("local_addr", nc.localAddr.String()).
			With("remote_addr", nc.remoteAddr.String()).
			Wrapf(err, "failed to read frame data")
	}

	plaintext, err := nc.noiseConn.Decrypt(ciphertext)
	if err != nil {
		nc.broken.Store(true)
		nc.handleAEADError(underlying)
		return nil, oops.
			Code("DECRYPT_FAILED").
			In("ntcp2").
			With("frame_length", frameLen).
			With("local_addr", nc.localAddr.String()).
			With("remote_addr", nc.remoteAddr.String()).
			Wrapf(err, "failed to decrypt frame")
	}
	return plaintext, nil
}

// bufferPlaintext copies decrypted plaintext into the caller's buffer and stores
// any remainder in readBuffer for subsequent Read calls.
func (nc *NTCP2Conn) bufferPlaintext(b []byte, plaintext []byte) int {
	n := copy(b, plaintext)
	if n < len(plaintext) {
		nc.readBuffer = make([]byte, len(plaintext)-n)
		copy(nc.readBuffer, plaintext[n:])
	}
	return n
}

// validateFrameLength checks that the deobfuscated frame length is within the
// NTCP2 spec range of MinDataPhaseFrameSize–SpecMaxFrameSize (16–65535).
// Per the spec: "Take the same error action for an invalid length field value
// in the data phase" — i.e., the probing-resistance delay from handleAEADError
// is applied before returning the error.
func (nc *NTCP2Conn) validateFrameLength(frameLen uint16) error {
	if frameLen < MinDataPhaseFrameSize {
		nc.applyProbingResistanceDelay()
		return oops.
			Code("FRAME_TOO_SMALL").
			In("ntcp2").
			With("frame_length", frameLen).
			With("min_frame_size", MinDataPhaseFrameSize).
			With("local_addr", nc.localAddr.String()).
			With("remote_addr", nc.remoteAddr.String()).
			Errorf("frame length %d below minimum %d", frameLen, MinDataPhaseFrameSize)
	}

	if int(frameLen) > SpecMaxFrameSize {
		nc.applyProbingResistanceDelay()
		return oops.
			Code("FRAME_TOO_LARGE").
			In("ntcp2").
			With("frame_length", frameLen).
			With("max_frame_size", SpecMaxFrameSize).
			With("local_addr", nc.localAddr.String()).
			With("remote_addr", nc.remoteAddr.String()).
			Errorf("frame length %d exceeds maximum %d", frameLen, SpecMaxFrameSize)
	}

	return nil
}

// applyProbingResistanceDelay applies the same probing-resistance delay
// as handleAEADError, per the NTCP2 spec: "Take the same error action
// for an invalid length field value in the data phase."
func (nc *NTCP2Conn) applyProbingResistanceDelay() {
	if underlying := nc.noiseConn.Underlying(); underlying != nil {
		nc.handleAEADError(underlying)
	}
}

// handleAEADError implements probing-resistance behaviour on AEAD authentication
// failure. Per the NTCP2 spec, the receiver should:
//  1. Read a random number of junk bytes for a random duration.
//  2. Send a TCP RST (abnormal close) rather than a graceful FIN.
//  3. Mark the connection as broken.
//
// Termination blocks (reason code 4 = AEAD failure) are handled by the
// router transport layer (go-i2p/go-i2p/lib/transport/ntcp).
func (nc *NTCP2Conn) handleAEADError(underlying net.Conn) {
	nc.broken.Store(true)

	// Generate a random byte count (0–AEADErrorMaxJunkBytes) to read before returning.
	// Use crypto/rand with rejection sampling to avoid modulo bias.
	var rndBuf [2]byte
	if _, err := rand.Read(rndBuf[:]); err != nil {
		nc.sendTCPRST(underlying)
		return // best effort
	}
	junkLen := int(binary.BigEndian.Uint16(rndBuf[:]) & (AEADErrorMaxJunkBytes - 1))
	if junkLen > 0 {
		// Set a short deadline so we don't block forever if the peer stops sending.
		underlying.SetReadDeadline(time.Now().Add(AEADErrorTimeout)) //nolint:errcheck
		junk := make([]byte, junkLen)
		underlying.Read(junk) //nolint:errcheck // best effort
	}

	// Per the spec: "This should be an abnormal close (TCP RST)"
	nc.sendTCPRST(underlying)
}

// sendTCPRST sends a TCP RST by setting SO_LINGER to 0 (immediate close without
// FIN handshake) and then closing the connection. Per the NTCP2 spec, AEAD failures
// should result in an abnormal close. If the underlying connection is not a
// *net.TCPConn, falls back to a normal Close().
func (nc *NTCP2Conn) sendTCPRST(conn net.Conn) {
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetLinger(0) //nolint:errcheck
		tcpConn.Close()      //nolint:errcheck
	} else {
		conn.Close() //nolint:errcheck
	}
}

// Write implements net.Conn.Write.
// When a length obfuscator is set, writes use NTCP2 framed I/O:
//  1. Encrypt the plaintext via the Noise cipher state
//  2. Compute the ciphertext length as a uint16
//  3. XOR with SipHash outbound mask to obfuscate the length
//  4. Write [2-byte obfuscated length][ciphertext] to the underlying TCP connection
//
// When no length obfuscator is set, delegates directly to NoiseConn.Write.
// Large writes are transparently split into multiple frames of at most
// MaxFrameSize minus Poly1305Overhead bytes of plaintext each.
func (nc *NTCP2Conn) Write(b []byte) (int, error) {
	if nc.broken.Load() {
		return 0, oops.
			Code("CONNECTION_BROKEN").
			In("ntcp2").
			Errorf("connection is broken due to previous framing error (SipHash state desynchronized)")
	}
	if nc.lengthObfuscator.Load() == nil {
		return nc.writeDirect(b)
	}
	return nc.writeFramed(b)
}

// writeDirect delegates directly to the underlying NoiseConn for unframed writes.
// Errors from NoiseConn are returned directly without re-wrapping, since
// NoiseConn already wraps errors with appropriate context.
func (nc *NTCP2Conn) writeDirect(b []byte) (int, error) {
	n, err := nc.noiseConn.Write(b)
	if err != nil {
		return n, err
	}

	nc.logger.Trace("NTCP2 data written (direct)",
		"bytes_written", n,
		"local_addr", nc.localAddr.String(),
		"remote_addr", nc.remoteAddr.String())

	return n, nil
}

// writeFramed writes NTCP2 data-phase frame(s) with SipHash length obfuscation.
// Large payloads are transparently split into multiple frames of at most
// getMaxFrameSize() - Poly1305Overhead bytes of plaintext each.
// The frame size is determined by the NTCP2Config if set, otherwise
// falls back to the constant MaxFrameSize. Per the spec, senders should
// "limit frames to a few KB rather than maximizing the frame size."
func (nc *NTCP2Conn) writeFramed(b []byte) (int, error) {
	nc.writeMu.Lock()
	defer nc.writeMu.Unlock()

	maxPlaintext := nc.getMaxFrameSize() - Poly1305Overhead
	totalWritten := 0

	for len(b) > 0 {
		chunk := b
		if len(chunk) > maxPlaintext {
			chunk = b[:maxPlaintext]
		}
		b = b[len(chunk):]

		n, err := nc.writeSingleFrame(chunk)
		totalWritten += n
		if err != nil {
			return totalWritten, err
		}
	}

	return totalWritten, nil
}

// writeSingleFrame encrypts one chunk and writes it as an NTCP2 wire frame.
func (nc *NTCP2Conn) writeSingleFrame(b []byte) (int, error) {
	if err := nc.guardWriteNonce(); err != nil {
		return 0, err
	}

	encrypted, err := nc.encryptFrame(b)
	if err != nil {
		return 0, err
	}

	slm := nc.lengthObfuscator.Load()
	frame := nc.buildWireFrame(encrypted, slm)

	if err := nc.writeWireFrame(frame); err != nil {
		return 0, err
	}

	nc.writeNonce++

	nc.logger.Trace("NTCP2 data written (framed)",
		"plaintext_length", len(b),
		"encrypted_length", len(encrypted),
		"frame_length", len(frame),
		"local_addr", nc.localAddr.String(),
		"remote_addr", nc.remoteAddr.String())

	return len(b), nil
}

// guardWriteNonce rejects write operations when the nonce counter has reached MaxNonce.
// Per the spec: "Connection must be dropped and restarted after it reaches that value."
func (nc *NTCP2Conn) guardWriteNonce() error {
	if nc.writeNonce >= MaxNonce {
		nc.broken.Store(true)
		return oops.
			Code("NONCE_EXHAUSTED").
			In("ntcp2").
			With("write_nonce", nc.writeNonce).
			With("max_nonce", MaxNonce).
			Errorf("write nonce exhausted (reached %d), connection must be terminated", nc.writeNonce)
	}
	return nil
}

// encryptFrame encrypts plaintext and validates the resulting ciphertext size
// against the NTCP2 maximum frame size.
func (nc *NTCP2Conn) encryptFrame(b []byte) ([]byte, error) {
	encrypted, err := nc.noiseConn.Encrypt(b)
	if err != nil {
		return nil, oops.
			Code("ENCRYPT_FAILED").
			In("ntcp2").
			With("plaintext_len", len(b)).
			With("local_addr", nc.localAddr.String()).
			With("remote_addr", nc.remoteAddr.String()).
			Wrapf(err, "failed to encrypt frame")
	}

	if len(encrypted) > SpecMaxFrameSize {
		return nil, oops.
			Code("FRAME_TOO_LARGE").
			In("ntcp2").
			With("encrypted_len", len(encrypted)).
			With("max_frame_size", SpecMaxFrameSize).
			Errorf("encrypted frame (%d bytes) exceeds maximum frame size (%d)", len(encrypted), SpecMaxFrameSize)
	}
	return encrypted, nil
}

// buildWireFrame constructs the NTCP2 wire frame by prepending a 2-byte SipHash-obfuscated
// length to the ciphertext. After this call the SipHash outbound state has advanced.
func (nc *NTCP2Conn) buildWireFrame(encrypted []byte, slm *SipHashLengthModifier) []byte {
	frameLen := uint16(len(encrypted))
	mask := slm.NextOutboundMask()
	obfuscatedLen := frameLen ^ mask

	frame := make([]byte, FrameLengthFieldSize+len(encrypted))
	binary.BigEndian.PutUint16(frame[:FrameLengthFieldSize], obfuscatedLen)
	copy(frame[FrameLengthFieldSize:], encrypted)
	return frame
}

// writeWireFrame writes the complete wire frame atomically to the underlying TCP connection.
// Marks the connection as broken on any write error or partial write.
func (nc *NTCP2Conn) writeWireFrame(frame []byte) error {
	underlying := nc.noiseConn.Underlying()
	n, err := underlying.Write(frame)
	if err != nil {
		nc.broken.Store(true)
		return oops.
			Code("WRITE_FRAME_FAILED").
			In("ntcp2").
			With("frame_length", len(frame)).
			With("local_addr", nc.localAddr.String()).
			With("remote_addr", nc.remoteAddr.String()).
			Wrapf(err, "failed to write frame")
	}

	if n != len(frame) {
		nc.broken.Store(true)
		return oops.
			Code("PARTIAL_WRITE").
			In("ntcp2").
			With("expected", len(frame)).
			With("written", n).
			Errorf("partial frame write: wrote %d of %d bytes", n, len(frame))
	}
	return nil
}

// getMaxFrameSize returns the configured maximum frame size for frame splitting.
// If an NTCP2Config is set and has a valid MaxFrameSize, that value is used.
// Otherwise falls back to the constant MaxFrameSize (65535).
// Per the spec, senders should prefer smaller frame sizes (a few KB).
func (nc *NTCP2Conn) getMaxFrameSize() int {
	cfg := nc.ntcp2Config.Load()
	if cfg != nil && cfg.MaxFrameSize > 0 && cfg.MaxFrameSize <= SpecMaxFrameSize {
		return cfg.MaxFrameSize
	}
	return SpecMaxFrameSize
}

// Close implements net.Conn.Close.
// Closes the underlying Noise connection, zeroes key material, and cleans up
// resources. Close is idempotent — calling it multiple times is safe.
func (nc *NTCP2Conn) Close() error {
	var closeErr error
	nc.closeOnce.Do(func() {
		nc.logger.Debug("NTCP2 connection closing",
			"local_addr", nc.localAddr.String(),
			"remote_addr", nc.remoteAddr.String())

		nc.zeroKeyMaterial()

		err := nc.noiseConn.Close()
		if err != nil {
			// If the connection was already RST'd (broken due to AEAD error
			// or nonce exhaustion), suppress "use of closed network connection"
			// errors since the socket was intentionally closed by sendTCPRST.
			if nc.broken.Load() {
				nc.logger.Debug("suppressing close error on broken connection",
					"error", err.Error())
				return
			}
			closeErr = oops.
				Code("CLOSE_FAILED").
				In("ntcp2").
				With("local_addr", nc.localAddr.String()).
				With("remote_addr", nc.remoteAddr.String()).
				Wrapf(err, "ntcp2 close failed")
		}
	})
	return closeErr
}

// zeroKeyMaterial zeroes SipHash keys and any buffered plaintext to prevent
// sensitive data from lingering in memory after connection close. Per the
// NTCP2 spec: "routers should zero-out any in-memory ephemeral data".
func (nc *NTCP2Conn) zeroKeyMaterial() {
	if slm := nc.lengthObfuscator.Load(); slm != nil {
		slm.ZeroKeys()
	}

	// Zero the Noise cipher state key material (send and receive CipherStates).
	if nc.noiseConn != nil {
		nc.noiseConn.ZeroKeys()
	}

	// Wipe any buffered plaintext (under readMu to avoid racing with Read).
	nc.readMu.Lock()
	for i := range nc.readBuffer {
		nc.readBuffer[i] = 0
	}
	nc.readBuffer = nil
	nc.readMu.Unlock()
}

// LocalAddr implements net.Conn.LocalAddr.
// Returns the NTCP2-specific local address.
func (nc *NTCP2Conn) LocalAddr() net.Addr {
	return nc.localAddr
}

// RemoteAddr implements net.Conn.RemoteAddr.
// Returns the NTCP2-specific remote address.
func (nc *NTCP2Conn) RemoteAddr() net.Addr {
	return nc.remoteAddr
}

// SetDeadline implements net.Conn.SetDeadline.
// Sets read and write deadlines on the underlying connection.
func (nc *NTCP2Conn) SetDeadline(t time.Time) error {
	err := nc.noiseConn.SetDeadline(t)
	if err != nil {
		return oops.
			Code("SET_DEADLINE_FAILED").
			In("ntcp2").
			With("deadline", t.String()).
			With("local_addr", nc.localAddr.String()).
			With("remote_addr", nc.remoteAddr.String()).
			Wrapf(err, "ntcp2 set deadline failed")
	}

	return nil
}

// SetReadDeadline implements net.Conn.SetReadDeadline.
// Sets the read deadline on the underlying connection.
func (nc *NTCP2Conn) SetReadDeadline(t time.Time) error {
	err := nc.noiseConn.SetReadDeadline(t)
	if err != nil {
		return oops.
			Code("SET_READ_DEADLINE_FAILED").
			In("ntcp2").
			With("deadline", t.String()).
			With("local_addr", nc.localAddr.String()).
			With("remote_addr", nc.remoteAddr.String()).
			Wrapf(err, "ntcp2 set read deadline failed")
	}

	return nil
}

// SetWriteDeadline implements net.Conn.SetWriteDeadline.
// Sets the write deadline on the underlying connection.
func (nc *NTCP2Conn) SetWriteDeadline(t time.Time) error {
	err := nc.noiseConn.SetWriteDeadline(t)
	if err != nil {
		return oops.
			Code("SET_WRITE_DEADLINE_FAILED").
			In("ntcp2").
			With("deadline", t.String()).
			With("local_addr", nc.localAddr.String()).
			With("remote_addr", nc.remoteAddr.String()).
			Wrapf(err, "ntcp2 set write deadline failed")
	}

	return nil
}

// RouterHash returns the router hash from the remote address.
// This is I2P-specific functionality for NTCP2 connections.
func (nc *NTCP2Conn) RouterHash() []byte {
	return nc.remoteAddr.RouterHash()
}

// Role returns the connection role (initiator or responder).
func (nc *NTCP2Conn) Role() string {
	return nc.localAddr.Role()
}

// UnderlyingConn returns the underlying NoiseConn for advanced operations.
// This allows access to Noise-specific functionality when needed.
func (nc *NTCP2Conn) UnderlyingConn() *noise.NoiseConn {
	return nc.noiseConn
}

// Rekey triggers a rekey operation on the underlying Noise connection.
// This delegates to NoiseConn.Rekey(), which advances the encryption key
// material per the Noise Protocol specification.
//
// This method allows NTCP2Conn to satisfy a Rekeyer interface:
//
//	type Rekeyer interface { Rekey() error }
func (nc *NTCP2Conn) Rekey() error {
	return nc.noiseConn.Rekey()
}

// PeerStaticKey returns the remote peer's Noise static public key (32 bytes).
// This is available after the handshake completes and can be used by the
// router transport layer (github.com/go-i2p/go-i2p/lib/transport/ntcp) to
// compute the full router hash via SHA-256(RouterIdentity) using
// github.com/go-i2p/common/router_identity.
func (nc *NTCP2Conn) PeerStaticKey() []byte {
	return nc.noiseConn.PeerStatic()
}

// HandshakeHash returns the Noise handshake hash (h) from the completed session.
// This is needed by the router transport layer to derive data-phase keys via
// DeriveSipHashKeys(ask_master, h) for SipHash frame length obfuscation.
// Returns nil if the handshake has not been initiated.
func (nc *NTCP2Conn) HandshakeHash() []byte {
	return nc.noiseConn.ChannelBinding()
}

// NonceExhaustionImminent returns true if either the read or write nonce
// counter has reached NonceRekeyThreshold, indicating that the connection
// is approaching the maximum nonce limit and should be replaced.
//
// The Noise Protocol's Rekey() operation does NOT reset nonce counters,
// so the correct response to imminent exhaustion is to establish a new
// connection rather than attempt a rekey.
func (nc *NTCP2Conn) NonceExhaustionImminent() bool {
	nc.writeMu.Lock()
	wn := nc.writeNonce
	nc.writeMu.Unlock()

	nc.readMu.Lock()
	rn := nc.readNonce
	nc.readMu.Unlock()

	return wn >= NonceRekeyThreshold || rn >= NonceRekeyThreshold
}
