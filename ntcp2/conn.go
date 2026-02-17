package ntcp2

import (
	"crypto/rand"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"sync"
	"time"

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
//
// TODO(ntcp2-spec): Nonce limit enforcement — spec requires dropping the connection when the
// nonce reaches 2^64-2. Currently no nonce tracking at this layer.
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
	lengthObfuscator *SipHashLengthModifier

	// readBuffer holds surplus plaintext from readFramed when the
	// decrypted frame is larger than the caller's Read buffer.
	readBuffer []byte

	// closeOnce ensures Close is idempotent and key material is zeroed exactly once.
	closeOnce sync.Once

	// logger for connection events
	logger logger.Logger
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
		logger:     *log,
	}

	conn.logger.Debug("NTCP2 connection created",
		"local_addr", localAddr.String(),
		"remote_addr", remoteAddr.String())

	return conn, nil
}

// SetLengthObfuscator sets the SipHash length obfuscator for data-phase framing.
// When set, Read/Write will use framed I/O with SipHash-obfuscated length prefixes.
// This should be called before any data-phase Read/Write operations.
func (nc *NTCP2Conn) SetLengthObfuscator(slm *SipHashLengthModifier) {
	nc.lengthObfuscator = slm
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
	if nc.lengthObfuscator == nil {
		return nc.readDirect(b)
	}
	// Drain buffered plaintext from a previous oversized frame first.
	if len(nc.readBuffer) > 0 {
		n := copy(b, nc.readBuffer)
		nc.readBuffer = nc.readBuffer[n:]
		if len(nc.readBuffer) == 0 {
			nc.readBuffer = nil
		}
		return n, nil
	}
	return nc.readFramed(b)
}

// readDirect delegates directly to the underlying NoiseConn for unframed reads.
// Per the io.Reader contract, returns both the bytes read and any error.
func (nc *NTCP2Conn) readDirect(b []byte) (int, error) {
	n, err := nc.noiseConn.Read(b)
	if err != nil {
		return n, oops.
			Code("READ_FAILED").
			In("ntcp2").
			With("local_addr", nc.localAddr.String()).
			With("remote_addr", nc.remoteAddr.String()).
			With("bytes_requested", len(b)).
			Wrapf(err, "ntcp2 read failed")
	}

	nc.logger.Trace("NTCP2 data read (direct)",
		"bytes_read", n,
		"local_addr", nc.localAddr.String(),
		"remote_addr", nc.remoteAddr.String())

	return n, nil
}

// readFramed reads an NTCP2 data-phase frame with SipHash length deobfuscation.
func (nc *NTCP2Conn) readFramed(b []byte) (int, error) {
	underlying := nc.noiseConn.Underlying()

	// Step 1: Read the 2-byte obfuscated length field
	lengthBuf := make([]byte, FrameLengthFieldSize)
	if _, err := io.ReadFull(underlying, lengthBuf); err != nil {
		return 0, oops.
			Code("READ_LENGTH_FAILED").
			In("ntcp2").
			With("local_addr", nc.localAddr.String()).
			With("remote_addr", nc.remoteAddr.String()).
			Wrapf(err, "failed to read frame length")
	}

	// Step 2: Deobfuscate using SipHash inbound mask
	nc.lengthObfuscator.mu.Lock()
	mask := nc.lengthObfuscator.getNextInboundMask()
	nc.lengthObfuscator.mu.Unlock()

	obfuscatedLen := binary.BigEndian.Uint16(lengthBuf)
	frameLen := obfuscatedLen ^ mask

	if err := nc.validateFrameLength(frameLen); err != nil {
		return 0, err
	}

	// Step 3: Read exactly frameLen bytes of ciphertext
	ciphertext := make([]byte, frameLen)
	if _, err := io.ReadFull(underlying, ciphertext); err != nil {
		return 0, oops.
			Code("READ_FRAME_FAILED").
			In("ntcp2").
			With("frame_length", frameLen).
			With("local_addr", nc.localAddr.String()).
			With("remote_addr", nc.remoteAddr.String()).
			Wrapf(err, "failed to read frame data")
	}

	// Step 4: Decrypt using the Noise cipher state
	plaintext, err := nc.noiseConn.Decrypt(ciphertext)
	if err != nil {
		// Probing resistance: read random junk before returning the error,
		// so the connection is not trivially distinguishable from random data.
		nc.handleAEADError(underlying)
		return 0, oops.
			Code("DECRYPT_FAILED").
			In("ntcp2").
			With("frame_length", frameLen).
			With("local_addr", nc.localAddr.String()).
			With("remote_addr", nc.remoteAddr.String()).
			Wrapf(err, "failed to decrypt frame")
	}

	// Step 5: Copy plaintext into caller's buffer; buffer any remainder
	n := copy(b, plaintext)
	if n < len(plaintext) {
		nc.readBuffer = make([]byte, len(plaintext)-n)
		copy(nc.readBuffer, plaintext[n:])
	}

	nc.logger.Trace("NTCP2 data read (framed)",
		"frame_length", frameLen,
		"plaintext_length", len(plaintext),
		"bytes_copied", n,
		"bytes_buffered", len(plaintext)-n,
		"local_addr", nc.localAddr.String(),
		"remote_addr", nc.remoteAddr.String())

	return n, nil
}

// validateFrameLength checks that the deobfuscated frame length is within the
// NTCP2 spec range of MinDataPhaseFrameSize–MaxFrameSize.
func (nc *NTCP2Conn) validateFrameLength(frameLen uint16) error {
	if frameLen == 0 {
		return oops.
			Code("ZERO_FRAME_LENGTH").
			In("ntcp2").
			With("local_addr", nc.localAddr.String()).
			With("remote_addr", nc.remoteAddr.String()).
			Errorf("received zero-length frame")
	}

	if frameLen < MinDataPhaseFrameSize {
		return oops.
			Code("FRAME_TOO_SMALL").
			In("ntcp2").
			With("frame_length", frameLen).
			With("min_frame_size", MinDataPhaseFrameSize).
			With("local_addr", nc.localAddr.String()).
			With("remote_addr", nc.remoteAddr.String()).
			Errorf("frame length %d below minimum %d", frameLen, MinDataPhaseFrameSize)
	}

	if int(frameLen) > MaxFrameSize {
		return oops.
			Code("FRAME_TOO_LARGE").
			In("ntcp2").
			With("frame_length", frameLen).
			With("max_frame_size", MaxFrameSize).
			With("local_addr", nc.localAddr.String()).
			With("remote_addr", nc.remoteAddr.String()).
			Errorf("frame length %d exceeds maximum %d", frameLen, MaxFrameSize)
	}

	return nil
}

// handleAEADError implements a best-effort probing-resistance delay
// before the connection is closed by the caller. Per the NTCP2 spec,
// on an AEAD authentication failure the receiver should read random
// bytes for a random duration before closing.
func (nc *NTCP2Conn) handleAEADError(underlying net.Conn) {
	// Generate a random byte count (0–1024) to read before returning.
	nBig, err := rand.Int(rand.Reader, big.NewInt(1024))
	if err != nil {
		return // best effort
	}
	junkLen := int(nBig.Int64())
	if junkLen == 0 {
		return
	}
	// Set a short deadline so we don't block forever if the peer stops sending.
	underlying.SetReadDeadline(time.Now().Add(2 * time.Second)) //nolint:errcheck
	junk := make([]byte, junkLen)
	underlying.Read(junk)                   //nolint:errcheck // best effort
	underlying.SetReadDeadline(time.Time{}) //nolint:errcheck
}

// Write implements net.Conn.Write.
// When a length obfuscator is set, writes use NTCP2 framed I/O:
//  1. Encrypt the plaintext via the Noise cipher state
//  2. Compute the ciphertext length as a uint16
//  3. XOR with SipHash outbound mask to obfuscate the length
//  4. Write [2-byte obfuscated length][ciphertext] to the underlying TCP connection
//
// When no length obfuscator is set, delegates directly to NoiseConn.Write.
//
// TODO(ntcp2-spec): Transparently split writes larger than MaxFrameSize minus
// Poly1305 overhead into multiple NTCP2 frames instead of returning an error.
func (nc *NTCP2Conn) Write(b []byte) (int, error) {
	if nc.lengthObfuscator == nil {
		return nc.writeDirect(b)
	}
	return nc.writeFramed(b)
}

// writeDirect delegates directly to the underlying NoiseConn for unframed writes.
func (nc *NTCP2Conn) writeDirect(b []byte) (int, error) {
	n, err := nc.noiseConn.Write(b)
	if err != nil {
		return 0, oops.
			Code("WRITE_FAILED").
			In("ntcp2").
			With("local_addr", nc.localAddr.String()).
			With("remote_addr", nc.remoteAddr.String()).
			With("bytes_to_write", len(b)).
			Wrapf(err, "ntcp2 write failed")
	}

	nc.logger.Trace("NTCP2 data written (direct)",
		"bytes_written", n,
		"local_addr", nc.localAddr.String(),
		"remote_addr", nc.remoteAddr.String())

	return n, nil
}

// writeFramed writes an NTCP2 data-phase frame with SipHash length obfuscation.
func (nc *NTCP2Conn) writeFramed(b []byte) (int, error) {
	// Step 1: Encrypt the plaintext
	encrypted, err := nc.noiseConn.Encrypt(b)
	if err != nil {
		return 0, oops.
			Code("ENCRYPT_FAILED").
			In("ntcp2").
			With("plaintext_len", len(b)).
			With("local_addr", nc.localAddr.String()).
			With("remote_addr", nc.remoteAddr.String()).
			Wrapf(err, "failed to encrypt frame")
	}

	// Step 2: Validate frame size
	if len(encrypted) > MaxFrameSize {
		return 0, oops.
			Code("FRAME_TOO_LARGE").
			In("ntcp2").
			With("encrypted_len", len(encrypted)).
			With("max_frame_size", MaxFrameSize).
			Errorf("encrypted frame (%d bytes) exceeds maximum frame size (%d)", len(encrypted), MaxFrameSize)
	}

	// Step 3: Compute obfuscated length
	frameLen := uint16(len(encrypted))

	nc.lengthObfuscator.mu.Lock()
	mask := nc.lengthObfuscator.getNextOutboundMask()
	nc.lengthObfuscator.mu.Unlock()

	obfuscatedLen := frameLen ^ mask

	// Step 4: Build the wire frame: [2-byte obfuscated length][ciphertext]
	frame := make([]byte, FrameLengthFieldSize+len(encrypted))
	binary.BigEndian.PutUint16(frame[:FrameLengthFieldSize], obfuscatedLen)
	copy(frame[FrameLengthFieldSize:], encrypted)

	// Step 5: Write the entire frame atomically to the underlying TCP connection
	underlying := nc.noiseConn.Underlying()
	n, err := underlying.Write(frame)
	if err != nil {
		return 0, oops.
			Code("WRITE_FRAME_FAILED").
			In("ntcp2").
			With("frame_length", len(frame)).
			With("local_addr", nc.localAddr.String()).
			With("remote_addr", nc.remoteAddr.String()).
			Wrapf(err, "failed to write frame")
	}

	if n != len(frame) {
		return 0, oops.
			Code("PARTIAL_WRITE").
			In("ntcp2").
			With("expected", len(frame)).
			With("written", n).
			Errorf("partial frame write: wrote %d of %d bytes", n, len(frame))
	}

	nc.logger.Trace("NTCP2 data written (framed)",
		"plaintext_length", len(b),
		"encrypted_length", len(encrypted),
		"frame_length", len(frame),
		"local_addr", nc.localAddr.String(),
		"remote_addr", nc.remoteAddr.String())

	return len(b), nil
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

		closeErr = nc.noiseConn.Close()
		if closeErr != nil {
			closeErr = oops.
				Code("CLOSE_FAILED").
				In("ntcp2").
				With("local_addr", nc.localAddr.String()).
				With("remote_addr", nc.remoteAddr.String()).
				Wrapf(closeErr, "ntcp2 close failed")
		}
	})
	return closeErr
}

// zeroKeyMaterial zeroes SipHash keys and any buffered plaintext to prevent
// sensitive data from lingering in memory after connection close. Per the
// NTCP2 spec: "routers should zero-out any in-memory ephemeral data".
func (nc *NTCP2Conn) zeroKeyMaterial() {
	if nc.lengthObfuscator != nil {
		nc.lengthObfuscator.mu.Lock()
		nc.lengthObfuscator.sipKeys[0] = 0
		nc.lengthObfuscator.sipKeys[1] = 0
		nc.lengthObfuscator.outboundIV = 0
		nc.lengthObfuscator.inboundIV = 0
		nc.lengthObfuscator.mu.Unlock()
	}
	// Wipe any buffered plaintext.
	for i := range nc.readBuffer {
		nc.readBuffer[i] = 0
	}
	nc.readBuffer = nil
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

// DestinationHash returns the destination hash from the remote address.
// Returns nil for router-to-router connections.
func (nc *NTCP2Conn) DestinationHash() []byte {
	return nc.remoteAddr.DestinationHash()
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
