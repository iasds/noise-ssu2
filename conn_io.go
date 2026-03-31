package noise

// conn_io.go contains the low-level I/O helpers for NoiseConn:
// read/write framing, encryption, decryption, modifier chain application,
// and state validation for the data transport path.

import (
	"encoding/binary"
	"io"
	"time"

	"github.com/go-i2p/go-noise/handshake"
	i2plogger "github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// applyOutboundModifier passes encrypted plaintext through the modifier chain
// for PhaseData (post-handshake data transport). Called by Write before encryption.
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

// applyHandshakeOutbound passes outgoing handshake data through the modifier
// chain for the given handshake phase. Called by sendNoiseHandshakeMsg after
// WriteMessage and before writeFramedMessage.
func (nc *NoiseConn) applyHandshakeOutbound(phase handshake.HandshakePhase, data []byte) ([]byte, error) {
	chain := nc.config.GetModifierChain()
	if chain == nil {
		return data, nil
	}
	return chain.ModifyOutbound(phase, data)
}

// applyHandshakeInbound passes incoming handshake data through the modifier
// chain for the given handshake phase. Called by receiveNoiseHandshakeMsg after
// readFramedMessage and before ReadMessage.
func (nc *NoiseConn) applyHandshakeInbound(phase handshake.HandshakePhase, data []byte) ([]byte, error) {
	chain := nc.config.GetModifierChain()
	if chain == nil {
		return data, nil
	}
	return chain.ModifyInbound(phase, data)
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
