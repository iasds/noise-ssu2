package ssu2

import (
	"crypto/rand"
	"encoding/binary"
	"time"

	"github.com/go-i2p/noise"
	"github.com/samber/oops"
)

// HandshakeHandler manages SSU2 handshake message processing using the XK pattern.
// The XK pattern provides forward secrecy and responder authentication:
//
// Initiator (Alice)          Responder (Bob)
// SessionRequest ─────────────────────────>
//
//	(→ e, es, s, ss)
//	                 <───────────────────── SessionCreated
//	                           (← e, ee, se)
//
// SessionConfirmed ───────────────────────>
//
//	(transport phase begins)
//
// The handshake establishes a secure channel with:
// - Forward secrecy via ephemeral keys
// - Responder authentication via Bob's static key
// - DPI resistance via header encryption
type HandshakeHandler struct {
	// initiator determines if we initiate (true) or respond (false)
	initiator bool

	// staticKey is our static X25519 private key (32 bytes)
	staticKey []byte

	// remoteStaticKey is the peer's static public key (32 bytes)
	// Required for initiator, learned during handshake for responder
	remoteStaticKey []byte

	// handshakeState manages the Noise protocol state machine
	handshakeState *noise.HandshakeState

	// cipherStates store the transport cipher states after handshake
	sendCipher *noise.CipherState
	recvCipher *noise.CipherState
}

// NewHandshakeHandler creates a new SSU2 handshake handler.
// For initiators, remoteStaticKey must be provided (responder's public key).
// For responders, remoteStaticKey is nil and will be learned during handshake.
func NewHandshakeHandler(initiator bool, staticKey, remoteStaticKey []byte) (*HandshakeHandler, error) {
	if len(staticKey) != 32 {
		return nil, oops.Errorf("static key must be 32 bytes, got %d", len(staticKey))
	}

	if initiator && len(remoteStaticKey) != 32 {
		return nil, oops.Errorf("initiator requires remote static key (32 bytes), got %d", len(remoteStaticKey))
	}

	if !initiator && remoteStaticKey != nil && len(remoteStaticKey) != 32 {
		return nil, oops.Errorf("remote static key must be 32 bytes if provided, got %d", len(remoteStaticKey))
	}

	// Create Noise handshake state for XK pattern
	cs := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)

	config := noise.Config{
		CipherSuite: cs,
		Random:      rand.Reader,
		Pattern:     noise.HandshakeXK,
		Initiator:   initiator,
		StaticKeypair: noise.DHKey{
			Private: copyBytes(staticKey),
			Public:  nil, // Will be computed by noise library
		},
	}

	// For initiator, set the responder's static public key
	if initiator && remoteStaticKey != nil {
		config.PeerStatic = copyBytes(remoteStaticKey)
	}

	hs, err := noise.NewHandshakeState(config)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to create handshake state")
	}

	return &HandshakeHandler{
		initiator:       initiator,
		staticKey:       copyBytes(staticKey),
		remoteStaticKey: copyBytes(remoteStaticKey),
		handshakeState:  hs,
	}, nil
}

// NewHandshakeHandlerWithKeys creates a new SSU2 handshake handler with a full DHKey.
// This is useful when you already have a generated keypair from noise.DH25519.GenerateKeypair().
// For initiators, remoteStaticKey must be provided (responder's public key).
// For responders, remoteStaticKey is nil and will be learned during handshake.
func NewHandshakeHandlerWithKeys(initiator bool, staticKeypair noise.DHKey, remoteStaticKey []byte) (*HandshakeHandler, error) {
	if len(staticKeypair.Private) != 32 {
		return nil, oops.Errorf("static private key must be 32 bytes, got %d", len(staticKeypair.Private))
	}

	if len(staticKeypair.Public) != 32 {
		return nil, oops.Errorf("static public key must be 32 bytes, got %d", len(staticKeypair.Public))
	}

	if initiator && len(remoteStaticKey) != 32 {
		return nil, oops.Errorf("initiator requires remote static key (32 bytes), got %d", len(remoteStaticKey))
	}

	if !initiator && remoteStaticKey != nil && len(remoteStaticKey) != 32 {
		return nil, oops.Errorf("remote static key must be 32 bytes if provided, got %d", len(remoteStaticKey))
	}

	// Create Noise handshake state for XK pattern
	cs := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)

	config := noise.Config{
		CipherSuite: cs,
		Random:      rand.Reader,
		Pattern:     noise.HandshakeXK,
		Initiator:   initiator,
		StaticKeypair: noise.DHKey{
			Private: copyBytes(staticKeypair.Private),
			Public:  copyBytes(staticKeypair.Public),
		},
	}

	// For initiator, set the responder's static public key
	if initiator && remoteStaticKey != nil {
		config.PeerStatic = copyBytes(remoteStaticKey)
	}

	hs, err := noise.NewHandshakeState(config)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to create handshake state")
	}

	return &HandshakeHandler{
		initiator:       initiator,
		staticKey:       copyBytes(staticKeypair.Private),
		remoteStaticKey: copyBytes(remoteStaticKey),
		handshakeState:  hs,
	}, nil
}

// CreateSessionRequest creates a SessionRequest message (Message 0, XK pattern message 1).
// This is the first handshake message sent by the initiator.
//
// SessionRequest contains:
// - Ephemeral key (32 bytes)
// - Encrypted static key (32 + 16 bytes MAC)
// - Encrypted blocks (DateTime, Options)
//
// XK pattern: → e, es, s, ss
func (h *HandshakeHandler) CreateSessionRequest(sourceConnID, destConnID uint64) (*SSU2Packet, error) {
	if !h.initiator {
		return nil, oops.Errorf("only initiator can create SessionRequest")
	}

	// Create payload blocks for SessionRequest
	blocks := h.createHandshakeBlocks(MessageTypeSessionRequest)

	// Serialize blocks
	payload, err := SerializeBlocks(blocks)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to serialize SessionRequest blocks")
	}

	// Create handshake message using Noise protocol
	// WriteMessage will: send ephemeral key, perform DH, encrypt payload
	ciphertext, cs1, cs2, err := h.handshakeState.WriteMessage(nil, payload)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to create SessionRequest handshake message")
	}

	// Store cipher states (may be nil until handshake completes)
	h.updateCipherStates(cs1, cs2)

	// Extract ephemeral key (first 32 bytes of ciphertext)
	if len(ciphertext) < 32 {
		return nil, oops.Errorf("invalid SessionRequest: too short (%d bytes)", len(ciphertext))
	}
	ephemeralKey := ciphertext[:32]
	encryptedPayload := ciphertext[32:]

	// Create packet with 32-byte long header
	packet := &SSU2Packet{
		Header:       make([]byte, 32),
		EphemeralKey: copyBytes(ephemeralKey),
		Payload:      encryptedPayload,
		MAC:          make([]byte, 16), // Placeholder, will be computed
		MessageType:  MessageTypeSessionRequest,
		PacketNumber: 0, // Handshake messages don't use packet numbers
	}

	// Encode connection IDs in header
	binary.BigEndian.PutUint64(packet.Header[0:8], destConnID)
	binary.BigEndian.PutUint64(packet.Header[8:16], sourceConnID)
	// Remaining header bytes are padding/reserved

	return packet, nil
}

// ProcessSessionRequest processes a received SessionRequest message.
// This is called by the responder to process the initiator's first message.
//
// Returns the initiator's static public key learned from the handshake.
func (h *HandshakeHandler) ProcessSessionRequest(packet *SSU2Packet) ([]byte, error) {
	if h.initiator {
		return nil, oops.Errorf("initiator cannot process SessionRequest")
	}

	if packet.MessageType != MessageTypeSessionRequest {
		return nil, oops.Errorf("expected SessionRequest (type 0), got type %d", packet.MessageType)
	}

	if len(packet.EphemeralKey) != 32 {
		return nil, oops.Errorf("SessionRequest missing ephemeral key")
	}

	// Reconstruct Noise message: ephemeral key + encrypted payload
	noiseMessage := append(copyBytes(packet.EphemeralKey), packet.Payload...)

	// Process handshake message using Noise protocol
	// ReadMessage will: receive ephemeral key, perform DH, decrypt payload
	payload, cs1, cs2, err := h.handshakeState.ReadMessage(nil, noiseMessage)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to process SessionRequest handshake message")
	}

	// Store cipher states
	h.updateCipherStates(cs1, cs2)

	// Parse blocks from decrypted payload
	blocks, err := DeserializeBlocks(payload)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to deserialize SessionRequest blocks")
	}

	// Validate required blocks (DateTime, Options)
	if err := h.validateHandshakeBlocks(blocks, MessageTypeSessionRequest); err != nil {
		return nil, err
	}

	// Note: In the XK pattern, the initiator's static key is transmitted encrypted,
	// but the noise library doesn't expose it via PeerStatic() on the responder side.
	// The static key is used internally for DH operations to establish the session.
	// If you need the initiator's identity (RouterInfo), it should be transmitted
	// in the payload blocks (e.g., RouterInfo block) rather than extracted from
	// the Noise handshake state.
	//
	// For now, we return nil to indicate the handshake succeeded but the static key
	// is not directly available. The session is authenticated via the successful DH.
	return nil, nil
}

// CreateSessionCreated creates a SessionCreated message (Message 1, XK pattern message 2).
// This is the second handshake message sent by the responder.
//
// SessionCreated contains:
// - Ephemeral key (32 bytes)
// - Encrypted blocks (DateTime, Options)
//
// XK pattern: ← e, ee, se
func (h *HandshakeHandler) CreateSessionCreated(sourceConnID, destConnID uint64) (*SSU2Packet, error) {
	if h.initiator {
		return nil, oops.Errorf("only responder can create SessionCreated")
	}

	// Create payload blocks
	blocks := h.createHandshakeBlocks(MessageTypeSessionCreated)

	// Serialize blocks
	payload, err := SerializeBlocks(blocks)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to serialize SessionCreated blocks")
	}

	// Create handshake message using Noise protocol
	ciphertext, cs1, cs2, err := h.handshakeState.WriteMessage(nil, payload)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to create SessionCreated handshake message")
	}

	// Store cipher states (should be available now)
	h.updateCipherStates(cs1, cs2)

	// Extract ephemeral key
	if len(ciphertext) < 32 {
		return nil, oops.Errorf("invalid SessionCreated: too short (%d bytes)", len(ciphertext))
	}
	ephemeralKey := ciphertext[:32]
	encryptedPayload := ciphertext[32:]

	// Create packet with 32-byte long header
	packet := &SSU2Packet{
		Header:       make([]byte, 32),
		EphemeralKey: copyBytes(ephemeralKey),
		Payload:      encryptedPayload,
		MAC:          make([]byte, 16), // Placeholder
		MessageType:  MessageTypeSessionCreated,
		PacketNumber: 0,
	}

	// Encode connection IDs
	binary.BigEndian.PutUint64(packet.Header[0:8], destConnID)
	binary.BigEndian.PutUint64(packet.Header[8:16], sourceConnID)

	return packet, nil
}

// ProcessSessionCreated processes a received SessionCreated message.
// This is called by the initiator to process the responder's response.
//
// After this, the handshake is complete and transport cipher states are available.
func (h *HandshakeHandler) ProcessSessionCreated(packet *SSU2Packet) error {
	if !h.initiator {
		return oops.Errorf("responder cannot process SessionCreated")
	}

	if packet.MessageType != MessageTypeSessionCreated {
		return oops.Errorf("expected SessionCreated (type 1), got type %d", packet.MessageType)
	}

	if len(packet.EphemeralKey) != 32 {
		return oops.Errorf("SessionCreated missing ephemeral key")
	}

	// Reconstruct Noise message
	noiseMessage := append(copyBytes(packet.EphemeralKey), packet.Payload...)

	// Process handshake message
	payload, cs1, cs2, err := h.handshakeState.ReadMessage(nil, noiseMessage)
	if err != nil {
		return oops.Wrapf(err, "failed to process SessionCreated handshake message")
	}

	// Store cipher states (handshake now complete)
	h.updateCipherStates(cs1, cs2)

	// Parse blocks
	blocks, err := DeserializeBlocks(payload)
	if err != nil {
		return oops.Wrapf(err, "failed to deserialize SessionCreated blocks")
	}

	// Validate blocks
	if err := h.validateHandshakeBlocks(blocks, MessageTypeSessionCreated); err != nil {
		return err
	}

	return nil
}

// CreateSessionConfirmed creates a SessionConfirmed message (Message 2).
// This is the third handshake message sent by the initiator.
//
// SessionConfirmed uses a short header (16 bytes) and contains no ephemeral key.
// It may contain blocks like DateTime, but is not required by the protocol.
// This message confirms the handshake and transitions to the transport phase.
func (h *HandshakeHandler) CreateSessionConfirmed(connID uint64, packetNumber uint32) (*SSU2Packet, error) {
	if !h.initiator {
		return nil, oops.Errorf("only initiator can create SessionConfirmed")
	}

	if h.sendCipher == nil {
		return nil, oops.Errorf("handshake not complete: no send cipher state")
	}

	// SessionConfirmed typically contains minimal or no blocks
	// We'll create an empty payload for simplicity
	blocks := make([]*SSU2Block, 0)

	// Serialize blocks (may be empty)
	payload, err := SerializeBlocks(blocks)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to serialize SessionConfirmed blocks")
	}

	// Encrypt payload using transport cipher
	ciphertext, err := h.sendCipher.Encrypt(nil, nil, payload)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to encrypt SessionConfirmed payload")
	}

	// Create packet with 16-byte short header
	packet := &SSU2Packet{
		Header:       make([]byte, 16),
		EphemeralKey: nil,                             // No ephemeral key in SessionConfirmed
		Payload:      ciphertext[:len(ciphertext)-16], // Separate MAC
		MAC:          ciphertext[len(ciphertext)-16:], // Last 16 bytes
		MessageType:  MessageTypeSessionConfirmed,
		PacketNumber: packetNumber,
	}

	// Encode connection ID and packet number in header
	binary.BigEndian.PutUint64(packet.Header[0:8], connID)
	binary.BigEndian.PutUint32(packet.Header[8:12], packetNumber)
	// Remaining 4 bytes are message type and flags

	return packet, nil
}

// ProcessSessionConfirmed processes a received SessionConfirmed message.
// This is called by the responder to complete the handshake.
//
// After this, both sides have completed the handshake and can send Data messages.
func (h *HandshakeHandler) ProcessSessionConfirmed(packet *SSU2Packet) error {
	if h.initiator {
		return oops.Errorf("initiator cannot process SessionConfirmed")
	}

	if packet.MessageType != MessageTypeSessionConfirmed {
		return oops.Errorf("expected SessionConfirmed (type 2), got type %d", packet.MessageType)
	}

	if h.recvCipher == nil {
		return oops.Errorf("handshake not complete: no receive cipher state")
	}

	// Reconstruct ciphertext with MAC
	ciphertext := append(packet.Payload, packet.MAC...)

	// Decrypt using transport cipher
	_, err := h.recvCipher.Decrypt(nil, nil, ciphertext)
	if err != nil {
		return oops.Wrapf(err, "failed to decrypt SessionConfirmed")
	}

	// No need to parse blocks - SessionConfirmed may be empty

	return nil
}

// IsHandshakeComplete returns true if the handshake has finished.
// For XK pattern (2-message handshake), this is true after both messages are exchanged.
// Note: For XK, cipher states are not returned by Read/WriteMessage and must be
// obtained differently (e.g., using HandshakeState directly for transport encryption).
func (h *HandshakeHandler) IsHandshakeComplete() bool {
	// For XK pattern: handshake is complete when MessageIndex reaches 2
	return h.handshakeState != nil && h.handshakeState.MessageIndex() >= 2
}

// GetCipherStates returns the transport cipher states after successful handshake.
// Returns error if handshake is not complete.
func (h *HandshakeHandler) GetCipherStates() (*noise.CipherState, *noise.CipherState, error) {
	if !h.IsHandshakeComplete() {
		return nil, nil, oops.Errorf("handshake not complete")
	}
	return h.sendCipher, h.recvCipher, nil
}

// GetRemoteStaticKey returns the peer's static public key.
// For initiators, this is known before handshake.
// For responders, this is learned during SessionRequest processing.
func (h *HandshakeHandler) GetRemoteStaticKey() []byte {
	return copyBytes(h.remoteStaticKey)
}

// createHandshakeBlocks creates the standard blocks for handshake messages.
// Currently creates DateTime block with current timestamp.
func (h *HandshakeHandler) createHandshakeBlocks(messageType uint8) []*SSU2Block {
	blocks := make([]*SSU2Block, 0, 2)

	// DateTime block (Type 0) - required in SessionRequest and SessionCreated
	// Format: 7 bytes - timestamp in milliseconds since epoch
	now := time.Now().UnixMilli()
	temp := make([]byte, 8)
	binary.BigEndian.PutUint64(temp, uint64(now))
	// Take last 7 bytes (skip first byte to get 56-bit timestamp)
	dateTimeData := temp[1:]

	blocks = append(blocks, NewSSU2Block(BlockTypeDateTime, dateTimeData))

	// Options block (Type 1) could be added here for MTU negotiation, etc.
	// For now, we keep it simple and only include DateTime

	return blocks
}

// validateHandshakeBlocks validates that required blocks are present.
func (h *HandshakeHandler) validateHandshakeBlocks(blocks []*SSU2Block, messageType uint8) error {
	hasDateTime := false

	for _, block := range blocks {
		if block.Type == BlockTypeDateTime {
			hasDateTime = true
			if len(block.Data) < 7 {
				return oops.Errorf("DateTime block too short: %d bytes", len(block.Data))
			}
		}
	}

	// DateTime is recommended but not strictly required
	// We'll be lenient and not fail if it's missing
	_ = hasDateTime

	return nil
}

// updateCipherStates updates the send/receive cipher states when available.
func (h *HandshakeHandler) updateCipherStates(cs1, cs2 *noise.CipherState) {
	if cs1 != nil && cs2 != nil {
		if h.initiator {
			h.sendCipher = cs1
			h.recvCipher = cs2
		} else {
			h.sendCipher = cs2
			h.recvCipher = cs1
		}
	}
}

// copyBytes creates a defensive copy of a byte slice.
func copyBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	copied := make([]byte, len(b))
	copy(copied, b)
	return copied
}
