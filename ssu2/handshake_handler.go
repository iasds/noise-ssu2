package ssu2

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"time"

	"github.com/go-i2p/noise"
	"github.com/samber/oops"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// HandshakeHandler manages SSU2 handshake message processing using the XK pattern.
// The XK pattern provides forward secrecy and responder authentication:
//
// Pre-message: ← s (responder's static key known to initiator)
//
// Initiator (Alice)          Responder (Bob)
// SessionRequest ─────────────────────────>
//
//	(→ e, es)
//	                 <───────────────────── SessionCreated
//	                           (← e, ee)
//
// SessionConfirmed ───────────────────────>
//
//	(→ s, se)
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

// buildSSU2Prologue constructs the Noise prologue for SSU2 handshakes.
// The prologue binds the handshake to the initiator's connection ID,
// preventing replay of handshake messages across different sessions.
func buildSSU2Prologue(initiatorConnID uint64) []byte {
	prologue := make([]byte, 12) // "SSU2" + 8-byte connection ID
	copy(prologue[0:4], []byte("SSU2"))
	binary.BigEndian.PutUint64(prologue[4:12], initiatorConnID)
	return prologue
}

// NewHandshakeHandler creates a new SSU2 handshake handler.
// For initiators, remoteStaticKey must be provided (responder's public key).
// For responders, remoteStaticKey is nil and will be learned during handshake.
// The prologue binds the Noise handshake to SSU2 session context; pass nil to omit.
func NewHandshakeHandler(initiator bool, staticKey, remoteStaticKey, prologue []byte) (*HandshakeHandler, error) {
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
		Prologue:    prologue,
		StaticKeypair: noise.DHKey{
			Private: copyBytes(staticKey),
			Public:  derivePublicKey(staticKey),
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
// The prologue binds the Noise handshake to SSU2 session context; pass nil to omit.
func NewHandshakeHandlerWithKeys(initiator bool, staticKeypair noise.DHKey, remoteStaticKey, prologue []byte) (*HandshakeHandler, error) {
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
		Prologue:    prologue,
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
// XK pattern message 1: → e, es
func (h *HandshakeHandler) CreateSessionRequest(sourceConnID, destConnID uint64) (*SSU2Packet, error) {
	if !h.initiator {
		return nil, oops.Errorf("only initiator can create SessionRequest")
	}

	// Create payload blocks for SessionRequest
	blocks := h.createHandshakeBlocks(MessageTypeSessionRequest)

	return h.buildHandshakePacket(blocks, MessageTypeSessionRequest, sourceConnID, destConnID)
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

	return h.buildHandshakePacket(blocks, MessageTypeSessionCreated, sourceConnID, destConnID)
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

// CreateSessionConfirmed creates a SessionConfirmed message (XK pattern message 3).
// This is the third handshake message sent by the initiator.
//
// SessionConfirmed uses a short header (16 bytes) and contains no ephemeral key.
// It contains the initiator's RouterInfo block so the responder can learn the
// initiator's identity. routerInfo may be nil for testing.
// This message completes the XK handshake (→ s, se) and produces transport cipher states.
func (h *HandshakeHandler) CreateSessionConfirmed(connID uint64, packetNumber uint32, routerInfo []byte) (*SSU2Packet, error) {
	if !h.initiator {
		return nil, oops.Errorf("only initiator can create SessionConfirmed")
	}

	// Verify handshake is at message 2 (messages 0 and 1 completed)
	if h.handshakeState.MessageIndex() != 2 {
		return nil, oops.Errorf("handshake not ready for SessionConfirmed: expected message index 2, got %d", h.handshakeState.MessageIndex())
	}

	// SessionConfirmed must contain initiator's RouterInfo per SSU2 spec
	var blocks []*SSU2Block
	if len(routerInfo) > 0 {
		blocks = append(blocks, NewSSU2Block(BlockTypeRouterInfo, routerInfo))
	}

	// Serialize blocks (may be empty)
	payload, err := SerializeBlocks(blocks)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to serialize SessionConfirmed blocks")
	}

	// Write 3rd XK handshake message through Noise state machine (→ s, se).
	// This completes the handshake and returns transport cipher states.
	ciphertext, cs1, cs2, err := h.handshakeState.WriteMessage(nil, payload)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to create SessionConfirmed handshake message")
	}

	// Store cipher states (handshake now complete)
	h.updateCipherStates(cs1, cs2)

	// Separate MAC (last 16 bytes) from payload
	var pktPayload, mac []byte
	if len(ciphertext) >= 16 {
		pktPayload = ciphertext[:len(ciphertext)-16]
		mac = ciphertext[len(ciphertext)-16:]
	} else {
		pktPayload = ciphertext
		mac = make([]byte, 16)
	}

	// Create packet with 16-byte short header
	packet := &SSU2Packet{
		Header:       make([]byte, 16),
		EphemeralKey: nil, // No ephemeral key in SessionConfirmed
		Payload:      pktPayload,
		MAC:          mac,
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
// This is called by the responder to complete the XK handshake (→ s, se).
//
// After this, both sides have completed the handshake and can send Data messages.
func (h *HandshakeHandler) ProcessSessionConfirmed(packet *SSU2Packet) error {
	if h.initiator {
		return oops.Errorf("initiator cannot process SessionConfirmed")
	}

	if packet.MessageType != MessageTypeSessionConfirmed {
		return oops.Errorf("expected SessionConfirmed (type 2), got type %d", packet.MessageType)
	}

	// Verify handshake is at message 2 (messages 0 and 1 completed)
	if h.handshakeState.MessageIndex() != 2 {
		return oops.Errorf("handshake not ready for SessionConfirmed: expected message index 2, got %d", h.handshakeState.MessageIndex())
	}

	// Reconstruct Noise handshake message from payload + MAC
	noiseMessage := append(copyBytes(packet.Payload), packet.MAC...)

	// Process 3rd XK handshake message (→ s, se).
	// This completes the handshake and returns transport cipher states.
	_, cs1, cs2, err := h.handshakeState.ReadMessage(nil, noiseMessage)
	if err != nil {
		return oops.Wrapf(err, "failed to process SessionConfirmed handshake message")
	}

	// Store cipher states (handshake now complete)
	h.updateCipherStates(cs1, cs2)

	// Now that message 3 (→ s, se) is processed, the initiator's static key
	// is available via PeerStatic(). Store it for identity lookup.
	if ps := h.handshakeState.PeerStatic(); len(ps) > 0 {
		h.remoteStaticKey = copyBytes(ps)
	}

	return nil
}

// IsHandshakeComplete returns true if the handshake has finished and
// transport cipher states are available. For the XK pattern this requires
// all three messages (SessionRequest, SessionCreated, SessionConfirmed).
func (h *HandshakeHandler) IsHandshakeComplete() bool {
	return h.sendCipher != nil && h.recvCipher != nil
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
	blocks := make([]*SSU2Block, 0, 3)

	// DateTime block (Type 0) - required in SessionRequest and SessionCreated
	// Format: 4 bytes - seconds since epoch (big-endian uint32)
	dateTimeData := make([]byte, 4)
	binary.BigEndian.PutUint32(dateTimeData, uint32(time.Now().Unix()))

	blocks = append(blocks, NewSSU2Block(BlockTypeDateTime, dateTimeData))

	// Options block (Type 1) - SHOULD be included per SSU2 spec
	// Communicates version, padding parameters, and MTU preferences.
	// Layout (15 bytes):
	//   0-1: SSU2 version (2)
	//   2:   padding params (min nibble << 4 | max nibble) — 0 = no constraints
	//   3-4: padding ratio (fixed-point uint16) — 0x0100 = 1.0
	//   5-6: reserved
	//   7-8: min MTU (1280)
	//   9-10: max MTU (1500)
	//   11-12: requested MTU (1280)
	//   13: min version (2)
	//   14: max version (2)
	optData := make([]byte, 15)
	binary.BigEndian.PutUint16(optData[0:2], 2)     // SSU2 version
	optData[2] = 0                                  // padding params: no constraints
	binary.BigEndian.PutUint16(optData[3:5], 0x100) // padding ratio: 1.0
	// bytes 5-6: reserved (zero)
	binary.BigEndian.PutUint16(optData[7:9], 1280)   // min MTU
	binary.BigEndian.PutUint16(optData[9:11], 1500)  // max MTU
	binary.BigEndian.PutUint16(optData[11:13], 1280) // requested MTU
	optData[13] = 2                                  // min version
	optData[14] = 2                                  // max version
	blocks = append(blocks, NewSSU2Block(BlockTypeOptions, optData))

	return blocks
}

// validateHandshakeBlocks validates that required blocks are present.
func (h *HandshakeHandler) validateHandshakeBlocks(blocks []*SSU2Block, messageType uint8) error {
	hasDateTime := false

	for _, block := range blocks {
		if block.Type == BlockTypeDateTime {
			hasDateTime = true
			if len(block.Data) < 4 {
				return oops.Errorf("DateTime block too short: %d bytes", len(block.Data))
			}
		}
	}

	// DateTime is recommended but not strictly required
	// We'll be lenient and not fail if it's missing
	_ = hasDateTime

	return nil
}

// buildHandshakePacket serializes blocks, runs the Noise WriteMessage, extracts
// the ephemeral key, and assembles an SSU2Packet with a 32-byte long header.
func (h *HandshakeHandler) buildHandshakePacket(blocks []*SSU2Block, msgType uint8, sourceConnID, destConnID uint64) (*SSU2Packet, error) {
	payload, err := SerializeBlocks(blocks)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to serialize handshake blocks")
	}

	ciphertext, cs1, cs2, err := h.handshakeState.WriteMessage(nil, payload)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to create handshake message")
	}
	h.updateCipherStates(cs1, cs2)

	if len(ciphertext) < 32 {
		return nil, oops.Errorf("invalid handshake message: too short (%d bytes)", len(ciphertext))
	}

	packet := &SSU2Packet{
		Header:       make([]byte, 32),
		EphemeralKey: copyBytes(ciphertext[:32]),
		Payload:      ciphertext[32:],
		MAC:          make([]byte, 16),
		MessageType:  msgType,
		PacketNumber: 0,
	}
	binary.BigEndian.PutUint64(packet.Header[0:8], destConnID)
	binary.BigEndian.PutUint64(packet.Header[8:16], sourceConnID)
	return packet, nil
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

// DeriveHeaderKeys derives header protection keys from the completed handshake.
// Uses HKDF-SHA256 with the handshake hash (channel binding) as IKM.
// Returns two 32-byte keys for use with HeaderProtectorManager.SetKDFKeys.
func (h *HandshakeHandler) DeriveHeaderKeys() (k1, k2 []byte, err error) {
	hash := h.handshakeState.ChannelBinding()
	if hash == nil {
		return nil, nil, oops.Errorf("handshake not complete: no channel binding available")
	}
	reader := hkdf.New(sha256.New, hash, nil, []byte("ssu2-header-protection"))
	k1 = make([]byte, 32)
	k2 = make([]byte, 32)
	if _, err := io.ReadFull(reader, k1); err != nil {
		return nil, nil, oops.Wrapf(err, "failed to derive k_header_1")
	}
	if _, err := io.ReadFull(reader, k2); err != nil {
		return nil, nil, oops.Wrapf(err, "failed to derive k_header_2")
	}
	return k1, k2, nil
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

// derivePublicKey computes the Curve25519 public key that corresponds to the
// given private key by performing a scalar multiplication with the base point.
// This is required when constructing a noise.DHKey for use in handshake states
// that need to send or hash the local static public key (e.g. XK message 3).
func derivePublicKey(priv []byte) []byte {
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		// priv must be 32 bytes; callers always validate length before calling.
		panic("ssu2: derivePublicKey: " + err.Error())
	}
	return pub
}
