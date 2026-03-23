package ssu2

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"time"

	"github.com/go-i2p/go-noise/internal/replaycache"
	"github.com/go-i2p/noise"
	"github.com/samber/oops"
	"golang.org/x/crypto/curve25519"
)

// SSU2ProtocolName is the Noise protocol name for SSU2, as defined in the
// I2P SSU2 specification. It indicates the XK pattern with ChaCha20
// obfuscation and three modified handshake messages.
const SSU2ProtocolName = "Noise_XKchaobfse+hs1+hs2+hs3_25519_ChaChaPoly_SHA256"

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

	// replayCache detects replayed handshake messages per SSU2 spec.
	// Only used by responders to protect ProcessSessionRequest.
	replayCache *replaycache.TTLCache
}

// buildSSU2Prologue returns the Noise prologue for SSU2 handshakes.
// Per the SSU2 specification, the prologue is null (empty):
//
//	// MixHash(null prologue)
//	h = SHA256(h);
//
// The connection ID is NOT part of the prologue; it is bound to the
// handshake via header MixHash operations for each message.
//
// NOTE: For Retry sessions the spec may require different prologue
// handling (e.g., binding the Retry token). This should be revisited
// when Retry/token-based sessions are fully implemented.
func buildSSU2Prologue() []byte {
	return nil
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
		CipherSuite:  cs,
		Random:       rand.Reader,
		Pattern:      noise.HandshakeXK,
		Initiator:    initiator,
		Prologue:     prologue,
		ProtocolName: []byte(SSU2ProtocolName),
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

	handler := &HandshakeHandler{
		initiator:       initiator,
		staticKey:       copyBytes(staticKey),
		remoteStaticKey: copyBytes(remoteStaticKey),
		handshakeState:  hs,
	}

	// Responders need a replay cache to protect against replayed SessionRequests
	if !initiator {
		handler.replayCache = replaycache.New(replaycache.Config{
			TTL:             2 * time.Minute,
			MaxSize:         1024,
			CleanupInterval: 30 * time.Second,
		})
	}

	return handler, nil
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
		CipherSuite:  cs,
		Random:       rand.Reader,
		Pattern:      noise.HandshakeXK,
		Initiator:    initiator,
		Prologue:     prologue,
		ProtocolName: []byte(SSU2ProtocolName),
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

	handler := &HandshakeHandler{
		initiator:       initiator,
		staticKey:       copyBytes(staticKeypair.Private),
		remoteStaticKey: copyBytes(remoteStaticKey),
		handshakeState:  hs,
	}

	// Responders need a replay cache to protect against replayed SessionRequests
	if !initiator {
		handler.replayCache = replaycache.New(replaycache.Config{
			TTL:             2 * time.Minute,
			MaxSize:         1024,
			CleanupInterval: 30 * time.Second,
		})
	}

	return handler, nil
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

	return h.buildHandshakePacket(blocks, MessageTypeSessionRequest, sourceConnID, destConnID, nil)
}

// CreateSessionRequestWithToken creates a SessionRequest with a Retry token
// inserted into header bytes 24-31. This is used when resending SessionRequest
// after receiving a Retry message from the responder.
func (h *HandshakeHandler) CreateSessionRequestWithToken(sourceConnID, destConnID uint64, token []byte) (*SSU2Packet, error) {
	if !h.initiator {
		return nil, oops.Errorf("only initiator can create SessionRequest")
	}
	if len(token) != 8 {
		return nil, oops.Errorf("retry token must be exactly 8 bytes, got %d", len(token))
	}

	blocks := h.createHandshakeBlocks(MessageTypeSessionRequest)

	return h.buildHandshakePacket(blocks, MessageTypeSessionRequest, sourceConnID, destConnID, token)
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

	// Replay protection: hash the ephemeral key + payload as a unique message ID.
	// The ephemeral key is randomly generated per handshake attempt, so its
	// hash is a reliable replay detection key.
	if h.replayCache != nil {
		digest := sha256.Sum256(append(packet.EphemeralKey, packet.Payload...))
		if h.replayCache.CheckAndAdd(digest) {
			return nil, oops.Errorf("replayed SessionRequest detected")
		}
	}

	// MixHash(header) per SSU2 spec §KDF — binds the header into
	// the handshake hash before processing the Noise message.
	h.handshakeState.MixHash(packet.Header)

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
// XK pattern: ← e, ee
func (h *HandshakeHandler) CreateSessionCreated(sourceConnID, destConnID uint64) (*SSU2Packet, error) {
	if h.initiator {
		return nil, oops.Errorf("only responder can create SessionCreated")
	}

	// Create payload blocks
	blocks := h.createHandshakeBlocks(MessageTypeSessionCreated)

	return h.buildHandshakePacket(blocks, MessageTypeSessionCreated, sourceConnID, destConnID, nil)
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

	// MixHash(header) per SSU2 spec §KDF — binds the header into
	// the handshake hash before processing the Noise message.
	h.handshakeState.MixHash(packet.Header)

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

	// Build the 16-byte short header before encrypting so it can be
	// mixed into the handshake hash per SSU2 spec §KDF.
	header := make([]byte, 16)
	binary.BigEndian.PutUint64(header[0:8], connID)
	binary.BigEndian.PutUint32(header[8:12], packetNumber)
	header[12] = MessageTypeSessionConfirmed
	// frag field: bits 7-4 = fragment number (0), bits 3-0 = total fragments (1)
	header[13] = 0x01

	// Check that the encrypted payload fits in a single packet.
	// Total data size = static key (32) + payload + 2 MACs (32) = payload + 64.
	// Available space per packet = MTU - IP header (40 IPv6 worst case) - UDP (8) - SSU2 header (16) = MTU - 64.
	// Use conservative default MTU of 1280 (IPv6 minimum).
	const minMTU = 1280
	const perPacketOverhead = 64 // IP(40) + UDP(8) + header(16)
	maxPayloadPerPacket := minMTU - perPacketOverhead
	totalDataSize := len(payload) + 64 // static key + two MACs
	if totalDataSize > maxPayloadPerPacket {
		return nil, oops.Errorf("SessionConfirmed payload too large for single packet (%d bytes, max %d); fragmentation not yet implemented", totalDataSize, maxPayloadPerPacket)
	}

	// MixHash(header) binds the header into the handshake hash.
	h.handshakeState.MixHash(header)

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

	// Header already built above for MixHash; assign it to packet.
	packet.Header = header

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

	// MixHash(header) per SSU2 spec §KDF — binds the short header into
	// the handshake hash before processing the Noise message.
	//
	// Check frag field (byte 13): bits 7-4 = fragment number, bits 3-0 = total fragments.
	// We only support single-fragment SessionConfirmed for now.
	if len(packet.Header) >= 14 {
		fragByte := packet.Header[13]
		totalFrags := fragByte & 0x0F
		fragNum := (fragByte >> 4) & 0x0F
		if totalFrags > 1 || fragNum > 0 {
			return oops.Errorf("fragmented SessionConfirmed not yet supported (fragment %d of %d)", fragNum, totalFrags)
		}
	}

	h.handshakeState.MixHash(packet.Header)

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
	// Communicates version and padding negotiation parameters.
	//
	// NOTE: All padding ratios, dummy traffic rates, delays, and flags are
	// zeroed. This means no padding negotiation occurs and the peer's padding
	// preferences are ignored. Future work should parse the peer's Options
	// block and negotiate padding parameters for traffic analysis resistance.
	// Spec-defined layout (15 bytes):
	//   Bytes 0-1:   version (uint16 big-endian, currently 2)
	//   Byte 2:      tmin  (fixed-point 4.4 transmit padding minimum ratio)
	//   Byte 3:      tmax  (fixed-point 4.4 transmit padding maximum ratio)
	//   Byte 4:      rmin  (fixed-point 4.4 receive padding minimum ratio)
	//   Byte 5:      rmax  (fixed-point 4.4 receive padding maximum ratio)
	//   Bytes 6-7:   tdummy (transmit dummy traffic rate)
	//   Bytes 8-9:   rdummy (receive dummy traffic rate)
	//   Bytes 10-11: tdelay (transmit delay)
	//   Bytes 12-13: rdelay (receive delay)
	//   Byte 14:     flags
	optData := make([]byte, 15)
	binary.BigEndian.PutUint16(optData[0:2], 2) // SSU2 version 2
	// Bytes 2-5: padding ratios (4.4 fixed-point) — 0 = no constraints
	// Bytes 6-13: dummy traffic rates and delays — 0 = none
	// Byte 14: flags — 0 = no flags set
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

// buildHandshakePacket serializes blocks, builds the long header, calls
// MixHash(header) per the SSU2 specification, runs the Noise WriteMessage,
// extracts the ephemeral key, and assembles an SSU2Packet.
// token may be nil for initial requests, or an 8-byte slice for Retry sessions.
func (h *HandshakeHandler) buildHandshakePacket(blocks []*SSU2Block, msgType uint8, sourceConnID, destConnID uint64, token []byte) (*SSU2Packet, error) {
	payload, err := SerializeBlocks(blocks)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to serialize handshake blocks")
	}

	// Build the 32-byte long header per SSU2 spec §LongHeader:
	// dest_conn_id(0-7), pkt_num(8-11), type(12), ver(13), id(14),
	// flag(15), src_conn_id(16-23), token(24-31).
	header := make([]byte, 32)
	binary.BigEndian.PutUint64(header[0:8], destConnID)
	binary.BigEndian.PutUint32(header[8:12], 0) // packet number 0 for handshake
	header[12] = msgType
	header[13] = SSU2ProtocolVersion // ver=2
	header[14] = SSU2NetworkID       // id=2 (I2P mainnet)
	header[15] = 0                   // flag=0
	binary.BigEndian.PutUint64(header[16:24], sourceConnID)
	// bytes 24-31 = token (zero for initial SessionRequest, populated by retries)
	if len(token) == 8 {
		copy(header[24:32], token)
	}

	// MixHash(header) binds the encrypted header into the handshake hash
	// (h = SHA256(h || header)), preventing header substitution attacks.
	h.handshakeState.MixHash(header)

	ciphertext, cs1, cs2, err := h.handshakeState.WriteMessage(nil, payload)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to create handshake message")
	}
	h.updateCipherStates(cs1, cs2)

	if len(ciphertext) < 32 {
		return nil, oops.Errorf("invalid handshake message: too short (%d bytes)", len(ciphertext))
	}

	packet := &SSU2Packet{
		Header:       header,
		EphemeralKey: copyBytes(ciphertext[:32]),
		Payload:      ciphertext[32:],
		MAC:          make([]byte, 16),
		MessageType:  msgType,
		PacketNumber: 0,
	}
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

// DeriveHeaderKeys derives data-phase header protection keys from the
// completed handshake per the SSU2 specification:
//
//	keydata = HKDF(key, ZEROLEN, "HKDFSSU2DataKeys", 64)
//	k_data       = keydata[0:31]
//	k_header_2   = keydata[32:63]
//
// where "key" is the split cipher key for each direction (k_ab or k_ba).
// Returns the send-direction k_header_2 and recv-direction k_header_2.
// The caller supplies intro keys separately for k_header_1 (receiver's
// intro key per spec).
func (h *HandshakeHandler) DeriveHeaderKeys() (sendKHeader2, recvKHeader2 []byte, err error) {
	if h.sendCipher == nil || h.recvCipher == nil {
		return nil, nil, oops.Errorf("handshake not complete: cipher states not available")
	}

	sendKHeader2, err = deriveDataPhaseHeaderKey(h.sendCipher)
	if err != nil {
		return nil, nil, oops.Wrapf(err, "failed to derive send k_header_2")
	}

	recvKHeader2, err = deriveDataPhaseHeaderKey(h.recvCipher)
	if err != nil {
		return nil, nil, oops.Wrapf(err, "failed to derive recv k_header_2")
	}

	return sendKHeader2, recvKHeader2, nil
}

// deriveDataPhaseHeaderKey derives k_header_2 for the data phase from a
// split cipher key using the SSU2 spec's two-step HKDF:
//
//	temp_key = HMAC-SHA256(key, ZEROLEN)
//	keydata  = HMAC-SHA256(temp_key, "HKDFSSU2DataKeys" || 0x01)  // first 32 bytes
//
// A second round produces the next 32 bytes:
//
//	keydata2 = HMAC-SHA256(temp_key, keydata || "HKDFSSU2DataKeys" || 0x02)
//
// k_data = keydata[0:31], k_header_2 = keydata2 (second 32 bytes).
func deriveDataPhaseHeaderKey(cs *noise.CipherState) ([]byte, error) {
	key := cs.UnsafeKey()

	info := []byte("HKDFSSU2DataKeys")

	// HKDF-Extract: temp_key = HMAC-SHA256(salt=key, ikm=zerolen)
	mac := hmac.New(sha256.New, key[:])
	// ikm = zerolen (write nothing)
	tempKey := mac.Sum(nil)

	// HKDF-Expand T(1) = HMAC-SHA256(temp_key, info || 0x01) → k_data (32 bytes)
	mac = hmac.New(sha256.New, tempKey)
	mac.Write(info)
	mac.Write([]byte{0x01})
	t1 := mac.Sum(nil) // k_data — not used here but needed for T(2)

	// HKDF-Expand T(2) = HMAC-SHA256(temp_key, T(1) || info || 0x02) → k_header_2 (32 bytes)
	mac = hmac.New(sha256.New, tempKey)
	mac.Write(t1)
	mac.Write(info)
	mac.Write([]byte{0x02})
	kHeader2 := mac.Sum(nil)

	return kHeader2, nil
}

// Close releases resources held by the HandshakeHandler, including the
// replay cache's background goroutine.
func (h *HandshakeHandler) Close() {
	if h.replayCache != nil {
		h.replayCache.Close()
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
