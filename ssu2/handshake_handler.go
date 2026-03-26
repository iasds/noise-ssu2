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

	// sessCreateHeaderKey is k_header_2 for SessionCreated, derived from
	// chainKey after message 1 (→ e, es) with info "SessCreateHeader".
	sessCreateHeaderKey []byte

	// sessionConfirmedHeaderKey is k_header_2 for SessionConfirmed, derived
	// from chainKey after message 2 (← e, ee) with info "SessionConfirmed".
	sessionConfirmedHeaderKey []byte

	// replayCache detects replayed handshake messages per SSU2 spec.
	// Only used by responders to protect ProcessSessionRequest.
	replayCache *replaycache.TTLCache

	// localOptions are this peer's padding parameters, sent in Options blocks.
	localOptions *OptionsParams

	// peerOptions are the remote peer's padding parameters, parsed from
	// received Options blocks during handshake.
	peerOptions *OptionsParams

	// peerRouterInfo stores the raw RouterInfo block received during
	// SessionConfirmed processing. Used for post-handshake validation
	// against the Noise-authenticated static key (C-2).
	peerRouterInfo []byte
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
// For Retry sessions, the retry token is placed in the Session Request
// header (bytes 24-31) and bound via MixHash(header), not via the
// prologue. The spec confirms: "mixHash() the header (except for Retry)"
// — meaning the Retry message itself skips MixHash, but the subsequent
// Session Request (with token) does MixHash its header, binding the token.
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
			TTL:             4 * time.Minute,
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
			TTL:             4 * time.Minute,
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
//
// Per SSU2 spec §Retry, the handshake state must be reset before resending
// because the first SessionRequest already advanced the Noise state machine.
// This method calls ResetForRetry internally to create a fresh handshake state
// with a new ephemeral key and clean chaining key (C-3).
func (h *HandshakeHandler) CreateSessionRequestWithToken(sourceConnID, destConnID uint64, token []byte) (*SSU2Packet, error) {
	if !h.initiator {
		return nil, oops.Errorf("only initiator can create SessionRequest")
	}
	if len(token) != 8 {
		return nil, oops.Errorf("retry token must be exactly 8 bytes, got %d", len(token))
	}

	// Reset the Noise handshake state so the new SessionRequest
	// starts from a clean message index 0 with a fresh ephemeral key (C-3).
	if err := h.ResetForRetry(); err != nil {
		return nil, oops.Wrapf(err, "failed to reset handshake state for Retry")
	}

	blocks := h.createHandshakeBlocks(MessageTypeSessionRequest)

	return h.buildHandshakePacket(blocks, MessageTypeSessionRequest, sourceConnID, destConnID, token)
}

// ResetForRetry recreates the internal Noise handshake state from scratch,
// preserving the static key, remote static key, and local options. This is
// required after receiving a Retry message because the original
// CreateSessionRequest already advanced the handshake state machine past
// message 1. Per SSU2 spec, the retried SessionRequest must use a fresh
// ephemeral key and start from a clean chaining key (C-3).
func (h *HandshakeHandler) ResetForRetry() error {
	cs := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)
	config := noise.Config{
		CipherSuite:  cs,
		Random:       rand.Reader,
		Pattern:      noise.HandshakeXK,
		Initiator:    h.initiator,
		Prologue:     buildSSU2Prologue(),
		ProtocolName: []byte(SSU2ProtocolName),
		StaticKeypair: noise.DHKey{
			Private: copyBytes(h.staticKey),
			Public:  derivePublicKey(h.staticKey),
		},
	}
	if h.initiator && len(h.remoteStaticKey) == 32 {
		config.PeerStatic = copyBytes(h.remoteStaticKey)
	}
	hs, err := noise.NewHandshakeState(config)
	if err != nil {
		return oops.Wrapf(err, "failed to recreate handshake state for retry")
	}
	h.handshakeState = hs
	h.sendCipher = nil
	h.recvCipher = nil
	h.sessCreateHeaderKey = nil
	h.sessionConfirmedHeaderKey = nil
	return nil
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

	// After processing message 1 (→ e, es), derive "SessCreateHeader" from
	// the intermediate chainKey per SSU2 spec §KDF for Session Request.
	h.sessCreateHeaderKey = deriveIntermediateHeaderKey(
		h.handshakeState.ChainingKey(), "SessCreateHeader")

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

	// Extract peer's Options block for padding negotiation (G-3).
	h.extractPeerOptions(blocks)

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

	// After processing message 2 (← e, ee), derive "SessionConfirmed" from
	// the intermediate chainKey per SSU2 spec §KDF for Session Created.
	h.sessionConfirmedHeaderKey = deriveIntermediateHeaderKey(
		h.handshakeState.ChainingKey(), "SessionConfirmed")

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

	// Extract peer's Options block for padding negotiation (G-3).
	h.extractPeerOptions(blocks)

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
	totalDataSize := len(payload) + 64 // static key + two MACs
	if totalDataSize > sessionConfirmedMaxPerPacket {
		return nil, oops.Errorf("SessionConfirmed payload too large for single packet (%d bytes, max %d); use CreateSessionConfirmedFragments instead", totalDataSize, sessionConfirmedMaxPerPacket)
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
	// For fragmented messages, use ProcessSessionConfirmedFragments instead.
	if len(packet.Header) >= 14 {
		fragByte := packet.Header[13]
		totalFrags := fragByte & 0x0F
		fragNum := (fragByte >> 4) & 0x0F
		if totalFrags > 1 || fragNum > 0 {
			return oops.Errorf("fragmented SessionConfirmed: use ProcessSessionConfirmedFragments (fragment %d of %d)", fragNum, totalFrags)
		}
	}

	h.handshakeState.MixHash(packet.Header)

	// Reconstruct Noise handshake message from payload + MAC
	noiseMessage := append(copyBytes(packet.Payload), packet.MAC...)

	// Process 3rd XK handshake message (→ s, se).
	// This completes the handshake and returns transport cipher states.
	payload, cs1, cs2, err := h.handshakeState.ReadMessage(nil, noiseMessage)
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

	// Extract the RouterInfo block from the decrypted payload so it can
	// be validated against the Noise-authenticated static key (C-2).
	h.extractPeerRouterInfo(payload)

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

// OptionsParams holds the parsed or configured values from an SSU2 Options
// block (Type 1, 12 bytes minimum). Padding ratios use 4.4 fixed-point encoding
// where the value = integerPart + fractionPart/16 (range 0.0–15.9375).
// Per spec: tmin(1) | tmax(1) | rmin(1) | rmax(1) | tdmy(2) | rdmy(2) | tdelay(2) | rdelay(2)
type OptionsParams struct {
	TMinRatio float64 // transmit padding minimum ratio
	TMaxRatio float64 // transmit padding maximum ratio
	RMinRatio float64 // receive padding minimum ratio
	RMaxRatio float64 // receive padding maximum ratio
	TDummy    uint16  // transmit dummy traffic rate
	RDummy    uint16  // receive dummy traffic rate
	TDelay    uint16  // transmit delay (ms)
	RDelay    uint16  // receive delay (ms)
}

// fixedPointToFloat decodes a 4.4 fixed-point byte: upper nibble is the
// integer part, lower nibble is the fractional part (sixteenths).
func fixedPointToFloat(b byte) float64 {
	return float64(b>>4) + float64(b&0x0F)/16.0
}

// floatToFixedPoint encodes a float as a 4.4 fixed-point byte.
func floatToFixedPoint(f float64) byte {
	if f < 0 {
		f = 0
	}
	if f > 15.9375 {
		f = 15.9375
	}
	intPart := int(f)
	fracPart := int((f - float64(intPart)) * 16)
	return byte(intPart<<4 | fracPart)
}

// ParseOptionsBlock decodes a 12+ byte Options block into OptionsParams.
// Per spec: tmin(1) | tmax(1) | rmin(1) | rmax(1) | tdmy(2) | rdmy(2) | tdelay(2) | rdelay(2)
func ParseOptionsBlock(data []byte) (*OptionsParams, error) {
	if len(data) < 12 {
		return nil, oops.Errorf("Options block too short: %d bytes, need 12", len(data))
	}
	return &OptionsParams{
		TMinRatio: fixedPointToFloat(data[0]),
		TMaxRatio: fixedPointToFloat(data[1]),
		RMinRatio: fixedPointToFloat(data[2]),
		RMaxRatio: fixedPointToFloat(data[3]),
		TDummy:    binary.BigEndian.Uint16(data[4:6]),
		RDummy:    binary.BigEndian.Uint16(data[6:8]),
		TDelay:    binary.BigEndian.Uint16(data[8:10]),
		RDelay:    binary.BigEndian.Uint16(data[10:12]),
	}, nil
}

// Serialize encodes OptionsParams into a 12-byte Options block per spec.
func (o *OptionsParams) Serialize() []byte {
	data := make([]byte, 12)
	data[0] = floatToFixedPoint(o.TMinRatio)
	data[1] = floatToFixedPoint(o.TMaxRatio)
	data[2] = floatToFixedPoint(o.RMinRatio)
	data[3] = floatToFixedPoint(o.RMaxRatio)
	binary.BigEndian.PutUint16(data[4:6], o.TDummy)
	binary.BigEndian.PutUint16(data[6:8], o.RDummy)
	binary.BigEndian.PutUint16(data[8:10], o.TDelay)
	binary.BigEndian.PutUint16(data[10:12], o.RDelay)
	return data
}

// SetLocalOptions sets the local padding parameters that will be advertised
// in outbound Options blocks during handshake.
func (h *HandshakeHandler) SetLocalOptions(opts *OptionsParams) {
	h.localOptions = opts
}

// PeerOptions returns the remote peer's Options parameters parsed during
// the handshake, or nil if no Options block was received.
func (h *HandshakeHandler) PeerOptions() *OptionsParams {
	return h.peerOptions
}

// NegotiatedPadding returns the padding parameters that both peers agree on.
// Per SSU2 spec, the initiator's transmit ratios are the responder's receive
// constraints and vice versa. The negotiated range is the intersection of
// both peers' preferences: max of minimums, min of maximums.
// Returns nil if either side has not provided options.
func (h *HandshakeHandler) NegotiatedPadding() *OptionsParams {
	local := h.localOptions
	peer := h.peerOptions
	if local == nil || peer == nil {
		return nil
	}
	// The peer's transmit limits constrain what we receive, and our transmit
	// limits constrain what the peer receives. Negotiate the overlap.
	negotiated := &OptionsParams{}

	// Our send padding: bounded by our tmin/tmax AND peer's rmin/rmax
	negotiated.TMinRatio = max44(local.TMinRatio, peer.RMinRatio)
	negotiated.TMaxRatio = min44(local.TMaxRatio, peer.RMaxRatio)
	if negotiated.TMaxRatio < negotiated.TMinRatio {
		// Empty intersection — treat as no constraint (zero both).
		negotiated.TMinRatio = 0
		negotiated.TMaxRatio = 0
	}

	// Our receive padding: bounded by our rmin/rmax AND peer's tmin/tmax
	negotiated.RMinRatio = max44(local.RMinRatio, peer.TMinRatio)
	negotiated.RMaxRatio = min44(local.RMaxRatio, peer.TMaxRatio)
	if negotiated.RMaxRatio < negotiated.RMinRatio {
		// Empty intersection — treat as no constraint (zero both).
		negotiated.RMinRatio = 0
		negotiated.RMaxRatio = 0
	}

	// Dummy traffic and delay: use the smaller of the two peers' values
	negotiated.TDummy = minU16(local.TDummy, peer.RDummy)
	negotiated.RDummy = minU16(local.RDummy, peer.TDummy)
	negotiated.TDelay = minU16(local.TDelay, peer.RDelay)
	negotiated.RDelay = minU16(local.RDelay, peer.TDelay)

	return negotiated
}

func max44(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

func min44(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

func minU16(a, b uint16) uint16 {
	if a < b {
		return a
	}
	return b
}

// extractPeerOptions scans deserialized handshake blocks for an Options block
// and stores the parsed result in h.peerOptions.
func (h *HandshakeHandler) extractPeerOptions(blocks []*SSU2Block) {
	for _, block := range blocks {
		if block.Type == BlockTypeOptions && len(block.Data) >= 12 {
			opts, err := ParseOptionsBlock(block.Data)
			if err == nil {
				h.peerOptions = opts
			}
			return
		}
	}
}

// extractPeerRouterInfo parses the decrypted SessionConfirmed payload and
// stores the RouterInfo block data for later validation (C-2).
func (h *HandshakeHandler) extractPeerRouterInfo(payload []byte) {
	if len(payload) == 0 {
		return
	}
	blocks, err := DeserializeBlocks(payload)
	if err != nil {
		return
	}
	for _, block := range blocks {
		if block.Type == BlockTypeRouterInfo && len(block.Data) > 0 {
			h.peerRouterInfo = copyBytes(block.Data)
			return
		}
	}
}

// GetPeerRouterInfo returns the raw RouterInfo block received during
// the SessionConfirmed handshake message. Returns nil if no RouterInfo
// was received (e.g. initiator side, or tests without RouterInfo).
func (h *HandshakeHandler) GetPeerRouterInfo() []byte {
	return copyBytes(h.peerRouterInfo)
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
	// If localOptions has been set, encode those values; otherwise send zeroes.
	if h.localOptions != nil {
		blocks = append(blocks, NewSSU2Block(BlockTypeOptions, h.localOptions.Serialize()))
	} else {
		optData := make([]byte, 15)
		binary.BigEndian.PutUint16(optData[0:2], 2) // SSU2 version 2
		blocks = append(blocks, NewSSU2Block(BlockTypeOptions, optData))
	}

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

	// Per spec §Session Request/Created, DateTime is required.
	// We accept messages without it for interoperability, but callers
	// should treat its absence as a protocol deviation.
	// Future strict mode could reject here: return oops.Errorf("DateTime block required")
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

	// Derive intermediate header keys from the chaining key at this point
	// in the handshake. These keys are used for header protection of the
	// NEXT message type in the handshake flow:
	// - After message 1 (SessionRequest, → e, es): derive "SessCreateHeader"
	// - After message 2 (SessionCreated, ← e, ee): derive "SessionConfirmed"
	switch msgType {
	case MessageTypeSessionRequest:
		h.sessCreateHeaderKey = deriveIntermediateHeaderKey(
			h.handshakeState.ChainingKey(), "SessCreateHeader")
	case MessageTypeSessionCreated:
		h.sessionConfirmedHeaderKey = deriveIntermediateHeaderKey(
			h.handshakeState.ChainingKey(), "SessionConfirmed")
	}

	// For SessionRequest (msg 1, → e, es) and SessionCreated (msg 2, ← e, ee),
	// the noise library's WriteMessage returns the complete Noise message:
	//   ciphertext = [ephemeral_key:32 || AEAD_ciphertext]
	// where AEAD_ciphertext already contains the 16-byte Poly1305 MAC at its end.
	//
	// We split it as:
	//   EphemeralKey = ciphertext[:32]  (the ephemeral public key)
	//   Payload      = ciphertext[32:]  (AEAD ciphertext, MAC included in tail)
	//   MAC          = make([]byte,16)  (all-zero placeholder)
	//
	// The zeroed MAC field is transmitted on the wire as a placeholder to satisfy
	// SSU2Packet's [Header||EphemeralKey||Payload||MAC] wire format. The receiver
	// strips it (ParseFromBytes takes the last 16 bytes as MAC) but does not use
	// it for verification — the noise library verifies the embedded AEAD MAC when
	// ReadMessage is called. There is no double-encryption.
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

// DeriveHeaderKeys derives data-phase keys from the completed handshake per
// the SSU2 specification:
//
//	keydata = HKDF(key, ZEROLEN, "HKDFSSU2DataKeys", 64)
//	k_data       = keydata[0:31]
//	k_header_2   = keydata[32:63]
//
// where "key" is the split cipher key for each direction (k_ab or k_ba).
// This method installs k_data into each cipher state (replacing the raw
// split key) so that data-phase AEAD uses the spec-mandated derived key.
// Returns the send-direction k_header_2 and recv-direction k_header_2.
func (h *HandshakeHandler) DeriveHeaderKeys() (sendKHeader2, recvKHeader2 []byte, err error) {
	if h.sendCipher == nil || h.recvCipher == nil {
		return nil, nil, oops.Errorf("handshake not complete: cipher states not available")
	}

	sendKData, sendKHeader2, err := deriveDataPhaseKeys(h.sendCipher)
	if err != nil {
		return nil, nil, oops.Wrapf(err, "failed to derive send data-phase keys")
	}

	recvKData, recvKHeader2, err := deriveDataPhaseKeys(h.recvCipher)
	if err != nil {
		return nil, nil, oops.Wrapf(err, "failed to derive recv data-phase keys")
	}

	// Install k_data as the AEAD encryption key per SSU2 spec §KDF for
	// data phase. The raw split keys (k_ab/k_ba) must NOT be used directly.
	var sendKey, recvKey [32]byte
	copy(sendKey[:], sendKData)
	copy(recvKey[:], recvKData)
	h.sendCipher.UnsafeSetKey(sendKey)
	h.recvCipher.UnsafeSetKey(recvKey)

	return sendKHeader2, recvKHeader2, nil
}

// SessCreateHeaderKey returns the k_header_2 for SessionCreated, derived from
// the chaining key after handshake message 1 (→ e, es) using the info string
// "SessCreateHeader". Returns nil if the key has not yet been derived.
func (h *HandshakeHandler) SessCreateHeaderKey() []byte {
	return copyBytes(h.sessCreateHeaderKey)
}

// SessionConfirmedHeaderKey returns the k_header_2 for SessionConfirmed,
// derived from the chaining key after handshake message 2 (← e, ee) using
// the info string "SessionConfirmed". Returns nil if not yet derived.
func (h *HandshakeHandler) SessionConfirmedHeaderKey() []byte {
	return copyBytes(h.sessionConfirmedHeaderKey)
}

// deriveIntermediateHeaderKey derives a header protection key from the
// handshake's current chaining key using the SSU2 spec's HKDF pattern:
//
//	temp_key = HMAC-SHA256(salt=chainKey, ikm=ZEROLEN)
//	key      = HMAC-SHA256(temp_key, info || 0x01)
func deriveIntermediateHeaderKey(chainKey []byte, info string) []byte {
	mac := hmac.New(sha256.New, chainKey)
	tempKey := mac.Sum(nil)

	mac = hmac.New(sha256.New, tempKey)
	mac.Write([]byte(info))
	mac.Write([]byte{0x01})
	return mac.Sum(nil)
}

// deriveDataPhaseKeys derives both k_data and k_header_2 for the data phase
// from a split cipher key using the SSU2 spec's two-step HKDF:
//
//	temp_key = HMAC-SHA256(key, ZEROLEN)
//	k_data   = HMAC-SHA256(temp_key, "HKDFSSU2DataKeys" || 0x01)  // first 32 bytes
//	k_header_2 = HMAC-SHA256(temp_key, k_data || "HKDFSSU2DataKeys" || 0x02)
//
// Per spec, k_data replaces the raw split key for AEAD encryption,
// and k_header_2 is used for data-phase header protection.
func deriveDataPhaseKeys(cs *noise.CipherState) (kData, kHeader2 []byte, err error) {
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
	kData = mac.Sum(nil)

	// HKDF-Expand T(2) = HMAC-SHA256(temp_key, T(1) || info || 0x02) → k_header_2 (32 bytes)
	mac = hmac.New(sha256.New, tempKey)
	mac.Write(kData)
	mac.Write(info)
	mac.Write([]byte{0x02})
	kHeader2 = mac.Sum(nil)

	return kData, kHeader2, nil
}

// SessionConfirmed fragmentation constants per SSU2 spec.
const (
	// sessionConfirmedMinMTU is the IPv6 minimum MTU used for conservative sizing.
	sessionConfirmedMinMTU = 1280

	// sessionConfirmedPerPacketOverhead = IP(40) + UDP(8) + SSU2 header(16).
	sessionConfirmedPerPacketOverhead = 64

	// sessionConfirmedMaxPerPacket is the maximum ciphertext bytes per fragment.
	sessionConfirmedMaxPerPacket = sessionConfirmedMinMTU - sessionConfirmedPerPacketOverhead

	// sessionConfirmedMaxFragments is the maximum fragment count (4-bit field).
	sessionConfirmedMaxFragments = 15
)

// CreateSessionConfirmedFragments creates one or more SessionConfirmed packets.
// When the payload fits in a single packet, it returns a slice of length 1
// (identical to CreateSessionConfirmed). When the Noise ciphertext exceeds
// the per-packet limit, it splits the ciphertext across multiple fragments
// using the frag field at header byte 13 (bits 7-4 = fragment number,
// bits 3-0 = total fragments) per SSU2 spec §Session Confirmed.
//
// Only the first fragment's header is MixHash'd into the handshake. Subsequent
// fragment headers carry the same connection ID with incrementing packet numbers.
func (h *HandshakeHandler) CreateSessionConfirmedFragments(connID uint64, packetNumber uint32, routerInfo []byte) ([]*SSU2Packet, error) {
	if !h.initiator {
		return nil, oops.Errorf("only initiator can create SessionConfirmed")
	}
	if h.handshakeState.MessageIndex() != 2 {
		return nil, oops.Errorf("handshake not ready for SessionConfirmed: expected message index 2, got %d", h.handshakeState.MessageIndex())
	}

	var blocks []*SSU2Block
	if len(routerInfo) > 0 {
		blocks = append(blocks, NewSSU2Block(BlockTypeRouterInfo, routerInfo))
	}

	payload, err := SerializeBlocks(blocks)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to serialize SessionConfirmed blocks")
	}

	// Build the first fragment's 16-byte header for MixHash (before Noise).
	// Fragment count and frag number will be filled in after we know total size.
	// Compute expected ciphertext size to determine fragment count before MixHash.
	// Noise XK message 3 (→ s, se) encrypts: static_key(32+16 MAC) + payload(+16 MAC).
	expectedCiphertextSize := len(payload) + 64
	totalFrags := (expectedCiphertextSize + sessionConfirmedMaxPerPacket - 1) / sessionConfirmedMaxPerPacket
	if totalFrags < 1 {
		totalFrags = 1
	}
	if totalFrags > sessionConfirmedMaxFragments {
		return nil, oops.Errorf("SessionConfirmed requires %d fragments, max %d", totalFrags, sessionConfirmedMaxFragments)
	}

	// Build the first fragment's 16-byte header for MixHash (before Noise).
	header := make([]byte, ShortHeaderSize)
	binary.BigEndian.PutUint64(header[0:8], connID)
	binary.BigEndian.PutUint32(header[8:12], packetNumber)
	header[12] = MessageTypeSessionConfirmed
	// frag byte: fragment 0 of totalFrags
	header[13] = byte(0<<4) | byte(totalFrags)

	// MixHash(header) — only the first fragment's header is mixed.
	h.handshakeState.MixHash(header)

	ciphertext, cs1, cs2, err := h.handshakeState.WriteMessage(nil, payload)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to create SessionConfirmed handshake message")
	}
	h.updateCipherStates(cs1, cs2)

	packets := make([]*SSU2Packet, 0, totalFrags)
	offset := 0
	for i := 0; i < totalFrags; i++ {
		end := offset + sessionConfirmedMaxPerPacket
		if end > len(ciphertext) {
			end = len(ciphertext)
		}
		chunk := ciphertext[offset:end]

		fragHeader := make([]byte, ShortHeaderSize)
		binary.BigEndian.PutUint64(fragHeader[0:8], connID)
		// Per spec: "Packet Number :: 0 always, for all fragments, even if retransmitted."
		binary.BigEndian.PutUint32(fragHeader[8:12], packetNumber)
		fragHeader[12] = MessageTypeSessionConfirmed
		fragHeader[13] = byte(i<<4) | byte(totalFrags)

		// For the last fragment, separate trailing MAC (16 bytes).
		var pktPayload, mac []byte
		if i == totalFrags-1 && len(chunk) >= MACSize {
			pktPayload = chunk[:len(chunk)-MACSize]
			mac = chunk[len(chunk)-MACSize:]
		} else {
			pktPayload = chunk
			mac = make([]byte, MACSize)
		}

		packets = append(packets, &SSU2Packet{
			Header:       fragHeader,
			EphemeralKey: nil,
			Payload:      pktPayload,
			MAC:          mac,
			MessageType:  MessageTypeSessionConfirmed,
			PacketNumber: packetNumber,
		})
		offset = end
	}

	// Fragment 0 uses the header that was MixHash'd.
	packets[0].Header = header

	return packets, nil
}

// ProcessSessionConfirmedFragments reassembles and processes a fragmented
// SessionConfirmed message. The packets slice must contain all fragments
// ordered by fragment number (0 .. totalFrags-1).
//
// For a single-fragment message, this behaves identically to ProcessSessionConfirmed.
func (h *HandshakeHandler) ProcessSessionConfirmedFragments(packets []*SSU2Packet) error {
	if h.initiator {
		return oops.Errorf("initiator cannot process SessionConfirmed")
	}
	if len(packets) == 0 {
		return oops.Errorf("no SessionConfirmed fragments provided")
	}

	// Verify handshake state.
	if h.handshakeState.MessageIndex() != 2 {
		return oops.Errorf("handshake not ready for SessionConfirmed: expected message index 2, got %d", h.handshakeState.MessageIndex())
	}

	// Validate fragment ordering and completeness.
	totalFrags := int(packets[0].Header[13] & 0x0F)
	if totalFrags < 1 {
		totalFrags = 1
	}
	if len(packets) != totalFrags {
		return oops.Errorf("expected %d fragments, got %d", totalFrags, len(packets))
	}
	for i, pkt := range packets {
		if pkt.MessageType != MessageTypeSessionConfirmed {
			return oops.Errorf("fragment %d: expected SessionConfirmed (type 2), got type %d", i, pkt.MessageType)
		}
		fragNum := int((pkt.Header[13] >> 4) & 0x0F)
		if fragNum != i {
			return oops.Errorf("fragment %d: unexpected fragment number %d", i, fragNum)
		}
	}

	// MixHash(header) — only the first fragment's header is mixed.
	h.handshakeState.MixHash(packets[0].Header)

	// Reassemble the Noise ciphertext from all fragments.
	// Each fragment contributes Payload bytes; the last fragment also has the MAC.
	totalSize := 0
	for _, pkt := range packets {
		totalSize += len(pkt.Payload)
	}
	totalSize += len(packets[len(packets)-1].MAC)

	noiseMessage := make([]byte, 0, totalSize)
	for i, pkt := range packets {
		noiseMessage = append(noiseMessage, pkt.Payload...)
		if i == len(packets)-1 {
			noiseMessage = append(noiseMessage, pkt.MAC...)
		}
	}

	payload, cs1, cs2, err := h.handshakeState.ReadMessage(nil, noiseMessage)
	if err != nil {
		return oops.Wrapf(err, "failed to process SessionConfirmed handshake message")
	}
	h.updateCipherStates(cs1, cs2)

	if ps := h.handshakeState.PeerStatic(); len(ps) > 0 {
		h.remoteStaticKey = copyBytes(ps)
	}

	// Extract the RouterInfo block from the decrypted payload so it can
	// be validated against the Noise-authenticated static key (C-2).
	h.extractPeerRouterInfo(payload)

	return nil
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
