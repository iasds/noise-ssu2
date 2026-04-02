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

	// maxClockSkew is the maximum allowed difference between local and
	// remote timestamps (G-1). If > 0, validateHandshakeBlocks rejects
	// DateTime blocks whose timestamp differs from local time by more
	// than this value. Set from SSU2Config.MaxClockSkew.
	maxClockSkew time.Duration
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
	log.WithField("initiator", initiator).Debug("Creating new HandshakeHandler")
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
	log.WithField("initiator", initiator).Debug("Creating new HandshakeHandler with keys")
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

// LocalOptions returns the locally configured Options parameters, or nil
// if none were set via SetLocalOptions (G-6).
func (h *HandshakeHandler) LocalOptions() *OptionsParams {
	return h.localOptions
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
		// Default 12-byte Options block per spec §Options Block (M-2).
		optData := make([]byte, 12)
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
			if err := h.validateTimestampSkew(block.Data); err != nil {
				return err
			}
		}
	}

	// Per spec §Session Request/Created, DateTime is required (M-1).
	if !hasDateTime {
		return oops.Errorf("DateTime block required in message type %d per SSU2 spec", messageType)
	}

	return nil
}

// validateTimestampSkew checks that the remote timestamp is within
// maxClockSkew of local time. If maxClockSkew is 0, skew validation
// is disabled (G-1).
func (h *HandshakeHandler) validateTimestampSkew(dateTimeData []byte) error {
	if h.maxClockSkew <= 0 {
		return nil
	}
	remoteTime := time.Unix(int64(binary.BigEndian.Uint32(dateTimeData[:4])), 0)
	skew := time.Since(remoteTime)
	if skew < 0 {
		skew = -skew
	}
	if skew > h.maxClockSkew {
		return oops.Errorf("clock skew %s exceeds maximum %s", skew, h.maxClockSkew)
	}
	return nil
}

// buildHandshakePacket serializes blocks, builds the long header, calls
// MixHash(header) per the SSU2 specification, runs the Noise WriteMessage,
// extracts the ephemeral key, and assembles an SSU2Packet.
// token may be nil for initial requests, or an 8-byte slice for Retry sessions.
func (h *HandshakeHandler) buildHandshakePacket(blocks []*SSU2Block, msgType uint8, sourceConnID, destConnID uint64, token []byte) (*SSU2Packet, error) {
	// Per SSU2 spec §Session Request: destConnID=0 is only valid for
	// the initial SessionRequest. Reject zero for all other message types (C-1).
	if destConnID == 0 && msgType != MessageTypeSessionRequest {
		return nil, oops.Errorf("destConnID=0 is only allowed for SessionRequest (type %d), got type %d", MessageTypeSessionRequest, msgType)
	}

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
	log.Debug("Deriving data-phase header keys")
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

// Close releases resources held by the HandshakeHandler, including the
// replay cache's background goroutine.
func (h *HandshakeHandler) Close() {
	log.Debug("Closing HandshakeHandler")
	if h.replayCache != nil {
		h.replayCache.Close()
	}
}

// ReconfigureReplayCache replaces the replay cache with one using the
// given TTL. This allows callers to override the default 4-minute TTL
// from SSU2Config (M-2).
func (h *HandshakeHandler) ReconfigureReplayCache(ttl time.Duration) {
	if h.replayCache != nil {
		h.replayCache.Close()
	}
	h.replayCache = replaycache.New(replaycache.Config{
		TTL:             ttl,
		MaxSize:         1024,
		CleanupInterval: 30 * time.Second,
	})
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
