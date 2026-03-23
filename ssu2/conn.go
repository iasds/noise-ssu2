package ssu2

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-i2p/noise"
	"github.com/samber/oops"
)

// ConnState represents the current state of an SSU2 connection.
type ConnState int

const (
	// StateInit is the initial state before handshake
	StateInit ConnState = iota
	// StateHandshaking is during the XK handshake
	StateHandshaking
	// StateEstablished means handshake complete, ready for data
	StateEstablished
	// StateClosing is graceful shutdown in progress
	StateClosing
	// StateClosed means connection is fully closed
	StateClosed
)

const (
	// rekeyThreshold is the send-sequence value at which we initiate a
	// NextNonce rekey. Per the SSU2 spec the 32-bit packet number must
	// not wrap, so we start the rekey handshake well before 0xFFFFFFFF.
	rekeyThreshold uint32 = 0xFFFF_FF00

	// maxPacketRetries is the maximum number of retransmission attempts
	// before a pending packet is dropped.
	maxPacketRetries = 5

	// retransmitInterval is how often the retransmit loop checks for
	// expired pending packets.
	retransmitInterval = 250 * time.Millisecond
)

// String returns a human-readable state name.
func (s ConnState) String() string {
	switch s {
	case StateInit:
		return "Init"
	case StateHandshaking:
		return "Handshaking"
	case StateEstablished:
		return "Established"
	case StateClosing:
		return "Closing"
	case StateClosed:
		return "Closed"
	default:
		return "Unknown"
	}
}

// SSU2Conn implements net.Conn for SSU2 transport connections over UDP.
// It integrates HandshakeHandler, DataHandler, and ACKHandler to provide
// a complete connection implementation following the SSU2 protocol.
//
// SSU2Conn handles:
// - XK pattern handshake (SessionRequest/Created/Confirmed)
// - Reliable ordered data delivery with ACKs
// - Fragment reassembly for large messages
// - Out-of-order packet buffering
// - RTT estimation and congestion control
// - Keepalive mechanism
//
// Thread Safety: All public methods are thread-safe.
type SSU2Conn struct {
	// underlying is the UDP connection for sending/receiving packets
	underlying net.PacketConn

	// remoteAddr is the UDP address of the peer
	remoteAddr *net.UDPAddr

	// ssu2Addr contains SSU2-specific addressing info
	ssu2Addr *SSU2Addr

	// config holds connection configuration
	config *SSU2Config

	// initiator indicates if we initiated the connection
	initiator bool

	// Protocol handlers
	handshakeHandler *HandshakeHandler
	dataHandler      *DataHandler
	ackHandler       *ACKHandler
	rttEstimator     *RTTEstimator
	recvWindow       *ReceiveWindow

	// Header protection (nil = disabled)
	headerProtector *HeaderProtectorManager

	// Connection state
	state      ConnState
	stateMutex sync.RWMutex
	closeChan  chan struct{}
	closeOnce  sync.Once
	closeErr   error
	closeMutex sync.Mutex

	// Cipher states for transport phase (after handshake)
	sendCipher  *noise.CipherState
	recvCipher  *noise.CipherState
	cipherMutex sync.RWMutex

	// Packet management
	sendQueue    chan *SSU2Packet
	recvQueue    chan *SSU2Packet
	sendSequence uint32
	sendSeqMutex sync.Mutex

	// Pending outbound packets awaiting ACK
	pendingPackets map[uint32]*PendingPacket
	pendingMutex   sync.RWMutex

	// Deadlines
	readDeadline  time.Time
	writeDeadline time.Time
	deadlineMutex sync.RWMutex

	// Keepalive
	lastActivity     time.Time
	lastActivityLock sync.RWMutex
	keepaliveTimer   *time.Timer

	// Nonce rekeying: tracks whether a NextNonce block has been sent
	// for the current send cipher. Reset after rekey completes.
	rekeyInFlight atomic.Bool

	// Background goroutines coordination
	wg sync.WaitGroup

	// Error counters for observability (recvLoop)
	readErrors    atomic.Uint64
	parseErrors   atomic.Uint64
	decryptErrors atomic.Uint64

	// validDataPacketsReceived counts successfully received data-phase packets.
	// Included in the Termination block per spec §Termination.
	validDataPacketsReceived atomic.Uint64
}

// PendingPacket tracks an outbound packet awaiting acknowledgment.
type PendingPacket struct {
	Packet           *SSU2Packet
	PlaintextPayload []byte // pre-encryption payload for retransmit
	SentTime         time.Time
	Retries          int
	NextRetry        time.Time
}

// NewSSU2Conn creates a new SSU2 connection.
// The connection starts in StateInit and must call Handshake() before data transfer.
//
// Parameters:
// - underlying: UDP PacketConn for sending/receiving
// - remoteAddr: Peer's UDP address
// - config: SSU2 configuration (validated before use)
// - initiator: true if we initiate handshake, false if responding
// - staticKey: our static X25519 private key (32 bytes)
// - remoteStaticKey: peer's static public key (32 bytes, required for initiator)
func NewSSU2Conn(
	underlying net.PacketConn,
	remoteAddr *net.UDPAddr,
	config *SSU2Config,
	initiator bool,
	staticKey []byte,
	remoteStaticKey []byte,
) (*SSU2Conn, error) {
	if underlying == nil {
		return nil, oops.Errorf("underlying PacketConn is nil")
	}
	if remoteAddr == nil {
		return nil, oops.Errorf("remoteAddr is nil")
	}
	if config == nil {
		return nil, oops.Errorf("config is nil")
	}

	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, oops.Wrapf(err, "invalid config")
	}

	// Determine connection ID before creating handshake handler (needed for prologue)
	connID := config.ConnectionID
	if connID == 0 {
		var genErr error
		connID, genErr = GenerateConnectionID()
		if genErr != nil {
			return nil, oops.Wrapf(genErr, "failed to generate connection ID")
		}
	}

	// Per spec: Source and Destination Connection IDs must NOT be identical.
	if config.InitiatorConnectionID != 0 && config.InitiatorConnectionID == connID {
		return nil, oops.Errorf("connection ID collision: source and destination IDs are identical (%d)", connID)
	}

	// Build Noise prologue — per spec, prologue is null (empty).
	prologue := buildSSU2Prologue()

	// Create handshake handler with prologue binding
	handshakeHandler, err := NewHandshakeHandler(initiator, staticKey, remoteStaticKey, prologue)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to create handshake handler")
	}

	// Create SSU2 address from config
	role := "initiator"
	if !initiator {
		role = "responder"
	}

	ssu2Addr, err := NewSSU2Addr(remoteAddr, config.RouterHash, connID, role)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to create SSU2 address")
	}

	// Create connection instance
	conn := &SSU2Conn{
		underlying:       underlying,
		remoteAddr:       remoteAddr,
		ssu2Addr:         ssu2Addr,
		config:           config,
		initiator:        initiator,
		handshakeHandler: handshakeHandler,
		dataHandler:      NewDataHandler(100), // 100 message queue size
		ackHandler:       NewACKHandler(),
		rttEstimator:     NewRTTEstimator(),
		recvWindow:       NewReceiveWindow(0, 256), // start at 0, max 256 packets
		state:            StateInit,
		closeChan:        make(chan struct{}),
		sendQueue:        make(chan *SSU2Packet, 64),
		recvQueue:        make(chan *SSU2Packet, 64),
		pendingPackets:   make(map[uint32]*PendingPacket),
		lastActivity:     time.Now(),
	}

	// Initialize header protection if intro keys are provided
	if len(config.IntroKey) == HeaderKeySize {
		hpm, hpErr := NewHeaderProtectorManager(config.IntroKey, config.RemoteIntroKey, initiator)
		if hpErr != nil {
			return nil, oops.Wrapf(hpErr, "failed to create header protector")
		}
		conn.headerProtector = hpm
	}

	return conn, nil
}

// messageTypeToHeaderType maps an SSU2 message type to the corresponding
// header protection type used for key selection.
func messageTypeToHeaderType(msgType uint8) HeaderType {
	switch msgType {
	case MessageTypeSessionRequest:
		return HeaderTypeSessionRequest
	case MessageTypeSessionCreated:
		return HeaderTypeSessionCreated
	case MessageTypeSessionConfirmed:
		// SessionConfirmed uses KDF-derived keys per spec.
		return HeaderTypeSessionConfirmed
	case MessageTypeRetry:
		return HeaderTypeRetry
	case MessageTypeTokenRequest:
		return HeaderTypeTokenRequest
	case MessageTypePeerTest:
		return HeaderTypePeerTest
	case MessageTypeHolePunch:
		return HeaderTypeHolePunch
	default:
		return HeaderTypeData
	}
}

// expectedInboundHeaderType returns the header type to use when decrypting
// inbound packets, based on the current connection state.
func (h *SSU2Conn) expectedInboundHeaderType() HeaderType {
	h.stateMutex.RLock()
	state := h.state
	h.stateMutex.RUnlock()

	if state == StateEstablished {
		return HeaderTypeData
	}
	// During handshake, use intro-key-based types.
	if h.initiator {
		return HeaderTypeSessionCreated
	}
	return HeaderTypeSessionRequest
}

// Handshake performs the SSU2 XK pattern handshake.
// For initiators: sends SessionRequest, receives SessionCreated, sends SessionConfirmed
// For responders: receives SessionRequest, sends SessionCreated, receives SessionConfirmed
//
// After successful handshake, connection state transitions to StateEstablished.
func (h *SSU2Conn) Handshake(ctx context.Context) error {
	h.stateMutex.Lock()
	if h.state != StateInit {
		h.stateMutex.Unlock()
		return oops.Errorf("invalid state for handshake: %s", h.state)
	}
	h.state = StateHandshaking
	h.stateMutex.Unlock()

	// Start recvLoop (needed during handshake for receivePacketWithTimeout).
	// Started here rather than in the constructor so that callers who create
	// a conn but never call Handshake or Close don't leak a goroutine.
	h.wg.Add(1)
	go h.recvLoop()

	if h.initiator {
		return h.handshakeInitiator(ctx)
	}
	return h.handshakeResponder(ctx)
}

// handshakeInitiator performs the initiator side of XK handshake.
func (h *SSU2Conn) handshakeInitiator(ctx context.Context) error {
	// Step 1: Create SessionRequest
	sessionRequest, err := h.handshakeHandler.CreateSessionRequest(h.config.ConnectionID, 0)
	if err != nil {
		return oops.Wrapf(err, "failed to create SessionRequest")
	}

	// Step 2: Send SessionRequest and wait for SessionCreated, with retransmit.
	// Per spec: handshake packets are retransmitted whole with identical contents.
	if err := h.sendPacketDirect(sessionRequest); err != nil {
		return oops.Wrapf(err, "failed to send SessionRequest")
	}

	response, err := h.receiveHandshakeWithRetransmit(ctx, sessionRequest, h.config.HandshakeTimeout)
	if err != nil {
		return oops.Wrapf(err, "failed to receive SessionCreated")
	}

	// Handle Retry: responder may require a token before proceeding.
	if response.MessageType == MessageTypeRetry {
		token, err := h.extractRetryToken(response)
		if err != nil {
			return oops.Wrapf(err, "failed to extract Retry token")
		}

		// Resend SessionRequest with the token inserted at header bytes 24-31.
		sessionRequest, err = h.handshakeHandler.CreateSessionRequestWithToken(
			h.config.ConnectionID, 0, token,
		)
		if err != nil {
			return oops.Wrapf(err, "failed to create SessionRequest with Retry token")
		}
		if err := h.sendPacketDirect(sessionRequest); err != nil {
			return oops.Wrapf(err, "failed to send SessionRequest with token")
		}
		response, err = h.receiveHandshakeWithRetransmit(ctx, sessionRequest, h.config.HandshakeTimeout)
		if err != nil {
			return oops.Wrapf(err, "failed to receive SessionCreated after Retry")
		}
	}

	if response.MessageType != MessageTypeSessionCreated {
		return oops.Errorf("expected SessionCreated, got type %d", response.MessageType)
	}

	// Step 3: Process SessionCreated
	if err := h.handshakeHandler.ProcessSessionCreated(response); err != nil {
		return oops.Wrapf(err, "failed to process SessionCreated")
	}

	// Step 4: Create and send SessionConfirmed (3rd XK message) with RouterInfo
	sessionConfirmed, err := h.handshakeHandler.CreateSessionConfirmed(h.config.ConnectionID, 1, h.config.RouterHash)
	if err != nil {
		return oops.Wrapf(err, "failed to create SessionConfirmed")
	}

	if err := h.sendPacketDirect(sessionConfirmed); err != nil {
		return oops.Wrapf(err, "failed to send SessionConfirmed")
	}

	// Step 5: Finalize handshake
	return h.finalizeHandshake()
}

// handshakeResponder performs the responder side of XK handshake.
func (h *SSU2Conn) handshakeResponder(ctx context.Context) error {
	// Step 1: Wait for SessionRequest (no retransmit on first receive)
	sessionRequest, err := h.receivePacketWithTimeout(ctx, h.config.HandshakeTimeout)
	if err != nil {
		return oops.Wrapf(err, "failed to receive SessionRequest")
	}

	if sessionRequest.MessageType != MessageTypeSessionRequest {
		return oops.Errorf("expected SessionRequest, got type %d", sessionRequest.MessageType)
	}

	// Step 2: Process SessionRequest
	_, err = h.handshakeHandler.ProcessSessionRequest(sessionRequest)
	if err != nil {
		return oops.Wrapf(err, "failed to process SessionRequest")
	}

	// Step 3: Create and send SessionCreated
	sessionCreated, err := h.handshakeHandler.CreateSessionCreated(0, h.config.ConnectionID)
	if err != nil {
		return oops.Wrapf(err, "failed to create SessionCreated")
	}

	if err := h.sendPacketDirect(sessionCreated); err != nil {
		return oops.Wrapf(err, "failed to send SessionCreated")
	}

	// Step 4: Wait for SessionConfirmed, retransmitting SessionCreated if needed.
	// Per spec: handshake packets are retransmitted whole with identical contents.
	sessionConfirmed, err := h.receiveHandshakeWithRetransmit(ctx, sessionCreated, h.config.HandshakeTimeout)
	if err != nil {
		return oops.Wrapf(err, "failed to receive SessionConfirmed")
	}

	if sessionConfirmed.MessageType != MessageTypeSessionConfirmed {
		return oops.Errorf("expected SessionConfirmed, got type %d", sessionConfirmed.MessageType)
	}

	// Step 5: Process SessionConfirmed
	if err := h.handshakeHandler.ProcessSessionConfirmed(sessionConfirmed); err != nil {
		return oops.Wrapf(err, "failed to process SessionConfirmed")
	}

	// Step 6: Finalize handshake
	return h.finalizeHandshake()
}

// finalizeHandshake checks completion, installs cipher states, transitions to
// established, and starts data loops. Shared by both initiator and responder.
func (h *SSU2Conn) finalizeHandshake() error {
	if !h.handshakeHandler.IsHandshakeComplete() {
		return oops.Errorf("handshake not complete after SessionConfirmed")
	}
	if err := h.installCipherStates(); err != nil {
		return oops.Wrapf(err, "failed to install cipher states")
	}

	// Install KDF-derived header protection keys for data phase
	if h.headerProtector != nil {
		k1, k2, err := h.handshakeHandler.DeriveHeaderKeys()
		if err != nil {
			return oops.Wrapf(err, "failed to derive header protection keys")
		}
		if err := h.headerProtector.SetKDFKeys(k1, k2); err != nil {
			return oops.Wrapf(err, "failed to set header protection KDF keys")
		}
	}

	h.stateMutex.Lock()
	h.state = StateEstablished
	h.stateMutex.Unlock()
	h.startDataLoops()
	return nil
}

// startDataLoops starts background goroutines for data transport.
// Called after handshake completes to avoid wasting resources on failed connections.
func (h *SSU2Conn) startDataLoops() {
	h.wg.Add(3)
	go h.sendLoop()
	go h.keepaliveLoop()
	go h.retransmitLoop()
}

// installCipherStates transfers transport cipher states from the handshake handler.
func (h *SSU2Conn) installCipherStates() error {
	send, recv, err := h.handshakeHandler.GetCipherStates()
	if err != nil {
		return err
	}
	h.cipherMutex.Lock()
	h.sendCipher = send
	h.recvCipher = recv
	h.cipherMutex.Unlock()

	// Wire NextNonce callback so peer-initiated rekeys are applied.
	cbs := h.dataHandler.getCallbacks()
	cbs.OnNextNonce = h.handlePeerNextNonce
	h.dataHandler.SetCallbacks(cbs)

	// Update router hash from peer's static key if available
	if peerKey := h.handshakeHandler.GetRemoteStaticKey(); len(peerKey) == 32 {
		hash := sha256.Sum256(peerKey)
		h.ssu2Addr.UpdateRouterHash(hash[:])
	}

	return nil
}

// validateReadyForIO checks that the connection is in the Established state
// and ready for read/write operations.
func (h *SSU2Conn) validateReadyForIO() error {
	h.stateMutex.RLock()
	state := h.state
	h.stateMutex.RUnlock()

	if state != StateEstablished {
		return oops.Errorf("connection not established: %s", state)
	}
	return nil
}

// Read implements net.Conn.Read.
// Reads data from the connection, reassembling I2NP messages from Data packets.
// Blocks until data is available, the read deadline expires, or the connection closes.
func (h *SSU2Conn) Read(b []byte) (int, error) {
	if err := h.validateReadyForIO(); err != nil {
		return 0, err
	}

	// Block until a message arrives, the connection closes, or the deadline expires
	var msg []byte
	select {
	case msg = <-h.dataHandler.MessageChan():
		// Message received
	case <-h.closeChan:
		return 0, oops.Errorf("connection closed")
	case <-h.getReadDeadline():
		return 0, oops.Errorf("read deadline exceeded")
	}

	// Copy message to buffer
	n := copy(b, msg)
	if n < len(msg) {
		return n, oops.Errorf("buffer too small: need %d bytes, got %d", len(msg), len(b))
	}

	return n, nil
}

// Write implements net.Conn.Write.
// Writes data to the connection, fragmenting if needed.
func (h *SSU2Conn) Write(b []byte) (int, error) {
	if err := h.validateReadyForIO(); err != nil {
		return 0, err
	}

	// Create I2NP message block
	block := &SSU2Block{
		Type: BlockTypeI2NPMessage,
		Data: copyBytes(b),
	}

	if err := h.writeBlock(block); err != nil {
		return 0, err
	}
	return len(b), nil
}

// WriteBlocks sends the provided SSU2 blocks as individual Data packets (one
// packet per block). Unlike Write, this bypasses the BlockTypeI2NPMessage
// wrapper and sends pre-built blocks directly. Use this to send fragment
// blocks (BlockTypeFirstFragment / BlockTypeFollowOnFragment) for large I2NP
// messages.
func (h *SSU2Conn) WriteBlocks(blocks []*SSU2Block) error {
	if err := h.validateReadyForIO(); err != nil {
		return err
	}
	for _, block := range blocks {
		if err := h.writeBlock(block); err != nil {
			return err
		}
	}
	return nil
}

// writeBlock sends a single SSU2Block as a Data packet.
func (h *SSU2Conn) writeBlock(block *SSU2Block) error {
	pktNum := h.nextSendSequence()
	hdr := make([]byte, ShortHeaderSize)
	binary.BigEndian.PutUint64(hdr[0:8], h.config.ConnectionID)
	binary.BigEndian.PutUint32(hdr[8:12], pktNum)
	// byte 12 = MessageType will be written by Serialize()
	packet := &SSU2Packet{
		MessageType:  MessageTypeData,
		PacketNumber: pktNum,
		Payload:      nil,
		Header:       hdr,
		MAC:          make([]byte, MACSize), // placeholder; real MAC is in encrypted payload
	}

	// Serialize block into payload
	payload, err := SerializeBlocks([]*SSU2Block{block})
	if err != nil {
		return oops.Wrapf(err, "failed to serialize block")
	}
	packet.Payload = payload

	// Enqueue for sending
	select {
	case h.sendQueue <- packet:
		return nil
	case <-h.closeChan:
		return oops.Errorf("connection closed")
	case <-h.getWriteDeadline():
		return oops.Errorf("write deadline exceeded")
	}
}

// Close implements net.Conn.Close.
// Sends a Termination block and closes the connection.
func (h *SSU2Conn) Close() error {
	h.closeOnce.Do(func() {
		// Update state first
		h.stateMutex.Lock()
		h.state = StateClosing
		h.stateMutex.Unlock()

		// Send Termination block (best effort)
		// Spec §Termination: validDataPacketsReceived(8 bytes, big-endian) + reason(1 byte)
		termBlock := &SSU2Block{
			Type: BlockTypeTermination,
			Data: make([]byte, 9),
		}
		binary.BigEndian.PutUint64(termBlock.Data[0:8], h.validDataPacketsReceived.Load())
		termBlock.Data[8] = 0 // Reason: 0 (normal close)

		// Create Data packet with termination block
		pktNum := h.nextSendSequence()
		hdr := make([]byte, ShortHeaderSize)
		binary.BigEndian.PutUint64(hdr[0:8], h.config.ConnectionID)
		binary.BigEndian.PutUint32(hdr[8:12], pktNum)
		packet := &SSU2Packet{
			MessageType:  MessageTypeData,
			PacketNumber: pktNum,
			Header:       hdr,
			MAC:          make([]byte, MACSize),
		}
		payload, err := SerializeBlocks([]*SSU2Block{termBlock})
		if err == nil {
			packet.Payload = payload
			_ = h.sendPacketDirect(packet) // Best effort, ignore errors
		}

		// Stop keepalive timer
		if h.keepaliveTimer != nil {
			h.keepaliveTimer.Stop()
		}

		// Close channels to signal goroutines to exit
		close(h.closeChan)

		// Wait for background goroutines to complete
		h.wg.Wait()

		// Update final state
		h.stateMutex.Lock()
		h.state = StateClosed
		h.stateMutex.Unlock()
	})

	h.closeMutex.Lock()
	defer h.closeMutex.Unlock()
	return h.closeErr
}

// LocalAddr implements net.Conn.LocalAddr.
func (h *SSU2Conn) LocalAddr() net.Addr {
	if localUDPAddr, ok := h.underlying.LocalAddr().(*net.UDPAddr); ok {
		role := "initiator"
		if !h.initiator {
			role = "responder"
		}
		addr, err := NewSSU2Addr(localUDPAddr, h.config.RouterHash, h.config.ConnectionID, role)
		if err == nil {
			return addr
		}
	}
	return h.underlying.LocalAddr()
}

// RemoteAddr implements net.Conn.RemoteAddr.
func (h *SSU2Conn) RemoteAddr() net.Addr {
	return h.ssu2Addr
}

// SetDeadline implements net.Conn.SetDeadline.
func (h *SSU2Conn) SetDeadline(t time.Time) error {
	h.deadlineMutex.Lock()
	defer h.deadlineMutex.Unlock()
	h.readDeadline = t
	h.writeDeadline = t
	return nil
}

// SetReadDeadline implements net.Conn.SetReadDeadline.
func (h *SSU2Conn) SetReadDeadline(t time.Time) error {
	h.deadlineMutex.Lock()
	defer h.deadlineMutex.Unlock()
	h.readDeadline = t
	return nil
}

// SetWriteDeadline implements net.Conn.SetWriteDeadline.
func (h *SSU2Conn) SetWriteDeadline(t time.Time) error {
	h.deadlineMutex.Lock()
	defer h.deadlineMutex.Unlock()
	h.writeDeadline = t
	return nil
}

// GetState returns the current connection state.
func (h *SSU2Conn) GetState() ConnState {
	h.stateMutex.RLock()
	defer h.stateMutex.RUnlock()
	return h.state
}

// RecvStats returns error counters from the receive loop for observability.
// Keys: "read_errors", "parse_errors", "decrypt_errors".
func (h *SSU2Conn) RecvStats() map[string]uint64 {
	return map[string]uint64{
		"read_errors":    h.readErrors.Load(),
		"parse_errors":   h.parseErrors.Load(),
		"decrypt_errors": h.decryptErrors.Load(),
	}
}

// SetDataHandlerCallbacks wires application-level callbacks for SSU2 block types
// received during the data phase. Call before Handshake() completes to ensure
// callbacks are active from the first data packet. Safe to call concurrently
// with an active connection; updates take effect on the next inbound packet.
func (h *SSU2Conn) SetDataHandlerCallbacks(cbs DataHandlerCallbacks) {
	h.dataHandler.SetCallbacks(cbs)
}

// sendLoop handles outbound packet transmission.
func (h *SSU2Conn) sendLoop() {
	defer h.wg.Done()

	for {
		select {
		case packet := <-h.sendQueue:
			if err := h.sendPacketDirect(packet); err != nil {
				// Log error but continue
				continue
			}
		case <-h.closeChan:
			return
		}
	}
}

// retransmitLoop periodically scans pendingPackets for RTO expiry and
// re-enqueues expired packets. Packets exceeding maxPacketRetries are dropped.
func (h *SSU2Conn) retransmitLoop() {
	defer h.wg.Done()

	ticker := time.NewTicker(retransmitInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			h.retransmitExpired()
		case <-h.closeChan:
			return
		}
	}
}

// retransmitExpired checks all pending packets and retransmits those that
// have exceeded their NextRetry deadline.
func (h *SSU2Conn) retransmitExpired() {
	now := time.Now()
	rto := h.rttEstimator.GetRTO()

	h.pendingMutex.Lock()
	defer h.pendingMutex.Unlock()

	for pn, pp := range h.pendingPackets {
		if now.Before(pp.NextRetry) {
			continue
		}

		if pp.Retries >= maxPacketRetries {
			delete(h.pendingPackets, pn)
			continue
		}

		pp.Retries++
		// Exponential backoff: double the RTO for each retry
		backoff := rto * time.Duration(1<<pp.Retries)
		pp.NextRetry = now.Add(backoff)

		// Per spec: retransmissions must use a fresh packet number.
		newPktNum := h.nextSendSequence()
		hdr := make([]byte, ShortHeaderSize)
		binary.BigEndian.PutUint64(hdr[0:8], h.config.ConnectionID)
		binary.BigEndian.PutUint32(hdr[8:12], newPktNum)
		newPacket := &SSU2Packet{
			MessageType:  MessageTypeData,
			PacketNumber: newPktNum,
			Header:       hdr,
			MAC:          make([]byte, MACSize),
			Payload:      make([]byte, len(pp.PlaintextPayload)),
		}
		copy(newPacket.Payload, pp.PlaintextPayload)

		// Remove old entry; sendPacketDirect will track the new one.
		delete(h.pendingPackets, pn)

		// Best-effort re-enqueue; drop if sendQueue is full
		select {
		case h.sendQueue <- newPacket:
		default:
		}
	}
}

// recvLoop handles inbound packet reception.
func (h *SSU2Conn) recvLoop() {
	defer h.wg.Done()

	// Buffer must hold any valid SSU2 packet; use MaxPacketSizeIPv4 so we
	// never truncate legitimate packets regardless of the configured MTU.
	buf := make([]byte, MaxPacketSizeIPv4)
	for {
		select {
		case <-h.closeChan:
			return
		default:
			_ = h.underlying.SetReadDeadline(time.Now().Add(1 * time.Second))

			n, addr, err := h.underlying.ReadFrom(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				h.readErrors.Add(1)
				continue
			}

			if packet := h.parseInboundPacket(buf[:n], addr); packet != nil {
				h.processInboundPacket(packet)
			}
		}
	}
}

// parseInboundPacket validates the source address, deserializes, and decrypts an
// inbound UDP datagram. Returns nil if the packet should be dropped.
func (h *SSU2Conn) parseInboundPacket(data []byte, addr net.Addr) *SSU2Packet {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok || !udpAddr.IP.Equal(h.remoteAddr.IP) || udpAddr.Port != h.remoteAddr.Port {
		return nil
	}

	// Decrypt header protection before parsing
	if h.headerProtector != nil {
		hType := h.expectedInboundHeaderType()
		if err := h.headerProtector.DecryptInboundHeader(data, hType); err != nil {
			h.parseErrors.Add(1)
			return nil
		}
	}

	packet := &SSU2Packet{}
	if err := packet.Deserialize(data); err != nil {
		h.parseErrors.Add(1)
		return nil
	}

	h.cipherMutex.Lock()
	cipher := h.recvCipher
	if cipher != nil && packet.MessageType == MessageTypeData && len(packet.Payload) > 0 {
		// Per SSU2 spec: nonce is the packet number, AD is the 16-byte header.
		cipher.SetNonce(uint64(packet.PacketNumber))
		decrypted, err := cipher.Decrypt(nil, packet.Header[:ShortHeaderSize], packet.Payload)
		if err != nil {
			h.cipherMutex.Unlock()
			h.decryptErrors.Add(1)
			return nil
		}
		packet.Payload = decrypted
	}
	h.cipherMutex.Unlock()

	h.updateActivity()
	return packet
}

// keepaliveLoop manages connection keepalive.
func (h *SSU2Conn) keepaliveLoop() {
	defer h.wg.Done()

	ticker := time.NewTicker(h.config.KeepaliveInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			h.lastActivityLock.RLock()
			timeSinceActivity := time.Since(h.lastActivity)
			h.lastActivityLock.RUnlock()

			// Check if we need to send keepalive
			if timeSinceActivity >= h.config.KeepaliveInterval {
				// Send ACK as keepalive (empty ACK)
				if ack, err := h.ackHandler.GenerateACK(); err == nil && ack != nil {
					pktNum := h.nextSendSequence()
					hdr := make([]byte, ShortHeaderSize)
					binary.BigEndian.PutUint64(hdr[0:8], h.config.ConnectionID)
					binary.BigEndian.PutUint32(hdr[8:12], pktNum)
					packet := &SSU2Packet{
						MessageType:  MessageTypeData,
						PacketNumber: pktNum,
						Header:       hdr,
						MAC:          make([]byte, MACSize),
					}
					payload, _ := SerializeBlocks([]*SSU2Block{ack})
					packet.Payload = payload
					_ = h.sendPacketDirect(packet)
				}
			}

			// Check for timeout (5 minutes default idle timeout)
			idleTimeout := 5 * time.Minute
			if timeSinceActivity >= idleTimeout {
				h.closeMutex.Lock()
				h.closeErr = oops.Errorf("idle timeout")
				h.closeMutex.Unlock()
				_ = h.Close()
				return
			}
		case <-h.closeChan:
			return
		}
	}
}

// sendPacketDirect sends a packet directly to the peer.
// For data packets in the established state, the payload is encrypted with AEAD.
func (h *SSU2Conn) sendPacketDirect(packet *SSU2Packet) error {
	// Save plaintext payload before encryption for potential retransmit.
	var plaintextPayload []byte

	// Encrypt payload for data packets when cipher states are available.
	// Lock is exclusive because SetNonce+Encrypt must be atomic.
	h.cipherMutex.Lock()
	cipher := h.sendCipher
	if cipher != nil && packet.MessageType == MessageTypeData && len(packet.Payload) > 0 {
		plaintextPayload = make([]byte, len(packet.Payload))
		copy(plaintextPayload, packet.Payload)
		// Per SSU2 spec: nonce is the packet number, AD is the 16-byte header.
		cipher.SetNonce(uint64(packet.PacketNumber))
		encrypted, err := cipher.Encrypt(nil, packet.Header[:ShortHeaderSize], packet.Payload)
		if err != nil {
			h.cipherMutex.Unlock()
			return oops.Wrapf(err, "failed to encrypt payload")
		}
		packet.Payload = encrypted
	}
	h.cipherMutex.Unlock()

	// Serialize packet
	data, err := packet.Serialize()
	if err != nil {
		return oops.Wrapf(err, "failed to serialize packet")
	}

	// Apply header protection if enabled
	if h.headerProtector != nil {
		hType := messageTypeToHeaderType(packet.MessageType)
		if hpErr := h.headerProtector.EncryptOutboundHeader(data, hType); hpErr != nil {
			return oops.Wrapf(hpErr, "failed to encrypt header")
		}
	}

	// Send to peer
	_, err = h.underlying.WriteTo(data, h.remoteAddr)
	if err != nil {
		return oops.Wrapf(err, "failed to write to UDP")
	}

	// Update activity
	h.updateActivity()

	// Track pending packet if it needs ACK
	if packet.MessageType == MessageTypeData && packet.PacketNumber > 0 {
		h.pendingMutex.Lock()
		h.pendingPackets[packet.PacketNumber] = &PendingPacket{
			Packet:           packet,
			PlaintextPayload: plaintextPayload,
			SentTime:         time.Now(),
			Retries:          0,
			NextRetry:        time.Now().Add(h.rttEstimator.GetRTO()),
		}
		h.pendingMutex.Unlock()
	}

	return nil
}

// processInboundPacket processes a received packet.
func (h *SSU2Conn) processInboundPacket(packet *SSU2Packet) {
	// Record for ACK
	if packet.PacketNumber > 0 {
		h.ackHandler.RecordReceived(packet.PacketNumber)
	}

	switch packet.MessageType {
	case MessageTypeData:
		h.validDataPacketsReceived.Add(1)
		// Check immediate-ack flag: header byte 13, bit 0
		if len(packet.Header) > 13 && packet.Header[13]&0x01 != 0 {
			h.sendImmediateACK()
		}
		h.processDataPacket(packet)
	case MessageTypeSessionRequest, MessageTypeSessionCreated, MessageTypeSessionConfirmed:
		select {
		case h.recvQueue <- packet:
		default:
		}
	}
}

// processDataPacket handles a data-phase packet: parses blocks and retires ACKed packets.
func (h *SSU2Conn) processDataPacket(packet *SSU2Packet) {
	blocks, err := h.dataHandler.ProcessDataPacket(packet)
	if err != nil {
		return
	}

	// Process ACK blocks
	for _, block := range blocks {
		if block.Type == BlockTypeACK {
			ackedNums, _ := h.ackHandler.ProcessACK(block)
			// Remove acknowledged packets from pending queue
			h.pendingMutex.Lock()
			for _, num := range ackedNums {
				delete(h.pendingPackets, num)
			}
			h.pendingMutex.Unlock()
		}
	}
}

// sendImmediateACK generates and sends an ACK packet without delay, honoring
// the immediate-ack flag (header byte 13 bit 0) from the peer.
func (h *SSU2Conn) sendImmediateACK() {
	ack, err := h.ackHandler.GenerateACK()
	if err != nil || ack == nil {
		return
	}
	pktNum := h.nextSendSequence()
	hdr := make([]byte, ShortHeaderSize)
	binary.BigEndian.PutUint64(hdr[0:8], h.config.ConnectionID)
	binary.BigEndian.PutUint32(hdr[8:12], pktNum)
	packet := &SSU2Packet{
		MessageType:  MessageTypeData,
		PacketNumber: pktNum,
		Header:       hdr,
		MAC:          make([]byte, MACSize),
	}
	payload, _ := SerializeBlocks([]*SSU2Block{ack})
	packet.Payload = payload
	_ = h.sendPacketDirect(packet)
}

// extractRetryToken parses a Retry message and returns the 8-byte token.
func (h *SSU2Conn) extractRetryToken(retry *SSU2Packet) ([]byte, error) {
	blocks, err := DeserializeBlocks(retry.Payload)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to parse Retry payload")
	}
	tokenBlock := FindBlockByType(blocks, BlockTypeNewToken)
	if tokenBlock == nil {
		return nil, oops.Errorf("Retry message missing NewToken block")
	}
	parsed, err := ParseNewTokenBlock(tokenBlock)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to parse NewToken block from Retry")
	}
	return parsed.Token, nil
}

// receivePacketWithTimeout waits for a packet with timeout.
func (h *SSU2Conn) receivePacketWithTimeout(ctx context.Context, timeout time.Duration) (*SSU2Packet, error) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case packet := <-h.recvQueue:
		return packet, nil
	case <-timer.C:
		return nil, oops.Errorf("timeout waiting for packet")
	case <-ctx.Done():
		return nil, oops.Wrapf(ctx.Err(), "context cancelled")
	case <-h.closeChan:
		return nil, oops.Errorf("connection closed")
	}
}

// receiveHandshakeWithRetransmit waits for the next handshake message, retransmitting
// lastSent if no response arrives within a per-attempt interval.
// Per spec: handshake packets MUST be retransmitted with the same packet number
// and identical encrypted contents.
func (h *SSU2Conn) receiveHandshakeWithRetransmit(ctx context.Context, lastSent *SSU2Packet, totalTimeout time.Duration) (*SSU2Packet, error) {
	const maxRetransmits = 3
	attemptTimeout := totalTimeout / time.Duration(maxRetransmits+1)
	if attemptTimeout < time.Second {
		attemptTimeout = time.Second
	}

	deadline := time.Now().Add(totalTimeout)
	for attempt := 0; attempt <= maxRetransmits; attempt++ {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			break
		}
		wait := attemptTimeout
		if wait > remaining {
			wait = remaining
		}

		pkt, err := h.receivePacketWithTimeout(ctx, wait)
		if err == nil {
			return pkt, nil
		}

		// On context cancellation or connection close, don't retry.
		select {
		case <-ctx.Done():
			return nil, oops.Wrapf(ctx.Err(), "context cancelled during handshake retransmit")
		case <-h.closeChan:
			return nil, oops.Errorf("connection closed during handshake retransmit")
		default:
		}

		// Retransmit the last sent handshake packet with identical contents.
		if attempt < maxRetransmits {
			_ = h.sendPacketDirect(lastSent)
		}
	}
	return nil, oops.Errorf("handshake timeout after %d retransmits", maxRetransmits)
}

// nextSendSequence returns the next packet sequence number.
// When the sequence crosses rekeyThreshold, it fires a one-shot
// NextNonce rekey so the cipher is refreshed before the 32-bit
// counter wraps.
//
// NOTE: The SSU2 spec marks NextNonce (block type 11) as "TODO only if we
// rotate keys" with size "TBD". This rekey mechanism is based on an
// unfinalized spec area and may need revision when the spec is updated.
func (h *SSU2Conn) nextSendSequence() uint32 {
	h.sendSeqMutex.Lock()
	defer h.sendSeqMutex.Unlock()
	seq := h.sendSequence
	h.sendSequence++

	// Trigger rekey exactly once when we cross the threshold.
	if seq >= rekeyThreshold && !h.rekeyInFlight.Load() {
		if h.rekeyInFlight.CompareAndSwap(false, true) {
			go h.initiateRekey()
		}
	}
	return seq
}

// initiateRekey sends a NextNonce block to the peer, then rekeys the local
// send cipher and resets the send sequence counter.
func (h *SSU2Conn) initiateRekey() {
	h.cipherMutex.Lock()
	defer h.cipherMutex.Unlock()

	if h.sendCipher == nil {
		return
	}

	// Rekey the send cipher (REKEY per Noise spec).
	h.sendCipher.Rekey()

	// New starting nonce for the rekeyed cipher is 0.
	h.sendCipher.SetNonce(0)

	// Build a NextNonce block with the new starting nonce (0).
	var nonceBuf [8]byte
	// nonceBuf is already zero-valued, which is what we want.
	block := &SSU2Block{
		Type: BlockTypeNextNonce,
		Data: nonceBuf[:],
	}

	// Reset send sequence so new packets start at 0.
	h.sendSeqMutex.Lock()
	h.sendSequence = 0
	h.sendSeqMutex.Unlock()

	// Best-effort send via the regular write path.
	// writeBlock will allocate its own sequence number (0) from the reset counter.
	_ = h.writeBlock(block)
}

// handlePeerNextNonce is the OnNextNonce callback wired in installCipherStates.
// When the peer sends us a NextNonce, we rekey the *receive* cipher to match.
func (h *SSU2Conn) handlePeerNextNonce(newNonce uint64) error {
	h.cipherMutex.Lock()
	defer h.cipherMutex.Unlock()

	if h.recvCipher == nil {
		return oops.Errorf("receive cipher not initialized")
	}

	h.recvCipher.Rekey()
	h.recvCipher.SetNonce(newNonce)

	log.WithField("newNonce", newNonce).Info("Applied peer NextNonce rekey on receive cipher")
	return nil
}

// updateActivity updates the last activity timestamp.
func (h *SSU2Conn) updateActivity() {
	h.lastActivityLock.Lock()
	defer h.lastActivityLock.Unlock()
	h.lastActivity = time.Now()
}

// getReadDeadline returns a channel that closes at read deadline.
func (h *SSU2Conn) getReadDeadline() <-chan time.Time {
	h.deadlineMutex.RLock()
	defer h.deadlineMutex.RUnlock()
	if h.readDeadline.IsZero() {
		return nil
	}
	return time.After(time.Until(h.readDeadline))
}

// getWriteDeadline returns a channel that closes at write deadline.
func (h *SSU2Conn) getWriteDeadline() <-chan time.Time {
	h.deadlineMutex.RLock()
	defer h.deadlineMutex.RUnlock()
	if h.writeDeadline.IsZero() {
		return nil
	}
	return time.After(time.Until(h.writeDeadline))
}
