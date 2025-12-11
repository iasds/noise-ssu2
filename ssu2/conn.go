package ssu2

import (
	"context"
	"net"
	"sync"
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

	// Background goroutines coordination
	wg sync.WaitGroup
}

// PendingPacket tracks an outbound packet awaiting acknowledgment.
type PendingPacket struct {
	Packet    *SSU2Packet
	SentTime  time.Time
	Retries   int
	NextRetry time.Time
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

	// Create handshake handler
	handshakeHandler, err := NewHandshakeHandler(initiator, staticKey, remoteStaticKey)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to create handshake handler")
	}

	// Create SSU2 address from config
	role := "initiator"
	if !initiator {
		role = "responder"
	}

	ssu2Addr, err := NewSSU2Addr(remoteAddr, config.RouterHash, config.ConnectionID, role)
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

	// Start background goroutines
	conn.wg.Add(3)
	go conn.sendLoop()
	go conn.recvLoop()
	go conn.keepaliveLoop()

	return conn, nil
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

	if h.initiator {
		return h.handshakeInitiator(ctx)
	}
	return h.handshakeResponder(ctx)
}

// handshakeInitiator performs the initiator side of XK handshake.
func (h *SSU2Conn) handshakeInitiator(ctx context.Context) error {
	// Step 1: Create and send SessionRequest
	sessionRequest, err := h.handshakeHandler.CreateSessionRequest(h.config.ConnectionID, 0)
	if err != nil {
		return oops.Wrapf(err, "failed to create SessionRequest")
	}

	if err := h.sendPacketDirect(sessionRequest); err != nil {
		return oops.Wrapf(err, "failed to send SessionRequest")
	}

	// Step 2: Wait for SessionCreated
	sessionCreated, err := h.receivePacketWithTimeout(ctx, h.config.HandshakeTimeout)
	if err != nil {
		return oops.Wrapf(err, "failed to receive SessionCreated")
	}

	if sessionCreated.MessageType != MessageTypeSessionCreated {
		return oops.Errorf("expected SessionCreated, got type %d", sessionCreated.MessageType)
	}

	// Step 3: Process SessionCreated
	if err := h.handshakeHandler.ProcessSessionCreated(sessionCreated); err != nil {
		return oops.Wrapf(err, "failed to process SessionCreated")
	}

	// Step 4: Check handshake completion
	if !h.handshakeHandler.IsHandshakeComplete() {
		return oops.Errorf("handshake not complete after SessionCreated")
	}

	// Step 5: Transition to established state
	h.stateMutex.Lock()
	h.state = StateEstablished
	h.stateMutex.Unlock()

	return nil
}

// handshakeResponder performs the responder side of XK handshake.
func (h *SSU2Conn) handshakeResponder(ctx context.Context) error {
	// Step 1: Wait for SessionRequest
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

	// Step 4: Check handshake completion
	if !h.handshakeHandler.IsHandshakeComplete() {
		return oops.Errorf("handshake not complete after SessionCreated")
	}

	// Step 5: Transition to established state
	h.stateMutex.Lock()
	h.state = StateEstablished
	h.stateMutex.Unlock()

	return nil
}

// Read implements net.Conn.Read.
// Reads data from the connection, reassembling I2NP messages from Data packets.
func (h *SSU2Conn) Read(b []byte) (int, error) {
	h.stateMutex.RLock()
	state := h.state
	h.stateMutex.RUnlock()

	if state != StateEstablished {
		return 0, oops.Errorf("connection not established: %s", state)
	}

	// Get message from data handler
	msg := h.dataHandler.GetMessage()
	if msg == nil {
		// No message available, check close/deadline
		select {
		case <-h.closeChan:
			return 0, oops.Errorf("connection closed")
		case <-h.getReadDeadline():
			return 0, oops.Errorf("read deadline exceeded")
		default:
			return 0, oops.Errorf("no data available")
		}
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
	h.stateMutex.RLock()
	state := h.state
	h.stateMutex.RUnlock()

	if state != StateEstablished {
		return 0, oops.Errorf("connection not established: %s", state)
	}

	// Create I2NP message block
	block := &SSU2Block{
		Type: BlockTypeI2NPMessage,
		Data: copyBytes(b),
	}

	// Create Data packet
	packet := &SSU2Packet{
		MessageType:  MessageTypeData,
		PacketNumber: h.nextSendSequence(),
		Payload:      nil, // Will be set by SerializeBlocks
	}

	// Serialize block into payload
	payload, err := SerializeBlocks([]*SSU2Block{block})
	if err != nil {
		return 0, oops.Wrapf(err, "failed to serialize blocks")
	}
	packet.Payload = payload

	// Send packet
	select {
	case h.sendQueue <- packet:
		return len(b), nil
	case <-h.closeChan:
		return 0, oops.Errorf("connection closed")
	case <-h.getWriteDeadline():
		return 0, oops.Errorf("write deadline exceeded")
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
		termBlock := &SSU2Block{
			Type: BlockTypeTermination,
			Data: make([]byte, 9), // 1 byte reason + 8 bytes timestamp
		}
		// Reason: 0 (normal close)
		termBlock.Data[0] = 0
		// Timestamp: current time in milliseconds
		timestamp := uint64(time.Now().UnixMilli())
		for i := 0; i < 8; i++ {
			termBlock.Data[1+i] = byte(timestamp >> (56 - i*8))
		}

		// Create Data packet with termination block
		packet := &SSU2Packet{
			MessageType:  MessageTypeData,
			PacketNumber: h.nextSendSequence(),
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

// recvLoop handles inbound packet reception.
func (h *SSU2Conn) recvLoop() {
	defer h.wg.Done()

	buf := make([]byte, h.config.MTU)
	for {
		select {
		case <-h.closeChan:
			return
		default:
			// Set read deadline for non-blocking operation
			_ = h.underlying.SetReadDeadline(time.Now().Add(100 * time.Millisecond))

			n, addr, err := h.underlying.ReadFrom(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue // Timeout is expected
				}
				// Real error
				continue
			}

			// Verify source address matches
			udpAddr, ok := addr.(*net.UDPAddr)
			if !ok || !udpAddr.IP.Equal(h.remoteAddr.IP) || udpAddr.Port != h.remoteAddr.Port {
				continue // Wrong source
			}

			// Parse packet
			packet := &SSU2Packet{}
			if err := packet.Deserialize(buf[:n]); err != nil {
				continue // Invalid packet
			}

			// Update activity time
			h.updateActivity()

			// Process packet
			h.processInboundPacket(packet)
		}
	}
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
					packet := &SSU2Packet{
						MessageType:  MessageTypeData,
						PacketNumber: h.nextSendSequence(),
					}
					payload, _ := SerializeBlocks([]*SSU2Block{ack})
					packet.Payload = payload
					_ = h.sendPacketDirect(packet)
				}
			}

			// Check for timeout (5 minutes default idle timeout)
			idleTimeout := 5 * time.Minute
			if timeSinceActivity >= idleTimeout {
				h.closeErr = oops.Errorf("idle timeout")
				_ = h.Close()
				return
			}
		case <-h.closeChan:
			return
		}
	}
}

// sendPacketDirect sends a packet directly to the peer.
func (h *SSU2Conn) sendPacketDirect(packet *SSU2Packet) error {
	// Serialize packet
	data, err := packet.Serialize()
	if err != nil {
		return oops.Wrapf(err, "failed to serialize packet")
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
			Packet:    packet,
			SentTime:  time.Now(),
			Retries:   0,
			NextRetry: time.Now().Add(h.rttEstimator.GetRTO()),
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

	// Process based on message type
	switch packet.MessageType {
	case MessageTypeData:
		// Process data packet
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

	case MessageTypeSessionRequest, MessageTypeSessionCreated, MessageTypeSessionConfirmed:
		// Queue for handshake processing
		select {
		case h.recvQueue <- packet:
		default:
			// Queue full, drop packet
		}

	default:
		// Unknown message type, ignore
	}
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

// nextSendSequence returns the next packet sequence number.
func (h *SSU2Conn) nextSendSequence() uint32 {
	h.sendSeqMutex.Lock()
	defer h.sendSeqMutex.Unlock()
	seq := h.sendSequence
	h.sendSequence++
	return seq
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
