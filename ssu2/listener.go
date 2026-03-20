package ssu2

import (
	"crypto/rand"
	"crypto/sha256"
	"net"
	"sync"
	"time"

	"github.com/samber/oops"
)

// SSU2Listener implements net.Listener for accepting SSU2 connections over UDP.
// It manages incoming packets, routes them to existing sessions, and creates
// new sessions for valid handshake packets.
//
// Design rationale:
// - Uses PacketRouter to dispatch packets to appropriate sessions
// - Uses TokenCache to validate retry tokens and prevent spoofing
// - Implements net.Listener interface for compatibility with standard library
// - Single UDP socket shared across all sessions (multiplexing)
// - Worker pool limits goroutine count under traffic floods
//
// Thread Safety: All public methods are thread-safe.
type SSU2Listener struct {
	// underlying is the UDP socket for receiving packets
	underlying net.PacketConn

	// config holds listener configuration
	config *SSU2Config

	// addr is the SSU2 address for this listener
	addr *SSU2Addr

	// sessions maps connection ID to active SSU2Conn instances
	sessions     map[uint64]*SSU2Conn
	sessionMutex sync.RWMutex

	// tokenCache validates retry tokens
	tokenCache *TokenCache

	// acceptQueue buffers established connections ready to be accepted
	acceptQueue chan *SSU2Conn

	// packetQueue buffers incoming packets for worker pool processing
	packetQueue chan incomingPacket

	// router routes packets to sessions
	router *PacketRouter

	// Lifecycle management
	closed       bool
	closeMutex   sync.Mutex
	shutdownChan chan struct{}
	wg           sync.WaitGroup
}

// incomingPacket holds a received packet and its source address for worker processing.
type incomingPacket struct {
	data       []byte
	remoteAddr *net.UDPAddr
}

// packetWorkers is the number of goroutines in the packet processing pool.
const packetWorkers = 8

// packetQueueSize is the buffer size for the incoming packet channel.
// Packets arriving when the queue is full are dropped.
const packetQueueSize = 256

// NewSSU2Listener creates a new SSU2 listener wrapping the specified packet connection.
// The listener starts in an idle state; call Start() to begin accepting connections.
//
// Parameters:
//   - underlying: UDP PacketConn to receive packets from
//   - config: SSU2 configuration for accepted connections
//
// Returns a new SSU2Listener ready to start, or an error if configuration is invalid.
func NewSSU2Listener(underlying net.PacketConn, config *SSU2Config) (*SSU2Listener, error) {
	if underlying == nil {
		return nil, oops.
			Code("INVALID_PACKET_CONN").
			In("ssu2_listener").
			Errorf("underlying packet connection cannot be nil")
	}

	if config == nil {
		return nil, oops.
			Code("INVALID_CONFIG").
			In("ssu2_listener").
			Errorf("configuration cannot be nil")
	}

	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, oops.Wrapf(err, "invalid configuration")
	}

	// Generate connection ID for listener address
	connID, err := GenerateConnectionID()
	if err != nil {
		return nil, oops.Wrapf(err, "failed to generate connection ID")
	}

	// Create listener SSU2 address
	routerHash := make([]byte, 32)
	if _, err := rand.Read(routerHash); err != nil {
		return nil, oops.Wrapf(err, "failed to generate router hash")
	}

	addr, err := NewSSU2Addr(underlying.LocalAddr(), routerHash, connID, "responder")
	if err != nil {
		return nil, oops.Wrapf(err, "failed to create SSU2 address")
	}

	l := &SSU2Listener{
		underlying:   underlying,
		config:       config,
		addr:         addr,
		sessions:     make(map[uint64]*SSU2Conn),
		tokenCache:   NewTokenCache(60 * time.Second),
		acceptQueue:  make(chan *SSU2Conn, 100), // Buffer 100 pending connections
		packetQueue:  make(chan incomingPacket, packetQueueSize),
		shutdownChan: make(chan struct{}),
	}

	// Create packet router with session creation callback
	l.router = NewPacketRouter(l.handleNewSession)

	return l, nil
}

// Start begins accepting connections on the listener.
// This starts a goroutine to read packets from the underlying connection
// and route them to appropriate sessions.
//
// Returns error if the listener is already closed.
func (l *SSU2Listener) Start() error {
	l.closeMutex.Lock()
	defer l.closeMutex.Unlock()

	if l.closed {
		return oops.
			Code("LISTENER_CLOSED").
			In("ssu2_listener").
			Errorf("listener is closed")
	}

	// Start packet processing worker pool
	for i := 0; i < packetWorkers; i++ {
		l.wg.Add(1)
		go l.packetWorker()
	}

	// Start packet receive loop
	l.wg.Add(1)
	go l.receiveLoop()

	return nil
}

// Accept waits for and returns the next connection to the listener.
// Implements net.Listener interface.
//
// Returns:
//   - net.Conn: The accepted connection
//   - error: If the listener is closed or an error occurs
func (l *SSU2Listener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.acceptQueue:
		if conn == nil {
			return nil, oops.
				Code("LISTENER_CLOSED").
				In("ssu2_listener").
				Errorf("listener closed")
		}
		return conn, nil
	case <-l.shutdownChan:
		return nil, oops.
			Code("LISTENER_CLOSED").
			In("ssu2_listener").
			Errorf("listener closed")
	}
}

// Close closes the listener, preventing new connections from being accepted.
// Existing sessions are not closed; they must be closed separately.
// Implements net.Listener interface.
//
// Returns error if close fails.
func (l *SSU2Listener) Close() error {
	l.closeMutex.Lock()
	defer l.closeMutex.Unlock()

	if l.closed {
		return nil // Already closed
	}

	l.closed = true
	close(l.shutdownChan)

	// Wait for goroutines to finish before closing channels.
	// This prevents send-on-closed-channel panics in handleNewSession.
	l.wg.Wait()

	// Safe to close accept queue now — all senders have exited
	close(l.acceptQueue)

	// Close underlying packet connection
	if err := l.underlying.Close(); err != nil {
		return oops.Wrapf(err, "failed to close underlying connection")
	}

	return nil
}

// Addr returns the listener's network address.
// Implements net.Listener interface.
//
// Returns the SSU2 address for this listener.
func (l *SSU2Listener) Addr() net.Addr {
	return l.addr
}

// receiveLoop continuously reads packets from the underlying connection
// and routes them to appropriate sessions or creates new sessions.
func (l *SSU2Listener) receiveLoop() {
	defer l.wg.Done()

	buf := make([]byte, MaxPacketSizeIPv4)
	_ = l.underlying.SetReadDeadline(time.Now().Add(100 * time.Millisecond))

	for {
		select {
		case <-l.shutdownChan:
			return
		default:
			l.readAndQueuePacket(buf)
		}
	}
}

// readAndQueuePacket reads a single packet from the UDP socket,
// copies it, and enqueues it for worker processing.
func (l *SSU2Listener) readAndQueuePacket(buf []byte) {
	n, remoteAddr, err := l.underlying.ReadFrom(buf)
	if err != nil {
		select {
		case <-l.shutdownChan:
		default:
			_ = l.underlying.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		}
		return
	}

	udpAddr, ok := remoteAddr.(*net.UDPAddr)
	if !ok {
		return
	}

	packetData := make([]byte, n)
	copy(packetData, buf[:n])

	select {
	case l.packetQueue <- incomingPacket{data: packetData, remoteAddr: udpAddr}:
	default:
	}

	_ = l.underlying.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
}

// packetWorker drains the packet queue and processes packets.
// Multiple workers run concurrently as a bounded pool.
func (l *SSU2Listener) packetWorker() {
	defer l.wg.Done()

	for {
		select {
		case pkt, ok := <-l.packetQueue:
			if !ok {
				return
			}
			l.handleIncomingPacket(pkt.data, pkt.remoteAddr)
		case <-l.shutdownChan:
			return
		}
	}
}

// handleIncomingPacket processes a received packet and routes it appropriately.
// This is called in a goroutine for each received packet.
func (l *SSU2Listener) handleIncomingPacket(data []byte, remoteAddr *net.UDPAddr) {
	// Parse packet (basic validation)
	packet := &SSU2Packet{}
	if err := packet.Deserialize(data); err != nil {
		// Invalid packet, ignore
		return
	}

	// Route packet to appropriate handler
	if err := l.router.RoutePacket(packet, remoteAddr); err != nil {
		// Routing failed, check if this is a token request
		if packet.MessageType == MessageTypeTokenRequest {
			_ = l.processTokenRequest(packet, remoteAddr)
		}
		// Otherwise ignore error
	}
}

// handleNewSession is called by the router when a handshake packet arrives
// for a new session. It creates a new SSU2Conn and adds it to the accept queue.
//
// For SessionRequest messages, if a token is present in the payload, it validates
// the token before accepting the session. If no token is present or validation
// fails, the session is still created but marked for token requirement checking.
func (l *SSU2Listener) handleNewSession(remoteAddr *net.UDPAddr, packet *SSU2Packet) (*SSU2Conn, error) {
	// For SessionRequest, attempt to validate token if present
	if packet.MessageType == MessageTypeSessionRequest {
		if err := l.validateSessionRequestToken(packet, remoteAddr); err != nil {
			log.WithField("remote", remoteAddr.String()).Warn("Token validation failed: " + err.Error())
			if l.config.StrictTokenValidation {
				return nil, oops.
					Code("TOKEN_VALIDATION_FAILED").
					In("ssu2_listener").
					Wrap(err)
			}
		}
	}

	// Generate connection ID for new session
	connID, err := GenerateConnectionID()
	if err != nil {
		return nil, oops.Wrapf(err, "failed to generate connection ID")
	}

	// Derive initial router hash from the SessionRequest ephemeral key.
	// The ephemeral key (32-byte X25519 public key) is available in cleartext
	// and uniquely identifies this handshake session. The real router hash
	// (SHA-256 of the peer's RouterInfo) is installed post-handshake by
	// installCipherStates once the peer's static key is known.
	var routerHash []byte
	if len(packet.EphemeralKey) == 32 {
		h := sha256.Sum256(packet.EphemeralKey)
		routerHash = h[:]
	} else {
		routerHash = make([]byte, 32)
	}

	// Create a connection-specific config with the generated connection ID
	// and derived router hash so NewSSU2Conn initializes all fields properly
	// (handshakeHandler, dataHandler, ackHandler, rttEstimator, recvWindow,
	// sendQueue, recvQueue, pendingPackets, lastActivity).
	connConfig := *l.config
	connConfig.ConnectionID = connID
	connConfig.RouterHash = routerHash
	connConfig.Initiator = false

	conn, err := NewSSU2Conn(l.underlying, remoteAddr, &connConfig, false, l.config.StaticKey, nil)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to create SSU2 connection")
	}

	// Add to sessions map
	l.sessionMutex.Lock()
	l.sessions[connID] = conn
	l.sessionMutex.Unlock()

	// Queue for acceptance
	select {
	case l.acceptQueue <- conn:
		// Connection queued successfully
	case <-l.shutdownChan:
		// Listener shutting down
		return nil, oops.
			Code("LISTENER_CLOSED").
			In("ssu2_listener").
			Errorf("listener closed during session creation")
	default:
		// Accept queue full, drop connection
		return nil, oops.
			Code("ACCEPT_QUEUE_FULL").
			In("ssu2_listener").
			Errorf("accept queue full, connection dropped")
	}

	return conn, nil
}

// validateSessionRequestToken extracts and validates the token from a SessionRequest.
// If the payload contains a NewToken block, the token is validated against the cache.
//
// Returns nil if token is valid or not present, error if token is invalid.
func (l *SSU2Listener) validateSessionRequestToken(packet *SSU2Packet, remoteAddr *net.UDPAddr) error {
	// Parse blocks from payload
	if len(packet.Payload) == 0 {
		return nil // No payload, no token to validate
	}

	blocks, err := DeserializeBlocks(packet.Payload)
	if err != nil {
		// Can't parse blocks - continue without token validation
		return nil
	}

	// Find NewToken block
	tokenBlock := FindBlockByType(blocks, BlockTypeNewToken)
	if tokenBlock == nil {
		return nil // No token block present
	}

	// Parse token from block
	newToken, err := ParseNewTokenBlock(tokenBlock)
	if err != nil {
		return oops.Wrapf(err, "failed to parse NewToken block")
	}

	// Check token expiration
	if time.Now().Unix() > int64(newToken.Expiration) {
		return oops.
			Code("TOKEN_EXPIRED").
			In("ssu2_listener").
			With("expiration", newToken.Expiration).
			Errorf("token has expired")
	}

	// Validate token against cache
	// Note: We use the 11-byte token from the block, padded to match cache storage
	fullToken := make([]byte, 32)
	copy(fullToken, newToken.Token)

	if !l.tokenCache.ValidateToken(fullToken, remoteAddr) {
		return oops.
			Code("INVALID_TOKEN").
			In("ssu2_listener").
			With("address", remoteAddr.String()).
			Errorf("token validation failed")
	}

	// Token is valid - consume it
	l.tokenCache.ConsumeToken(fullToken, remoteAddr)

	return nil
}

// processTokenRequest handles a TokenRequest message by generating and sending
// a Retry message with a new token.
func (l *SSU2Listener) processTokenRequest(packet *SSU2Packet, remoteAddr *net.UDPAddr) error {
	// Generate token for this address
	token, err := l.tokenCache.GenerateToken(remoteAddr)
	if err != nil {
		return oops.Wrapf(err, "failed to generate token")
	}

	// Create and send Retry message with token
	return l.sendRetry(remoteAddr, token, packet.Header)
}

// sendRetry sends a Retry message containing the specified token to the remote address.
// The Retry message includes a NewToken block and echoes necessary header data.
//
// Parameters:
//   - remoteAddr: Destination UDP address
//   - token: 32-byte token value (will use first 11 bytes for NewToken block)
//   - originalHeader: Header from TokenRequest (for connection ID extraction)
func (l *SSU2Listener) sendRetry(remoteAddr *net.UDPAddr, token []byte, originalHeader []byte) error {
	if len(token) < 11 {
		return oops.Errorf("token too short: need at least 11 bytes, got %d", len(token))
	}

	// Calculate token expiration (TTL from token cache)
	expiration := time.Now().Add(l.tokenCache.GetTTL())

	// Create NewToken block with first 11 bytes of token
	tokenBlock, err := NewNewTokenBlock(expiration, token[:11])
	if err != nil {
		return oops.Wrapf(err, "failed to create NewToken block")
	}

	// Serialize block into payload
	payload, err := tokenBlock.Serialize()
	if err != nil {
		return oops.Wrapf(err, "failed to serialize NewToken block")
	}

	// Create Retry packet (Type 9, uses long header)
	retryPacket := NewSSU2Packet(MessageTypeRetry, 0)

	// Build header (32 bytes for Retry message)
	// Header format per SSU2: includes destination/source connection IDs and flags
	header := make([]byte, LongHeaderSize)

	// Copy connection ID from original request if available
	if len(originalHeader) >= 8 {
		copy(header[0:8], originalHeader[0:8]) // Destination connection ID
	}

	// Set message type flags in header
	header[8] = MessageTypeRetry

	retryPacket.Header = header
	retryPacket.Payload = payload
	retryPacket.MAC = make([]byte, MACSize) // Will be computed by crypto layer

	// Serialize packet
	packetData, err := retryPacket.Serialize()
	if err != nil {
		return oops.Wrapf(err, "failed to serialize Retry packet")
	}

	// Send packet
	_, err = l.underlying.WriteTo(packetData, remoteAddr)
	if err != nil {
		return oops.Wrapf(err, "failed to send Retry packet")
	}

	return nil
}

// removeSession removes a session from the listener's session map.
// This should be called when a connection closes.
func (l *SSU2Listener) removeSession(connID uint64) {
	l.sessionMutex.Lock()
	defer l.sessionMutex.Unlock()

	delete(l.sessions, connID)
}

// SessionCount returns the current number of active sessions.
// Useful for monitoring and debugging.
func (l *SSU2Listener) SessionCount() int {
	l.sessionMutex.RLock()
	defer l.sessionMutex.RUnlock()

	return len(l.sessions)
}
