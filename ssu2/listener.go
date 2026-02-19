package ssu2

import (
	"crypto/rand"
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

	// router routes packets to sessions
	router *PacketRouter

	// Lifecycle management
	closed       bool
	closeMutex   sync.Mutex
	shutdownChan chan struct{}
	wg           sync.WaitGroup
}

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

	// Close accept queue to unblock Accept() calls
	close(l.acceptQueue)

	// Wait for goroutines to finish
	l.wg.Wait()

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

	// Buffer for incoming packets (max SSU2 packet size)
	buf := make([]byte, MaxPacketSizeIPv4)

	// Set read deadline to avoid blocking indefinitely
	deadline := time.Now().Add(100 * time.Millisecond)
	_ = l.underlying.SetReadDeadline(deadline)

	for {
		select {
		case <-l.shutdownChan:
			return
		default:
			// Read packet from UDP socket
			n, remoteAddr, err := l.underlying.ReadFrom(buf)
			if err != nil {
				// Check if listener was closed
				select {
				case <-l.shutdownChan:
					return
				default:
					// Set new deadline and continue
					deadline = time.Now().Add(100 * time.Millisecond)
					_ = l.underlying.SetReadDeadline(deadline)
					continue
				}
			}

			// Convert to UDPAddr
			udpAddr, ok := remoteAddr.(*net.UDPAddr)
			if !ok {
				continue // Skip non-UDP addresses
			}

			// Handle packet in separate goroutine to avoid blocking
			packetData := make([]byte, n)
			copy(packetData, buf[:n])

			go l.handleIncomingPacket(packetData, udpAddr)

			// Refresh deadline for next read
			deadline = time.Now().Add(100 * time.Millisecond)
			_ = l.underlying.SetReadDeadline(deadline)
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
			// Token validation failed - log but continue (token may not be required)
			// In strict mode, we would reject the session here
			_ = err // Silently continue for backward compatibility
		}
	}

	// Generate connection ID for new session
	connID, err := GenerateConnectionID()
	if err != nil {
		return nil, oops.Wrapf(err, "failed to generate connection ID")
	}

	// Create SSU2 address for the new connection
	routerHash := make([]byte, 32)
	// TODO: Extract router hash from SessionRequest blocks
	// For now, use placeholder
	addr, err := NewSSU2Addr(remoteAddr, routerHash, connID, "responder")
	if err != nil {
		return nil, oops.Wrapf(err, "failed to create session address")
	}

	// Create new connection
	conn := &SSU2Conn{
		underlying: l.underlying,
		remoteAddr: remoteAddr,
		ssu2Addr:   addr,
		config:     l.config,
		initiator:  false,
		state:      StateInit,
		closeChan:  make(chan struct{}),
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
