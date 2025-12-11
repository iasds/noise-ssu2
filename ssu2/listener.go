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
func (l *SSU2Listener) handleNewSession(remoteAddr *net.UDPAddr, packet *SSU2Packet) (*SSU2Conn, error) {
	// For SessionRequest, validate token if present
	if packet.MessageType == MessageTypeSessionRequest {
		// TODO: Extract and validate token from packet blocks
		// For now, assume valid (will be implemented with block parsing)
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

// processTokenRequest handles a TokenRequest message by generating and sending
// a Retry message with a new token.
func (l *SSU2Listener) processTokenRequest(packet *SSU2Packet, remoteAddr *net.UDPAddr) error {
	// Generate token for this address
	token, err := l.tokenCache.GenerateToken(remoteAddr)
	if err != nil {
		return oops.Wrapf(err, "failed to generate token")
	}

	// Send Retry message with token
	return l.sendRetry(remoteAddr, token)
}

// sendRetry sends a Retry message containing the specified token to the remote address.
func (l *SSU2Listener) sendRetry(remoteAddr *net.UDPAddr, token []byte) error {
	// TODO: Construct Retry packet with token block (Type 17)
	// For now, this is a placeholder that will be implemented with full block support
	_ = token
	_ = remoteAddr

	return oops.
		Code("NOT_IMPLEMENTED").
		In("ssu2_listener").
		Errorf("sendRetry not yet implemented - requires block construction")
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
