package ssu2

import (
	"encoding/binary"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-i2p/common/data"
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
	// The 256-packet gap (0xFFFFFFFF - 0xFFFFFF00) provides enough lead
	// time for the NextNonce block to be sent, acknowledged, and for both
	// sides to switch to the new key before the counter is exhausted (M-3).
	//
	// WARNING: NextNonce (block type 11) is based on an UNFINALIZED spec
	// area (see SSU2 spec §3.7 "NextNonce") with size "TBD".
	// UNFINALIZED_SPEC: This threshold and the rekey mechanism may need
	// revision for interoperability when the spec is finalised.
	rekeyThreshold uint32 = 0xFFFF_FF00

	// maxPacketRetries is the maximum number of retransmission attempts
	// before a pending packet is dropped.
	maxPacketRetries = 5

	// retransmitInterval is how often the retransmit loop checks for
	// expired pending packets.
	retransmitInterval = 250 * time.Millisecond

	// destroyTimeout is the default time to wait after sending a Termination
	// block before releasing session resources. Per spec §Termination:
	// "Wait for 11 seconds (the maximum RTO)" after sending a Termination
	// block. Can be overridden via SSU2Config.DestroyTimeout (M-4).
	destroyTimeout = 11 * time.Second
)

// String returns a human-readable state name.
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
	handshakeHandler     *HandshakeHandler
	dataHandler          *DataHandler
	ackHandler           *ACKHandler
	rttEstimator         *RTTEstimator
	recvWindow           *ReceiveWindow
	congestionController *CongestionController

	// Header protection (nil = disabled)
	headerProtector *HeaderProtectorManager

	// SipHash length obfuscation (nil = disabled)
	sipHashModifier atomic.Pointer[SipHashLengthModifier]

	// Path validation for connection migration (G-7)
	pathValidator *PathValidator

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

	// remoteConnectionID is the peer's connection ID, learned during
	// the handshake. Outbound data-phase packets must use this value
	// as the Destination Connection ID per SSU2 spec.
	remoteConnectionID uint64

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

	// validDataPacketsSent counts successfully sent data-phase packets.
	// Compared against the peer's reported count in Termination blocks
	// to detect packet loss during close (G-7).
	validDataPacketsSent atomic.Uint64
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
	if err := validateConnInputs(underlying, remoteAddr, config); err != nil {
		return nil, err
	}

	connID, err := resolveConnectionID(config)
	if err != nil {
		return nil, err
	}

	if config.InitiatorConnectionID != 0 && config.InitiatorConnectionID == connID {
		return nil, oops.Errorf("connection ID collision: source and destination IDs are identical (%d)", connID)
	}

	handshakeHandler, err := buildHandshakeHandler(initiator, staticKey, remoteStaticKey, config)
	if err != nil {
		return nil, err
	}

	ssu2Addr, err := newSSU2AddrForConn(remoteAddr, config.RouterHash, connID, initiator)
	if err != nil {
		return nil, err
	}

	conn := assembleSSU2Conn(underlying, remoteAddr, ssu2Addr, config, initiator, handshakeHandler)

	if err := conn.initHeaderProtection(config, initiator); err != nil {
		return nil, err
	}

	conn.dataHandler.StartReaper()

	return conn, nil
}

func validateConnInputs(underlying net.PacketConn, remoteAddr *net.UDPAddr, config *SSU2Config) error {
	if underlying == nil {
		return oops.Errorf("underlying PacketConn is nil")
	}
	if remoteAddr == nil {
		return oops.Errorf("remoteAddr is nil")
	}
	if config == nil {
		return oops.Errorf("config is nil")
	}
	if err := config.Validate(); err != nil {
		return oops.Wrapf(err, "invalid config")
	}
	return nil
}

func resolveConnectionID(config *SSU2Config) (uint64, error) {
	connID := config.ConnectionID
	if connID == 0 {
		var err error
		connID, err = GenerateConnectionID()
		if err != nil {
			return 0, oops.Wrapf(err, "failed to generate connection ID")
		}
	}
	return connID, nil
}

func buildHandshakeHandler(initiator bool, staticKey, remoteStaticKey []byte, config *SSU2Config) (*HandshakeHandler, error) {
	prologue := buildSSU2Prologue()
	handler, err := NewHandshakeHandler(initiator, staticKey, remoteStaticKey, prologue)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to create handshake handler")
	}

	if config.ReplayCacheTTL > 0 && !initiator {
		handler.ReconfigureReplayCache(config.ReplayCacheTTL)
	}
	handler.maxClockSkew = config.MaxClockSkew
	handler.SetLocalOptions(&OptionsParams{
		TMinRatio: 0,
		TMaxRatio: config.PaddingRatio,
		RMinRatio: 0,
		RMaxRatio: config.PaddingRatio,
	})
	return handler, nil
}

func newSSU2AddrForConn(remoteAddr *net.UDPAddr, routerHash data.Hash, connID uint64, initiator bool) (*SSU2Addr, error) {
	role := "initiator"
	if !initiator {
		role = "responder"
	}
	addr, err := NewSSU2Addr(remoteAddr, routerHash, connID, role)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to create SSU2 address")
	}
	return addr, nil
}

func assembleSSU2Conn(
	underlying net.PacketConn,
	remoteAddr *net.UDPAddr,
	ssu2Addr *SSU2Addr,
	config *SSU2Config,
	initiator bool,
	handshakeHandler *HandshakeHandler,
) *SSU2Conn {
	rttEst := NewRTTEstimator()
	conn := &SSU2Conn{
		underlying:           underlying,
		remoteAddr:           remoteAddr,
		ssu2Addr:             ssu2Addr,
		config:               config,
		initiator:            initiator,
		handshakeHandler:     handshakeHandler,
		dataHandler:          newDataHandlerFromConfig(config),
		ackHandler:           NewACKHandler(),
		rttEstimator:         rttEst,
		congestionController: NewCongestionControllerWithMTU(rttEst, config.MTU),
		recvWindow:           NewReceiveWindow(0, config.ReceiveWindowSize),
		state:                StateInit,
		closeChan:            make(chan struct{}),
		sendQueue:            make(chan *SSU2Packet, 64),
		recvQueue:            make(chan *SSU2Packet, 64),
		pendingPackets:       make(map[uint32]*PendingPacket),
		lastActivity:         time.Now(),
	}

	conn.pathValidator = NewPathValidator(conn)
	conn.pathValidator.SetCongestionController(conn.congestionController)
	return conn
}

func (c *SSU2Conn) initHeaderProtection(config *SSU2Config, initiator bool) error {
	if len(config.IntroKey) == HeaderKeySize {
		hpm, err := NewHeaderProtectorManager(config.IntroKey, config.RemoteIntroKey, initiator)
		if err != nil {
			return oops.Wrapf(err, "failed to create header protector")
		}
		c.headerProtector = hpm
	}
	return nil
}

// messageTypeToHeaderType maps an SSU2 message type to the corresponding
// header protection type used for key selection.
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
// Close implements net.Conn.Close.
// Sends a Termination block with reason NormalClose and closes the connection.
func (h *SSU2Conn) Close() error {
	return h.CloseWithReason(TerminationNormalClose, nil)
}

// CloseWithReason sends a Termination block with the given reason code
// and optional additional data, then closes the connection.
// Per spec §Termination, the data is: validDataPacketsReceived (8 bytes)
// + reason (1 byte) + additional data (optional).
// CloseWithReason sends a Termination block with the given reason code
// and optional additional data, then closes the connection.
// Per spec §Termination, the data is: validDataPacketsReceived (8 bytes)
// + reason (1 byte) + additional data (optional).
func (h *SSU2Conn) CloseWithReason(reason TerminationReason, additionalData []byte) error {
	h.closeOnce.Do(func() {
		// Update state first
		h.stateMutex.Lock()
		h.state = StateClosing
		h.stateMutex.Unlock()

		// Send Termination block (best effort)
		// Spec §Termination: validDataPacketsReceived(8 bytes, big-endian) + reason(1 byte) + additionalData
		termData := make([]byte, 9+len(additionalData))
		binary.BigEndian.PutUint64(termData[0:8], h.validDataPacketsReceived.Load())
		termData[8] = byte(reason)
		if len(additionalData) > 0 {
			copy(termData[9:], additionalData)
		}
		termBlock := &SSU2Block{
			Type: BlockTypeTermination,
			Data: termData,
		}

		// Create Data packet with termination block
		pktNum := h.nextSendSequence()
		hdr := make([]byte, ShortHeaderSize)
		binary.BigEndian.PutUint64(hdr[0:8], h.remoteConnectionID)
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

		// Per spec §Termination: wait briefly for the peer's Termination
		// response before tearing down the session. This avoids lingering
		// half-open state on the remote side.
		if h.config.DestroyTimeout > 0 {
			time.Sleep(h.config.DestroyTimeout)
		}

		// Stop keepalive timer
		if h.keepaliveTimer != nil {
			h.keepaliveTimer.Stop()
		}

		// Stop fragment reaper
		if h.dataHandler != nil {
			h.dataHandler.Close()
		}

		// Zero SipHash key material
		if mod := h.sipHashModifier.Load(); mod != nil {
			mod.ZeroKeys()
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
// RemoteAddr implements net.Conn.RemoteAddr.
func (h *SSU2Conn) RemoteAddr() net.Addr {
	return h.ssu2Addr
}

// SendToAddress sends a block to a specific UDP address (implements PathValidationConn).
// SendToAddress sends a block to a specific UDP address (implements PathValidationConn).
func (h *SSU2Conn) SendToAddress(block *SSU2Block, addr *net.UDPAddr) error {
	pktNum := h.nextSendSequence()
	hdr := make([]byte, ShortHeaderSize)
	binary.BigEndian.PutUint64(hdr[0:8], h.remoteConnectionID)
	binary.BigEndian.PutUint32(hdr[8:12], pktNum)
	packet := &SSU2Packet{
		MessageType:  MessageTypeData,
		PacketNumber: pktNum,
		Header:       hdr,
		MAC:          make([]byte, MACSize),
	}
	payload, err := SerializeBlocks([]*SSU2Block{block})
	if err != nil {
		return oops.Wrapf(err, "failed to serialize block for path validation")
	}
	packet.Payload = payload
	data, err := packet.Serialize()
	if err != nil {
		return oops.Wrapf(err, "failed to serialize packet for path validation")
	}
	_, err = h.underlying.WriteTo(data, addr)
	return err
}

// GetRemoteAddr returns the current remote UDP address (implements PathValidationConn).
// GetRemoteAddr returns the current remote UDP address (implements PathValidationConn).
func (h *SSU2Conn) GetRemoteAddr() *net.UDPAddr {
	return h.remoteAddr
}

// SetRemoteAddr updates the remote address after successful path validation (implements PathValidationConn).
// SetRemoteAddr updates the remote address after successful path validation (implements PathValidationConn).
func (h *SSU2Conn) SetRemoteAddr(addr *net.UDPAddr) error {
	if addr == nil {
		return oops.Errorf("address is nil")
	}
	h.remoteAddr = addr
	return nil
}

// SetDeadline implements net.Conn.SetDeadline.
// SetDeadline implements net.Conn.SetDeadline.
func (h *SSU2Conn) SetDeadline(t time.Time) error {
	h.deadlineMutex.Lock()
	defer h.deadlineMutex.Unlock()
	h.readDeadline = t
	h.writeDeadline = t
	return nil
}

// SetReadDeadline implements net.Conn.SetReadDeadline.
// SetReadDeadline implements net.Conn.SetReadDeadline.
func (h *SSU2Conn) SetReadDeadline(t time.Time) error {
	h.deadlineMutex.Lock()
	defer h.deadlineMutex.Unlock()
	h.readDeadline = t
	return nil
}

// SetWriteDeadline implements net.Conn.SetWriteDeadline.
// SetWriteDeadline implements net.Conn.SetWriteDeadline.
func (h *SSU2Conn) SetWriteDeadline(t time.Time) error {
	h.deadlineMutex.Lock()
	defer h.deadlineMutex.Unlock()
	h.writeDeadline = t
	return nil
}

// GetState returns the current connection state.
// GetState returns the current connection state.
func (h *SSU2Conn) GetState() ConnState {
	h.stateMutex.RLock()
	defer h.stateMutex.RUnlock()
	return h.state
}

// RecvStats returns error counters from the receive loop for observability.
// Keys: "read_errors", "parse_errors", "decrypt_errors".
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
// SetDataHandlerCallbacks wires application-level callbacks for SSU2 block types
// received during the data phase. Call before Handshake() completes to ensure
// callbacks are active from the first data packet. Safe to call concurrently
// with an active connection; updates take effect on the next inbound packet.
func (h *SSU2Conn) SetDataHandlerCallbacks(cbs DataHandlerCallbacks) {
	h.dataHandler.SetCallbacks(cbs)
}

// sendLoop handles outbound packet transmission.
