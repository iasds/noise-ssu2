package ssu2

import (
	"encoding/binary"
	"sync"
	"sync/atomic"
	"time"

	"github.com/samber/oops"
)

// DataHandler manages Data message processing for SSU2 connections.
// It handles I2NP message extraction, fragmentation/reassembly, and
// maintains a queue of complete messages ready for the application layer.
//
// Data messages (Type 6) can contain:
// - BlockTypeI2NPMessage (Type 3): Complete I2NP messages
// - BlockTypeFirstFragment (Type 4): First fragment of large message
// - BlockTypeFollowOnFragment (Type 5): Subsequent fragments
// - All other 17 block types (DateTime, ACK, Relay*, PeerTest, etc.)
type DataHandler struct {
	// messageQueue holds complete I2NP messages ready for delivery
	messageQueue chan []byte

	// fragments tracks partial messages being reassembled
	fragments map[uint32]*FragmentSet

	// mutex protects fragments map
	mutex sync.RWMutex

	// stats tracks message processing statistics
	stats DataHandlerStats

	// blockRouter routes non-I2NP blocks to registered handlers
	blockRouter *BlockRouter

	// callbackMu protects concurrent access to callbacks.
	callbackMu sync.RWMutex

	// callbacks for specific block types
	callbacks DataHandlerCallbacks
}

// DataHandlerCallbacks defines optional callbacks for block types
// that need external handling.
type DataHandlerCallbacks struct {
	// OnTermination is called when a Termination block is received.
	// validDataReceived is the number of valid data packets received (8-byte uint64);
	// reason is the termination code; additionalData is the remaining bytes per SSU2 spec.
	OnTermination func(validDataReceived uint64, reason uint8, additionalData []byte)

	// OnNewToken is called when a NewToken block is received
	OnNewToken func(token []byte)

	// OnRelayRequest is called when a RelayRequest block is received
	OnRelayRequest func(block *SSU2Block) error

	// OnRelayResponse is called when a RelayResponse block is received
	OnRelayResponse func(block *SSU2Block) error

	// OnRelayIntro is called when a RelayIntro block is received
	OnRelayIntro func(block *SSU2Block) error

	// OnRelayTagRequest is called when a RelayTagRequest block is received
	OnRelayTagRequest func(block *SSU2Block) error

	// OnRelayTag is called when a RelayTag block is received
	OnRelayTag func(block *SSU2Block) error

	// OnPeerTest is called when a PeerTest block is received
	OnPeerTest func(block *SSU2Block) error

	// OnPathChallenge is called when a PathChallenge block is received
	OnPathChallenge func(data []byte) error

	// OnPathResponse is called when a PathResponse block is received
	OnPathResponse func(data []byte) error

	// OnRouterInfo is called when a RouterInfo block is received
	OnRouterInfo func(data []byte) error

	// OnOptions is called when an Options block is received
	OnOptions func(data []byte) error

	// OnAddress is called when an Address block is received
	OnAddress func(data []byte) error

	// OnACK is called when an ACK block is received
	OnACK func(block *SSU2Block) error

	// OnDateTime is called when a DateTime block is received
	OnDateTime func(timestamp uint32) error

	// OnNextNonce is called when a NextNonce block is received.
	// The newNonce is the 8-byte value signaling the peer's next send nonce.
	OnNextNonce func(newNonce uint64) error
}

// DataHandlerStats tracks statistics for monitoring and debugging.
type DataHandlerStats struct {
	MessagesReceived    uint64 // Complete messages received
	FragmentsReceived   uint64 // Total fragments received
	MessagesReassembled uint64 // Messages successfully reassembled
	MessagesDropped     uint64 // Messages dropped (timeout, errors)
	BlocksProcessed     uint64 // Total blocks processed
	UnknownBlocks       uint64 // Unknown block types received
}

// FragmentSet represents a message being reassembled from fragments.
type FragmentSet struct {
	MessageID       uint32           // I2NP message identifier
	I2NPType        uint8            // I2NP message type from First Fragment
	ShortExpiration uint32           // I2NP short expiration from First Fragment
	Fragments       map[uint8][]byte // Fragment number -> data
	ReceivedSize    uint32           // Bytes received so far
	HasLast         bool             // Whether we've received the last fragment
	LastFragNum     uint8            // Fragment number of the last fragment
	CreatedAt       time.Time        // When first fragment arrived
	LastUpdate      time.Time        // Last fragment received time
}

// NewDataHandler creates a new Data message handler.
// queueSize determines how many complete messages can be buffered.
func NewDataHandler(queueSize int) *DataHandler {
	if queueSize <= 0 {
		queueSize = 100 // Default queue size
	}

	return &DataHandler{
		messageQueue: make(chan []byte, queueSize),
		fragments:    make(map[uint32]*FragmentSet),
		blockRouter:  NewBlockRouter(),
	}
}

// SetCallbacks sets the callback handlers for block types.
func (h *DataHandler) SetCallbacks(callbacks DataHandlerCallbacks) {
	h.callbackMu.Lock()
	defer h.callbackMu.Unlock()
	h.callbacks = callbacks
}

// getCallbacks returns a snapshot of the current callbacks.
// Callers should use the snapshot rather than reading h.callbacks directly
// to avoid races with SetCallbacks.
func (h *DataHandler) getCallbacks() DataHandlerCallbacks {
	h.callbackMu.RLock()
	defer h.callbackMu.RUnlock()
	return h.callbacks
}

// GetBlockRouter returns the block router for registering external handlers.
func (h *DataHandler) GetBlockRouter() *BlockRouter {
	return h.blockRouter
}

// ProcessDataPacket processes a Data packet and extracts I2NP messages.
// Returns extracted blocks and any error encountered.
// All 20 SSU2 block types are explicitly handled.
func (h *DataHandler) ProcessDataPacket(packet *SSU2Packet) ([]*SSU2Block, error) {
	if packet.MessageType != MessageTypeData {
		return nil, oops.Errorf("expected Data packet (type %d), got type %d",
			MessageTypeData, packet.MessageType)
	}

	// Deserialize blocks from payload
	blocks, err := DeserializeBlocks(packet.Payload)
	if err != nil {
		h.incrementStat(&h.stats.MessagesDropped)
		return nil, oops.Wrapf(err, "failed to deserialize blocks from Data packet")
	}

	// Process each block
	for _, block := range blocks {
		h.incrementStat(&h.stats.BlocksProcessed)
		if err := h.processBlock(block); err != nil {
			return blocks, err
		}
	}

	return blocks, nil
}

// processBlock routes a single block to its appropriate handler.
// For critical message blocks (I2NP, fragments), errors are returned.
// For non-critical blocks, errors are logged and processing continues.
func (h *DataHandler) processBlock(block *SSU2Block) error {
	switch block.Type {
	case BlockTypeI2NPMessage:
		return h.handleI2NPMessage(block.Data)
	case BlockTypeFirstFragment:
		return h.handleFirstFragment(block.Data)
	case BlockTypeFollowOnFragment:
		return h.handleFollowOnFragment(block.Data)
	case BlockTypePadding:
		return nil
	default:
		h.dispatchNonCriticalBlock(block)
		return nil
	}
}

// dispatchNonCriticalBlock handles blocks where errors are logged, not propagated.
func (h *DataHandler) dispatchNonCriticalBlock(block *SSU2Block) {
	var err error
	switch block.Type {
	case BlockTypeTermination:
		err = h.handleTermination(block.Data)
	case BlockTypeNewToken:
		err = h.handleNewToken(block.Data)
	case BlockTypeRelayRequest:
		err = h.handleRelayRequest(block)
	case BlockTypeRelayResponse:
		err = h.handleRelayResponse(block)
	case BlockTypeRelayIntro:
		err = h.handleRelayIntro(block)
	case BlockTypeRelayTagRequest:
		err = h.handleRelayTagRequest(block)
	case BlockTypeRelayTag:
		err = h.handleRelayTag(block)
	case BlockTypePeerTest:
		err = h.handlePeerTest(block)
	case BlockTypePathChallenge:
		err = h.handlePathChallenge(block.Data)
	case BlockTypePathResponse:
		err = h.handlePathResponse(block.Data)
	case BlockTypeDateTime:
		err = h.handleDateTime(block.Data)
	case BlockTypeOptions:
		err = h.handleOptions(block.Data)
	case BlockTypeRouterInfo:
		err = h.handleRouterInfo(block.Data)
	case BlockTypeAddress:
		err = h.handleAddress(block.Data)
	case BlockTypeACK:
		err = h.handleACK(block)
	case BlockTypeNextNonce:
		err = h.handleNextNonce(block.Data)
	default:
		h.incrementStat(&h.stats.UnknownBlocks)
		log.WithFields(map[string]interface{}{
			"blockType":  block.Type,
			"dataLength": len(block.Data),
		}).Warn("Received unknown block type")
		return
	}
	if err != nil {
		log.WithFields(map[string]interface{}{
			"blockType": block.Type,
			"error":     err,
		}).Debug("Error handling block")
	}
}

// handleI2NPMessage queues a complete I2NP message for delivery.
func (h *DataHandler) handleI2NPMessage(data []byte) error {
	if len(data) == 0 {
		h.incrementStat(&h.stats.MessagesDropped)
		return oops.Errorf("I2NP message block is empty")
	}

	// Make defensive copy
	msg := make([]byte, len(data))
	copy(msg, data)

	// Try to queue message (non-blocking if full)
	select {
	case h.messageQueue <- msg:
		h.incrementStat(&h.stats.MessagesReceived)
		return nil
	default:
		h.incrementStat(&h.stats.MessagesDropped)
		return oops.Errorf("message queue full, dropping message")
	}
}

// handleFirstFragment processes the first fragment of a message.
// SSU2 spec format: I2NP type(1) + messageID(4) + shortExpiration(4) + data
func (h *DataHandler) handleFirstFragment(data []byte) error {
	if len(data) < 9 {
		h.incrementStat(&h.stats.MessagesDropped)
		return oops.Errorf("first fragment too short: %d bytes, need at least 9", len(data))
	}

	i2npType := data[0]
	messageID := binary.BigEndian.Uint32(data[1:5])
	shortExpiration := binary.BigEndian.Uint32(data[5:9])
	fragmentData := data[9:]

	h.mutex.Lock()
	defer h.mutex.Unlock()

	// Check if we already have this message ID
	if _, exists := h.fragments[messageID]; exists {
		h.incrementStat(&h.stats.MessagesDropped)
		return oops.Errorf("duplicate first fragment for message ID %d", messageID)
	}

	// Create new fragment set
	fragmentSet := &FragmentSet{
		MessageID:       messageID,
		I2NPType:        i2npType,
		ShortExpiration: shortExpiration,
		Fragments:       make(map[uint8][]byte),
		ReceivedSize:    uint32(len(fragmentData)),
		CreatedAt:       time.Now(),
		LastUpdate:      time.Now(),
	}

	// Store first fragment (fragment number 0)
	fragmentSet.Fragments[0] = make([]byte, len(fragmentData))
	copy(fragmentSet.Fragments[0], fragmentData)

	h.fragments[messageID] = fragmentSet
	h.incrementStat(&h.stats.FragmentsReceived)

	return nil
}

// handleFollowOnFragment processes subsequent fragments of a message.
// SSU2 spec format: FragmentInfo(1) + MessageID(4) + Data
// FragmentInfo: (fragNum << 1) | isLast
func (h *DataHandler) handleFollowOnFragment(data []byte) error {
	if len(data) < 5 {
		h.incrementStat(&h.stats.MessagesDropped)
		return oops.Errorf("follow-on fragment too short: %d bytes, need at least 5", len(data))
	}

	fragInfo := data[0]
	fragmentNum := fragInfo >> 1
	isLast := (fragInfo & 0x01) != 0
	messageID := binary.BigEndian.Uint32(data[1:5])
	fragmentData := data[5:]

	h.mutex.Lock()
	defer h.mutex.Unlock()

	// Find fragment set
	fragmentSet, exists := h.fragments[messageID]
	if !exists {
		h.incrementStat(&h.stats.MessagesDropped)
		return oops.Errorf("follow-on fragment for unknown message ID %d", messageID)
	}

	// Check for duplicate fragment
	if _, exists := fragmentSet.Fragments[fragmentNum]; exists {
		// Duplicate fragment - ignore silently
		return nil
	}

	// Store fragment
	fragmentSet.Fragments[fragmentNum] = make([]byte, len(fragmentData))
	copy(fragmentSet.Fragments[fragmentNum], fragmentData)
	fragmentSet.ReceivedSize += uint32(len(fragmentData))
	fragmentSet.LastUpdate = time.Now()
	h.incrementStat(&h.stats.FragmentsReceived)

	if isLast {
		fragmentSet.HasLast = true
		fragmentSet.LastFragNum = fragmentNum
	}

	// Attempt reassembly if we have the last fragment and all preceding ones
	if fragmentSet.HasLast {
		if err := h.reassembleMessage(messageID); err != nil {
			return err
		}
	}

	return nil
}

// reassembleMessage combines all fragments into a complete message.
// Must be called with mutex held.
func (h *DataHandler) reassembleMessage(messageID uint32) error {
	fragmentSet := h.fragments[messageID]
	if fragmentSet == nil {
		return oops.Errorf("fragment set not found for message ID %d", messageID)
	}

	// Check we have all fragments from 0 through LastFragNum
	if !fragmentSet.HasLast {
		return nil // Not ready yet
	}
	for i := uint8(0); i <= fragmentSet.LastFragNum; i++ {
		if _, exists := fragmentSet.Fragments[i]; !exists {
			return nil // Missing fragment, wait for it
		}
	}

	// Reassemble fragments in order
	var message []byte
	for i := uint8(0); i <= fragmentSet.LastFragNum; i++ {
		message = append(message, fragmentSet.Fragments[i]...)
	}

	// Queue complete message
	select {
	case h.messageQueue <- message:
		h.incrementStat(&h.stats.MessagesReassembled)
		delete(h.fragments, messageID)
		return nil
	default:
		h.incrementStat(&h.stats.MessagesDropped)
		delete(h.fragments, messageID)
		return oops.Errorf("message queue full, dropping reassembled message")
	}
}

// GetMessage retrieves the next complete I2NP message from the queue.
// Returns nil if no messages are available (non-blocking).
func (h *DataHandler) GetMessage() []byte {
	select {
	case msg := <-h.messageQueue:
		return msg
	default:
		return nil
	}
}

// GetMessageBlocking waits for the next message with optional timeout.
// Returns nil if timeout expires.
func (h *DataHandler) GetMessageBlocking(timeout time.Duration) []byte {
	if timeout <= 0 {
		// Block indefinitely
		return <-h.messageQueue
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case msg := <-h.messageQueue:
		return msg
	case <-timer.C:
		return nil
	}
}

// HasMessages returns true if messages are available in the queue.
func (h *DataHandler) HasMessages() bool {
	return len(h.messageQueue) > 0
}

// MessageChan returns the receive-only channel for complete I2NP messages.
// Used by SSU2Conn.Read to block until a message is available.
func (h *DataHandler) MessageChan() <-chan []byte {
	return h.messageQueue
}

// CleanupExpiredFragments removes fragment sets that haven't been updated
// within the specified timeout. Should be called periodically.
func (h *DataHandler) CleanupExpiredFragments(timeout time.Duration) int {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	now := time.Now()
	removed := 0

	for messageID, fragmentSet := range h.fragments {
		if now.Sub(fragmentSet.LastUpdate) > timeout {
			delete(h.fragments, messageID)
			h.incrementStat(&h.stats.MessagesDropped)
			removed++
		}
	}

	return removed
}

// GetStats returns a copy of current statistics.
func (h *DataHandler) GetStats() DataHandlerStats {
	return DataHandlerStats{
		MessagesReceived:    atomic.LoadUint64(&h.stats.MessagesReceived),
		FragmentsReceived:   atomic.LoadUint64(&h.stats.FragmentsReceived),
		MessagesReassembled: atomic.LoadUint64(&h.stats.MessagesReassembled),
		MessagesDropped:     atomic.LoadUint64(&h.stats.MessagesDropped),
		BlocksProcessed:     atomic.LoadUint64(&h.stats.BlocksProcessed),
		UnknownBlocks:       atomic.LoadUint64(&h.stats.UnknownBlocks),
	}
}

// GetFragmentCount returns the number of incomplete fragment sets.
func (h *DataHandler) GetFragmentCount() int {
	h.mutex.RLock()
	defer h.mutex.RUnlock()
	return len(h.fragments)
}

// Clear removes all queued messages and fragments.
func (h *DataHandler) Clear() {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	// Drain message queue
	for {
		select {
		case <-h.messageQueue:
		default:
			goto done
		}
	}
done:

	// Clear fragments
	h.fragments = make(map[uint32]*FragmentSet)
}

// incrementStat atomically increments a statistic counter.
func (h *DataHandler) incrementStat(stat *uint64) {
	atomic.AddUint64(stat, 1)
}

// === Block Type Handler Methods ===
// Each method handles a specific SSU2 block type, either directly
// or by delegating to registered callbacks.

// handleTermination processes a Termination block (Type 6).
// SSU2 spec format: validDataPacketsReceived (8 bytes) + reason (1 byte) + additionalData (optional)
// Minimum length: 9 bytes.
func (h *DataHandler) handleTermination(data []byte) error {
	if len(data) < 9 {
		return oops.Errorf("Termination block too short: %d bytes, need at least 9", len(data))
	}

	validDataReceived := binary.BigEndian.Uint64(data[0:8])
	reason := data[8]
	additionalData := data[9:]

	log.WithFields(map[string]interface{}{
		"validDataReceived": validDataReceived,
		"reason":            reason,
		"additionalDataLen": len(additionalData),
	}).Info("Received Termination block")

	cbs := h.getCallbacks()
	if cbs.OnTermination != nil {
		cbs.OnTermination(validDataReceived, reason, additionalData)
	}

	return nil
}

// handleNewToken processes a NewToken block (Type 17).
// NewToken format: Expires (4 bytes) + Token (8 bytes) = 12 bytes minimum
func (h *DataHandler) handleNewToken(data []byte) error {
	if len(data) < 12 {
		return oops.Errorf("NewToken block too short: %d bytes, need 12", len(data))
	}

	log.WithField("tokenLength", len(data)).Debug("Received NewToken block")

	cbs := h.getCallbacks()
	if cbs.OnNewToken != nil {
		cbs.OnNewToken(data)
	}

	return nil
}

// handleNextNonce processes a NextNonce block (Type 11).
// NextNonce format: 8 bytes representing the new nonce value.
func (h *DataHandler) handleNextNonce(data []byte) error {
	if len(data) < 8 {
		return oops.Errorf("NextNonce block too short: %d bytes, need 8", len(data))
	}

	newNonce := binary.BigEndian.Uint64(data[0:8])

	log.WithField("newNonce", newNonce).Debug("Received NextNonce block")

	cbs := h.getCallbacks()
	if cbs.OnNextNonce != nil {
		return cbs.OnNextNonce(newNonce)
	}

	return nil
}

// handleRelayRequest processes a RelayRequest block (Type 7).
func (h *DataHandler) handleRelayRequest(block *SSU2Block) error {
	log.WithField("dataLength", len(block.Data)).Debug("Received RelayRequest block")

	cbs := h.getCallbacks()
	if cbs.OnRelayRequest != nil {
		return cbs.OnRelayRequest(block)
	}

	// No callback registered - block will be handled by relay manager if connected
	return nil
}

// handleRelayResponse processes a RelayResponse block (Type 8).
func (h *DataHandler) handleRelayResponse(block *SSU2Block) error {
	log.WithField("dataLength", len(block.Data)).Debug("Received RelayResponse block")

	cbs := h.getCallbacks()
	if cbs.OnRelayResponse != nil {
		return cbs.OnRelayResponse(block)
	}

	return nil
}

// handleRelayIntro processes a RelayIntro block (Type 9).
func (h *DataHandler) handleRelayIntro(block *SSU2Block) error {
	log.WithField("dataLength", len(block.Data)).Debug("Received RelayIntro block")

	cbs := h.getCallbacks()
	if cbs.OnRelayIntro != nil {
		return cbs.OnRelayIntro(block)
	}

	return nil
}

// handleRelayTagRequest processes a RelayTagRequest block (Type 15).
func (h *DataHandler) handleRelayTagRequest(block *SSU2Block) error {
	log.WithField("dataLength", len(block.Data)).Debug("Received RelayTagRequest block")

	cbs := h.getCallbacks()
	if cbs.OnRelayTagRequest != nil {
		return cbs.OnRelayTagRequest(block)
	}

	return nil
}

// handleRelayTag processes a RelayTag block (Type 16).
func (h *DataHandler) handleRelayTag(block *SSU2Block) error {
	log.WithField("dataLength", len(block.Data)).Debug("Received RelayTag block")

	cbs := h.getCallbacks()
	if cbs.OnRelayTag != nil {
		return cbs.OnRelayTag(block)
	}

	return nil
}

// handlePeerTest processes a PeerTest block (Type 10).
func (h *DataHandler) handlePeerTest(block *SSU2Block) error {
	log.WithField("dataLength", len(block.Data)).Debug("Received PeerTest block")

	cbs := h.getCallbacks()
	if cbs.OnPeerTest != nil {
		return cbs.OnPeerTest(block)
	}

	return nil
}

// handlePathChallenge processes a PathChallenge block (Type 18).
func (h *DataHandler) handlePathChallenge(data []byte) error {
	log.WithField("dataLength", len(data)).Debug("Received PathChallenge block")

	cbs := h.getCallbacks()
	if cbs.OnPathChallenge != nil {
		return cbs.OnPathChallenge(data)
	}

	return nil
}

// handlePathResponse processes a PathResponse block (Type 19).
func (h *DataHandler) handlePathResponse(data []byte) error {
	log.WithField("dataLength", len(data)).Debug("Received PathResponse block")

	cbs := h.getCallbacks()
	if cbs.OnPathResponse != nil {
		return cbs.OnPathResponse(data)
	}

	return nil
}

// handleDateTime processes a DateTime block (Type 0).
// DateTime format: Timestamp (4 bytes, seconds since epoch)
func (h *DataHandler) handleDateTime(data []byte) error {
	if len(data) < 4 {
		return oops.Errorf("DateTime block too short: %d bytes, need 4", len(data))
	}

	timestamp := uint32(data[0])<<24 | uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])

	cbs := h.getCallbacks()
	if cbs.OnDateTime != nil {
		return cbs.OnDateTime(timestamp)
	}

	return nil
}

// handleOptions processes an Options block (Type 1).
func (h *DataHandler) handleOptions(data []byte) error {
	log.WithField("dataLength", len(data)).Debug("Received Options block")

	cbs := h.getCallbacks()
	if cbs.OnOptions != nil {
		return cbs.OnOptions(data)
	}

	return nil
}

// handleRouterInfo processes a RouterInfo block (Type 2).
func (h *DataHandler) handleRouterInfo(data []byte) error {
	log.WithField("dataLength", len(data)).Debug("Received RouterInfo block")

	cbs := h.getCallbacks()
	if cbs.OnRouterInfo != nil {
		return cbs.OnRouterInfo(data)
	}

	return nil
}

// handleAddress processes an Address block (Type 13).
// Address format: IP (4 or 16 bytes) + Port (2 bytes)
func (h *DataHandler) handleAddress(data []byte) error {
	log.WithField("dataLength", len(data)).Debug("Received Address block")

	cbs := h.getCallbacks()
	if cbs.OnAddress != nil {
		return cbs.OnAddress(data)
	}

	return nil
}

// handleACK processes an ACK block (Type 12).
func (h *DataHandler) handleACK(block *SSU2Block) error {
	cbs := h.getCallbacks()
	if cbs.OnACK != nil {
		return cbs.OnACK(block)
	}

	// ACK blocks are typically handled by the ack_handler component
	return nil
}
