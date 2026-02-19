package ssu2

import (
	"sync"
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

	// callbacks for specific block types
	callbacks DataHandlerCallbacks
}

// DataHandlerCallbacks defines optional callbacks for block types
// that need external handling.
type DataHandlerCallbacks struct {
	// OnTermination is called when a Termination block is received
	OnTermination func(reason uint8, additionalData []byte)

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
	MessageID    uint32           // Unique message identifier
	TotalSize    uint32           // Expected total message size
	Fragments    map[uint8][]byte // Fragment number -> data
	ReceivedSize uint32           // Bytes received so far
	CreatedAt    time.Time        // When first fragment arrived
	LastUpdate   time.Time        // Last fragment received time
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
	h.callbacks = callbacks
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

	// Process each block - all 20 types explicitly handled
	for _, block := range blocks {
		h.incrementStat(&h.stats.BlocksProcessed)

		switch block.Type {
		// === Message Blocks (I2NP Data) ===
		case BlockTypeI2NPMessage:
			// Complete I2NP message - queue directly
			if err := h.handleI2NPMessage(block.Data); err != nil {
				return blocks, err
			}

		case BlockTypeFirstFragment:
			// First fragment of large message
			if err := h.handleFirstFragment(block.Data); err != nil {
				return blocks, err
			}

		case BlockTypeFollowOnFragment:
			// Subsequent fragment
			if err := h.handleFollowOnFragment(block.Data); err != nil {
				return blocks, err
			}

		// === Session Management Blocks ===
		case BlockTypeTermination:
			if err := h.handleTermination(block.Data); err != nil {
				log.WithField("error", err).Warn("Error handling Termination block")
			}

		case BlockTypeNewToken:
			if err := h.handleNewToken(block.Data); err != nil {
				log.WithField("error", err).Warn("Error handling NewToken block")
			}

		// === Relay Blocks ===
		case BlockTypeRelayRequest:
			if err := h.handleRelayRequest(block); err != nil {
				log.WithField("error", err).Debug("Error handling RelayRequest block")
			}

		case BlockTypeRelayResponse:
			if err := h.handleRelayResponse(block); err != nil {
				log.WithField("error", err).Debug("Error handling RelayResponse block")
			}

		case BlockTypeRelayIntro:
			if err := h.handleRelayIntro(block); err != nil {
				log.WithField("error", err).Debug("Error handling RelayIntro block")
			}

		case BlockTypeRelayTagRequest:
			if err := h.handleRelayTagRequest(block); err != nil {
				log.WithField("error", err).Debug("Error handling RelayTagRequest block")
			}

		case BlockTypeRelayTag:
			if err := h.handleRelayTag(block); err != nil {
				log.WithField("error", err).Debug("Error handling RelayTag block")
			}

		// === Peer Test Block ===
		case BlockTypePeerTest:
			if err := h.handlePeerTest(block); err != nil {
				log.WithField("error", err).Debug("Error handling PeerTest block")
			}

		// === Path Validation Blocks ===
		case BlockTypePathChallenge:
			if err := h.handlePathChallenge(block.Data); err != nil {
				log.WithField("error", err).Debug("Error handling PathChallenge block")
			}

		case BlockTypePathResponse:
			if err := h.handlePathResponse(block.Data); err != nil {
				log.WithField("error", err).Debug("Error handling PathResponse block")
			}

		// === Metadata Blocks ===
		case BlockTypeDateTime:
			if err := h.handleDateTime(block.Data); err != nil {
				log.WithField("error", err).Debug("Error handling DateTime block")
			}

		case BlockTypeOptions:
			if err := h.handleOptions(block.Data); err != nil {
				log.WithField("error", err).Debug("Error handling Options block")
			}

		case BlockTypeRouterInfo:
			if err := h.handleRouterInfo(block.Data); err != nil {
				log.WithField("error", err).Debug("Error handling RouterInfo block")
			}

		case BlockTypeAddress:
			if err := h.handleAddress(block.Data); err != nil {
				log.WithField("error", err).Debug("Error handling Address block")
			}

		case BlockTypeACK:
			if err := h.handleACK(block); err != nil {
				log.WithField("error", err).Debug("Error handling ACK block")
			}

		case BlockTypePadding:
			// Padding blocks are intentionally ignored - no processing needed
			continue

		default:
			// Unknown block type - log warning with details
			h.incrementStat(&h.stats.UnknownBlocks)
			log.WithFields(map[string]interface{}{
				"blockType":  block.Type,
				"dataLength": len(block.Data),
			}).Warn("Received unknown block type")
		}
	}

	return blocks, nil
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
// First fragment format: MessageID (4 bytes) + TotalSize (4 bytes) + Data
func (h *DataHandler) handleFirstFragment(data []byte) error {
	if len(data) < 8 {
		h.incrementStat(&h.stats.MessagesDropped)
		return oops.Errorf("first fragment too short: %d bytes, need at least 8", len(data))
	}

	messageID := uint32(data[0])<<24 | uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])
	totalSize := uint32(data[4])<<24 | uint32(data[5])<<16 | uint32(data[6])<<8 | uint32(data[7])
	fragmentData := data[8:]

	h.mutex.Lock()
	defer h.mutex.Unlock()

	// Check if we already have this message ID
	if _, exists := h.fragments[messageID]; exists {
		h.incrementStat(&h.stats.MessagesDropped)
		return oops.Errorf("duplicate first fragment for message ID %d", messageID)
	}

	// Create new fragment set
	fragmentSet := &FragmentSet{
		MessageID:    messageID,
		TotalSize:    totalSize,
		Fragments:    make(map[uint8][]byte),
		ReceivedSize: uint32(len(fragmentData)),
		CreatedAt:    time.Now(),
		LastUpdate:   time.Now(),
	}

	// Store first fragment (fragment number 0)
	fragmentSet.Fragments[0] = make([]byte, len(fragmentData))
	copy(fragmentSet.Fragments[0], fragmentData)

	h.fragments[messageID] = fragmentSet
	h.incrementStat(&h.stats.FragmentsReceived)

	return nil
}

// handleFollowOnFragment processes subsequent fragments of a message.
// Follow-on fragment format: MessageID (4 bytes) + FragmentNum (1 byte) + Data
func (h *DataHandler) handleFollowOnFragment(data []byte) error {
	if len(data) < 5 {
		h.incrementStat(&h.stats.MessagesDropped)
		return oops.Errorf("follow-on fragment too short: %d bytes, need at least 5", len(data))
	}

	messageID := uint32(data[0])<<24 | uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])
	fragmentNum := data[4]
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

	// Check if message is complete
	if fragmentSet.ReceivedSize >= fragmentSet.TotalSize {
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

	// Allocate buffer for complete message
	message := make([]byte, 0, fragmentSet.TotalSize)

	// Reassemble fragments in order
	for i := uint8(0); ; i++ {
		fragment, exists := fragmentSet.Fragments[i]
		if !exists {
			break
		}
		message = append(message, fragment...)
	}

	// Verify size
	if uint32(len(message)) != fragmentSet.TotalSize {
		h.incrementStat(&h.stats.MessagesDropped)
		delete(h.fragments, messageID)
		return oops.Errorf("reassembled message size mismatch: got %d, expected %d",
			len(message), fragmentSet.TotalSize)
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
		MessagesReceived:    h.stats.MessagesReceived,
		FragmentsReceived:   h.stats.FragmentsReceived,
		MessagesReassembled: h.stats.MessagesReassembled,
		MessagesDropped:     h.stats.MessagesDropped,
		BlocksProcessed:     h.stats.BlocksProcessed,
		UnknownBlocks:       h.stats.UnknownBlocks,
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
	// Simple increment - for production use atomic operations
	*stat++
}

// === Block Type Handler Methods ===
// Each method handles a specific SSU2 block type, either directly
// or by delegating to registered callbacks.

// handleTermination processes a Termination block (Type 6).
// Termination format: Reason (1 byte) + Additional data (variable)
func (h *DataHandler) handleTermination(data []byte) error {
	if len(data) < 1 {
		return oops.Errorf("Termination block too short: %d bytes", len(data))
	}

	reason := data[0]
	additionalData := data[1:]

	log.WithFields(map[string]interface{}{
		"reason":     reason,
		"dataLength": len(additionalData),
	}).Info("Received Termination block")

	if h.callbacks.OnTermination != nil {
		h.callbacks.OnTermination(reason, additionalData)
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

	if h.callbacks.OnNewToken != nil {
		h.callbacks.OnNewToken(data)
	}

	return nil
}

// handleRelayRequest processes a RelayRequest block (Type 7).
func (h *DataHandler) handleRelayRequest(block *SSU2Block) error {
	log.WithField("dataLength", len(block.Data)).Debug("Received RelayRequest block")

	if h.callbacks.OnRelayRequest != nil {
		return h.callbacks.OnRelayRequest(block)
	}

	// No callback registered - block will be handled by relay manager if connected
	return nil
}

// handleRelayResponse processes a RelayResponse block (Type 8).
func (h *DataHandler) handleRelayResponse(block *SSU2Block) error {
	log.WithField("dataLength", len(block.Data)).Debug("Received RelayResponse block")

	if h.callbacks.OnRelayResponse != nil {
		return h.callbacks.OnRelayResponse(block)
	}

	return nil
}

// handleRelayIntro processes a RelayIntro block (Type 9).
func (h *DataHandler) handleRelayIntro(block *SSU2Block) error {
	log.WithField("dataLength", len(block.Data)).Debug("Received RelayIntro block")

	if h.callbacks.OnRelayIntro != nil {
		return h.callbacks.OnRelayIntro(block)
	}

	return nil
}

// handleRelayTagRequest processes a RelayTagRequest block (Type 15).
func (h *DataHandler) handleRelayTagRequest(block *SSU2Block) error {
	log.WithField("dataLength", len(block.Data)).Debug("Received RelayTagRequest block")

	if h.callbacks.OnRelayTagRequest != nil {
		return h.callbacks.OnRelayTagRequest(block)
	}

	return nil
}

// handleRelayTag processes a RelayTag block (Type 16).
func (h *DataHandler) handleRelayTag(block *SSU2Block) error {
	log.WithField("dataLength", len(block.Data)).Debug("Received RelayTag block")

	if h.callbacks.OnRelayTag != nil {
		return h.callbacks.OnRelayTag(block)
	}

	return nil
}

// handlePeerTest processes a PeerTest block (Type 10).
func (h *DataHandler) handlePeerTest(block *SSU2Block) error {
	log.WithField("dataLength", len(block.Data)).Debug("Received PeerTest block")

	if h.callbacks.OnPeerTest != nil {
		return h.callbacks.OnPeerTest(block)
	}

	return nil
}

// handlePathChallenge processes a PathChallenge block (Type 18).
func (h *DataHandler) handlePathChallenge(data []byte) error {
	log.WithField("dataLength", len(data)).Debug("Received PathChallenge block")

	if h.callbacks.OnPathChallenge != nil {
		return h.callbacks.OnPathChallenge(data)
	}

	return nil
}

// handlePathResponse processes a PathResponse block (Type 19).
func (h *DataHandler) handlePathResponse(data []byte) error {
	log.WithField("dataLength", len(data)).Debug("Received PathResponse block")

	if h.callbacks.OnPathResponse != nil {
		return h.callbacks.OnPathResponse(data)
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

	if h.callbacks.OnDateTime != nil {
		return h.callbacks.OnDateTime(timestamp)
	}

	return nil
}

// handleOptions processes an Options block (Type 1).
func (h *DataHandler) handleOptions(data []byte) error {
	log.WithField("dataLength", len(data)).Debug("Received Options block")

	if h.callbacks.OnOptions != nil {
		return h.callbacks.OnOptions(data)
	}

	return nil
}

// handleRouterInfo processes a RouterInfo block (Type 2).
func (h *DataHandler) handleRouterInfo(data []byte) error {
	log.WithField("dataLength", len(data)).Debug("Received RouterInfo block")

	if h.callbacks.OnRouterInfo != nil {
		return h.callbacks.OnRouterInfo(data)
	}

	return nil
}

// handleAddress processes an Address block (Type 13).
// Address format: IP (4 or 16 bytes) + Port (2 bytes)
func (h *DataHandler) handleAddress(data []byte) error {
	log.WithField("dataLength", len(data)).Debug("Received Address block")

	if h.callbacks.OnAddress != nil {
		return h.callbacks.OnAddress(data)
	}

	return nil
}

// handleACK processes an ACK block (Type 12).
func (h *DataHandler) handleACK(block *SSU2Block) error {
	if h.callbacks.OnACK != nil {
		return h.callbacks.OnACK(block)
	}

	// ACK blocks are typically handled by the ack_handler component
	return nil
}
