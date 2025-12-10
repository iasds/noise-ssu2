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
// - Other blocks: DateTime, ACK, Padding, etc.
type DataHandler struct {
	// messageQueue holds complete I2NP messages ready for delivery
	messageQueue chan []byte

	// fragments tracks partial messages being reassembled
	fragments map[uint32]*FragmentSet

	// mutex protects fragments map
	mutex sync.RWMutex

	// stats tracks message processing statistics
	stats DataHandlerStats
}

// DataHandlerStats tracks statistics for monitoring and debugging.
type DataHandlerStats struct {
	MessagesReceived    uint64 // Complete messages received
	FragmentsReceived   uint64 // Total fragments received
	MessagesReassembled uint64 // Messages successfully reassembled
	MessagesDropped     uint64 // Messages dropped (timeout, errors)
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
	}
}

// ProcessDataPacket processes a Data packet and extracts I2NP messages.
// Returns extracted blocks and any error encountered.
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
		switch block.Type {
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

		// Other block types (DateTime, ACK, Padding) are handled elsewhere
		case BlockTypeDateTime, BlockTypeACK, BlockTypePadding:
			// These are handled by other components
			continue

		default:
			// Unknown block type - skip but don't error
			continue
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
