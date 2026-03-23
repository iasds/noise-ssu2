package ssu2

import (
	"encoding/binary"
	"sync"
	"time"

	"github.com/samber/oops"
)

// ACKHandler manages acknowledgment generation and processing for SSU2 connections.
// It tracks received packets, generates ACK blocks, and processes incoming ACKs
// to manage retransmission and congestion control.
//
// ACK Block Format (Type 12) per SSU2 spec:
//   - Bytes 0-3: Through Packet Number (highest PN being acked, big-endian)
//   - Byte 4:    acnt — number of consecutive packets acked at and below the
//     Through PN, MINUS 1 (so 0 means only the Through PN itself)
//   - Bytes 5+:  Optional ranges, each 2 bytes:
//     Byte 0: nacks minus 1 (gap of non-received packets)
//     Byte 1: acks minus 1  (run of received packets)
//
// Minimum size: 5 bytes (4-byte Through PN + 1-byte acnt)
type ACKHandler struct {
	mu sync.Mutex

	// receivedPackets tracks packet numbers we've received and need to ACK
	receivedPackets []uint32

	// pendingACKs tracks packets awaiting acknowledgment
	pendingACKs map[uint32]*PendingACK

	// lastACKTime is when we last sent an ACK
	lastACKTime time.Time

	// ackDelay is the calculated delay before sending ACK
	ackDelay time.Duration
}

// PendingACK tracks an unacknowledged packet awaiting confirmation.
type PendingACK struct {
	PacketNumber uint32
	SentTime     time.Time
	Retries      int
}

// NewACKHandler creates a new ACK handler with default settings.
func NewACKHandler() *ACKHandler {
	return &ACKHandler{
		receivedPackets: make([]uint32, 0, 64),
		pendingACKs:     make(map[uint32]*PendingACK),
		ackDelay:        10 * time.Millisecond, // Default from SSU2.md
	}
}

// RecordReceived marks a packet number as received and needing acknowledgment.
// This should be called for every successfully processed inbound packet.
func (h *ACKHandler) RecordReceived(packetNum uint32) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.receivedPackets = append(h.receivedPackets, packetNum)
}

// ShouldSendACK determines if an ACK should be sent based on timing and packet count.
// Per SSU2.md: ACK delay = max(10, min(rtt/6, 150)) ms
func (h *ACKHandler) ShouldSendACK(rtt time.Duration) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.receivedPackets) == 0 {
		return false
	}

	// Calculate dynamic ACK delay based on RTT
	delay := rtt / 6
	if delay < 10*time.Millisecond {
		delay = 10 * time.Millisecond
	}
	if delay > 150*time.Millisecond {
		delay = 150 * time.Millisecond
	}
	h.ackDelay = delay

	// Send ACK if delay elapsed or we have many packets
	timeSinceLastACK := time.Since(h.lastACKTime)
	return timeSinceLastACK >= h.ackDelay || len(h.receivedPackets) >= 10
}

// GenerateACK creates an ACK block (Type 12) for all received packets.
// Returns nil if there are no packets to acknowledge.
func (h *ACKHandler) GenerateACK() (*SSU2Block, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.receivedPackets) == 0 {
		return nil, nil
	}

	// Sort received packets descending and deduplicate
	sorted := sortDescDedupPackets(h.receivedPackets)

	throughPN := sorted[0]

	// Count initial consecutive run from the top (including throughPN)
	consecutiveCount := 1
	for i := 1; i < len(sorted); i++ {
		if sorted[i] == sorted[i-1]-1 {
			consecutiveCount++
		} else {
			break
		}
	}
	acnt := uint8(consecutiveCount - 1) // stored minus 1

	// Build optional nack/ack range pairs for remaining packets
	var rangeBytes []byte
	i := consecutiveCount
	for i < len(sorted) {
		// Gap: number of missing packets between previous run and next acked
		prevPN := sorted[i-1]
		nextPN := sorted[i]
		nackCount := int(prevPN - nextPN - 1)
		if nackCount < 1 {
			nackCount = 1
		}
		if nackCount > 255 {
			nackCount = 255 // cap at 1-byte max
		}

		// Ack run: count consecutive packets starting at sorted[i]
		ackRun := 1
		j := i + 1
		for j < len(sorted) && sorted[j] == sorted[j-1]-1 {
			ackRun++
			j++
		}
		if ackRun > 255 {
			ackRun = 255 // cap at 1-byte max
		}

		rangeBytes = append(rangeBytes, uint8(nackCount), uint8(ackRun))
		i = j
	}

	// Encode: 4 bytes throughPN + 1 byte acnt + range pairs
	data := make([]byte, 5+len(rangeBytes))
	binary.BigEndian.PutUint32(data[0:4], throughPN)
	data[4] = acnt
	copy(data[5:], rangeBytes)

	block := NewSSU2Block(BlockTypeACK, data)
	h.lastACKTime = time.Now()
	h.receivedPackets = h.receivedPackets[:0]

	return block, nil
}

// ProcessACK handles an incoming ACK block, removing acknowledged packets
// from the pending queue. Returns the list of acked packet numbers.
func (h *ACKHandler) ProcessACK(ackBlock *SSU2Block) ([]uint32, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if ackBlock.Type != BlockTypeACK {
		return nil, oops.Errorf("expected ACK block type %d, got %d",
			BlockTypeACK, ackBlock.Type)
	}

	data := ackBlock.Data
	if len(data) < 5 {
		return nil, oops.Errorf("ACK block too short: %d bytes, minimum 5", len(data))
	}

	// Parse header
	throughPN := binary.BigEndian.Uint32(data[0:4])
	acnt := int(data[4])

	var ackedPackets []uint32

	// Initial consecutive run: throughPN down through throughPN-acnt
	if uint32(acnt) > throughPN {
		return nil, oops.Errorf("ACK acnt (%d) exceeds throughPN (%d)", acnt, throughPN)
	}
	for i := 0; i <= acnt; i++ {
		pn := throughPN - uint32(i)
		ackedPackets = append(ackedPackets, pn)
		delete(h.pendingACKs, pn)
	}

	// cursor tracks the next position below the last acked packet
	base := throughPN - uint32(acnt)
	if base == 0 {
		return ackedPackets, nil
	}
	cursor := base - 1

	// Parse optional nack/ack range pairs
	offset := 5
	for offset+1 < len(data) {
		nacks := int(data[offset])  // raw count per spec
		acks := int(data[offset+1]) // raw count per spec
		offset += 2

		// Skip the gap (nacked packets) — check for underflow
		if uint32(nacks) > cursor {
			return nil, oops.Errorf("ACK nack range (%d) exceeds cursor (%d)", nacks, cursor)
		}
		cursor -= uint32(nacks)

		// Collect the ack run — check for underflow
		if uint32(acks) > cursor+1 {
			return nil, oops.Errorf("ACK ack range (%d) exceeds remaining cursor (%d)", acks, cursor)
		}
		for i := 0; i < acks; i++ {
			ackedPackets = append(ackedPackets, cursor)
			delete(h.pendingACKs, cursor)
			cursor--
		}
	}

	return ackedPackets, nil
}

// AddPending marks a packet as sent and awaiting acknowledgment.
func (h *ACKHandler) AddPending(packetNum uint32) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.pendingACKs[packetNum] = &PendingACK{
		PacketNumber: packetNum,
		SentTime:     time.Now(),
		Retries:      0,
	}
}

// GetPending returns all packet numbers currently awaiting acknowledgment.
func (h *ACKHandler) GetPending() []uint32 {
	h.mu.Lock()
	defer h.mu.Unlock()
	pending := make([]uint32, 0, len(h.pendingACKs))
	for pktNum := range h.pendingACKs {
		pending = append(pending, pktNum)
	}
	return pending
}

// GetPendingPacket returns details about a specific pending packet.
func (h *ACKHandler) GetPendingPacket(packetNum uint32) (*PendingACK, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	ack, exists := h.pendingACKs[packetNum]
	return ack, exists
}

// HasPending returns true if there are packets awaiting acknowledgment.
func (h *ACKHandler) HasPending() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.pendingACKs) > 0
}

// ClearPending removes all pending acknowledgments (used on connection close).
func (h *ACKHandler) ClearPending() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.pendingACKs = make(map[uint32]*PendingACK)
	h.receivedPackets = h.receivedPackets[:0]
}

// sortDescDedupPackets returns a deduplicated copy of packets sorted in
// descending order.
func sortDescDedupPackets(packets []uint32) []uint32 {
	if len(packets) == 0 {
		return nil
	}

	sorted := make([]uint32, len(packets))
	copy(sorted, packets)

	// Sort descending (simple insertion sort — received lists are typically small)
	for i := 1; i < len(sorted); i++ {
		key := sorted[i]
		j := i - 1
		for j >= 0 && sorted[j] < key {
			sorted[j+1] = sorted[j]
			j--
		}
		sorted[j+1] = key
	}

	// Deduplicate (sorted is descending, so duplicates are adjacent)
	out := sorted[:1]
	for i := 1; i < len(sorted); i++ {
		if sorted[i] != out[len(out)-1] {
			out = append(out, sorted[i])
		}
	}

	return out
}
