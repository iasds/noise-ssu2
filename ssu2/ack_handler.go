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

	// ackThreshold is the number of received packets that triggers an
	// immediate ACK regardless of delay timer.
	ackThreshold int

	// maxACKDataSize is the maximum size in bytes of the ACK block data
	// (excluding the 3-byte block header). This prevents ACK blocks from
	// consuming excessive MTU space. Default: 504 bytes (~half of 1280 MTU
	// minus headers).
	maxACKDataSize int
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
		ackDelay:        10 * time.Millisecond, // Default from ssu2.rst
		ackThreshold:    10,
		maxACKDataSize:  504, // ~half of 1280 MTU minus headers
	}
}

// RecordReceived marks a packet number as received and needing acknowledgment.
// This should be called for every successfully processed inbound packet.
func (h *ACKHandler) RecordReceived(packetNum uint32) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.receivedPackets = append(h.receivedPackets, packetNum)
}

// SetACKThreshold sets the number of received packets that triggers an
// immediate ACK. Must be >= 1.
func (h *ACKHandler) SetACKThreshold(threshold int) {
	if threshold < 1 {
		threshold = 1
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.ackThreshold = threshold
}

// SetMaxACKDataSize sets the maximum ACK block data size in bytes.
// This limits ACK blocks to fit within the available MTU. Must be >= 5
// (minimum ACK block: 4-byte throughPN + 1-byte acnt).
func (h *ACKHandler) SetMaxACKDataSize(size int) {
	if size < 5 {
		size = 5
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.maxACKDataSize = size
}

// ShouldSendACK determines if an ACK should be sent based on timing and packet count.
// Per ssu2.rst: ACK delay = max(10, min(rtt/6, 150)) ms
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
	return timeSinceLastACK >= h.ackDelay || len(h.receivedPackets) >= h.ackThreshold
}

// GenerateACK creates an ACK block (Type 12) for all received packets.
// Returns nil if there are no packets to acknowledge.
func (h *ACKHandler) GenerateACK() (*SSU2Block, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.receivedPackets) == 0 {
		return nil, nil
	}

	sorted := sortDescDedupPackets(h.receivedPackets)
	throughPN := sorted[0]
	acnt := countConsecutiveFromTop(sorted) - 1

	rangeBytes := buildACKRanges(sorted, int(acnt)+1, h.maxACKDataSize-5)

	data := make([]byte, 5+len(rangeBytes))
	binary.BigEndian.PutUint32(data[0:4], throughPN)
	data[4] = uint8(acnt)
	copy(data[5:], rangeBytes)

	block := NewSSU2Block(BlockTypeACK, data)
	h.lastACKTime = time.Now()
	h.receivedPackets = h.receivedPackets[:0]

	return block, nil
}

// countConsecutiveFromTop counts how many packets form a consecutive run
// from the highest packet number downward.
func countConsecutiveFromTop(sorted []uint32) int {
	count := 1
	for i := 1; i < len(sorted); i++ {
		if sorted[i] == sorted[i-1]-1 {
			count++
		} else {
			break
		}
	}
	return count
}

// buildACKRanges builds nack/ack range pairs for non-consecutive packets.
func buildACKRanges(sorted []uint32, start, maxBytes int) []byte {
	var rangeBytes []byte
	i := start
	for i < len(sorted) {
		if len(rangeBytes)+2 > maxBytes {
			break
		}
		prevPN := sorted[i-1]
		nextPN := sorted[i]
		nackCount := int(prevPN - nextPN - 1)
		if nackCount < 1 {
			nackCount = 1
		}
		if nackCount > 256 {
			nackCount = 256
		}

		ackRun := 1
		j := i + 1
		for j < len(sorted) && sorted[j] == sorted[j-1]-1 {
			ackRun++
			j++
		}
		if ackRun > 256 {
			ackRun = 256
		}

		rangeBytes = append(rangeBytes, uint8(nackCount-1), uint8(ackRun-1))
		i = j
	}
	return rangeBytes
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
		nacks := int(data[offset]) + 1  // stored minus 1 per spec
		acks := int(data[offset+1]) + 1 // stored minus 1 per spec
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
