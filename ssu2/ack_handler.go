package ssu2

import (
	"encoding/binary"
	"time"

	"github.com/samber/oops"
)

// ACKHandler manages acknowledgment generation and processing for SSU2 connections.
// It tracks received packets, generates ACK blocks, and processes incoming ACKs
// to manage retransmission and congestion control.
//
// ACK Block Format (Type 12):
// - Byte 0: ACK count (number of packet ranges)
// - Bytes 1-4: ACK delay in milliseconds (uint32, big-endian)
// - Followed by packet ranges (each range: start uint32 + end uint32)
//
// Minimum size: 5 bytes (1 byte count + 4 bytes delay, 0 ranges for keepalive)
type ACKHandler struct {
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
	h.receivedPackets = append(h.receivedPackets, packetNum)
}

// ShouldSendACK determines if an ACK should be sent based on timing and packet count.
// Per SSU2.md: ACK delay = max(10, min(rtt/6, 150)) ms
func (h *ACKHandler) ShouldSendACK(rtt time.Duration) bool {
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
	if len(h.receivedPackets) == 0 {
		return nil, nil
	}

	// Compress packet numbers into ranges for efficiency
	ranges := compressPacketRanges(h.receivedPackets)

	// Calculate ACK delay in milliseconds
	ackDelayMS := uint32(time.Since(h.lastACKTime).Milliseconds())
	if ackDelayMS > 65535 {
		ackDelayMS = 65535 // Cap at max uint16 for reasonable delays
	}

	// Build ACK block data:
	// Byte 0: range count
	// Bytes 1-4: ACK delay (ms)
	// Bytes 5+: ranges (start:4 + end:4 per range)
	data := make([]byte, 5+len(ranges)*8)
	data[0] = uint8(len(ranges))
	binary.BigEndian.PutUint32(data[1:5], ackDelayMS)

	// Encode packet ranges
	offset := 5
	for _, r := range ranges {
		binary.BigEndian.PutUint32(data[offset:offset+4], r.start)
		binary.BigEndian.PutUint32(data[offset+4:offset+8], r.end)
		offset += 8
	}

	block := NewSSU2Block(BlockTypeACK, data)
	h.lastACKTime = time.Now()
	h.receivedPackets = h.receivedPackets[:0] // Clear acknowledged packets

	return block, nil
}

// ProcessACK handles an incoming ACK block, removing acknowledged packets
// from the pending queue and calculating RTT samples.
func (h *ACKHandler) ProcessACK(ackBlock *SSU2Block) ([]uint32, error) {
	if ackBlock.Type != BlockTypeACK {
		return nil, oops.Errorf("expected ACK block type %d, got %d",
			BlockTypeACK, ackBlock.Type)
	}

	data := ackBlock.Data
	if len(data) < 5 {
		return nil, oops.Errorf("ACK block too short: %d bytes, minimum 5", len(data))
	}

	// Parse ACK block
	rangeCount := int(data[0])
	ackDelayMS := binary.BigEndian.Uint32(data[1:5])
	_ = ackDelayMS // Delay available for future use

	expectedSize := 5 + rangeCount*8
	if len(data) < expectedSize {
		return nil, oops.Errorf("ACK block size mismatch: got %d bytes, expected %d",
			len(data), expectedSize)
	}

	// Extract acknowledged packet numbers
	var ackedPackets []uint32
	offset := 5
	for i := 0; i < rangeCount; i++ {
		start := binary.BigEndian.Uint32(data[offset : offset+4])
		end := binary.BigEndian.Uint32(data[offset+4 : offset+8])
		offset += 8

		if start > end {
			return nil, oops.Errorf("invalid ACK range: start %d > end %d", start, end)
		}

		// Collect all packet numbers in range
		for pktNum := start; pktNum <= end; pktNum++ {
			ackedPackets = append(ackedPackets, pktNum)

			// Remove from pending queue
			delete(h.pendingACKs, pktNum)
		}
	}

	return ackedPackets, nil
}

// AddPending marks a packet as sent and awaiting acknowledgment.
func (h *ACKHandler) AddPending(packetNum uint32) {
	h.pendingACKs[packetNum] = &PendingACK{
		PacketNumber: packetNum,
		SentTime:     time.Now(),
		Retries:      0,
	}
}

// GetPending returns all packet numbers currently awaiting acknowledgment.
func (h *ACKHandler) GetPending() []uint32 {
	pending := make([]uint32, 0, len(h.pendingACKs))
	for pktNum := range h.pendingACKs {
		pending = append(pending, pktNum)
	}
	return pending
}

// GetPendingPacket returns details about a specific pending packet.
func (h *ACKHandler) GetPendingPacket(packetNum uint32) (*PendingACK, bool) {
	ack, exists := h.pendingACKs[packetNum]
	return ack, exists
}

// HasPending returns true if there are packets awaiting acknowledgment.
func (h *ACKHandler) HasPending() bool {
	return len(h.pendingACKs) > 0
}

// ClearPending removes all pending acknowledgments (used on connection close).
func (h *ACKHandler) ClearPending() {
	h.pendingACKs = make(map[uint32]*PendingACK)
	h.receivedPackets = h.receivedPackets[:0]
}

// packetRange represents a contiguous range of packet numbers.
type packetRange struct {
	start uint32
	end   uint32
}

// compressPacketRanges converts a list of packet numbers into ranges.
// Example: [1, 2, 3, 5, 6, 10] -> [(1,3), (5,6), (10,10)]
func compressPacketRanges(packets []uint32) []packetRange {
	if len(packets) == 0 {
		return nil
	}

	// Sort packets (simple bubble sort for small lists)
	sorted := make([]uint32, len(packets))
	copy(sorted, packets)
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[i] > sorted[j] {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}

	// Build ranges
	var ranges []packetRange
	start := sorted[0]
	end := sorted[0]

	for i := 1; i < len(sorted); i++ {
		if sorted[i] == end+1 {
			end = sorted[i] // Extend current range
		} else {
			ranges = append(ranges, packetRange{start, end})
			start = sorted[i]
			end = sorted[i]
		}
	}
	ranges = append(ranges, packetRange{start, end})

	return ranges
}
