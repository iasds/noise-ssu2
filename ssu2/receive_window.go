package ssu2

import (
	"sync"

	"github.com/samber/oops"
)

// ReceiveWindow manages out-of-order packet buffering for reliable UDP delivery.
// It tracks the next expected packet number and buffers packets that arrive early,
// releasing them in order once gaps are filled.
//
// The window is thread-safe and handles:
//   - Out-of-order packet arrival (buffer and release in sequence)
//   - Duplicate packets (detect and discard)
//   - Old packets (detect and discard)
//   - Window size limits (prevent memory exhaustion)
//
// Typical usage:
//
//	window := NewReceiveWindow(1000, 100) // start at packet 1000, max 100 buffered
//	ready, err := window.Insert(packet)
//	if err != nil {
//	    // handle error (duplicate, window full, etc.)
//	}
//	for _, pkt := range ready {
//	    // process packets in order
//	}
type ReceiveWindow struct {
	// expected is the next packet number we expect to receive in sequence
	expected uint32

	// window buffers packets that arrived out of order (pktNum > expected)
	// Key: packet number, Value: buffered packet
	window map[uint32]*SSU2Packet

	// maxSize is the maximum number of packets to buffer before rejecting new ones
	// This prevents memory exhaustion from malicious or broken peers
	maxSize int

	// mutex protects all fields for concurrent access
	mutex sync.RWMutex
}

// SSU2Packet is defined in packet.go

const (
	// DefaultMaxWindowSize is the default maximum number of buffered packets.
	// This prevents memory exhaustion while allowing reasonable out-of-order tolerance.
	// Based on typical UDP window sizes and SSU2 requirements.
	DefaultMaxWindowSize = 256

	// MaxPacketNumber is the maximum packet number (2^32 - 1 per SSU2.md)
	MaxPacketNumber = 0xFFFFFFFF
)

// NewReceiveWindow creates a new receive window starting at the given packet number.
// The maxSize parameter limits how many out-of-order packets can be buffered.
//
// Parameters:
//   - expected: The first packet number we expect to receive
//   - maxSize: Maximum buffered packets (use DefaultMaxWindowSize if unsure)
//
// Returns a new ReceiveWindow ready to accept packets.
func NewReceiveWindow(expected uint32, maxSize int) *ReceiveWindow {
	if maxSize <= 0 {
		maxSize = DefaultMaxWindowSize
	}

	return &ReceiveWindow{
		expected: expected,
		window:   make(map[uint32]*SSU2Packet),
		maxSize:  maxSize,
	}
}

// Insert adds a packet to the receive window and returns any packets that can now
// be processed in order. The returned slice contains packets in sequence, starting
// with the newly inserted packet if it was the expected one.
//
// Behavior:
//   - If pktNum == expected: return immediately plus any consecutive buffered packets
//   - If pktNum > expected: buffer for later (if window not full)
//   - If pktNum < expected: reject as duplicate/old packet
//
// Thread-safe: can be called concurrently from multiple goroutines.
//
// Returns:
//   - ready: Slice of packets ready to process, in sequence order (may be empty)
//   - error: Non-nil if packet is duplicate, old, or window is full
func (rw *ReceiveWindow) Insert(packet *SSU2Packet) ([]*SSU2Packet, error) {
	if packet == nil {
		return nil, oops.Errorf("cannot insert nil packet")
	}

	rw.mutex.Lock()
	defer rw.mutex.Unlock()

	pktNum := packet.PacketNumber

	// Case 1: Old or duplicate packet (already processed)
	if pktNum < rw.expected {
		return nil, oops.
			With("packetNumber", pktNum).
			With("expected", rw.expected).
			Errorf("packet already processed (old or duplicate)")
	}

	// Case 2: Expected packet - but check if it's already buffered (shouldn't happen normally)
	if pktNum == rw.expected {
		// Check if we somehow already have this packet buffered
		// This can happen if SetExpected was called while packets were buffered
		if _, exists := rw.window[pktNum]; exists {
			return nil, oops.
				With("packetNumber", pktNum).
				With("expected", rw.expected).
				Errorf("duplicate expected packet (already buffered)")
		}

		ready := []*SSU2Packet{packet}
		rw.expected++

		// Check if we can release buffered packets
		for {
			if buffered, exists := rw.window[rw.expected]; exists {
				ready = append(ready, buffered)
				delete(rw.window, rw.expected)
				rw.expected++
			} else {
				break // Gap in sequence, stop releasing
			}
		}

		return ready, nil
	}

	// Case 3: Future packet - buffer it
	// First check if already buffered (duplicate of future packet)
	if _, exists := rw.window[pktNum]; exists {
		return nil, oops.
			With("packetNumber", pktNum).
			With("expected", rw.expected).
			Errorf("duplicate future packet")
	}

	// Check window size limit
	if len(rw.window) >= rw.maxSize {
		return nil, oops.
			With("packetNumber", pktNum).
			With("expected", rw.expected).
			With("windowSize", len(rw.window)).
			With("maxSize", rw.maxSize).
			Errorf("receive window full")
	}

	// Buffer the packet
	rw.window[pktNum] = packet
	return []*SSU2Packet{}, nil // Empty slice, no packets ready yet
}

// GetExpected returns the next expected packet number.
// Thread-safe: can be called concurrently.
func (rw *ReceiveWindow) GetExpected() uint32 {
	rw.mutex.RLock()
	defer rw.mutex.RUnlock()
	return rw.expected
}

// GetWindowSize returns the current number of buffered packets.
// Thread-safe: can be called concurrently.
func (rw *ReceiveWindow) GetWindowSize() int {
	rw.mutex.RLock()
	defer rw.mutex.RUnlock()
	return len(rw.window)
}

// SetExpected updates the expected packet number. This is useful for
// synchronizing the window after connection initialization or recovery.
// Any buffered packets before the new expected number are discarded.
//
// Thread-safe: can be called concurrently.
func (rw *ReceiveWindow) SetExpected(expected uint32) {
	rw.mutex.Lock()
	defer rw.mutex.Unlock()

	// Discard any buffered packets before the new expected number
	for pktNum := range rw.window {
		if pktNum < expected {
			delete(rw.window, pktNum)
		}
	}

	rw.expected = expected
}

// Clear resets the receive window, discarding all buffered packets.
// The expected packet number is reset to the provided value.
//
// Thread-safe: can be called concurrently.
func (rw *ReceiveWindow) Clear(expected uint32) {
	rw.mutex.Lock()
	defer rw.mutex.Unlock()

	// Create new map to clear all buffered packets
	rw.window = make(map[uint32]*SSU2Packet)
	rw.expected = expected
}

// HasGaps returns true if there are buffered packets waiting for missing packets.
// This indicates packet loss or severe reordering.
//
// Thread-safe: can be called concurrently.
func (rw *ReceiveWindow) HasGaps() bool {
	rw.mutex.RLock()
	defer rw.mutex.RUnlock()
	return len(rw.window) > 0
}

// GetGapInfo returns information about gaps in the receive window.
// Returns the range of buffered packet numbers and the count.
// Useful for diagnostics and selective ACK generation.
//
// Thread-safe: can be called concurrently.
func (rw *ReceiveWindow) GetGapInfo() (minBuffered, maxBuffered uint32, count int) {
	rw.mutex.RLock()
	defer rw.mutex.RUnlock()

	if len(rw.window) == 0 {
		return 0, 0, 0
	}

	minBuffered = MaxPacketNumber
	maxBuffered = 0

	for pktNum := range rw.window {
		if pktNum < minBuffered {
			minBuffered = pktNum
		}
		if pktNum > maxBuffered {
			maxBuffered = pktNum
		}
	}

	return minBuffered, maxBuffered, len(rw.window)
}
