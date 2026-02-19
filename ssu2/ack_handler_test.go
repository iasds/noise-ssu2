package ssu2

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewACKHandler tests ACK handler creation
func TestNewACKHandler(t *testing.T) {
	handler := NewACKHandler()

	assert.NotNil(t, handler)
	assert.Empty(t, handler.receivedPackets)
	assert.Empty(t, handler.pendingACKs)
	assert.Equal(t, 10*time.Millisecond, handler.ackDelay)
	assert.False(t, handler.HasPending())
}

// TestACKHandler_RecordReceived tests recording received packets
func TestACKHandler_RecordReceived(t *testing.T) {
	handler := NewACKHandler()

	handler.RecordReceived(100)
	handler.RecordReceived(101)
	handler.RecordReceived(102)

	assert.Len(t, handler.receivedPackets, 3)
	assert.Contains(t, handler.receivedPackets, uint32(100))
	assert.Contains(t, handler.receivedPackets, uint32(101))
	assert.Contains(t, handler.receivedPackets, uint32(102))
}

// TestACKHandler_ShouldSendACK tests ACK sending decision
func TestACKHandler_ShouldSendACK(t *testing.T) {
	tests := []struct {
		name             string
		packets          []uint32
		rtt              time.Duration
		timeSinceLastACK time.Duration
		want             bool
	}{
		{
			name:    "no packets",
			packets: []uint32{},
			rtt:     100 * time.Millisecond,
			want:    false,
		},
		{
			name:             "delay not elapsed",
			packets:          []uint32{1, 2, 3},
			rtt:              100 * time.Millisecond,
			timeSinceLastACK: 5 * time.Millisecond,
			want:             false,
		},
		{
			name:             "delay elapsed",
			packets:          []uint32{1, 2, 3},
			rtt:              60 * time.Millisecond,
			timeSinceLastACK: 11 * time.Millisecond,
			want:             true,
		},
		{
			name:    "many packets",
			packets: make([]uint32, 15), // 15 packets triggers immediate ACK
			rtt:     100 * time.Millisecond,
			want:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := NewACKHandler()
			for _, pkt := range tt.packets {
				handler.RecordReceived(pkt)
			}

			if tt.timeSinceLastACK > 0 {
				handler.lastACKTime = time.Now().Add(-tt.timeSinceLastACK)
			}

			got := handler.ShouldSendACK(tt.rtt)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestACKHandler_ShouldSendACK_DelayCalculation tests dynamic ACK delay
func TestACKHandler_ShouldSendACK_DelayCalculation(t *testing.T) {
	tests := []struct {
		name      string
		rtt       time.Duration
		wantDelay time.Duration
	}{
		{
			name:      "low RTT - capped at 10ms",
			rtt:       30 * time.Millisecond,
			wantDelay: 10 * time.Millisecond,
		},
		{
			name:      "medium RTT",
			rtt:       120 * time.Millisecond,
			wantDelay: 20 * time.Millisecond, // 120/6 = 20
		},
		{
			name:      "high RTT - capped at 150ms",
			rtt:       2000 * time.Millisecond,
			wantDelay: 150 * time.Millisecond,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := NewACKHandler()
			handler.RecordReceived(1)
			handler.lastACKTime = time.Now().Add(-200 * time.Millisecond)

			handler.ShouldSendACK(tt.rtt)
			assert.Equal(t, tt.wantDelay, handler.ackDelay)
		})
	}
}

// TestACKHandler_GenerateACK tests ACK block generation
func TestACKHandler_GenerateACK(t *testing.T) {
	tests := []struct {
		name       string
		packets    []uint32
		wantRanges int
		wantNil    bool
	}{
		{
			name:    "no packets",
			packets: []uint32{},
			wantNil: true,
		},
		{
			name:       "single packet",
			packets:    []uint32{100},
			wantRanges: 1,
		},
		{
			name:       "contiguous range",
			packets:    []uint32{100, 101, 102, 103},
			wantRanges: 1,
		},
		{
			name:       "multiple ranges",
			packets:    []uint32{100, 101, 105, 106, 110},
			wantRanges: 3,
		},
		{
			name:       "out of order",
			packets:    []uint32{105, 100, 102, 101, 103},
			wantRanges: 2, // [100-103], [105]
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := NewACKHandler()
			for _, pkt := range tt.packets {
				handler.RecordReceived(pkt)
			}

			block, err := handler.GenerateACK()
			require.NoError(t, err)

			if tt.wantNil {
				assert.Nil(t, block)
				return
			}

			require.NotNil(t, block)
			assert.Equal(t, BlockTypeACK, block.Type)
			assert.GreaterOrEqual(t, len(block.Data), 5)

			// Verify range count
			rangeCount := int(block.Data[0])
			assert.Equal(t, tt.wantRanges, rangeCount)

			// Verify received packets cleared
			assert.Empty(t, handler.receivedPackets)
		})
	}
}

// TestACKHandler_GenerateACK_Format tests ACK block data format
func TestACKHandler_GenerateACK_Format(t *testing.T) {
	handler := NewACKHandler()
	handler.RecordReceived(100)
	handler.RecordReceived(101)
	handler.RecordReceived(102)

	block, err := handler.GenerateACK()
	require.NoError(t, err)
	require.NotNil(t, block)

	data := block.Data
	assert.GreaterOrEqual(t, len(data), 5)

	// Check header
	rangeCount := data[0]
	assert.Equal(t, uint8(1), rangeCount) // One contiguous range

	// ACK delay should be present (4 bytes)
	assert.GreaterOrEqual(t, len(data), 5)

	// Check range (should be 100-102)
	assert.Equal(t, 5+8, len(data)) // Header + one range (8 bytes)
}

// TestACKHandler_ProcessACK tests processing incoming ACK blocks
func TestACKHandler_ProcessACK(t *testing.T) {
	tests := []struct {
		name        string
		createBlock func() *SSU2Block
		wantPackets []uint32
		wantError   bool
	}{
		{
			name: "single range",
			createBlock: func() *SSU2Block {
				data := make([]byte, 13)
				data[0] = 1 // 1 range
				// ACK delay (bytes 1-4) already zero
				// Range: 100-102
				data[5] = 0
				data[6] = 0
				data[7] = 0
				data[8] = 100
				data[9] = 0
				data[10] = 0
				data[11] = 0
				data[12] = 102
				return NewSSU2Block(BlockTypeACK, data)
			},
			wantPackets: []uint32{100, 101, 102},
		},
		{
			name: "multiple ranges",
			createBlock: func() *SSU2Block {
				data := make([]byte, 21)
				data[0] = 2 // 2 ranges
				// Range 1: 100-102
				data[5] = 0
				data[6] = 0
				data[7] = 0
				data[8] = 100
				data[9] = 0
				data[10] = 0
				data[11] = 0
				data[12] = 102
				// Range 2: 200-201
				data[13] = 0
				data[14] = 0
				data[15] = 0
				data[16] = 200
				data[17] = 0
				data[18] = 0
				data[19] = 0
				data[20] = 201
				return NewSSU2Block(BlockTypeACK, data)
			},
			wantPackets: []uint32{100, 101, 102, 200, 201},
		},
		{
			name: "wrong block type",
			createBlock: func() *SSU2Block {
				return NewSSU2Block(BlockTypePadding, []byte{1, 2, 3, 4, 5})
			},
			wantError: true,
		},
		{
			name: "too short",
			createBlock: func() *SSU2Block {
				return NewSSU2Block(BlockTypeACK, []byte{1, 2, 3}) // Only 3 bytes
			},
			wantError: true,
		},
		{
			name: "invalid range",
			createBlock: func() *SSU2Block {
				data := make([]byte, 13)
				data[0] = 1 // 1 range
				// Range: 102-100 (start > end)
				data[5] = 0
				data[6] = 0
				data[7] = 0
				data[8] = 102
				data[9] = 0
				data[10] = 0
				data[11] = 0
				data[12] = 100
				return NewSSU2Block(BlockTypeACK, data)
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := NewACKHandler()
			block := tt.createBlock()

			packets, err := handler.ProcessACK(block)

			if tt.wantError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.ElementsMatch(t, tt.wantPackets, packets)
		})
	}
}

// TestACKHandler_AddPending tests adding pending ACKs
func TestACKHandler_AddPending(t *testing.T) {
	handler := NewACKHandler()

	handler.AddPending(100)
	handler.AddPending(101)
	handler.AddPending(102)

	assert.True(t, handler.HasPending())
	assert.Len(t, handler.pendingACKs, 3)

	pending, exists := handler.GetPendingPacket(100)
	assert.True(t, exists)
	assert.Equal(t, uint32(100), pending.PacketNumber)
	assert.Equal(t, 0, pending.Retries)
	assert.WithinDuration(t, time.Now(), pending.SentTime, time.Second)
}

// TestACKHandler_GetPending tests retrieving pending packet list
func TestACKHandler_GetPending(t *testing.T) {
	handler := NewACKHandler()

	handler.AddPending(100)
	handler.AddPending(101)
	handler.AddPending(102)

	pending := handler.GetPending()
	assert.Len(t, pending, 3)
	assert.Contains(t, pending, uint32(100))
	assert.Contains(t, pending, uint32(101))
	assert.Contains(t, pending, uint32(102))
}

// TestACKHandler_ProcessACK_RemovesPending tests ACK processing removes pending
func TestACKHandler_ProcessACK_RemovesPending(t *testing.T) {
	handler := NewACKHandler()

	// Add pending packets
	handler.AddPending(100)
	handler.AddPending(101)
	handler.AddPending(102)
	handler.AddPending(200)

	assert.Len(t, handler.pendingACKs, 4)

	// Create ACK for packets 100-102
	data := make([]byte, 13)
	data[0] = 1 // 1 range
	data[5] = 0
	data[6] = 0
	data[7] = 0
	data[8] = 100
	data[9] = 0
	data[10] = 0
	data[11] = 0
	data[12] = 102
	block := NewSSU2Block(BlockTypeACK, data)

	_, err := handler.ProcessACK(block)
	require.NoError(t, err)

	// Packets 100-102 should be removed, 200 should remain
	assert.Len(t, handler.pendingACKs, 1)
	_, exists := handler.GetPendingPacket(200)
	assert.True(t, exists)
	_, exists = handler.GetPendingPacket(100)
	assert.False(t, exists)
}

// TestACKHandler_ClearPending tests clearing all pending ACKs
func TestACKHandler_ClearPending(t *testing.T) {
	handler := NewACKHandler()

	handler.AddPending(100)
	handler.AddPending(101)
	handler.RecordReceived(200)
	handler.RecordReceived(201)

	assert.True(t, handler.HasPending())
	assert.NotEmpty(t, handler.receivedPackets)

	handler.ClearPending()

	assert.False(t, handler.HasPending())
	assert.Empty(t, handler.receivedPackets)
	assert.Empty(t, handler.pendingACKs)
}

// TestACKHandler_RoundTrip tests full ACK cycle
func TestACKHandler_RoundTrip(t *testing.T) {
	sender := NewACKHandler()
	receiver := NewACKHandler()

	// Sender sends packets 100-102
	sender.AddPending(100)
	sender.AddPending(101)
	sender.AddPending(102)

	// Receiver records receiving them
	receiver.RecordReceived(100)
	receiver.RecordReceived(101)
	receiver.RecordReceived(102)

	// Receiver generates ACK
	ackBlock, err := receiver.GenerateACK()
	require.NoError(t, err)
	require.NotNil(t, ackBlock)

	// Sender processes ACK
	ackedPackets, err := sender.ProcessACK(ackBlock)
	require.NoError(t, err)

	// Verify all packets acknowledged
	assert.ElementsMatch(t, []uint32{100, 101, 102}, ackedPackets)
	assert.False(t, sender.HasPending())
}

// TestCompressPacketRanges tests packet range compression
func TestCompressPacketRanges(t *testing.T) {
	tests := []struct {
		name    string
		packets []uint32
		want    []packetRange
	}{
		{
			name:    "empty",
			packets: []uint32{},
			want:    nil,
		},
		{
			name:    "single packet",
			packets: []uint32{100},
			want:    []packetRange{{100, 100}},
		},
		{
			name:    "contiguous range",
			packets: []uint32{100, 101, 102, 103},
			want:    []packetRange{{100, 103}},
		},
		{
			name:    "two ranges",
			packets: []uint32{100, 101, 105, 106},
			want:    []packetRange{{100, 101}, {105, 106}},
		},
		{
			name:    "three ranges",
			packets: []uint32{100, 101, 105, 110, 111, 112},
			want:    []packetRange{{100, 101}, {105, 105}, {110, 112}},
		},
		{
			name:    "unsorted input",
			packets: []uint32{105, 100, 102, 101, 103},
			want:    []packetRange{{100, 103}, {105, 105}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := compressPacketRanges(tt.packets)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestACKHandler_EmptyDelay tests ACK generation with zero delay
func TestACKHandler_EmptyDelay(t *testing.T) {
	handler := NewACKHandler()
	handler.lastACKTime = time.Now() // Just set, no delay

	handler.RecordReceived(100)

	block, err := handler.GenerateACK()
	require.NoError(t, err)
	require.NotNil(t, block)

	// ACK delay should be very small (0-1 ms)
	data := block.Data
	assert.GreaterOrEqual(t, len(data), 5)
}

// Benchmark tests
func BenchmarkACKHandler_RecordReceived(b *testing.B) {
	handler := NewACKHandler()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		handler.RecordReceived(uint32(i))
	}
}

func BenchmarkACKHandler_GenerateACK(b *testing.B) {
	handler := NewACKHandler()
	for i := 0; i < 10; i++ {
		handler.RecordReceived(uint32(i * 10))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = handler.GenerateACK()
		// Re-add packets for next iteration
		for j := 0; j < 10; j++ {
			handler.RecordReceived(uint32(j * 10))
		}
	}
}

func BenchmarkACKHandler_ProcessACK(b *testing.B) {
	// Create ACK block
	data := make([]byte, 13)
	data[0] = 1 // 1 range
	data[8] = 100
	data[12] = 110
	block := NewSSU2Block(BlockTypeACK, data)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		handler := NewACKHandler()
		for j := uint32(100); j <= 110; j++ {
			handler.AddPending(j)
		}
		_, _ = handler.ProcessACK(block)
	}
}

func BenchmarkCompressPacketRanges(b *testing.B) {
	packets := make([]uint32, 100)
	for i := 0; i < 100; i++ {
		packets[i] = uint32(i * 2) // Create gaps
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = compressPacketRanges(packets)
	}
}
