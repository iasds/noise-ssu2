package ssu2

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewDataHandler(t *testing.T) {
	tests := []struct {
		name      string
		queueSize int
		expected  int
	}{
		{
			name:      "default queue size",
			queueSize: 0,
			expected:  100,
		},
		{
			name:      "negative queue size uses default",
			queueSize: -5,
			expected:  100,
		},
		{
			name:      "custom queue size",
			queueSize: 50,
			expected:  50,
		},
		{
			name:      "large queue size",
			queueSize: 1000,
			expected:  1000,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := NewDataHandler(tt.queueSize)
			require.NotNil(t, handler)
			assert.NotNil(t, handler.messageQueue)
			assert.NotNil(t, handler.fragments)
			assert.Equal(t, tt.expected, cap(handler.messageQueue))
			assert.Equal(t, 0, len(handler.fragments))
		})
	}
}

func TestDataHandler_ProcessDataPacket_InvalidType(t *testing.T) {
	handler := NewDataHandler(10)

	// Create packet with wrong message type
	packet := &SSU2Packet{
		MessageType: MessageTypeSessionRequest, // Wrong type
		Payload:     []byte{},
	}

	blocks, err := handler.ProcessDataPacket(packet)
	assert.Error(t, err)
	assert.Nil(t, blocks)
	assert.Contains(t, err.Error(), "expected Data packet")
}

func TestDataHandler_ProcessDataPacket_MalformedBlocks(t *testing.T) {
	handler := NewDataHandler(10)

	// Create packet with invalid block data
	packet := &SSU2Packet{
		MessageType: MessageTypeData,
		Payload:     []byte{0xFF, 0xFF}, // Invalid TLV data
	}

	blocks, err := handler.ProcessDataPacket(packet)
	assert.Error(t, err)
	assert.Nil(t, blocks)
	assert.Contains(t, err.Error(), "failed to deserialize blocks")

	// Verify stats
	stats := handler.GetStats()
	assert.Equal(t, uint64(1), stats.MessagesDropped)
}

func TestDataHandler_ProcessDataPacket_I2NPMessage(t *testing.T) {
	handler := NewDataHandler(10)

	// Create I2NP message block
	i2npData := []byte("Test I2NP Message Data")
	block := NewSSU2Block(BlockTypeI2NPMessage, i2npData)

	// Serialize blocks
	blocks := []*SSU2Block{block}
	payload, err := SerializeBlocks(blocks)
	require.NoError(t, err)

	// Create Data packet
	packet := &SSU2Packet{
		MessageType: MessageTypeData,
		Payload:     payload,
	}

	// Process packet
	returnedBlocks, err := handler.ProcessDataPacket(packet)
	require.NoError(t, err)
	assert.Len(t, returnedBlocks, 1)

	// Verify message was queued
	assert.True(t, handler.HasMessages())
	msg := handler.GetMessage()
	require.NotNil(t, msg)
	assert.Equal(t, i2npData, msg)

	// Verify stats
	stats := handler.GetStats()
	assert.Equal(t, uint64(1), stats.MessagesReceived)
	assert.Equal(t, uint64(0), stats.MessagesDropped)
}

func TestDataHandler_ProcessDataPacket_EmptyI2NPMessage(t *testing.T) {
	handler := NewDataHandler(10)

	// Create empty I2NP message block
	block := NewSSU2Block(BlockTypeI2NPMessage, []byte{})

	// Serialize blocks
	blocks := []*SSU2Block{block}
	payload, err := SerializeBlocks(blocks)
	require.NoError(t, err)

	// Create Data packet
	packet := &SSU2Packet{
		MessageType: MessageTypeData,
		Payload:     payload,
	}

	// Process packet
	returnedBlocks, err := handler.ProcessDataPacket(packet)
	require.Error(t, err)
	assert.NotNil(t, returnedBlocks) // Blocks are returned even on error
	assert.Contains(t, err.Error(), "I2NP message block is empty")

	// Verify stats
	stats := handler.GetStats()
	assert.Equal(t, uint64(0), stats.MessagesReceived)
	assert.Equal(t, uint64(1), stats.MessagesDropped)
}

func TestDataHandler_ProcessDataPacket_MultipleBlocks(t *testing.T) {
	handler := NewDataHandler(10)

	// Create multiple I2NP message blocks
	i2npData1 := []byte("Message 1")
	i2npData2 := []byte("Message 2")
	i2npData3 := []byte("Message 3")

	blocks := []*SSU2Block{
		NewSSU2Block(BlockTypeI2NPMessage, i2npData1),
		NewSSU2Block(BlockTypeI2NPMessage, i2npData2),
		NewSSU2Block(BlockTypeI2NPMessage, i2npData3),
	}

	// Serialize blocks
	payload, err := SerializeBlocks(blocks)
	require.NoError(t, err)

	// Create Data packet
	packet := &SSU2Packet{
		MessageType: MessageTypeData,
		Payload:     payload,
	}

	// Process packet
	returnedBlocks, err := handler.ProcessDataPacket(packet)
	require.NoError(t, err)
	assert.Len(t, returnedBlocks, 3)

	// Verify all messages were queued
	msg1 := handler.GetMessage()
	msg2 := handler.GetMessage()
	msg3 := handler.GetMessage()

	require.NotNil(t, msg1)
	require.NotNil(t, msg2)
	require.NotNil(t, msg3)

	assert.Equal(t, i2npData1, msg1)
	assert.Equal(t, i2npData2, msg2)
	assert.Equal(t, i2npData3, msg3)

	// Verify stats
	stats := handler.GetStats()
	assert.Equal(t, uint64(3), stats.MessagesReceived)
}

func TestDataHandler_ProcessDataPacket_MixedBlocks(t *testing.T) {
	handler := NewDataHandler(10)

	// Create mixed block types
	i2npData := []byte("I2NP Message")
	dateTimeData := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00} // 7-byte timestamp (minimum)
	paddingData := make([]byte, 16)

	blocks := []*SSU2Block{
		NewSSU2Block(BlockTypeDateTime, dateTimeData),
		NewSSU2Block(BlockTypeI2NPMessage, i2npData),
		NewSSU2Block(BlockTypePadding, paddingData),
	}

	// Serialize blocks
	payload, err := SerializeBlocks(blocks)
	require.NoError(t, err)

	// Create Data packet
	packet := &SSU2Packet{
		MessageType: MessageTypeData,
		Payload:     payload,
	}

	// Process packet
	returnedBlocks, err := handler.ProcessDataPacket(packet)
	require.NoError(t, err)
	assert.Len(t, returnedBlocks, 3)

	// Only I2NP message should be queued
	assert.True(t, handler.HasMessages())
	msg := handler.GetMessage()
	require.NotNil(t, msg)
	assert.Equal(t, i2npData, msg)

	// No more messages
	assert.False(t, handler.HasMessages())
}

func TestDataHandler_FirstFragment(t *testing.T) {
	handler := NewDataHandler(10)

	// Create first fragment
	messageID := uint32(12345)
	totalSize := uint32(100)
	fragmentData := []byte("First fragment data")

	// Build first fragment block data
	blockData := make([]byte, 8+len(fragmentData))
	blockData[0] = byte(messageID >> 24)
	blockData[1] = byte(messageID >> 16)
	blockData[2] = byte(messageID >> 8)
	blockData[3] = byte(messageID)
	blockData[4] = byte(totalSize >> 24)
	blockData[5] = byte(totalSize >> 16)
	blockData[6] = byte(totalSize >> 8)
	blockData[7] = byte(totalSize)
	copy(blockData[8:], fragmentData)

	block := NewSSU2Block(BlockTypeFirstFragment, blockData)

	// Serialize and create packet
	payload, err := SerializeBlocks([]*SSU2Block{block})
	require.NoError(t, err)

	packet := &SSU2Packet{
		MessageType: MessageTypeData,
		Payload:     payload,
	}

	// Process packet
	_, err = handler.ProcessDataPacket(packet)
	require.NoError(t, err)

	// Verify fragment set created
	assert.Equal(t, 1, handler.GetFragmentCount())

	// Verify stats
	stats := handler.GetStats()
	assert.Equal(t, uint64(1), stats.FragmentsReceived)
	assert.Equal(t, uint64(0), stats.MessagesReassembled)

	// No complete message yet
	assert.False(t, handler.HasMessages())
}

func TestDataHandler_FirstFragment_TooShort(t *testing.T) {
	handler := NewDataHandler(10)

	// Create invalid first fragment (too short)
	blockData := []byte{0x00, 0x01, 0x02} // Only 3 bytes, need at least 8

	block := NewSSU2Block(BlockTypeFirstFragment, blockData)

	// Serialize and create packet
	payload, err := SerializeBlocks([]*SSU2Block{block})
	require.NoError(t, err)

	packet := &SSU2Packet{
		MessageType: MessageTypeData,
		Payload:     payload,
	}

	// Process packet should fail
	_, err = handler.ProcessDataPacket(packet)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "first fragment too short")

	// Verify stats
	stats := handler.GetStats()
	assert.Equal(t, uint64(1), stats.MessagesDropped)
}

func TestDataHandler_FirstFragment_Duplicate(t *testing.T) {
	handler := NewDataHandler(10)

	messageID := uint32(12345)
	totalSize := uint32(100)
	fragmentData := []byte("First fragment data")

	// Build first fragment block data
	blockData := make([]byte, 8+len(fragmentData))
	blockData[0] = byte(messageID >> 24)
	blockData[1] = byte(messageID >> 16)
	blockData[2] = byte(messageID >> 8)
	blockData[3] = byte(messageID)
	blockData[4] = byte(totalSize >> 24)
	blockData[5] = byte(totalSize >> 16)
	blockData[6] = byte(totalSize >> 8)
	blockData[7] = byte(totalSize)
	copy(blockData[8:], fragmentData)

	block := NewSSU2Block(BlockTypeFirstFragment, blockData)

	// Serialize and create packet
	payload, err := SerializeBlocks([]*SSU2Block{block})
	require.NoError(t, err)

	packet := &SSU2Packet{
		MessageType: MessageTypeData,
		Payload:     payload,
	}

	// Process first fragment
	_, err = handler.ProcessDataPacket(packet)
	require.NoError(t, err)

	// Process duplicate first fragment
	_, err = handler.ProcessDataPacket(packet)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate first fragment")

	// Verify stats - only the second (duplicate) first fragment is dropped
	stats := handler.GetStats()
	assert.Equal(t, uint64(1), stats.MessagesDropped)
}

func TestDataHandler_FollowOnFragment(t *testing.T) {
	handler := NewDataHandler(10)

	messageID := uint32(12345)
	firstData := []byte("First fragment data")
	secondData := []byte("Second fragment data")
	totalSize := uint32(len(firstData) + len(secondData)) // Total size matches actual data

	// Send first fragment
	firstBlockData := make([]byte, 8+len(firstData))
	firstBlockData[0] = byte(messageID >> 24)
	firstBlockData[1] = byte(messageID >> 16)
	firstBlockData[2] = byte(messageID >> 8)
	firstBlockData[3] = byte(messageID)
	firstBlockData[4] = byte(totalSize >> 24)
	firstBlockData[5] = byte(totalSize >> 16)
	firstBlockData[6] = byte(totalSize >> 8)
	firstBlockData[7] = byte(totalSize)
	copy(firstBlockData[8:], firstData)

	firstBlock := NewSSU2Block(BlockTypeFirstFragment, firstBlockData)
	payload1, err := SerializeBlocks([]*SSU2Block{firstBlock})
	require.NoError(t, err)

	packet1 := &SSU2Packet{
		MessageType: MessageTypeData,
		Payload:     payload1,
	}

	_, err = handler.ProcessDataPacket(packet1)
	require.NoError(t, err)
	assert.Equal(t, 1, handler.GetFragmentCount())

	// Send follow-on fragment
	followOnBlockData := make([]byte, 5+len(secondData))
	followOnBlockData[0] = byte(messageID >> 24)
	followOnBlockData[1] = byte(messageID >> 16)
	followOnBlockData[2] = byte(messageID >> 8)
	followOnBlockData[3] = byte(messageID)
	followOnBlockData[4] = 1 // Fragment number
	copy(followOnBlockData[5:], secondData)

	followOnBlock := NewSSU2Block(BlockTypeFollowOnFragment, followOnBlockData)
	payload2, err := SerializeBlocks([]*SSU2Block{followOnBlock})
	require.NoError(t, err)

	packet2 := &SSU2Packet{
		MessageType: MessageTypeData,
		Payload:     payload2,
	}

	_, err = handler.ProcessDataPacket(packet2)
	require.NoError(t, err)

	// Message should be complete and queued
	if !handler.HasMessages() {
		t.Logf("Fragment count: %d, Received size: %d, Total size: %d", handler.GetFragmentCount(), uint32(len(firstData)+len(secondData)), totalSize)
	}
	assert.True(t, handler.HasMessages())
	msg := handler.GetMessage()
	require.NotNil(t, msg)

	// Verify reassembled message
	expected := append(firstData, secondData...)
	assert.Equal(t, expected, msg)

	// Fragment set should be cleaned up
	assert.Equal(t, 0, handler.GetFragmentCount())

	// Verify stats
	stats := handler.GetStats()
	assert.Equal(t, uint64(2), stats.FragmentsReceived)
	assert.Equal(t, uint64(1), stats.MessagesReassembled)
}

func TestDataHandler_FollowOnFragment_TooShort(t *testing.T) {
	handler := NewDataHandler(10)

	// Create invalid follow-on fragment (too short)
	blockData := []byte{0x00, 0x01} // Only 2 bytes, need at least 5

	block := NewSSU2Block(BlockTypeFollowOnFragment, blockData)

	// Serialize and create packet
	payload, err := SerializeBlocks([]*SSU2Block{block})
	require.NoError(t, err)

	packet := &SSU2Packet{
		MessageType: MessageTypeData,
		Payload:     payload,
	}

	// Process packet should fail
	_, err = handler.ProcessDataPacket(packet)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "follow-on fragment too short")

	// Verify stats
	stats := handler.GetStats()
	assert.Equal(t, uint64(1), stats.MessagesDropped)
}

func TestDataHandler_FollowOnFragment_UnknownMessageID(t *testing.T) {
	handler := NewDataHandler(10)

	messageID := uint32(99999)
	fragmentData := []byte("Fragment data")

	// Build follow-on fragment without first fragment
	blockData := make([]byte, 5+len(fragmentData))
	blockData[0] = byte(messageID >> 24)
	blockData[1] = byte(messageID >> 16)
	blockData[2] = byte(messageID >> 8)
	blockData[3] = byte(messageID)
	blockData[4] = 1 // Fragment number
	copy(blockData[5:], fragmentData)

	block := NewSSU2Block(BlockTypeFollowOnFragment, blockData)

	// Serialize and create packet
	payload, err := SerializeBlocks([]*SSU2Block{block})
	require.NoError(t, err)

	packet := &SSU2Packet{
		MessageType: MessageTypeData,
		Payload:     payload,
	}

	// Process packet should fail
	_, err = handler.ProcessDataPacket(packet)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown message ID")

	// Verify stats
	stats := handler.GetStats()
	assert.Equal(t, uint64(1), stats.MessagesDropped)
}

func TestDataHandler_FollowOnFragment_Duplicate(t *testing.T) {
	handler := NewDataHandler(10)

	messageID := uint32(12345)
	totalSize := uint32(100)
	firstData := []byte("First fragment data")

	// Send first fragment
	firstBlockData := make([]byte, 8+len(firstData))
	firstBlockData[0] = byte(messageID >> 24)
	firstBlockData[1] = byte(messageID >> 16)
	firstBlockData[2] = byte(messageID >> 8)
	firstBlockData[3] = byte(messageID)
	firstBlockData[4] = byte(totalSize >> 24)
	firstBlockData[5] = byte(totalSize >> 16)
	firstBlockData[6] = byte(totalSize >> 8)
	firstBlockData[7] = byte(totalSize)
	copy(firstBlockData[8:], firstData)

	firstBlock := NewSSU2Block(BlockTypeFirstFragment, firstBlockData)
	payload1, err := SerializeBlocks([]*SSU2Block{firstBlock})
	require.NoError(t, err)

	packet1 := &SSU2Packet{
		MessageType: MessageTypeData,
		Payload:     payload1,
	}

	_, err = handler.ProcessDataPacket(packet1)
	require.NoError(t, err)

	// Send same follow-on fragment twice
	fragmentData := []byte("Follow-on data")
	followOnBlockData := make([]byte, 5+len(fragmentData))
	followOnBlockData[0] = byte(messageID >> 24)
	followOnBlockData[1] = byte(messageID >> 16)
	followOnBlockData[2] = byte(messageID >> 8)
	followOnBlockData[3] = byte(messageID)
	followOnBlockData[4] = 1 // Fragment number
	copy(followOnBlockData[5:], fragmentData)

	followOnBlock := NewSSU2Block(BlockTypeFollowOnFragment, followOnBlockData)
	payload2, err := SerializeBlocks([]*SSU2Block{followOnBlock})
	require.NoError(t, err)

	packet2 := &SSU2Packet{
		MessageType: MessageTypeData,
		Payload:     payload2,
	}

	// First follow-on should succeed
	_, err = handler.ProcessDataPacket(packet2)
	require.NoError(t, err)

	// Second should succeed silently (duplicate handling)
	_, err = handler.ProcessDataPacket(packet2)
	require.NoError(t, err)

	// Verify fragment count unchanged
	assert.Equal(t, 1, handler.GetFragmentCount())
}

func TestDataHandler_FragmentReassembly_SizeMismatch(t *testing.T) {
	handler := NewDataHandler(10)

	messageID := uint32(12345)
	totalSize := uint32(10)              // Claim 10 bytes total
	firstData := []byte("First")         // 5 bytes
	secondData := []byte("Second-Extra") // More than 5 bytes - will cause mismatch

	// Send first fragment
	firstBlockData := make([]byte, 8+len(firstData))
	firstBlockData[0] = byte(messageID >> 24)
	firstBlockData[1] = byte(messageID >> 16)
	firstBlockData[2] = byte(messageID >> 8)
	firstBlockData[3] = byte(messageID)
	firstBlockData[4] = byte(totalSize >> 24)
	firstBlockData[5] = byte(totalSize >> 16)
	firstBlockData[6] = byte(totalSize >> 8)
	firstBlockData[7] = byte(totalSize)
	copy(firstBlockData[8:], firstData)

	firstBlock := NewSSU2Block(BlockTypeFirstFragment, firstBlockData)
	payload1, err := SerializeBlocks([]*SSU2Block{firstBlock})
	require.NoError(t, err)

	packet1 := &SSU2Packet{
		MessageType: MessageTypeData,
		Payload:     payload1,
	}

	_, err = handler.ProcessDataPacket(packet1)
	require.NoError(t, err)

	// Send follow-on fragment that makes total > declared size
	followOnBlockData := make([]byte, 5+len(secondData))
	followOnBlockData[0] = byte(messageID >> 24)
	followOnBlockData[1] = byte(messageID >> 16)
	followOnBlockData[2] = byte(messageID >> 8)
	followOnBlockData[3] = byte(messageID)
	followOnBlockData[4] = 1 // Fragment number
	copy(followOnBlockData[5:], secondData)

	followOnBlock := NewSSU2Block(BlockTypeFollowOnFragment, followOnBlockData)
	payload2, err := SerializeBlocks([]*SSU2Block{followOnBlock})
	require.NoError(t, err)

	packet2 := &SSU2Packet{
		MessageType: MessageTypeData,
		Payload:     payload2,
	}

	// Process - should trigger reassembly attempt and fail due to size >= totalSize
	_, err = handler.ProcessDataPacket(packet2)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "size mismatch")

	// Fragment set should be cleaned up
	assert.Equal(t, 0, handler.GetFragmentCount())

	// Verify stats
	stats := handler.GetStats()
	assert.Equal(t, uint64(1), stats.MessagesDropped)
}

func TestDataHandler_GetMessage_NonBlocking(t *testing.T) {
	handler := NewDataHandler(10)

	// Queue a message
	i2npData := []byte("Test message")
	block := NewSSU2Block(BlockTypeI2NPMessage, i2npData)
	payload, err := SerializeBlocks([]*SSU2Block{block})
	require.NoError(t, err)

	packet := &SSU2Packet{
		MessageType: MessageTypeData,
		Payload:     payload,
	}

	_, err = handler.ProcessDataPacket(packet)
	require.NoError(t, err)

	// Get message (non-blocking)
	msg := handler.GetMessage()
	require.NotNil(t, msg)
	assert.Equal(t, i2npData, msg)

	// No more messages
	msg = handler.GetMessage()
	assert.Nil(t, msg)
}

func TestDataHandler_GetMessageBlocking_WithTimeout(t *testing.T) {
	handler := NewDataHandler(10)

	// Test timeout with no messages
	start := time.Now()
	msg := handler.GetMessageBlocking(50 * time.Millisecond)
	elapsed := time.Since(start)

	assert.Nil(t, msg)
	assert.True(t, elapsed >= 50*time.Millisecond, "should wait at least 50ms")
	assert.True(t, elapsed < 100*time.Millisecond, "should not wait much longer than 50ms")
}

func TestDataHandler_GetMessageBlocking_WithMessage(t *testing.T) {
	handler := NewDataHandler(10)

	// Queue a message in a goroutine after a delay
	i2npData := []byte("Delayed message")
	go func() {
		time.Sleep(20 * time.Millisecond)
		block := NewSSU2Block(BlockTypeI2NPMessage, i2npData)
		payload, _ := SerializeBlocks([]*SSU2Block{block})
		packet := &SSU2Packet{
			MessageType: MessageTypeData,
			Payload:     payload,
		}
		handler.ProcessDataPacket(packet)
	}()

	// Get message with timeout
	start := time.Now()
	msg := handler.GetMessageBlocking(100 * time.Millisecond)
	elapsed := time.Since(start)

	require.NotNil(t, msg)
	assert.Equal(t, i2npData, msg)
	assert.True(t, elapsed >= 20*time.Millisecond, "should wait at least 20ms")
	assert.True(t, elapsed < 50*time.Millisecond, "should not wait much longer than message arrival")
}

func TestDataHandler_HasMessages(t *testing.T) {
	handler := NewDataHandler(10)

	// Initially no messages
	assert.False(t, handler.HasMessages())

	// Queue a message
	i2npData := []byte("Test message")
	block := NewSSU2Block(BlockTypeI2NPMessage, i2npData)
	payload, err := SerializeBlocks([]*SSU2Block{block})
	require.NoError(t, err)

	packet := &SSU2Packet{
		MessageType: MessageTypeData,
		Payload:     payload,
	}

	_, err = handler.ProcessDataPacket(packet)
	require.NoError(t, err)

	// Should have messages now
	assert.True(t, handler.HasMessages())

	// Retrieve message
	handler.GetMessage()

	// No more messages
	assert.False(t, handler.HasMessages())
}

func TestDataHandler_CleanupExpiredFragments(t *testing.T) {
	handler := NewDataHandler(10)

	messageID1 := uint32(12345)
	messageID2 := uint32(67890)
	totalSize := uint32(100)
	fragmentData := []byte("Fragment data")

	// Create two fragment sets
	for _, msgID := range []uint32{messageID1, messageID2} {
		blockData := make([]byte, 8+len(fragmentData))
		blockData[0] = byte(msgID >> 24)
		blockData[1] = byte(msgID >> 16)
		blockData[2] = byte(msgID >> 8)
		blockData[3] = byte(msgID)
		blockData[4] = byte(totalSize >> 24)
		blockData[5] = byte(totalSize >> 16)
		blockData[6] = byte(totalSize >> 8)
		blockData[7] = byte(totalSize)
		copy(blockData[8:], fragmentData)

		block := NewSSU2Block(BlockTypeFirstFragment, blockData)
		payload, err := SerializeBlocks([]*SSU2Block{block})
		require.NoError(t, err)

		packet := &SSU2Packet{
			MessageType: MessageTypeData,
			Payload:     payload,
		}

		_, err = handler.ProcessDataPacket(packet)
		require.NoError(t, err)
	}

	// Both fragment sets should exist
	assert.Equal(t, 2, handler.GetFragmentCount())

	// Wait a bit and cleanup with short timeout
	time.Sleep(10 * time.Millisecond)
	removed := handler.CleanupExpiredFragments(5 * time.Millisecond)

	// Both should be removed
	assert.Equal(t, 2, removed)
	assert.Equal(t, 0, handler.GetFragmentCount())

	// Verify stats
	stats := handler.GetStats()
	assert.Equal(t, uint64(2), stats.MessagesDropped) // 2 from cleanup
}

func TestDataHandler_CleanupExpiredFragments_NoExpired(t *testing.T) {
	handler := NewDataHandler(10)

	messageID := uint32(12345)
	totalSize := uint32(100)
	fragmentData := []byte("Fragment data")

	// Create fragment set
	blockData := make([]byte, 8+len(fragmentData))
	blockData[0] = byte(messageID >> 24)
	blockData[1] = byte(messageID >> 16)
	blockData[2] = byte(messageID >> 8)
	blockData[3] = byte(messageID)
	blockData[4] = byte(totalSize >> 24)
	blockData[5] = byte(totalSize >> 16)
	blockData[6] = byte(totalSize >> 8)
	blockData[7] = byte(totalSize)
	copy(blockData[8:], fragmentData)

	block := NewSSU2Block(BlockTypeFirstFragment, blockData)
	payload, err := SerializeBlocks([]*SSU2Block{block})
	require.NoError(t, err)

	packet := &SSU2Packet{
		MessageType: MessageTypeData,
		Payload:     payload,
	}

	_, err = handler.ProcessDataPacket(packet)
	require.NoError(t, err)

	// Fragment set should exist
	assert.Equal(t, 1, handler.GetFragmentCount())

	// Cleanup with long timeout - nothing should be removed
	removed := handler.CleanupExpiredFragments(1 * time.Hour)
	assert.Equal(t, 0, removed)
	assert.Equal(t, 1, handler.GetFragmentCount())
}

func TestDataHandler_GetStats(t *testing.T) {
	handler := NewDataHandler(10)

	// Initial stats should be zero
	stats := handler.GetStats()
	assert.Equal(t, uint64(0), stats.MessagesReceived)
	assert.Equal(t, uint64(0), stats.FragmentsReceived)
	assert.Equal(t, uint64(0), stats.MessagesReassembled)
	assert.Equal(t, uint64(0), stats.MessagesDropped)

	// Process some messages
	i2npData := []byte("Test message")
	block := NewSSU2Block(BlockTypeI2NPMessage, i2npData)
	payload, err := SerializeBlocks([]*SSU2Block{block})
	require.NoError(t, err)

	packet := &SSU2Packet{
		MessageType: MessageTypeData,
		Payload:     payload,
	}

	_, err = handler.ProcessDataPacket(packet)
	require.NoError(t, err)

	// Check updated stats
	stats = handler.GetStats()
	assert.Equal(t, uint64(1), stats.MessagesReceived)
}

func TestDataHandler_GetFragmentCount(t *testing.T) {
	handler := NewDataHandler(10)

	// Initially zero
	assert.Equal(t, 0, handler.GetFragmentCount())

	// Add fragment
	messageID := uint32(12345)
	totalSize := uint32(100)
	fragmentData := []byte("Fragment data")

	blockData := make([]byte, 8+len(fragmentData))
	blockData[0] = byte(messageID >> 24)
	blockData[1] = byte(messageID >> 16)
	blockData[2] = byte(messageID >> 8)
	blockData[3] = byte(messageID)
	blockData[4] = byte(totalSize >> 24)
	blockData[5] = byte(totalSize >> 16)
	blockData[6] = byte(totalSize >> 8)
	blockData[7] = byte(totalSize)
	copy(blockData[8:], fragmentData)

	block := NewSSU2Block(BlockTypeFirstFragment, blockData)
	payload, err := SerializeBlocks([]*SSU2Block{block})
	require.NoError(t, err)

	packet := &SSU2Packet{
		MessageType: MessageTypeData,
		Payload:     payload,
	}

	_, err = handler.ProcessDataPacket(packet)
	require.NoError(t, err)

	// Should have one fragment set
	assert.Equal(t, 1, handler.GetFragmentCount())
}

func TestDataHandler_Clear(t *testing.T) {
	handler := NewDataHandler(10)

	// Queue messages
	for i := 0; i < 3; i++ {
		i2npData := []byte("Test message")
		block := NewSSU2Block(BlockTypeI2NPMessage, i2npData)
		payload, err := SerializeBlocks([]*SSU2Block{block})
		require.NoError(t, err)

		packet := &SSU2Packet{
			MessageType: MessageTypeData,
			Payload:     payload,
		}

		_, err = handler.ProcessDataPacket(packet)
		require.NoError(t, err)
	}

	// Add fragments
	messageID := uint32(12345)
	totalSize := uint32(100)
	fragmentData := []byte("Fragment data")

	blockData := make([]byte, 8+len(fragmentData))
	blockData[0] = byte(messageID >> 24)
	blockData[1] = byte(messageID >> 16)
	blockData[2] = byte(messageID >> 8)
	blockData[3] = byte(messageID)
	blockData[4] = byte(totalSize >> 24)
	blockData[5] = byte(totalSize >> 16)
	blockData[6] = byte(totalSize >> 8)
	blockData[7] = byte(totalSize)
	copy(blockData[8:], fragmentData)

	block := NewSSU2Block(BlockTypeFirstFragment, blockData)
	payload, err := SerializeBlocks([]*SSU2Block{block})
	require.NoError(t, err)

	packet := &SSU2Packet{
		MessageType: MessageTypeData,
		Payload:     payload,
	}

	_, err = handler.ProcessDataPacket(packet)
	require.NoError(t, err)

	// Verify we have messages and fragments
	assert.True(t, handler.HasMessages())
	assert.Equal(t, 1, handler.GetFragmentCount())

	// Clear everything
	handler.Clear()

	// Everything should be gone
	assert.False(t, handler.HasMessages())
	assert.Equal(t, 0, handler.GetFragmentCount())
}

func TestDataHandler_QueueFull(t *testing.T) {
	handler := NewDataHandler(2) // Small queue

	// Fill queue
	for i := 0; i < 2; i++ {
		i2npData := []byte("Test message")
		block := NewSSU2Block(BlockTypeI2NPMessage, i2npData)
		payload, err := SerializeBlocks([]*SSU2Block{block})
		require.NoError(t, err)

		packet := &SSU2Packet{
			MessageType: MessageTypeData,
			Payload:     payload,
		}

		_, err = handler.ProcessDataPacket(packet)
		require.NoError(t, err)
	}

	// Try to add one more - should fail
	i2npData := []byte("Test message")
	block := NewSSU2Block(BlockTypeI2NPMessage, i2npData)
	payload, err := SerializeBlocks([]*SSU2Block{block})
	require.NoError(t, err)

	packet := &SSU2Packet{
		MessageType: MessageTypeData,
		Payload:     payload,
	}

	_, err = handler.ProcessDataPacket(packet)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "queue full")

	// Verify stats
	stats := handler.GetStats()
	assert.Equal(t, uint64(2), stats.MessagesReceived)
	assert.Equal(t, uint64(1), stats.MessagesDropped)
}

// Benchmarks

func BenchmarkDataHandler_ProcessI2NPMessage(b *testing.B) {
	handler := NewDataHandler(1000)

	// Create I2NP message packet
	i2npData := make([]byte, 1024) // 1KB message
	for i := range i2npData {
		i2npData[i] = byte(i % 256)
	}

	block := NewSSU2Block(BlockTypeI2NPMessage, i2npData)
	payload, _ := SerializeBlocks([]*SSU2Block{block})

	packet := &SSU2Packet{
		MessageType: MessageTypeData,
		Payload:     payload,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		handler.ProcessDataPacket(packet)

		// Drain queue to avoid filling up
		if i%100 == 0 {
			for handler.HasMessages() {
				handler.GetMessage()
			}
		}
	}
}

func BenchmarkDataHandler_ProcessFragments(b *testing.B) {
	handler := NewDataHandler(1000)

	// Create first fragment packet
	messageID := uint32(12345)
	totalSize := uint32(2048)
	fragmentData := make([]byte, 1024)

	firstBlockData := make([]byte, 8+len(fragmentData))
	firstBlockData[0] = byte(messageID >> 24)
	firstBlockData[1] = byte(messageID >> 16)
	firstBlockData[2] = byte(messageID >> 8)
	firstBlockData[3] = byte(messageID)
	firstBlockData[4] = byte(totalSize >> 24)
	firstBlockData[5] = byte(totalSize >> 16)
	firstBlockData[6] = byte(totalSize >> 8)
	firstBlockData[7] = byte(totalSize)
	copy(firstBlockData[8:], fragmentData)

	firstBlock := NewSSU2Block(BlockTypeFirstFragment, firstBlockData)
	payload1, _ := SerializeBlocks([]*SSU2Block{firstBlock})

	packet1 := &SSU2Packet{
		MessageType: MessageTypeData,
		Payload:     payload1,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		handler.Clear() // Clear between iterations
		handler.ProcessDataPacket(packet1)
	}
}

func BenchmarkDataHandler_GetMessage(b *testing.B) {
	handler := NewDataHandler(10000)

	// Pre-fill queue
	i2npData := []byte("Test message data")
	block := NewSSU2Block(BlockTypeI2NPMessage, i2npData)
	payload, _ := SerializeBlocks([]*SSU2Block{block})

	packet := &SSU2Packet{
		MessageType: MessageTypeData,
		Payload:     payload,
	}

	for i := 0; i < 1000; i++ {
		handler.ProcessDataPacket(packet)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		msg := handler.GetMessage()
		if msg == nil {
			// Refill queue
			for j := 0; j < 1000; j++ {
				handler.ProcessDataPacket(packet)
			}
		}
	}
}

func BenchmarkDataHandler_CleanupFragments(b *testing.B) {
	handler := NewDataHandler(10)

	// Create some expired fragments
	for i := 0; i < 100; i++ {
		messageID := uint32(i)
		totalSize := uint32(100)
		fragmentData := []byte("Fragment data")

		blockData := make([]byte, 8+len(fragmentData))
		blockData[0] = byte(messageID >> 24)
		blockData[1] = byte(messageID >> 16)
		blockData[2] = byte(messageID >> 8)
		blockData[3] = byte(messageID)
		blockData[4] = byte(totalSize >> 24)
		blockData[5] = byte(totalSize >> 16)
		blockData[6] = byte(totalSize >> 8)
		blockData[7] = byte(totalSize)
		copy(blockData[8:], fragmentData)

		block := NewSSU2Block(BlockTypeFirstFragment, blockData)
		payload, _ := SerializeBlocks([]*SSU2Block{block})

		packet := &SSU2Packet{
			MessageType: MessageTypeData,
			Payload:     payload,
		}

		handler.ProcessDataPacket(packet)
	}

	time.Sleep(10 * time.Millisecond)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		handler.CleanupExpiredFragments(1 * time.Millisecond)
	}
}

// ============================================================================
// Tests for All 20 Block Type Handlers
// ============================================================================

// TestDataHandler_AllBlockTypesExplicitlyHandled verifies all 20 block types
// have explicit handlers and are processed without errors.
func TestDataHandler_AllBlockTypesExplicitlyHandled(t *testing.T) {
	handler := NewDataHandler(100)

	// Define test data for each block type with correct minimum sizes
	tests := []struct {
		blockType uint8
		name      string
		data      []byte
	}{
		{BlockTypeDateTime, "DateTime", make([]byte, 7)},       // minDateTimeSize = 7
		{BlockTypeOptions, "Options", make([]byte, 15)},        // minOptionsSize = 15
		{BlockTypeRouterInfo, "RouterInfo", make([]byte, 100)}, // Variable
		{BlockTypeI2NPMessage, "I2NPMessage", []byte("test i2np message")},
		{BlockTypeFirstFragment, "FirstFragment", append([]byte{0, 0, 0, 1, 0, 0, 0, 100}, make([]byte, 50)...)},
		{BlockTypeFollowOnFragment, "FollowOnFragment", append([]byte{0, 0, 0, 1, 1}, make([]byte, 50)...)},
		{BlockTypeTermination, "Termination", make([]byte, 9)},         // minTerminationSize = 9
		{BlockTypeRelayRequest, "RelayRequest", make([]byte, 50)},      // Variable
		{BlockTypeRelayResponse, "RelayResponse", make([]byte, 50)},    // Variable
		{BlockTypeRelayIntro, "RelayIntro", make([]byte, 50)},          // Variable
		{BlockTypePeerTest, "PeerTest", make([]byte, 50)},              // Variable
		{BlockTypeACK, "ACK", make([]byte, 5)},                         // minACKSize = 5
		{BlockTypeAddress, "Address", make([]byte, 9)},                 // minAddressSizeIPv4 = 9
		{BlockTypeRelayTagRequest, "RelayTagRequest", make([]byte, 3)}, // minRelayTagRequestSize = 3
		{BlockTypeRelayTag, "RelayTag", make([]byte, 7)},               // minRelayTagSize = 7
		{BlockTypeNewToken, "NewToken", make([]byte, 15)},              // minNewTokenSize = 15
		{BlockTypePathChallenge, "PathChallenge", make([]byte, 8)},     // Variable
		{BlockTypePathResponse, "PathResponse", make([]byte, 8)},       // Variable
		{BlockTypePadding, "Padding", make([]byte, 16)},                // Variable
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			block := NewSSU2Block(tc.blockType, tc.data)
			payload, err := SerializeBlocks([]*SSU2Block{block})
			require.NoError(t, err)

			packet := &SSU2Packet{
				MessageType: MessageTypeData,
				Payload:     payload,
			}

			blocks, err := handler.ProcessDataPacket(packet)
			assert.NoError(t, err)
			assert.Len(t, blocks, 1)
			assert.Equal(t, tc.blockType, blocks[0].Type)
		})
	}
}

// TestDataHandler_SetCallbacks verifies callback registration and invocation.
func TestDataHandler_SetCallbacks(t *testing.T) {
	handler := NewDataHandler(100)

	var terminationCalled bool
	var terminationReason uint8
	var newTokenCalled bool
	var dateTimeCalled bool
	var dateTimeValue uint32

	handler.SetCallbacks(DataHandlerCallbacks{
		OnTermination: func(reason uint8, data []byte) {
			terminationCalled = true
			terminationReason = reason
		},
		OnNewToken: func(token []byte) {
			newTokenCalled = true
		},
		OnDateTime: func(timestamp uint32) error {
			dateTimeCalled = true
			dateTimeValue = timestamp
			return nil
		},
	})

	// Test Termination callback
	t.Run("Termination callback", func(t *testing.T) {
		block := NewSSU2Block(BlockTypeTermination, make([]byte, 9)) // minTerminationSize = 9
		block.Data[0] = 0x05                                         // Set reason code
		payload, _ := SerializeBlocks([]*SSU2Block{block})
		packet := &SSU2Packet{
			MessageType: MessageTypeData,
			Payload:     payload,
		}

		_, err := handler.ProcessDataPacket(packet)
		assert.NoError(t, err)
		assert.True(t, terminationCalled)
		assert.Equal(t, uint8(0x05), terminationReason)
	})

	// Test NewToken callback
	t.Run("NewToken callback", func(t *testing.T) {
		block := NewSSU2Block(BlockTypeNewToken, make([]byte, 15)) // minNewTokenSize = 15
		payload, _ := SerializeBlocks([]*SSU2Block{block})
		packet := &SSU2Packet{
			MessageType: MessageTypeData,
			Payload:     payload,
		}

		_, err := handler.ProcessDataPacket(packet)
		assert.NoError(t, err)
		assert.True(t, newTokenCalled)
	})

	// Test DateTime callback
	t.Run("DateTime callback", func(t *testing.T) {
		// DateTime needs 7 bytes minimum, timestamp in first 4 bytes: 0x12345678
		data := make([]byte, 7)
		data[0] = 0x12
		data[1] = 0x34
		data[2] = 0x56
		data[3] = 0x78
		block := NewSSU2Block(BlockTypeDateTime, data)
		payload, _ := SerializeBlocks([]*SSU2Block{block})
		packet := &SSU2Packet{
			MessageType: MessageTypeData,
			Payload:     payload,
		}

		_, err := handler.ProcessDataPacket(packet)
		assert.NoError(t, err)
		assert.True(t, dateTimeCalled)
		assert.Equal(t, uint32(0x12345678), dateTimeValue)
	})
}

// TestDataHandler_RelayCallbacks verifies relay block callbacks.
func TestDataHandler_RelayCallbacks(t *testing.T) {
	handler := NewDataHandler(100)

	var relayRequestCalled, relayResponseCalled, relayIntroCalled bool
	var relayTagRequestCalled, relayTagCalled bool

	handler.SetCallbacks(DataHandlerCallbacks{
		OnRelayRequest: func(block *SSU2Block) error {
			relayRequestCalled = true
			return nil
		},
		OnRelayResponse: func(block *SSU2Block) error {
			relayResponseCalled = true
			return nil
		},
		OnRelayIntro: func(block *SSU2Block) error {
			relayIntroCalled = true
			return nil
		},
		OnRelayTagRequest: func(block *SSU2Block) error {
			relayTagRequestCalled = true
			return nil
		},
		OnRelayTag: func(block *SSU2Block) error {
			relayTagCalled = true
			return nil
		},
	})

	relayTests := []struct {
		name      string
		blockType uint8
		checkVar  *bool
	}{
		{"RelayRequest", BlockTypeRelayRequest, &relayRequestCalled},
		{"RelayResponse", BlockTypeRelayResponse, &relayResponseCalled},
		{"RelayIntro", BlockTypeRelayIntro, &relayIntroCalled},
		{"RelayTagRequest", BlockTypeRelayTagRequest, &relayTagRequestCalled},
		{"RelayTag", BlockTypeRelayTag, &relayTagCalled},
	}

	for _, tc := range relayTests {
		t.Run(tc.name, func(t *testing.T) {
			*tc.checkVar = false
			block := NewSSU2Block(tc.blockType, make([]byte, 50))
			payload, _ := SerializeBlocks([]*SSU2Block{block})
			packet := &SSU2Packet{
				MessageType: MessageTypeData,
				Payload:     payload,
			}

			_, err := handler.ProcessDataPacket(packet)
			assert.NoError(t, err)
			assert.True(t, *tc.checkVar, "callback should have been called for %s", tc.name)
		})
	}
}

// TestDataHandler_PathValidationCallbacks verifies path validation callbacks.
func TestDataHandler_PathValidationCallbacks(t *testing.T) {
	handler := NewDataHandler(100)

	var pathChallengeCalled, pathResponseCalled bool
	var challengeData, responseData []byte

	handler.SetCallbacks(DataHandlerCallbacks{
		OnPathChallenge: func(data []byte) error {
			pathChallengeCalled = true
			challengeData = data
			return nil
		},
		OnPathResponse: func(data []byte) error {
			pathResponseCalled = true
			responseData = data
			return nil
		},
	})

	t.Run("PathChallenge callback", func(t *testing.T) {
		testData := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
		block := NewSSU2Block(BlockTypePathChallenge, testData)
		payload, _ := SerializeBlocks([]*SSU2Block{block})
		packet := &SSU2Packet{
			MessageType: MessageTypeData,
			Payload:     payload,
		}

		_, err := handler.ProcessDataPacket(packet)
		assert.NoError(t, err)
		assert.True(t, pathChallengeCalled)
		assert.Equal(t, testData, challengeData)
	})

	t.Run("PathResponse callback", func(t *testing.T) {
		testData := []byte{0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18}
		block := NewSSU2Block(BlockTypePathResponse, testData)
		payload, _ := SerializeBlocks([]*SSU2Block{block})
		packet := &SSU2Packet{
			MessageType: MessageTypeData,
			Payload:     payload,
		}

		_, err := handler.ProcessDataPacket(packet)
		assert.NoError(t, err)
		assert.True(t, pathResponseCalled)
		assert.Equal(t, testData, responseData)
	})
}

// TestDataHandler_UnknownBlockTypeLogged verifies unknown blocks are tracked.
func TestDataHandler_UnknownBlockTypeLogged(t *testing.T) {
	handler := NewDataHandler(100)

	// Unknown block type 255
	block := NewSSU2Block(255, []byte{0x01, 0x02, 0x03})
	payload, _ := SerializeBlocks([]*SSU2Block{block})
	packet := &SSU2Packet{
		MessageType: MessageTypeData,
		Payload:     payload,
	}

	blocks, err := handler.ProcessDataPacket(packet)
	assert.NoError(t, err)
	assert.Len(t, blocks, 1)

	stats := handler.GetStats()
	assert.Equal(t, uint64(1), stats.UnknownBlocks)
	assert.Equal(t, uint64(1), stats.BlocksProcessed)
}

// TestDataHandler_PaddingBlockIgnored verifies padding blocks are silently skipped.
func TestDataHandler_PaddingBlockIgnored(t *testing.T) {
	handler := NewDataHandler(100)

	// Create a packet with only padding
	block := NewSSU2Block(BlockTypePadding, make([]byte, 256))
	payload, _ := SerializeBlocks([]*SSU2Block{block})
	packet := &SSU2Packet{
		MessageType: MessageTypeData,
		Payload:     payload,
	}

	blocks, err := handler.ProcessDataPacket(packet)
	assert.NoError(t, err)
	assert.Len(t, blocks, 1)

	stats := handler.GetStats()
	// Padding is processed but not counted as unknown
	assert.Equal(t, uint64(0), stats.UnknownBlocks)
	assert.Equal(t, uint64(1), stats.BlocksProcessed)
}

// TestDataHandler_BlocksProcessedStat verifies BlocksProcessed stat.
func TestDataHandler_BlocksProcessedStat(t *testing.T) {
	handler := NewDataHandler(100)

	// Create packet with multiple blocks
	blocks := []*SSU2Block{
		NewSSU2Block(BlockTypeDateTime, make([]byte, 7)), // minDateTimeSize = 7
		NewSSU2Block(BlockTypeOptions, make([]byte, 15)),
		NewSSU2Block(BlockTypePadding, make([]byte, 16)),
		NewSSU2Block(BlockTypeI2NPMessage, []byte("test message")),
	}

	payload, _ := SerializeBlocks(blocks)
	packet := &SSU2Packet{
		MessageType: MessageTypeData,
		Payload:     payload,
	}

	_, err := handler.ProcessDataPacket(packet)
	assert.NoError(t, err)

	stats := handler.GetStats()
	assert.Equal(t, uint64(4), stats.BlocksProcessed)
}

// TestDataHandler_GetBlockRouter verifies router accessor.
func TestDataHandler_GetBlockRouter(t *testing.T) {
	handler := NewDataHandler(100)
	router := handler.GetBlockRouter()

	require.NotNil(t, router)
	assert.IsType(t, &BlockRouter{}, router)
}

// TestDataHandler_TerminationBlockShort verifies handling of malformed Termination.
// Note: Serialization validates block sizes, so this tests receiving malformed data.
func TestDataHandler_TerminationBlockShort(t *testing.T) {
	handler := NewDataHandler(100)

	// Create raw bytes that bypass serialization validation
	// Block header: Type (1 byte) + Length (2 bytes) + Data
	// Type 6 (Termination) with 0-byte data
	rawPayload := []byte{0x06, 0x00, 0x00} // Type=6, Length=0

	packet := &SSU2Packet{
		MessageType: MessageTypeData,
		Payload:     rawPayload,
	}

	// Should process without fatal error, but the block will have empty data
	blocks, err := handler.ProcessDataPacket(packet)
	assert.NoError(t, err) // Block errors are logged, not returned
	assert.Len(t, blocks, 1)
	assert.Equal(t, BlockTypeTermination, blocks[0].Type)
}

// TestDataHandler_NewTokenBlockShort verifies handling of malformed NewToken.
func TestDataHandler_NewTokenBlockShort(t *testing.T) {
	handler := NewDataHandler(100)

	// Create raw bytes with Type 17 (NewToken) and 2-byte data
	rawPayload := []byte{0x11, 0x00, 0x02, 0x01, 0x02} // Type=17, Length=2, Data=2 bytes

	packet := &SSU2Packet{
		MessageType: MessageTypeData,
		Payload:     rawPayload,
	}

	// Should process without fatal error
	blocks, err := handler.ProcessDataPacket(packet)
	assert.NoError(t, err)
	assert.Len(t, blocks, 1)
	assert.Equal(t, BlockTypeNewToken, blocks[0].Type)
}

// TestDataHandler_DateTimeBlockShort verifies handling of malformed DateTime.
func TestDataHandler_DateTimeBlockShort(t *testing.T) {
	handler := NewDataHandler(100)

	// Create raw bytes with Type 0 (DateTime) and 2-byte data
	rawPayload := []byte{0x00, 0x00, 0x02, 0x01, 0x02} // Type=0, Length=2, Data=2 bytes

	packet := &SSU2Packet{
		MessageType: MessageTypeData,
		Payload:     rawPayload,
	}

	// Should process without fatal error
	blocks, err := handler.ProcessDataPacket(packet)
	assert.NoError(t, err)
	assert.Len(t, blocks, 1)
	assert.Equal(t, BlockTypeDateTime, blocks[0].Type)
}

// TestDataHandler_MultipleBlockTypes verifies mixed block handling.
func TestDataHandler_MultipleBlockTypes(t *testing.T) {
	handler := NewDataHandler(100)

	var terminationCalled, ackCalled bool
	handler.SetCallbacks(DataHandlerCallbacks{
		OnTermination: func(reason uint8, data []byte) {
			terminationCalled = true
		},
		OnACK: func(block *SSU2Block) error {
			ackCalled = true
			return nil
		},
	})

	blocks := []*SSU2Block{
		NewSSU2Block(BlockTypeDateTime, make([]byte, 7)),    // minDateTimeSize = 7
		NewSSU2Block(BlockTypeACK, make([]byte, 5)),         // minACKSize = 5
		NewSSU2Block(BlockTypeTermination, make([]byte, 9)), // minTerminationSize = 9, first byte is reason
		NewSSU2Block(BlockTypePadding, make([]byte, 16)),
	}
	blocks[2].Data[0] = 0x01 // Set termination reason

	payload, _ := SerializeBlocks(blocks)
	packet := &SSU2Packet{
		MessageType: MessageTypeData,
		Payload:     payload,
	}

	result, err := handler.ProcessDataPacket(packet)
	assert.NoError(t, err)
	assert.Len(t, result, 4)
	assert.True(t, terminationCalled)
	assert.True(t, ackCalled)
}

// TestDataHandler_PeerTestCallback verifies PeerTest callback.
func TestDataHandler_PeerTestCallback(t *testing.T) {
	handler := NewDataHandler(100)

	var peerTestCalled bool
	var receivedBlock *SSU2Block

	handler.SetCallbacks(DataHandlerCallbacks{
		OnPeerTest: func(block *SSU2Block) error {
			peerTestCalled = true
			receivedBlock = block
			return nil
		},
	})

	testData := make([]byte, 50)
	for i := range testData {
		testData[i] = byte(i)
	}

	block := NewSSU2Block(BlockTypePeerTest, testData)
	payload, _ := SerializeBlocks([]*SSU2Block{block})
	packet := &SSU2Packet{
		MessageType: MessageTypeData,
		Payload:     payload,
	}

	_, err := handler.ProcessDataPacket(packet)
	assert.NoError(t, err)
	assert.True(t, peerTestCalled)
	assert.Equal(t, BlockTypePeerTest, receivedBlock.Type)
	assert.Equal(t, testData, receivedBlock.Data)
}

// TestDataHandler_MetadataBlockCallbacks verifies metadata block callbacks.
func TestDataHandler_MetadataBlockCallbacks(t *testing.T) {
	handler := NewDataHandler(100)

	var optionsCalled, routerInfoCalled, addressCalled bool
	var optionsData, routerInfoData, addressData []byte

	handler.SetCallbacks(DataHandlerCallbacks{
		OnOptions: func(data []byte) error {
			optionsCalled = true
			optionsData = data
			return nil
		},
		OnRouterInfo: func(data []byte) error {
			routerInfoCalled = true
			routerInfoData = data
			return nil
		},
		OnAddress: func(data []byte) error {
			addressCalled = true
			addressData = data
			return nil
		},
	})

	t.Run("Options callback", func(t *testing.T) {
		testData := make([]byte, 15)
		block := NewSSU2Block(BlockTypeOptions, testData)
		payload, _ := SerializeBlocks([]*SSU2Block{block})
		packet := &SSU2Packet{
			MessageType: MessageTypeData,
			Payload:     payload,
		}

		_, err := handler.ProcessDataPacket(packet)
		assert.NoError(t, err)
		assert.True(t, optionsCalled)
		assert.Equal(t, testData, optionsData)
	})

	t.Run("RouterInfo callback", func(t *testing.T) {
		testData := make([]byte, 100)
		block := NewSSU2Block(BlockTypeRouterInfo, testData)
		payload, _ := SerializeBlocks([]*SSU2Block{block})
		packet := &SSU2Packet{
			MessageType: MessageTypeData,
			Payload:     payload,
		}

		_, err := handler.ProcessDataPacket(packet)
		assert.NoError(t, err)
		assert.True(t, routerInfoCalled)
		assert.Equal(t, testData, routerInfoData)
	})

	t.Run("Address callback", func(t *testing.T) {
		testData := make([]byte, 9) // IPv4 + port
		block := NewSSU2Block(BlockTypeAddress, testData)
		payload, _ := SerializeBlocks([]*SSU2Block{block})
		packet := &SSU2Packet{
			MessageType: MessageTypeData,
			Payload:     payload,
		}

		_, err := handler.ProcessDataPacket(packet)
		assert.NoError(t, err)
		assert.True(t, addressCalled)
		assert.Equal(t, testData, addressData)
	})
}
