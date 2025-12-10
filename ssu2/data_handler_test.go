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
