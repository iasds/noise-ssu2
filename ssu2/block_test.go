package ssu2

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewSSU2Block tests block creation
func TestNewSSU2Block(t *testing.T) {
	tests := []struct {
		name      string
		blockType uint8
		data      []byte
	}{
		{"DateTime block", BlockTypeDateTime, make([]byte, 7)},
		{"Options block", BlockTypeOptions, make([]byte, 15)},
		{"Padding block", BlockTypePadding, make([]byte, 10)},
		{"Empty data", BlockTypePadding, []byte{}},
		{"Nil data", BlockTypePadding, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			block := NewSSU2Block(tt.blockType, tt.data)
			assert.Equal(t, tt.blockType, block.Type)
			assert.Equal(t, tt.data, block.Data)
		})
	}
}

// TestSSU2Block_Serialize tests block serialization
func TestSSU2Block_Serialize(t *testing.T) {
	tests := []struct {
		name        string
		block       *SSU2Block
		wantSize    int
		wantTypePos int
		wantLenPos  int
		wantDataPos int
	}{
		{
			name:        "DateTime block",
			block:       NewSSU2Block(BlockTypeDateTime, make([]byte, 7)),
			wantSize:    10, // 3 header + 7 data
			wantTypePos: 0,
			wantLenPos:  1,
			wantDataPos: 3,
		},
		{
			name:        "Options block",
			block:       NewSSU2Block(BlockTypeOptions, make([]byte, 15)),
			wantSize:    18, // 3 header + 15 data
			wantTypePos: 0,
			wantLenPos:  1,
			wantDataPos: 3,
		},
		{
			name:        "Padding with data",
			block:       NewSSU2Block(BlockTypePadding, []byte{1, 2, 3, 4, 5}),
			wantSize:    8, // 3 header + 5 data
			wantTypePos: 0,
			wantLenPos:  1,
			wantDataPos: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.block.Serialize()
			require.NoError(t, err)
			assert.Equal(t, tt.wantSize, len(data))

			// Verify Type field
			assert.Equal(t, tt.block.Type, data[tt.wantTypePos])

			// Verify Length field (big-endian)
			dataLen := len(tt.block.Data)
			assert.Equal(t, uint8(dataLen>>8), data[tt.wantLenPos])
			assert.Equal(t, uint8(dataLen&0xFF), data[tt.wantLenPos+1])

			// Verify Data field
			if dataLen > 0 {
				assert.Equal(t, tt.block.Data, data[tt.wantDataPos:])
			}
		})
	}
}

// TestSSU2Block_Serialize_Invalid tests serialization errors
func TestSSU2Block_Serialize_Invalid(t *testing.T) {
	tests := []struct {
		name       string
		block      *SSU2Block
		wantErrMsg string
	}{
		{
			name:       "DateTime too short",
			block:      NewSSU2Block(BlockTypeDateTime, make([]byte, 6)),
			wantErrMsg: "DateTime block too short",
		},
		{
			name:       "Options too short",
			block:      NewSSU2Block(BlockTypeOptions, make([]byte, 14)),
			wantErrMsg: "Options block too short",
		},
		{
			name:       "Termination too short",
			block:      NewSSU2Block(BlockTypeTermination, make([]byte, 8)),
			wantErrMsg: "Termination block too short",
		},
		{
			name:       "ACK too short",
			block:      NewSSU2Block(BlockTypeACK, make([]byte, 4)),
			wantErrMsg: "ACK block too short",
		},
		{
			name:       "Address too short",
			block:      NewSSU2Block(BlockTypeAddress, make([]byte, 8)),
			wantErrMsg: "Address block too short",
		},
		{
			name:       "RelayTagRequest too short",
			block:      NewSSU2Block(BlockTypeRelayTagRequest, make([]byte, 2)),
			wantErrMsg: "RelayTagRequest block too short",
		},
		{
			name:       "RelayTag too short",
			block:      NewSSU2Block(BlockTypeRelayTag, make([]byte, 6)),
			wantErrMsg: "RelayTag block too short",
		},
		{
			name:       "NewToken too short",
			block:      NewSSU2Block(BlockTypeNewToken, make([]byte, 14)),
			wantErrMsg: "NewToken block too short",
		},
		{
			name:       "Data too large",
			block:      NewSSU2Block(BlockTypePadding, make([]byte, maxBlockLength+1)),
			wantErrMsg: "block data too large",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.block.Serialize()
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErrMsg)
		})
	}
}

// TestSSU2Block_Deserialize tests block deserialization
func TestSSU2Block_Deserialize(t *testing.T) {
	tests := []struct {
		name         string
		createData   func() []byte
		wantType     uint8
		wantDataLen  int
		wantConsumed int
	}{
		{
			name: "DateTime block",
			createData: func() []byte {
				return []byte{
					BlockTypeDateTime, // Type
					0, 7,              // Length (big-endian)
					1, 2, 3, 4, 5, 6, 7, // Data (7 bytes)
				}
			},
			wantType:     BlockTypeDateTime,
			wantDataLen:  7,
			wantConsumed: 10,
		},
		{
			name: "Options block",
			createData: func() []byte {
				return []byte{
					BlockTypeOptions, // Type
					0, 15,            // Length
					1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, // 15 bytes
				}
			},
			wantType:     BlockTypeOptions,
			wantDataLen:  15,
			wantConsumed: 18,
		},
		{
			name: "Padding with specific data",
			createData: func() []byte {
				return []byte{
					BlockTypePadding, // Type
					0, 5,             // Length
					0xAA, 0xBB, 0xCC, 0xDD, 0xEE, // Data
				}
			},
			wantType:     BlockTypePadding,
			wantDataLen:  5,
			wantConsumed: 8,
		},
		{
			name: "Block with extra trailing data",
			createData: func() []byte {
				return []byte{
					BlockTypePadding, // Type
					0, 3,             // Length
					1, 2, 3, // Data
					99, 99, 99, // Extra data (should be ignored)
				}
			},
			wantType:     BlockTypePadding,
			wantDataLen:  3,
			wantConsumed: 6, // Should only consume block data
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := tt.createData()
			block := &SSU2Block{}

			consumed, err := block.Deserialize(data)
			require.NoError(t, err)
			assert.Equal(t, tt.wantConsumed, consumed)
			assert.Equal(t, tt.wantType, block.Type)
			assert.Equal(t, tt.wantDataLen, len(block.Data))
		})
	}
}

// TestSSU2Block_Deserialize_Invalid tests deserialization errors
func TestSSU2Block_Deserialize_Invalid(t *testing.T) {
	tests := []struct {
		name       string
		data       []byte
		wantErrMsg string
	}{
		{
			name:       "Data too short for header",
			data:       []byte{BlockTypeDateTime, 0}, // Missing length byte
			wantErrMsg: "block too short",
		},
		{
			name:       "Empty data",
			data:       []byte{},
			wantErrMsg: "block too short",
		},
		{
			name: "Insufficient data for declared length",
			data: []byte{
				BlockTypeDateTime,
				0, 10, // Says 10 bytes of data
				1, 2, 3, // But only 3 bytes provided
			},
			wantErrMsg: "insufficient data",
		},
		{
			name: "DateTime block with insufficient data",
			data: []byte{
				BlockTypeDateTime,
				0, 6, // Length 6 (but minimum is 7)
				1, 2, 3, 4, 5, 6,
			},
			wantErrMsg: "DateTime block too short",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			block := &SSU2Block{}
			_, err := block.Deserialize(tt.data)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErrMsg)
		})
	}
}

// TestSSU2Block_RoundTrip tests serialize/deserialize consistency
func TestSSU2Block_RoundTrip(t *testing.T) {
	tests := []struct {
		name      string
		blockType uint8
		data      []byte
	}{
		{"DateTime", BlockTypeDateTime, []byte{1, 2, 3, 4, 5, 6, 7}},
		{"Options", BlockTypeOptions, make([]byte, 15)},
		{"RouterInfo", BlockTypeRouterInfo, []byte("router info data")},
		{"I2NP", BlockTypeI2NPMessage, []byte("i2np message content")},
		{"Padding", BlockTypePadding, []byte{0, 0, 0, 0, 0}},
		{"Large padding", BlockTypePadding, make([]byte, 1000)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create original block
			original := NewSSU2Block(tt.blockType, tt.data)

			// Serialize
			serialized, err := original.Serialize()
			require.NoError(t, err)

			// Deserialize
			restored := &SSU2Block{}
			consumed, err := restored.Deserialize(serialized)
			require.NoError(t, err)
			assert.Equal(t, len(serialized), consumed)

			// Compare
			assert.Equal(t, original.Type, restored.Type)
			assert.Equal(t, original.Data, restored.Data)
		})
	}
}

// TestSSU2Block_Size tests size calculation
func TestSSU2Block_Size(t *testing.T) {
	tests := []struct {
		name     string
		block    *SSU2Block
		wantSize int
	}{
		{
			name:     "DateTime block",
			block:    NewSSU2Block(BlockTypeDateTime, make([]byte, 7)),
			wantSize: 10, // 3 header + 7 data
		},
		{
			name:     "Empty data",
			block:    NewSSU2Block(BlockTypePadding, []byte{}),
			wantSize: 3, // Just header
		},
		{
			name:     "Large block",
			block:    NewSSU2Block(BlockTypePadding, make([]byte, 1000)),
			wantSize: 1003, // 3 header + 1000 data
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.wantSize, tt.block.Size())
		})
	}
}

// TestSSU2Block_Getters tests getter methods
func TestSSU2Block_Getters(t *testing.T) {
	blockType := BlockTypeDateTime
	data := []byte{1, 2, 3, 4, 5, 6, 7}

	block := NewSSU2Block(blockType, data)

	assert.Equal(t, blockType, block.GetType())
	assert.Equal(t, data, block.GetData())
}

// TestSerializeBlocks tests multi-block serialization
func TestSerializeBlocks(t *testing.T) {
	tests := []struct {
		name      string
		blocks    []*SSU2Block
		wantSize  int
		wantError bool
	}{
		{
			name: "Multiple valid blocks",
			blocks: []*SSU2Block{
				NewSSU2Block(BlockTypeDateTime, make([]byte, 7)),
				NewSSU2Block(BlockTypePadding, []byte{1, 2, 3}),
				NewSSU2Block(BlockTypeOptions, make([]byte, 15)),
			},
			wantSize:  10 + 6 + 18, // Sum of each block's size
			wantError: false,
		},
		{
			name:      "Empty blocks slice",
			blocks:    []*SSU2Block{},
			wantSize:  0,
			wantError: false,
		},
		{
			name: "Single block",
			blocks: []*SSU2Block{
				NewSSU2Block(BlockTypePadding, []byte{1, 2, 3, 4, 5}),
			},
			wantSize:  8,
			wantError: false,
		},
		{
			name: "Invalid block in sequence",
			blocks: []*SSU2Block{
				NewSSU2Block(BlockTypeDateTime, make([]byte, 7)),
				NewSSU2Block(BlockTypeDateTime, make([]byte, 6)), // Too short
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := SerializeBlocks(tt.blocks)
			if tt.wantError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.wantSize, len(data))
			}
		})
	}
}

// TestDeserializeBlocks tests multi-block deserialization
func TestDeserializeBlocks(t *testing.T) {
	tests := []struct {
		name       string
		createData func() []byte
		wantCount  int
		wantTypes  []uint8
	}{
		{
			name: "Multiple blocks",
			createData: func() []byte {
				blocks := []*SSU2Block{
					NewSSU2Block(BlockTypeDateTime, make([]byte, 7)),
					NewSSU2Block(BlockTypePadding, []byte{1, 2, 3}),
				}
				data, _ := SerializeBlocks(blocks)
				return data
			},
			wantCount: 2,
			wantTypes: []uint8{BlockTypeDateTime, BlockTypePadding},
		},
		{
			name: "Single block",
			createData: func() []byte {
				block := NewSSU2Block(BlockTypeOptions, make([]byte, 15))
				data, _ := block.Serialize()
				return data
			},
			wantCount: 1,
			wantTypes: []uint8{BlockTypeOptions},
		},
		{
			name: "Empty data",
			createData: func() []byte {
				return []byte{}
			},
			wantCount: 0,
			wantTypes: []uint8{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := tt.createData()
			blocks, err := DeserializeBlocks(data)
			require.NoError(t, err)
			assert.Equal(t, tt.wantCount, len(blocks))

			if len(tt.wantTypes) > 0 {
				for i, expectedType := range tt.wantTypes {
					assert.Equal(t, expectedType, blocks[i].Type)
				}
			}
		})
	}
}

// TestDeserializeBlocks_Invalid tests deserialization error handling
func TestDeserializeBlocks_Invalid(t *testing.T) {
	tests := []struct {
		name       string
		data       []byte
		wantErrMsg string
	}{
		{
			name: "Truncated block",
			data: []byte{
				BlockTypeDateTime,
				0, 10, // Says 10 bytes
				1, 2, 3, // But only 3 bytes
			},
			wantErrMsg: "insufficient data",
		},
		{
			name: "Invalid block in sequence",
			data: []byte{
				BlockTypeDateTime, 0, 7, 1, 2, 3, 4, 5, 6, 7, // Valid
				BlockTypeDateTime, 0, 6, 1, 2, 3, 4, 5, 6, // Too short for DateTime
			},
			wantErrMsg: "DateTime block too short",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DeserializeBlocks(tt.data)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErrMsg)
		})
	}
}

// TestSerializeDeserializeBlocks_RoundTrip tests full round-trip
func TestSerializeDeserializeBlocks_RoundTrip(t *testing.T) {
	original := []*SSU2Block{
		NewSSU2Block(BlockTypeDateTime, []byte{1, 2, 3, 4, 5, 6, 7}),
		NewSSU2Block(BlockTypeOptions, make([]byte, 15)),
		NewSSU2Block(BlockTypePadding, []byte{0xAA, 0xBB, 0xCC}),
		NewSSU2Block(BlockTypeRouterInfo, []byte("test router info")),
	}

	// Serialize
	serialized, err := SerializeBlocks(original)
	require.NoError(t, err)

	// Deserialize
	restored, err := DeserializeBlocks(serialized)
	require.NoError(t, err)

	// Compare
	require.Equal(t, len(original), len(restored))
	for i := range original {
		assert.Equal(t, original[i].Type, restored[i].Type)
		assert.Equal(t, original[i].Data, restored[i].Data)
	}
}

// TestIsKnownBlockType tests block type validation
func TestIsKnownBlockType(t *testing.T) {
	tests := []struct {
		name      string
		blockType uint8
		want      bool
	}{
		{"DateTime", BlockTypeDateTime, true},
		{"Options", BlockTypeOptions, true},
		{"RouterInfo", BlockTypeRouterInfo, true},
		{"I2NP", BlockTypeI2NPMessage, true},
		{"FirstFragment", BlockTypeFirstFragment, true},
		{"FollowOnFragment", BlockTypeFollowOnFragment, true},
		{"Termination", BlockTypeTermination, true},
		{"RelayRequest", BlockTypeRelayRequest, true},
		{"RelayResponse", BlockTypeRelayResponse, true},
		{"RelayIntro", BlockTypeRelayIntro, true},
		{"PeerTest", BlockTypePeerTest, true},
		{"ACK", BlockTypeACK, true},
		{"Address", BlockTypeAddress, true},
		{"RelayTagRequest", BlockTypeRelayTagRequest, true},
		{"RelayTag", BlockTypeRelayTag, true},
		{"NewToken", BlockTypeNewToken, true},
		{"PathChallenge", BlockTypePathChallenge, true},
		{"PathResponse", BlockTypePathResponse, true},
		{"Padding", BlockTypePadding, true},
		{"Unknown type 11", 11, false},
		{"Unknown type 14", 14, false},
		{"Unknown type 20", 20, false},
		{"Unknown type 255", 255, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, IsKnownBlockType(tt.blockType))
		})
	}
}

// TestGetBlockTypeName tests block type name retrieval
func TestGetBlockTypeName(t *testing.T) {
	tests := []struct {
		blockType uint8
		wantName  string
	}{
		{BlockTypeDateTime, "DateTime"},
		{BlockTypeOptions, "Options"},
		{BlockTypeRouterInfo, "RouterInfo"},
		{BlockTypeI2NPMessage, "I2NPMessage"},
		{BlockTypeFirstFragment, "FirstFragment"},
		{BlockTypeFollowOnFragment, "FollowOnFragment"},
		{BlockTypeTermination, "Termination"},
		{BlockTypeRelayRequest, "RelayRequest"},
		{BlockTypeRelayResponse, "RelayResponse"},
		{BlockTypeRelayIntro, "RelayIntro"},
		{BlockTypePeerTest, "PeerTest"},
		{BlockTypeACK, "ACK"},
		{BlockTypeAddress, "Address"},
		{BlockTypeRelayTagRequest, "RelayTagRequest"},
		{BlockTypeRelayTag, "RelayTag"},
		{BlockTypeNewToken, "NewToken"},
		{BlockTypePathChallenge, "PathChallenge"},
		{BlockTypePathResponse, "PathResponse"},
		{BlockTypePadding, "Padding"},
		{11, "Unknown"},
		{255, "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.wantName, func(t *testing.T) {
			assert.Equal(t, tt.wantName, GetBlockTypeName(tt.blockType))
		})
	}
}

// TestSSU2Block_AllBlockTypes tests all block types can be created and serialized
func TestSSU2Block_AllBlockTypes(t *testing.T) {
	tests := []struct {
		name      string
		blockType uint8
		minSize   int
	}{
		{"DateTime", BlockTypeDateTime, 7},
		{"Options", BlockTypeOptions, 15},
		{"RouterInfo", BlockTypeRouterInfo, 0},
		{"I2NP", BlockTypeI2NPMessage, 0},
		{"FirstFragment", BlockTypeFirstFragment, 0},
		{"FollowOnFragment", BlockTypeFollowOnFragment, 0},
		{"Termination", BlockTypeTermination, 9},
		{"RelayRequest", BlockTypeRelayRequest, 0},
		{"RelayResponse", BlockTypeRelayResponse, 0},
		{"RelayIntro", BlockTypeRelayIntro, 0},
		{"PeerTest", BlockTypePeerTest, 0},
		{"ACK", BlockTypeACK, 5},
		{"Address", BlockTypeAddress, 9},
		{"RelayTagRequest", BlockTypeRelayTagRequest, 3},
		{"RelayTag", BlockTypeRelayTag, 7},
		{"NewToken", BlockTypeNewToken, 15},
		{"PathChallenge", BlockTypePathChallenge, 0},
		{"PathResponse", BlockTypePathResponse, 0},
		{"Padding", BlockTypePadding, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create data meeting minimum size
			dataSize := tt.minSize
			if dataSize == 0 {
				dataSize = 10 // Use reasonable size for variable-length blocks
			}
			data := make([]byte, dataSize)

			block := NewSSU2Block(tt.blockType, data)
			serialized, err := block.Serialize()
			require.NoError(t, err)
			assert.NotNil(t, serialized)

			// Deserialize and verify
			restored := &SSU2Block{}
			_, err = restored.Deserialize(serialized)
			require.NoError(t, err)
			assert.Equal(t, tt.blockType, restored.Type)
		})
	}
}

// TestSSU2Block_MaxSize tests maximum size handling
func TestSSU2Block_MaxSize(t *testing.T) {
	t.Run("Maximum allowed size", func(t *testing.T) {
		block := NewSSU2Block(BlockTypePadding, make([]byte, maxBlockLength))
		data, err := block.Serialize()
		require.NoError(t, err)
		assert.Equal(t, maxBlockLength+3, len(data)) // +3 for header
	})

	t.Run("Size exceeds maximum", func(t *testing.T) {
		block := NewSSU2Block(BlockTypePadding, make([]byte, maxBlockLength+1))
		_, err := block.Serialize()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "block data too large")
	})
}

// TestSSU2Block_BinaryData tests blocks with binary data
func TestSSU2Block_BinaryData(t *testing.T) {
	// Create block with all possible byte values
	data := make([]byte, 256)
	for i := range data {
		data[i] = byte(i)
	}

	block := NewSSU2Block(BlockTypeRouterInfo, data)
	serialized, err := block.Serialize()
	require.NoError(t, err)

	restored := &SSU2Block{}
	_, err = restored.Deserialize(serialized)
	require.NoError(t, err)

	assert.True(t, bytes.Equal(data, restored.Data))
}

// Benchmark tests
func BenchmarkSSU2Block_Serialize(b *testing.B) {
	block := NewSSU2Block(BlockTypePadding, make([]byte, 100))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = block.Serialize()
	}
}

func BenchmarkSSU2Block_Deserialize(b *testing.B) {
	block := NewSSU2Block(BlockTypePadding, make([]byte, 100))
	data, _ := block.Serialize()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		restored := &SSU2Block{}
		_, _ = restored.Deserialize(data)
	}
}

func BenchmarkSerializeBlocks(b *testing.B) {
	blocks := []*SSU2Block{
		NewSSU2Block(BlockTypeDateTime, make([]byte, 7)),
		NewSSU2Block(BlockTypeOptions, make([]byte, 15)),
		NewSSU2Block(BlockTypePadding, make([]byte, 50)),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = SerializeBlocks(blocks)
	}
}

func BenchmarkDeserializeBlocks(b *testing.B) {
	blocks := []*SSU2Block{
		NewSSU2Block(BlockTypeDateTime, make([]byte, 7)),
		NewSSU2Block(BlockTypeOptions, make([]byte, 15)),
		NewSSU2Block(BlockTypePadding, make([]byte, 50)),
	}
	data, _ := SerializeBlocks(blocks)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = DeserializeBlocks(data)
	}
}

// TestSSU2Block_Constants verifies constant values
func TestSSU2Block_Constants(t *testing.T) {
	assert.Equal(t, uint8(0), BlockTypeDateTime)
	assert.Equal(t, uint8(1), BlockTypeOptions)
	assert.Equal(t, uint8(2), BlockTypeRouterInfo)
	assert.Equal(t, uint8(3), BlockTypeI2NPMessage)
	assert.Equal(t, uint8(4), BlockTypeFirstFragment)
	assert.Equal(t, uint8(5), BlockTypeFollowOnFragment)
	assert.Equal(t, uint8(6), BlockTypeTermination)
	assert.Equal(t, uint8(7), BlockTypeRelayRequest)
	assert.Equal(t, uint8(8), BlockTypeRelayResponse)
	assert.Equal(t, uint8(9), BlockTypeRelayIntro)
	assert.Equal(t, uint8(10), BlockTypePeerTest)
	assert.Equal(t, uint8(12), BlockTypeACK)
	assert.Equal(t, uint8(13), BlockTypeAddress)
	assert.Equal(t, uint8(15), BlockTypeRelayTagRequest)
	assert.Equal(t, uint8(16), BlockTypeRelayTag)
	assert.Equal(t, uint8(17), BlockTypeNewToken)
	assert.Equal(t, uint8(18), BlockTypePathChallenge)
	assert.Equal(t, uint8(19), BlockTypePathResponse)
	assert.Equal(t, uint8(254), BlockTypePadding)

	assert.Equal(t, 3, minBlockHeaderSize)
	assert.Equal(t, 65535, maxBlockLength)
}

// TestNewNewTokenBlock tests NewToken block creation
func TestNewNewTokenBlock(t *testing.T) {
	t.Run("valid token creates block", func(t *testing.T) {
		expiration := time.Now().Add(60 * time.Second)
		token := make([]byte, 11) // Minimum size
		for i := range token {
			token[i] = byte(i + 1)
		}

		block, err := NewNewTokenBlock(expiration, token)
		require.NoError(t, err)
		require.NotNil(t, block)

		assert.Equal(t, BlockTypeNewToken, block.Type)
		assert.Equal(t, 15, len(block.Data)) // 4 + 11
	})

	t.Run("token too short returns error", func(t *testing.T) {
		expiration := time.Now().Add(60 * time.Second)
		shortToken := make([]byte, 10) // Too short

		block, err := NewNewTokenBlock(expiration, shortToken)
		assert.Error(t, err)
		assert.Nil(t, block)
		assert.Contains(t, err.Error(), "at least 11 bytes")
	})

	t.Run("larger token creates larger block", func(t *testing.T) {
		expiration := time.Now().Add(60 * time.Second)
		token := make([]byte, 20) // Larger than minimum

		block, err := NewNewTokenBlock(expiration, token)
		require.NoError(t, err)
		assert.Equal(t, 24, len(block.Data)) // 4 + 20
	})
}

// TestParseNewTokenBlock tests parsing NewToken blocks
func TestParseNewTokenBlock(t *testing.T) {
	t.Run("valid block parses correctly", func(t *testing.T) {
		expiration := time.Now().Add(60 * time.Second)
		token := make([]byte, 11)
		for i := range token {
			token[i] = byte(i + 0xA0)
		}

		// Create block
		block, err := NewNewTokenBlock(expiration, token)
		require.NoError(t, err)

		// Parse it back
		parsed, err := ParseNewTokenBlock(block)
		require.NoError(t, err)
		require.NotNil(t, parsed)

		// Verify expiration (allow 1 second tolerance)
		assert.InDelta(t, expiration.Unix(), int64(parsed.Expiration), 1)

		// Verify token
		assert.Equal(t, token, parsed.Token)
	})

	t.Run("wrong block type returns error", func(t *testing.T) {
		block := NewSSU2Block(BlockTypePadding, make([]byte, 15))

		parsed, err := ParseNewTokenBlock(block)
		assert.Error(t, err)
		assert.Nil(t, parsed)
		assert.Contains(t, err.Error(), "expected NewToken block")
	})

	t.Run("block too short returns error", func(t *testing.T) {
		block := &SSU2Block{
			Type: BlockTypeNewToken,
			Data: make([]byte, 10), // Too short
		}

		parsed, err := ParseNewTokenBlock(block)
		assert.Error(t, err)
		assert.Nil(t, parsed)
		assert.Contains(t, err.Error(), "too short")
	})
}

// TestNewTokenBlockRoundTrip tests serialization/deserialization roundtrip
func TestNewTokenBlockRoundTrip(t *testing.T) {
	expiration := time.Now().Add(120 * time.Second)
	token := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B}

	// Create block
	block, err := NewNewTokenBlock(expiration, token)
	require.NoError(t, err)

	// Serialize
	data, err := block.Serialize()
	require.NoError(t, err)

	// Deserialize
	restored := &SSU2Block{}
	_, err = restored.Deserialize(data)
	require.NoError(t, err)

	// Parse
	parsed, err := ParseNewTokenBlock(restored)
	require.NoError(t, err)

	// Verify roundtrip
	assert.Equal(t, uint32(expiration.Unix()), parsed.Expiration)
	assert.Equal(t, token, parsed.Token)
}

// TestFindBlockByType tests finding blocks in a slice
func TestFindBlockByType(t *testing.T) {
	blocks := []*SSU2Block{
		NewSSU2Block(BlockTypeDateTime, make([]byte, 7)),
		NewSSU2Block(BlockTypeOptions, make([]byte, 15)),
		NewSSU2Block(BlockTypeNewToken, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}),
		NewSSU2Block(BlockTypePadding, make([]byte, 10)),
	}

	t.Run("finds existing block", func(t *testing.T) {
		found := FindBlockByType(blocks, BlockTypeNewToken)
		require.NotNil(t, found)
		assert.Equal(t, BlockTypeNewToken, found.Type)
	})

	t.Run("finds first matching block", func(t *testing.T) {
		found := FindBlockByType(blocks, BlockTypeDateTime)
		require.NotNil(t, found)
		assert.Equal(t, BlockTypeDateTime, found.Type)
	})

	t.Run("returns nil for missing type", func(t *testing.T) {
		found := FindBlockByType(blocks, BlockTypeACK)
		assert.Nil(t, found)
	})

	t.Run("handles empty slice", func(t *testing.T) {
		found := FindBlockByType([]*SSU2Block{}, BlockTypeDateTime)
		assert.Nil(t, found)
	})

	t.Run("handles nil slice", func(t *testing.T) {
		found := FindBlockByType(nil, BlockTypeDateTime)
		assert.Nil(t, found)
	})
}
