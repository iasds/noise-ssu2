package ssu2

import (
	"encoding/binary"

	"github.com/samber/oops"
)

// SSU2Block represents an SSU2 protocol block within a packet payload.
// Blocks use TLV (Type-Length-Value) encoding:
//   - Type: 1 byte (block type identifier)
//   - Length: 2 bytes (big-endian, length of Value field only)
//   - Value: variable length data
//
// SSU2 packets can contain multiple blocks concatenated together.
// Block types are defined in SSU2.md specification.
type SSU2Block struct {
	// Type identifies the block type (0-254)
	// See BlockType* constants for valid values
	Type uint8

	// Data contains the block payload (Value in TLV encoding)
	// Length is implicit from len(Data)
	Data []byte
}

// Block type constants from SSU2.md
const (
	BlockTypeDateTime         uint8 = 0   // Timestamp block (7 bytes)
	BlockTypeOptions          uint8 = 1   // Connection options (15+ bytes)
	BlockTypeRouterInfo       uint8 = 2   // RouterInfo structure (variable)
	BlockTypeI2NPMessage      uint8 = 3   // I2NP message (variable)
	BlockTypeFirstFragment    uint8 = 4   // First fragment of message (variable)
	BlockTypeFollowOnFragment uint8 = 5   // Subsequent fragment (variable)
	BlockTypeTermination      uint8 = 6   // Connection termination (9 bytes)
	BlockTypeRelayRequest     uint8 = 7   // Relay request (variable)
	BlockTypeRelayResponse    uint8 = 8   // Relay response (variable)
	BlockTypeRelayIntro       uint8 = 9   // Relay introduction (variable)
	BlockTypePeerTest         uint8 = 10  // Peer test message (variable)
	BlockTypeACK              uint8 = 12  // Acknowledgment (5+ bytes)
	BlockTypeAddress          uint8 = 13  // Address block (9 or 21 bytes)
	BlockTypeRelayTagRequest  uint8 = 15  // Request relay tag (3 bytes)
	BlockTypeRelayTag         uint8 = 16  // Relay tag assignment (7 bytes)
	BlockTypeNewToken         uint8 = 17  // New session token (15 bytes)
	BlockTypePathChallenge    uint8 = 18  // Path validation challenge (variable)
	BlockTypePathResponse     uint8 = 19  // Path validation response (variable)
	BlockTypePadding          uint8 = 254 // Padding block (variable)
)

// Minimum block data sizes from SSU2.md
const (
	minBlockHeaderSize     = 3     // Type (1) + Length (2)
	minDateTimeSize        = 7     // Timestamp data
	minOptionsSize         = 15    // Options data
	minTerminationSize     = 9     // Termination data
	minACKSize             = 5     // ACK data
	minAddressSizeIPv4     = 9     // IPv4 address
	minAddressSizeIPv6     = 21    // IPv6 address
	minRelayTagRequestSize = 3     // Relay tag request data
	minRelayTagSize        = 7     // Relay tag data
	minNewTokenSize        = 15    // New token data
	maxBlockLength         = 65535 // Maximum length field value (2 bytes)
)

// NewSSU2Block creates a new block with the specified type and data.
//
// Parameters:
//   - blockType: Block type constant (BlockType*)
//   - data: Block payload data
//
// Returns a new SSU2Block ready for serialization.
func NewSSU2Block(blockType uint8, data []byte) *SSU2Block {
	return &SSU2Block{
		Type: blockType,
		Data: data,
	}
}

// Serialize encodes the block to wire format (TLV encoding).
// Format: [Type:1][Length:2][Data:Length]
//
// The Length field is big-endian and contains only the data length,
// not including the 3-byte header.
//
// Returns:
//   - []byte: Wire format block data
//   - error: If block is invalid or data too large
func (b *SSU2Block) Serialize() ([]byte, error) {
	// Validate block
	if err := b.validate(); err != nil {
		return nil, oops.Wrapf(err, "invalid block")
	}

	// Allocate buffer: Type (1) + Length (2) + Data
	dataLen := len(b.Data)
	buf := make([]byte, minBlockHeaderSize+dataLen)

	// Encode Type
	buf[0] = b.Type

	// Encode Length (big-endian, 2 bytes)
	binary.BigEndian.PutUint16(buf[1:3], uint16(dataLen))

	// Copy Data
	if dataLen > 0 {
		copy(buf[3:], b.Data)
	}

	return buf, nil
}

// Deserialize decodes a block from wire format.
// Reads the TLV structure and populates this block's fields.
//
// Parameters:
//   - data: Wire format block data (must be at least 3 bytes)
//
// Returns:
//   - int: Number of bytes consumed from data
//   - error: If data is malformed or too short
func (b *SSU2Block) Deserialize(data []byte) (int, error) {
	// Check minimum size
	if len(data) < minBlockHeaderSize {
		return 0, oops.Errorf("block too short: %d bytes (minimum %d)", len(data), minBlockHeaderSize)
	}

	// Decode Type
	b.Type = data[0]

	// Decode Length (big-endian)
	dataLen := int(binary.BigEndian.Uint16(data[1:3]))

	// Check if we have enough data
	totalLen := minBlockHeaderSize + dataLen
	if len(data) < totalLen {
		return 0, oops.Errorf("insufficient data: have %d bytes, need %d (header + %d data)",
			len(data), totalLen, dataLen)
	}

	// Extract Data
	if dataLen > 0 {
		b.Data = make([]byte, dataLen)
		copy(b.Data, data[3:3+dataLen])
	} else {
		b.Data = nil
	}

	// Validate decoded block
	if err := b.validate(); err != nil {
		return 0, oops.Wrapf(err, "invalid decoded block")
	}

	return totalLen, nil
}

// validate checks that the block meets minimum size requirements per SSU2.md.
func (b *SSU2Block) validate() error {
	dataLen := len(b.Data)

	// Check maximum length
	if dataLen > maxBlockLength {
		return oops.Errorf("block data too large: %d bytes (maximum %d)", dataLen, maxBlockLength)
	}

	// Validate minimum sizes for specific block types
	switch b.Type {
	case BlockTypeDateTime:
		if dataLen < minDateTimeSize {
			return oops.Errorf("DateTime block too short: %d bytes (minimum %d)", dataLen, minDateTimeSize)
		}
	case BlockTypeOptions:
		if dataLen < minOptionsSize {
			return oops.Errorf("Options block too short: %d bytes (minimum %d)", dataLen, minOptionsSize)
		}
	case BlockTypeTermination:
		if dataLen < minTerminationSize {
			return oops.Errorf("Termination block too short: %d bytes (minimum %d)", dataLen, minTerminationSize)
		}
	case BlockTypeACK:
		if dataLen < minACKSize {
			return oops.Errorf("ACK block too short: %d bytes (minimum %d)", dataLen, minACKSize)
		}
	case BlockTypeAddress:
		if dataLen < minAddressSizeIPv4 {
			return oops.Errorf("Address block too short: %d bytes (minimum %d)", dataLen, minAddressSizeIPv4)
		}
	case BlockTypeRelayTagRequest:
		if dataLen < minRelayTagRequestSize {
			return oops.Errorf("RelayTagRequest block too short: %d bytes (minimum %d)", dataLen, minRelayTagRequestSize)
		}
	case BlockTypeRelayTag:
		if dataLen < minRelayTagSize {
			return oops.Errorf("RelayTag block too short: %d bytes (minimum %d)", dataLen, minRelayTagSize)
		}
	case BlockTypeNewToken:
		if dataLen < minNewTokenSize {
			return oops.Errorf("NewToken block too short: %d bytes (minimum %d)", dataLen, minNewTokenSize)
		}
	}

	return nil
}

// Size returns the total wire format size in bytes (header + data).
func (b *SSU2Block) Size() int {
	return minBlockHeaderSize + len(b.Data)
}

// GetType returns the block type.
func (b *SSU2Block) GetType() uint8 {
	return b.Type
}

// GetData returns the block data payload.
func (b *SSU2Block) GetData() []byte {
	return b.Data
}

// SerializeBlocks serializes multiple blocks into a single byte slice.
// This is useful for creating packet payloads that contain multiple blocks.
//
// Parameters:
//   - blocks: Slice of blocks to serialize
//
// Returns:
//   - []byte: Concatenated wire format of all blocks
//   - error: If any block fails to serialize
func SerializeBlocks(blocks []*SSU2Block) ([]byte, error) {
	if len(blocks) == 0 {
		return []byte{}, nil
	}

	// Calculate total size
	totalSize := 0
	for _, block := range blocks {
		totalSize += block.Size()
	}

	// Allocate buffer
	buf := make([]byte, 0, totalSize)

	// Serialize each block
	for i, block := range blocks {
		data, err := block.Serialize()
		if err != nil {
			return nil, oops.Wrapf(err, "failed to serialize block %d (type %d)", i, block.Type)
		}
		buf = append(buf, data...)
	}

	return buf, nil
}

// DeserializeBlocks deserializes multiple blocks from a byte slice.
// Reads blocks until all data is consumed or an error occurs.
//
// Parameters:
//   - data: Wire format data containing one or more blocks
//
// Returns:
//   - []*SSU2Block: Slice of deserialized blocks
//   - error: If deserialization fails
func DeserializeBlocks(data []byte) ([]*SSU2Block, error) {
	if len(data) == 0 {
		return []*SSU2Block{}, nil
	}

	blocks := make([]*SSU2Block, 0)
	offset := 0

	for offset < len(data) {
		block := &SSU2Block{}
		consumed, err := block.Deserialize(data[offset:])
		if err != nil {
			return nil, oops.Wrapf(err, "failed to deserialize block at offset %d", offset)
		}

		blocks = append(blocks, block)
		offset += consumed
	}

	return blocks, nil
}

// IsKnownBlockType returns true if the block type is defined in the SSU2 specification.
func IsKnownBlockType(blockType uint8) bool {
	switch blockType {
	case BlockTypeDateTime,
		BlockTypeOptions,
		BlockTypeRouterInfo,
		BlockTypeI2NPMessage,
		BlockTypeFirstFragment,
		BlockTypeFollowOnFragment,
		BlockTypeTermination,
		BlockTypeRelayRequest,
		BlockTypeRelayResponse,
		BlockTypeRelayIntro,
		BlockTypePeerTest,
		BlockTypeACK,
		BlockTypeAddress,
		BlockTypeRelayTagRequest,
		BlockTypeRelayTag,
		BlockTypeNewToken,
		BlockTypePathChallenge,
		BlockTypePathResponse,
		BlockTypePadding:
		return true
	default:
		return false
	}
}

// GetBlockTypeName returns a human-readable name for the block type.
func GetBlockTypeName(blockType uint8) string {
	switch blockType {
	case BlockTypeDateTime:
		return "DateTime"
	case BlockTypeOptions:
		return "Options"
	case BlockTypeRouterInfo:
		return "RouterInfo"
	case BlockTypeI2NPMessage:
		return "I2NPMessage"
	case BlockTypeFirstFragment:
		return "FirstFragment"
	case BlockTypeFollowOnFragment:
		return "FollowOnFragment"
	case BlockTypeTermination:
		return "Termination"
	case BlockTypeRelayRequest:
		return "RelayRequest"
	case BlockTypeRelayResponse:
		return "RelayResponse"
	case BlockTypeRelayIntro:
		return "RelayIntro"
	case BlockTypePeerTest:
		return "PeerTest"
	case BlockTypeACK:
		return "ACK"
	case BlockTypeAddress:
		return "Address"
	case BlockTypeRelayTagRequest:
		return "RelayTagRequest"
	case BlockTypeRelayTag:
		return "RelayTag"
	case BlockTypeNewToken:
		return "NewToken"
	case BlockTypePathChallenge:
		return "PathChallenge"
	case BlockTypePathResponse:
		return "PathResponse"
	case BlockTypePadding:
		return "Padding"
	default:
		return "Unknown"
	}
}
