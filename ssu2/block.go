package ssu2

import (
	"encoding/binary"
	"net"
	"time"

	"github.com/samber/oops"
)

// SSU2Block represents an SSU2 protocol block within a packet payload.
// Blocks use TLV (Type-Length-Value) encoding:
//   - Type: 1 byte (block type identifier)
//   - Length: 2 bytes (big-endian, length of Value field only)
//   - Value: variable length data
//
// SSU2 packets can contain multiple blocks concatenated together.
// Block types are defined in ssu2.rst specification.
type SSU2Block struct {
	// Type identifies the block type (0-254)
	// See BlockType* constants for valid values
	Type uint8

	// Data contains the block payload (Value in TLV encoding)
	// Length is implicit from len(Data)
	Data []byte
}

// Block type constants from ssu2.rst
const (
	BlockTypeDateTime          uint8 = 0   // Timestamp block (4 bytes, seconds since epoch)
	BlockTypeOptions           uint8 = 1   // Connection options (15+ bytes)
	BlockTypeRouterInfo        uint8 = 2   // RouterInfo structure (variable)
	BlockTypeI2NPMessage       uint8 = 3   // I2NP message (variable)
	BlockTypeFirstFragment     uint8 = 4   // First fragment of message (variable)
	BlockTypeFollowOnFragment  uint8 = 5   // Subsequent fragment (variable)
	BlockTypeTermination       uint8 = 6   // Connection termination (9+ bytes)
	BlockTypeRelayRequest      uint8 = 7   // Relay request (variable)
	BlockTypeRelayResponse     uint8 = 8   // Relay response (variable)
	BlockTypeRelayIntro        uint8 = 9   // Relay introduction (variable)
	BlockTypePeerTest          uint8 = 10  // Peer test message (variable)
	BlockTypeNextNonce         uint8 = 11  // Nonce rekeying (8 bytes)
	BlockTypeACK               uint8 = 12  // Acknowledgment (5+ bytes)
	BlockTypeAddress           uint8 = 13  // Address block (9 or 21 bytes)
	BlockTypeReserved14        uint8 = 14  // Reserved per spec (do not use)
	BlockTypeRelayTagRequest   uint8 = 15  // Request relay tag (3 bytes)
	BlockTypeRelayTag          uint8 = 16  // Relay tag assignment (7 bytes)
	BlockTypeNewToken          uint8 = 17  // New session token (15 bytes)
	BlockTypePathChallenge     uint8 = 18  // Path validation challenge (variable)
	BlockTypePathResponse      uint8 = 19  // Path validation response (variable)
	BlockTypeFirstPacketNumber uint8 = 20  // Initial packet number for data phase (4 bytes)
	BlockTypeCongestion        uint8 = 21  // Congestion experience signaling (1 byte)
	BlockTypePadding           uint8 = 254 // Padding block (variable)
)

// TerminationReason represents the reason code in a Termination block.
// Spec §Termination defines 23 reason codes (0–22).
type TerminationReason uint8

const (
	TerminationNormalClose           TerminationReason = 0  // Normal close or unspecified
	TerminationReceived              TerminationReason = 1  // Termination received
	TerminationIdleTimeout           TerminationReason = 2  // Idle timeout
	TerminationRouterShutdown        TerminationReason = 3  // Router shutdown
	TerminationDataPhaseAEADFailure  TerminationReason = 4  // Data phase AEAD failure
	TerminationIncompatibleOptions   TerminationReason = 5  // Incompatible options
	TerminationIncompatibleSignature TerminationReason = 6  // Incompatible signature type
	TerminationClockSkew             TerminationReason = 7  // Clock skew
	TerminationPaddingViolation      TerminationReason = 8  // Padding violation
	TerminationAEADFramingError      TerminationReason = 9  // AEAD framing error
	TerminationPayloadFormatError    TerminationReason = 10 // Payload format error
	TerminationSessionRequestError   TerminationReason = 11 // Session request error
	TerminationSessionCreatedError   TerminationReason = 12 // Session created error
	TerminationSessionConfirmedError TerminationReason = 13 // Session confirmed error
	TerminationTimeout               TerminationReason = 14 // Timeout
	TerminationRISigVerifyFail       TerminationReason = 15 // RI signature verification fail
	TerminationSParamMissing         TerminationReason = 16 // s parameter missing, invalid, or mismatched in RouterInfo
	TerminationBanned                TerminationReason = 17 // Banned
	TerminationBadToken              TerminationReason = 18 // Bad token
	TerminationConnectionLimits      TerminationReason = 19 // Connection limits
	TerminationIncompatibleVersion   TerminationReason = 20 // Incompatible version
	TerminationWrongNetID            TerminationReason = 21 // Wrong net ID
	TerminationReplacedByNewSession  TerminationReason = 22 // Replaced by new session
)

// String returns the human-readable name for the termination reason.
func (r TerminationReason) String() string {
	switch r {
	case TerminationNormalClose:
		return "NormalClose"
	case TerminationReceived:
		return "TerminationReceived"
	case TerminationIdleTimeout:
		return "IdleTimeout"
	case TerminationRouterShutdown:
		return "RouterShutdown"
	case TerminationDataPhaseAEADFailure:
		return "DataPhaseAEADFailure"
	case TerminationIncompatibleOptions:
		return "IncompatibleOptions"
	case TerminationIncompatibleSignature:
		return "IncompatibleSignature"
	case TerminationClockSkew:
		return "ClockSkew"
	case TerminationPaddingViolation:
		return "PaddingViolation"
	case TerminationAEADFramingError:
		return "AEADFramingError"
	case TerminationPayloadFormatError:
		return "PayloadFormatError"
	case TerminationSessionRequestError:
		return "SessionRequestError"
	case TerminationSessionCreatedError:
		return "SessionCreatedError"
	case TerminationSessionConfirmedError:
		return "SessionConfirmedError"
	case TerminationTimeout:
		return "Timeout"
	case TerminationRISigVerifyFail:
		return "RISigVerifyFail"
	case TerminationSParamMissing:
		return "SParamMissing"
	case TerminationBanned:
		return "Banned"
	case TerminationBadToken:
		return "BadToken"
	case TerminationConnectionLimits:
		return "ConnectionLimits"
	case TerminationIncompatibleVersion:
		return "IncompatibleVersion"
	case TerminationWrongNetID:
		return "WrongNetID"
	case TerminationReplacedByNewSession:
		return "ReplacedByNewSession"
	default:
		return "Unknown"
	}
}

// Minimum block data sizes from ssu2.rst
const (
	minBlockHeaderSize       = 3     // Type (1) + Length (2)
	minDateTimeSize          = 4     // Timestamp data (seconds since epoch)
	minOptionsSize           = 12    // Options data (per spec minimum)
	minTerminationSize       = 5     // Termination data: reason(1) + valid-data-packets-received(4)
	minNextNonceSize         = 8     // Next nonce (8 bytes)
	minACKSize               = 5     // ACK data
	minReserved14Size        = 0     // Reserved block type (no data expected)
	minAddressSizeIPv4       = 6     // IPv4 address: port(2) + IP(4)
	minAddressSizeIPv6       = 18    // IPv6 address: port(2) + IP(16)
	minRelayTagRequestSize   = 4     // Relay tag request: nonce (4 bytes) per spec
	minRelayTagSize          = 4     // Relay tag data: relay_tag(4) + expiration(3) = 7 total block, but data length is 4 minimum
	minNewTokenSize          = 12    // New token data: 4 expiration + 8 token
	minFirstPacketNumberSize = 4     // Initial packet number (4 bytes)
	minCongestionSize        = 1     // Congestion experience (1 byte)
	maxBlockLength           = 65535 // Maximum length field value (2 bytes)
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

// blockMinSizes maps block types to their minimum data sizes per ssu2.rst.
var blockMinSizes = map[uint8]int{
	BlockTypeDateTime:          minDateTimeSize,
	BlockTypeOptions:           minOptionsSize,
	BlockTypeTermination:       minTerminationSize,
	BlockTypeNextNonce:         minNextNonceSize,
	BlockTypeACK:               minACKSize,
	BlockTypeReserved14:        minReserved14Size,
	BlockTypeAddress:           minAddressSizeIPv4,
	BlockTypeRelayTagRequest:   minRelayTagRequestSize,
	BlockTypeRelayTag:          minRelayTagSize,
	BlockTypeNewToken:          minNewTokenSize,
	BlockTypeFirstPacketNumber: minFirstPacketNumberSize,
	BlockTypeCongestion:        minCongestionSize,
}

// validate checks that the block meets minimum size requirements per ssu2.rst.
func (b *SSU2Block) validate() error {
	dataLen := len(b.Data)

	// Check maximum length
	if dataLen > maxBlockLength {
		return oops.Errorf("block data too large: %d bytes (maximum %d)", dataLen, maxBlockLength)
	}

	// Validate minimum size for known block types
	if minSize, ok := blockMinSizes[b.Type]; ok && dataLen < minSize {
		return oops.Errorf("%s block too short: %d bytes (minimum %d)",
			GetBlockTypeName(b.Type), dataLen, minSize)
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
		BlockTypeNextNonce,
		BlockTypeACK,
		BlockTypeAddress,
		BlockTypeReserved14,
		BlockTypeRelayTagRequest,
		BlockTypeRelayTag,
		BlockTypeNewToken,
		BlockTypePathChallenge,
		BlockTypePathResponse,
		BlockTypeFirstPacketNumber,
		BlockTypeCongestion,
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
	case BlockTypeNextNonce:
		return "NextNonce"
	case BlockTypeACK:
		return "ACK"
	case BlockTypeAddress:
		return "Address"
	case BlockTypeReserved14:
		return "Reserved14"
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
	case BlockTypeFirstPacketNumber:
		return "FirstPacketNumber"
	case BlockTypeCongestion:
		return "Congestion"
	case BlockTypePadding:
		return "Padding"
	default:
		return "Unknown"
	}
}

// NewTokenBlock represents a NewToken (Type 17) block.
// Per SSU2 spec, this block contains:
//   - 4 bytes: Token expiration timestamp (seconds since epoch)
//   - 8 bytes: Token (randomly-generated, big-endian)
//
// Total data size: 12 bytes
type NewTokenBlock struct {
	Expiration uint32 // Unix timestamp when token expires
	Token      []byte // Token value (8 bytes per spec)
}

// NewNewTokenBlock creates a NewToken block with the specified expiration and token.
// Per SSU2 spec, the token must be exactly 8 bytes.
func NewNewTokenBlock(expiration time.Time, token []byte) (*SSU2Block, error) {
	if len(token) != TokenSize {
		return nil, oops.Errorf("token must be exactly %d bytes per SSU2 spec, got %d", TokenSize, len(token))
	}

	// Build block data: expiration (4) + token (8)
	data := make([]byte, 4+len(token))
	binary.BigEndian.PutUint32(data[0:4], uint32(expiration.Unix()))
	copy(data[4:], token)

	return NewSSU2Block(BlockTypeNewToken, data), nil
}

// ParseNewTokenBlock extracts the expiration and token from a NewToken block.
func ParseNewTokenBlock(block *SSU2Block) (*NewTokenBlock, error) {
	if block.Type != BlockTypeNewToken {
		return nil, oops.Errorf("expected NewToken block (type %d), got type %d", BlockTypeNewToken, block.Type)
	}

	if len(block.Data) < minNewTokenSize {
		return nil, oops.Errorf("NewToken block data too short: %d bytes (minimum %d)", len(block.Data), minNewTokenSize)
	}

	return &NewTokenBlock{
		Expiration: binary.BigEndian.Uint32(block.Data[0:4]),
		Token:      block.Data[4:],
	}, nil
}

// FindBlockByType searches for a block of the specified type in a slice of blocks.
// Returns the first matching block, or nil if not found.
func FindBlockByType(blocks []*SSU2Block, blockType uint8) *SSU2Block {
	for _, block := range blocks {
		if block.Type == blockType {
			return block
		}
	}
	return nil
}

// AddressBlock represents a decoded Address block (type 13).
// Per spec: port(2) + IP(4 for IPv4, 16 for IPv6).
type AddressBlock struct {
	IP   net.IP
	Port uint16
}

// EncodeAddressBlock creates an Address block from an IP and port.
func EncodeAddressBlock(ip net.IP, port uint16) *SSU2Block {
	ip4 := ip.To4()
	var data []byte
	if ip4 != nil {
		data = make([]byte, 6)
		binary.BigEndian.PutUint16(data[0:2], port)
		copy(data[2:6], ip4)
	} else {
		data = make([]byte, 18)
		binary.BigEndian.PutUint16(data[0:2], port)
		copy(data[2:18], ip.To16())
	}
	return NewSSU2Block(BlockTypeAddress, data)
}

// DecodeAddressBlock parses an Address block into IP and port.
func DecodeAddressBlock(block *SSU2Block) (*AddressBlock, error) {
	if block.Type != BlockTypeAddress {
		return nil, oops.Errorf("expected Address block (type %d), got type %d", BlockTypeAddress, block.Type)
	}
	switch len(block.Data) {
	case minAddressSizeIPv4: // 6 = port(2) + IPv4(4)
		return &AddressBlock{
			Port: binary.BigEndian.Uint16(block.Data[0:2]),
			IP:   net.IP(block.Data[2:6]),
		}, nil
	case minAddressSizeIPv6: // 18 = port(2) + IPv6(16)
		return &AddressBlock{
			Port: binary.BigEndian.Uint16(block.Data[0:2]),
			IP:   net.IP(block.Data[2:18]),
		}, nil
	default:
		return nil, oops.Errorf("Address block unexpected size: %d bytes (expected %d or %d)",
			len(block.Data), minAddressSizeIPv4, minAddressSizeIPv6)
	}
}
