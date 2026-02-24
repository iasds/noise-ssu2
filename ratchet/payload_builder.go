package ratchet

import (
	"encoding/binary"
	"time"

	"github.com/samber/oops"
)

// nowFunc returns the current time. It is a variable so tests can override it.
var nowFunc = time.Now

// PayloadBuilder constructs a spec-compliant payload from a sequence of blocks.
// It enforces ordering rules from ratchet.md §"Block Ordering Rules":
//   - Padding, if present, must be the last block.
//   - Termination, if present, must be last except for padding.
//   - Multiple padding blocks are not allowed.
//
// Use the message-type-specific constructors (NewSessionPayloadBuilder,
// ExistingSessionPayloadBuilder) for full validation.
type PayloadBuilder struct {
	blocks []PayloadBlock
}

// NewPayloadBuilder creates an empty PayloadBuilder.
func NewPayloadBuilder() *PayloadBuilder {
	return &PayloadBuilder{}
}

// AddBlock appends a block to the payload.
func (pb *PayloadBuilder) AddBlock(block PayloadBlock) *PayloadBuilder {
	pb.blocks = append(pb.blocks, block)
	return pb
}

// Build serializes all blocks into a single byte slice.
// Returns an error if the payload exceeds maxPayloadSize or block ordering
// rules are violated.
func (pb *PayloadBuilder) Build() ([]byte, error) {
	if err := pb.validate(); err != nil {
		return nil, err
	}

	totalSize := 0
	for _, b := range pb.blocks {
		totalSize += b.SerializeSize()
	}
	if totalSize > maxPayloadSize {
		return nil, oops.Errorf("payload size %d exceeds maximum %d", totalSize, maxPayloadSize)
	}

	buf := make([]byte, totalSize)
	offset := 0
	for _, b := range pb.blocks {
		n, err := b.Serialize(buf[offset:])
		if err != nil {
			return nil, oops.Wrapf(err, "failed to serialize block type %d", b.Type)
		}
		offset += n
	}
	return buf, nil
}

// validate checks block ordering rules per the spec.
func (pb *PayloadBuilder) validate() error {
	if len(pb.blocks) == 0 {
		return nil // empty payload is allowed
	}

	paddingCount := 0
	terminationIdx := -1
	paddingIdx := -1

	for i, b := range pb.blocks {
		switch b.Type {
		case BlockPadding:
			paddingCount++
			if paddingCount > 1 {
				return oops.Errorf("multiple padding blocks not allowed")
			}
			paddingIdx = i
		case BlockTermination:
			terminationIdx = i
		}
	}

	// Padding must be the last block.
	if paddingIdx >= 0 && paddingIdx != len(pb.blocks)-1 {
		return oops.Errorf("padding block must be the last block (found at index %d of %d)", paddingIdx, len(pb.blocks)-1)
	}

	// Termination must be last except for padding.
	if terminationIdx >= 0 {
		expectedLast := len(pb.blocks) - 1
		if paddingIdx >= 0 {
			expectedLast = len(pb.blocks) - 2
		}
		if terminationIdx != expectedLast {
			return oops.Errorf("termination block must be last non-padding block (found at index %d, expected %d)", terminationIdx, expectedLast)
		}
	}

	return nil
}

// NewSessionPayloadBuilder creates a PayloadBuilder pre-populated with a DateTime block
// as required by the New Session format. Additional allowed blocks: GarlicClove, Options, Padding.
// Spec ref: ratchet.md §"Block Ordering Rules" — "In the New Session message,
// the DateTime block is required, and must be the first block."
func NewSessionPayloadBuilder() *PayloadBuilder {
	return NewPayloadBuilder().AddBlock(NewDateTimeBlock(nowFunc()))
}

// ExistingSessionPayloadBuilder creates an empty PayloadBuilder for Existing Session
// messages, which have no required blocks and allow all block types.
func ExistingSessionPayloadBuilder() *PayloadBuilder {
	return NewPayloadBuilder()
}

// ParsePayload deserializes a byte slice into a sequence of PayloadBlocks.
// Unknown block types are preserved (the spec requires receivers to ignore them).
// Returns an error for malformed data (truncated headers, length overflows).
func ParsePayload(data []byte) ([]PayloadBlock, error) {
	var blocks []PayloadBlock
	offset := 0

	for offset < len(data) {
		remaining := len(data) - offset
		if remaining < blockHeaderSize {
			return nil, oops.Errorf("truncated block header at offset %d: %d bytes remaining, need %d", offset, remaining, blockHeaderSize)
		}

		blockType := BlockType(data[offset])
		blockLen := int(binary.BigEndian.Uint16(data[offset+1 : offset+3]))
		offset += blockHeaderSize

		if blockLen > len(data)-offset {
			return nil, oops.Errorf("block type %d at offset %d: data length %d exceeds remaining %d bytes", blockType, offset-blockHeaderSize, blockLen, len(data)-offset)
		}

		blockData := make([]byte, blockLen)
		copy(blockData, data[offset:offset+blockLen])

		blocks = append(blocks, PayloadBlock{
			Type: blockType,
			Data: blockData,
		})
		offset += blockLen
	}

	return blocks, nil
}

// FindBlock returns the first block of the given type, or nil if not found.
func FindBlock(blocks []PayloadBlock, blockType BlockType) *PayloadBlock {
	for i := range blocks {
		if blocks[i].Type == blockType {
			return &blocks[i]
		}
	}
	return nil
}

// FindBlocks returns all blocks of the given type.
func FindBlocks(blocks []PayloadBlock, blockType BlockType) []PayloadBlock {
	var result []PayloadBlock
	for _, b := range blocks {
		if b.Type == blockType {
			result = append(result, b)
		}
	}
	return result
}
