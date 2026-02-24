package ratchet

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// Block Construction
// ============================================================================

func TestNewDateTimeBlock(t *testing.T) {
	ts := time.Unix(1700000000, 0)
	b := NewDateTimeBlock(ts)

	assert.Equal(t, BlockDateTime, b.Type)
	assert.Len(t, b.Data, 4)

	parsed, err := b.DateTime()
	require.NoError(t, err)
	assert.Equal(t, ts.Unix(), parsed.Unix())
}

func TestNewDateTimeBlock_ZeroTime(t *testing.T) {
	ts := time.Unix(0, 0)
	b := NewDateTimeBlock(ts)
	parsed, err := b.DateTime()
	require.NoError(t, err)
	assert.Equal(t, int64(0), parsed.Unix())
}

func TestNewTerminationBlock(t *testing.T) {
	b := NewTerminationBlock(TerminationNormal, nil)
	assert.Equal(t, BlockTermination, b.Type)
	assert.Len(t, b.Data, 1)

	reason, addl, err := b.TerminationInfo()
	require.NoError(t, err)
	assert.Equal(t, TerminationNormal, reason)
	assert.Empty(t, addl)
}

func TestNewTerminationBlock_WithData(t *testing.T) {
	extra := []byte("session expired")
	b := NewTerminationBlock(TerminationReceived, extra)

	reason, addl, err := b.TerminationInfo()
	require.NoError(t, err)
	assert.Equal(t, TerminationReceived, reason)
	assert.Equal(t, extra, addl)
}

func TestNewMessageNumberBlock(t *testing.T) {
	b := NewMessageNumberBlock(12345)
	assert.Equal(t, BlockMessageNumber, b.Type)
	assert.Len(t, b.Data, 2)

	pn, err := b.MessageNumber()
	require.NoError(t, err)
	assert.Equal(t, uint16(12345), pn)
}

func TestNewMessageNumberBlock_MaxValue(t *testing.T) {
	b := NewMessageNumberBlock(65535)
	pn, err := b.MessageNumber()
	require.NoError(t, err)
	assert.Equal(t, uint16(65535), pn)
}

func TestNewNextKeyBlock_WithKey(t *testing.T) {
	var key [32]byte
	for i := range key {
		key[i] = byte(i)
	}
	b := NewNextKeyBlock(42, &key, false, true)
	assert.Equal(t, BlockNextKey, b.Type)
	assert.Len(t, b.Data, 35)

	info, err := b.NextKey()
	require.NoError(t, err)
	assert.True(t, info.KeyPresent)
	assert.False(t, info.Reverse)
	assert.True(t, info.RequestReverse)
	assert.Equal(t, uint16(42), info.KeyID)
	assert.Equal(t, key, info.PublicKey)
}

func TestNewNextKeyBlock_WithoutKey(t *testing.T) {
	b := NewNextKeyBlock(7, nil, true, false)
	assert.Equal(t, BlockNextKey, b.Type)
	assert.Len(t, b.Data, 3)

	info, err := b.NextKey()
	require.NoError(t, err)
	assert.False(t, info.KeyPresent)
	assert.True(t, info.Reverse)
	assert.False(t, info.RequestReverse)
	assert.Equal(t, uint16(7), info.KeyID)
}

func TestNewNextKeyBlock_ReverseOverridesRequestReverse(t *testing.T) {
	// When reverse=true, requestReverse should not be set per spec
	b := NewNextKeyBlock(0, nil, true, true)
	info, err := b.NextKey()
	require.NoError(t, err)
	assert.True(t, info.Reverse)
	assert.False(t, info.RequestReverse)
}

func TestNewAckBlock(t *testing.T) {
	acks := []AckEntry{
		{TagSetID: 1, N: 100},
		{TagSetID: 2, N: 200},
	}
	b := NewAckBlock(acks)
	assert.Equal(t, BlockAck, b.Type)
	assert.Len(t, b.Data, 8)

	parsed, err := b.Acks()
	require.NoError(t, err)
	assert.Equal(t, acks, parsed)
}

func TestNewAckRequestBlock(t *testing.T) {
	b := NewAckRequestBlock(0)
	assert.Equal(t, BlockAckRequest, b.Type)
	assert.Equal(t, []byte{0}, b.Data)
}

func TestNewGarlicCloveBlock(t *testing.T) {
	cloveData := []byte{0x01, 0x02, 0x03, 0x04}
	b := NewGarlicCloveBlock(cloveData)
	assert.Equal(t, BlockGarlicClove, b.Type)
	assert.Equal(t, cloveData, b.Data)
}

func TestNewPaddingBlock(t *testing.T) {
	b := NewPaddingBlock(16)
	assert.Equal(t, BlockPadding, b.Type)
	assert.Len(t, b.Data, 16)
	// Padding is all zeros
	for _, v := range b.Data {
		assert.Equal(t, byte(0), v)
	}
}

func TestNewPaddingBlock_NegativeSize(t *testing.T) {
	b := NewPaddingBlock(-5)
	assert.Empty(t, b.Data)
}

func TestNewPaddingBlock_Zero(t *testing.T) {
	b := NewPaddingBlock(0)
	assert.Empty(t, b.Data)
}

// ============================================================================
// Block Parsing Errors
// ============================================================================

func TestDateTime_WrongType(t *testing.T) {
	b := PayloadBlock{Type: BlockPadding, Data: []byte{0, 0, 0, 0}}
	_, err := b.DateTime()
	assert.Error(t, err)
}

func TestDateTime_WrongSize(t *testing.T) {
	b := PayloadBlock{Type: BlockDateTime, Data: []byte{0, 0}}
	_, err := b.DateTime()
	assert.Error(t, err)
}

func TestTerminationInfo_WrongType(t *testing.T) {
	b := PayloadBlock{Type: BlockDateTime, Data: []byte{0}}
	_, _, err := b.TerminationInfo()
	assert.Error(t, err)
}

func TestTerminationInfo_EmptyData(t *testing.T) {
	b := PayloadBlock{Type: BlockTermination, Data: []byte{}}
	_, _, err := b.TerminationInfo()
	assert.Error(t, err)
}

func TestMessageNumber_WrongType(t *testing.T) {
	b := PayloadBlock{Type: BlockPadding, Data: []byte{0, 0}}
	_, err := b.MessageNumber()
	assert.Error(t, err)
}

func TestMessageNumber_WrongSize(t *testing.T) {
	b := PayloadBlock{Type: BlockMessageNumber, Data: []byte{0}}
	_, err := b.MessageNumber()
	assert.Error(t, err)
}

func TestNextKey_WrongType(t *testing.T) {
	b := PayloadBlock{Type: BlockPadding, Data: []byte{0, 0, 0}}
	_, err := b.NextKey()
	assert.Error(t, err)
}

func TestNextKey_InvalidSize(t *testing.T) {
	// Neither 3 nor 35 bytes
	b := PayloadBlock{Type: BlockNextKey, Data: []byte{0, 0, 0, 0, 0}}
	_, err := b.NextKey()
	assert.Error(t, err)
}

func TestNextKey_KeyPresentButTooShort(t *testing.T) {
	// Flag says key present but only 3 bytes
	data := []byte{NextKeyFlagKeyPresent, 0, 0}
	b := PayloadBlock{Type: BlockNextKey, Data: data}
	_, err := b.NextKey()
	assert.Error(t, err)
}

func TestAcks_WrongType(t *testing.T) {
	b := PayloadBlock{Type: BlockPadding, Data: []byte{0, 0, 0, 0}}
	_, err := b.Acks()
	assert.Error(t, err)
}

func TestAcks_InvalidSize(t *testing.T) {
	b := PayloadBlock{Type: BlockAck, Data: []byte{0, 0, 0}} // not a multiple of 4
	_, err := b.Acks()
	assert.Error(t, err)
}

func TestAcks_EmptyData(t *testing.T) {
	b := PayloadBlock{Type: BlockAck, Data: []byte{}}
	_, err := b.Acks()
	assert.Error(t, err)
}

// ============================================================================
// Serialization
// ============================================================================

func TestSerialize_DateTime(t *testing.T) {
	b := NewDateTimeBlock(time.Unix(1700000000, 0))
	buf := make([]byte, b.SerializeSize())
	n, err := b.Serialize(buf)
	require.NoError(t, err)
	assert.Equal(t, 7, n) // 3 header + 4 data

	// Verify wire format: [type=0] [size=0,4] [timestamp]
	assert.Equal(t, byte(0), buf[0])
	assert.Equal(t, uint16(4), binary.BigEndian.Uint16(buf[1:3]))
}

func TestSerialize_BufferTooSmall(t *testing.T) {
	b := NewDateTimeBlock(time.Unix(0, 0))
	buf := make([]byte, 2) // too small
	_, err := b.Serialize(buf)
	assert.Error(t, err)
}

func TestSerializeSize(t *testing.T) {
	tests := []struct {
		name     string
		block    PayloadBlock
		expected int
	}{
		{"DateTime", NewDateTimeBlock(time.Now()), 7},
		{"Termination_no_data", NewTerminationBlock(TerminationNormal, nil), 4},
		{"MessageNumber", NewMessageNumberBlock(0), 5},
		{"NextKey_no_key", NewNextKeyBlock(0, nil, false, false), 6},
		{"NextKey_with_key", NewNextKeyBlock(0, &[32]byte{}, false, false), 38},
		{"AckRequest", NewAckRequestBlock(0), 4},
		{"Padding_10", NewPaddingBlock(10), 13},
		{"Padding_0", NewPaddingBlock(0), 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.block.SerializeSize())
		})
	}
}

// ============================================================================
// PayloadBuilder
// ============================================================================

func TestPayloadBuilder_Empty(t *testing.T) {
	pb := NewPayloadBuilder()
	data, err := pb.Build()
	require.NoError(t, err)
	assert.Empty(t, data)
}

func TestPayloadBuilder_SingleBlock(t *testing.T) {
	pb := NewPayloadBuilder().AddBlock(NewDateTimeBlock(time.Unix(1700000000, 0)))
	data, err := pb.Build()
	require.NoError(t, err)
	assert.Len(t, data, 7)
}

func TestPayloadBuilder_MultipleBlocks(t *testing.T) {
	pb := NewPayloadBuilder().
		AddBlock(NewDateTimeBlock(time.Unix(1700000000, 0))).
		AddBlock(NewGarlicCloveBlock([]byte{1, 2, 3})).
		AddBlock(NewPaddingBlock(5))

	data, err := pb.Build()
	require.NoError(t, err)
	// 7 (datetime) + 6 (garlic: 3 header + 3 data) + 8 (padding: 3 header + 5 data) = 21
	assert.Len(t, data, 21)
}

func TestPayloadBuilder_PaddingMustBeLast(t *testing.T) {
	pb := NewPayloadBuilder().
		AddBlock(NewPaddingBlock(5)).
		AddBlock(NewDateTimeBlock(time.Now()))

	_, err := pb.Build()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "padding block must be the last block")
}

func TestPayloadBuilder_MultiplePaddingBlocks(t *testing.T) {
	pb := NewPayloadBuilder().
		AddBlock(NewPaddingBlock(5)).
		AddBlock(NewPaddingBlock(5))

	_, err := pb.Build()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "multiple padding blocks")
}

func TestPayloadBuilder_TerminationBeforePadding(t *testing.T) {
	pb := NewPayloadBuilder().
		AddBlock(NewTerminationBlock(TerminationNormal, nil)).
		AddBlock(NewPaddingBlock(5))

	data, err := pb.Build()
	require.NoError(t, err)
	assert.NotEmpty(t, data)
}

func TestPayloadBuilder_TerminationNotLast(t *testing.T) {
	pb := NewPayloadBuilder().
		AddBlock(NewDateTimeBlock(time.Now())).
		AddBlock(NewTerminationBlock(TerminationNormal, nil)).
		AddBlock(NewGarlicCloveBlock([]byte{1}))

	_, err := pb.Build()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "termination block must be last non-padding block")
}

func TestNewSessionPayloadBuilder(t *testing.T) {
	// Override time for deterministic test
	origNow := nowFunc
	nowFunc = func() time.Time { return time.Unix(1700000000, 0) }
	defer func() { nowFunc = origNow }()

	pb := NewSessionPayloadBuilder().
		AddBlock(NewGarlicCloveBlock([]byte("test clove")))

	data, err := pb.Build()
	require.NoError(t, err)

	// Parse and verify DateTime is first
	blocks, err := ParsePayload(data)
	require.NoError(t, err)
	require.Len(t, blocks, 2)
	assert.Equal(t, BlockDateTime, blocks[0].Type)
	assert.Equal(t, BlockGarlicClove, blocks[1].Type)
}

func TestExistingSessionPayloadBuilder(t *testing.T) {
	pb := ExistingSessionPayloadBuilder().
		AddBlock(NewGarlicCloveBlock([]byte("clove data"))).
		AddBlock(NewNextKeyBlock(1, &[32]byte{1}, false, false)).
		AddBlock(NewPaddingBlock(8))

	data, err := pb.Build()
	require.NoError(t, err)
	assert.NotEmpty(t, data)
}

// ============================================================================
// ParsePayload
// ============================================================================

func TestParsePayload_Empty(t *testing.T) {
	blocks, err := ParsePayload(nil)
	require.NoError(t, err)
	assert.Empty(t, blocks)
}

func TestParsePayload_SingleBlock(t *testing.T) {
	pb := NewPayloadBuilder().AddBlock(NewDateTimeBlock(time.Unix(1700000000, 0)))
	data, err := pb.Build()
	require.NoError(t, err)

	blocks, err := ParsePayload(data)
	require.NoError(t, err)
	require.Len(t, blocks, 1)
	assert.Equal(t, BlockDateTime, blocks[0].Type)

	parsed, err := blocks[0].DateTime()
	require.NoError(t, err)
	assert.Equal(t, int64(1700000000), parsed.Unix())
}

func TestParsePayload_MultipleBlocks(t *testing.T) {
	clove := []byte{0xAA, 0xBB, 0xCC}
	pb := NewPayloadBuilder().
		AddBlock(NewDateTimeBlock(time.Unix(100, 0))).
		AddBlock(NewGarlicCloveBlock(clove)).
		AddBlock(NewAckRequestBlock(0)).
		AddBlock(NewPaddingBlock(4))
	data, err := pb.Build()
	require.NoError(t, err)

	blocks, err := ParsePayload(data)
	require.NoError(t, err)
	require.Len(t, blocks, 4)
	assert.Equal(t, BlockDateTime, blocks[0].Type)
	assert.Equal(t, BlockGarlicClove, blocks[1].Type)
	assert.Equal(t, clove, blocks[1].Data)
	assert.Equal(t, BlockAckRequest, blocks[2].Type)
	assert.Equal(t, BlockPadding, blocks[3].Type)
}

func TestParsePayload_TruncatedHeader(t *testing.T) {
	// Only 2 bytes, need at least 3 for a header
	_, err := ParsePayload([]byte{0, 0})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "truncated block header")
}

func TestParsePayload_DataOverrun(t *testing.T) {
	// Header says 10 bytes of data, but only 2 available
	data := []byte{0, 0, 10, 0xFF, 0xFF}
	_, err := ParsePayload(data)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds remaining")
}

func TestParsePayload_UnknownBlockType(t *testing.T) {
	// Unknown type 200 with 2 bytes of data
	data := []byte{200, 0, 2, 0xAA, 0xBB}
	blocks, err := ParsePayload(data)
	require.NoError(t, err)
	require.Len(t, blocks, 1)
	assert.Equal(t, BlockType(200), blocks[0].Type)
	assert.Equal(t, []byte{0xAA, 0xBB}, blocks[0].Data)
}

func TestParsePayload_ZeroLengthBlock(t *testing.T) {
	// Padding with zero data
	data := []byte{254, 0, 0}
	blocks, err := ParsePayload(data)
	require.NoError(t, err)
	require.Len(t, blocks, 1)
	assert.Equal(t, BlockPadding, blocks[0].Type)
	assert.Empty(t, blocks[0].Data)
}

// ============================================================================
// Round-trip: Build → Parse → Verify
// ============================================================================

func TestRoundTrip_ComplexPayload(t *testing.T) {
	var key [32]byte
	for i := range key {
		key[i] = byte(i + 10)
	}

	origBlocks := []PayloadBlock{
		NewDateTimeBlock(time.Unix(1700000000, 0)),
		NewGarlicCloveBlock([]byte("test clove data")),
		NewGarlicCloveBlock([]byte("second clove")),
		NewNextKeyBlock(5, &key, false, true),
		NewAckBlock([]AckEntry{{TagSetID: 1, N: 42}, {TagSetID: 3, N: 99}}),
		NewMessageNumberBlock(500),
		NewPaddingBlock(12),
	}

	pb := NewPayloadBuilder()
	for _, b := range origBlocks {
		pb.AddBlock(b)
	}
	data, err := pb.Build()
	require.NoError(t, err)

	parsed, err := ParsePayload(data)
	require.NoError(t, err)
	require.Len(t, parsed, len(origBlocks))

	for i, b := range parsed {
		assert.Equal(t, origBlocks[i].Type, b.Type, "block %d type mismatch", i)
		assert.Equal(t, origBlocks[i].Data, b.Data, "block %d data mismatch", i)
	}
}

func TestRoundTrip_NextKeyReverseKey(t *testing.T) {
	var key [32]byte
	for i := range key {
		key[i] = 0xFF - byte(i)
	}
	b := NewNextKeyBlock(100, &key, true, false)

	buf := make([]byte, b.SerializeSize())
	_, err := b.Serialize(buf)
	require.NoError(t, err)

	blocks, err := ParsePayload(buf)
	require.NoError(t, err)
	require.Len(t, blocks, 1)

	info, err := blocks[0].NextKey()
	require.NoError(t, err)
	assert.True(t, info.KeyPresent)
	assert.True(t, info.Reverse)
	assert.Equal(t, uint16(100), info.KeyID)
	assert.Equal(t, key, info.PublicKey)
}

func TestRoundTrip_TerminationWithData(t *testing.T) {
	extra := []byte("debug: timeout after 30s")
	b := NewTerminationBlock(TerminationReason(42), extra)

	buf := make([]byte, b.SerializeSize())
	_, err := b.Serialize(buf)
	require.NoError(t, err)

	blocks, err := ParsePayload(buf)
	require.NoError(t, err)
	require.Len(t, blocks, 1)

	reason, addl, err := blocks[0].TerminationInfo()
	require.NoError(t, err)
	assert.Equal(t, TerminationReason(42), reason)
	assert.Equal(t, extra, addl)
}

// ============================================================================
// FindBlock / FindBlocks
// ============================================================================

func TestFindBlock_Found(t *testing.T) {
	blocks := []PayloadBlock{
		NewDateTimeBlock(time.Now()),
		NewGarlicCloveBlock([]byte("data")),
		NewPaddingBlock(0),
	}
	b := FindBlock(blocks, BlockGarlicClove)
	require.NotNil(t, b)
	assert.Equal(t, BlockGarlicClove, b.Type)
}

func TestFindBlock_NotFound(t *testing.T) {
	blocks := []PayloadBlock{
		NewDateTimeBlock(time.Now()),
	}
	b := FindBlock(blocks, BlockTermination)
	assert.Nil(t, b)
}

func TestFindBlocks_Multiple(t *testing.T) {
	blocks := []PayloadBlock{
		NewDateTimeBlock(time.Now()),
		NewGarlicCloveBlock([]byte("clove1")),
		NewGarlicCloveBlock([]byte("clove2")),
		NewGarlicCloveBlock([]byte("clove3")),
		NewPaddingBlock(0),
	}
	cloves := FindBlocks(blocks, BlockGarlicClove)
	assert.Len(t, cloves, 3)
}

func TestFindBlocks_None(t *testing.T) {
	blocks := []PayloadBlock{
		NewDateTimeBlock(time.Now()),
	}
	result := FindBlocks(blocks, BlockTermination)
	assert.Empty(t, result)
}

// ============================================================================
// Wire format correctness
// ============================================================================

func TestWireFormat_ManualParse(t *testing.T) {
	// Construct a payload manually and verify parsing matches
	// DateTime(0, size=4, timestamp=0x65B8D800) + Padding(254, size=2, data=0x00,0x00)
	raw := []byte{
		0x00, 0x00, 0x04, 0x65, 0xB8, 0xD8, 0x00, // DateTime
		0xFE, 0x00, 0x02, 0x00, 0x00, // Padding
	}
	blocks, err := ParsePayload(raw)
	require.NoError(t, err)
	require.Len(t, blocks, 2)

	assert.Equal(t, BlockDateTime, blocks[0].Type)
	ts := binary.BigEndian.Uint32(blocks[0].Data)
	assert.Equal(t, uint32(0x65B8D800), ts)

	assert.Equal(t, BlockPadding, blocks[1].Type)
	assert.Len(t, blocks[1].Data, 2)
}

func TestWireFormat_NextKey_FlagEncoding(t *testing.T) {
	// Verify bit-level flag encoding
	b := NewNextKeyBlock(256, nil, false, true)
	assert.Equal(t, byte(NextKeyFlagKeyPresent|NextKeyFlagRequestReverse)&^NextKeyFlagKeyPresent, b.Data[0]&(NextKeyFlagKeyPresent|NextKeyFlagReverse|NextKeyFlagRequestReverse))
	// flags = 0x04 (request reverse, no key present, not reverse)
	assert.Equal(t, byte(0x04), b.Data[0])
	// key ID = 256 big endian
	assert.Equal(t, uint16(256), binary.BigEndian.Uint16(b.Data[1:3]))
}
