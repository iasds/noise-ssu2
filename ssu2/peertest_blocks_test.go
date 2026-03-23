package ssu2

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPeerTestMessageCode_String tests the String method for message codes.
func TestPeerTestMessageCode_String(t *testing.T) {
	tests := []struct {
		code     PeerTestMessageCode
		expected string
	}{
		{PeerTestRequest, "Request"},
		{PeerTestRelay, "Relay"},
		{PeerTestResponse, "Response"},
		{PeerTestResult, "Result"},
		{PeerTestProbe, "Probe"},
		{PeerTestReply, "Reply"},
		{PeerTestConfirmation, "Confirmation"},
		{PeerTestMessageCode(99), "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.code.String())
		})
	}
}

// TestEncodePeerTestBlock_AllMessages tests encoding each message type.
func TestEncodePeerTestBlock_AllMessages(t *testing.T) {
	signedData := make([]byte, 32)
	for i := range signedData {
		signedData[i] = byte(i)
	}

	tests := []struct {
		name  string
		block *PeerTestBlock
	}{
		{
			name: "Message1_Request",
			block: &PeerTestBlock{
				MessageCode: PeerTestRequest,
				Nonce:       0x12345678,
				Version:     2,
				SignedData:  signedData,
			},
		},
		{
			name: "Message2_Relay",
			block: &PeerTestBlock{
				MessageCode: PeerTestRelay,
				Nonce:       0xAABBCCDD,
				Timestamp:   1234567890,
				Version:     2,
				SignedData:  signedData,
			},
		},
		{
			name: "Message3_Response",
			block: &PeerTestBlock{
				MessageCode: PeerTestResponse,
				Nonce:       0x11223344,
				Version:     2,
			},
		},
		{
			name: "Message4_Result",
			block: &PeerTestBlock{
				MessageCode: PeerTestResult,
				StatusCode:  0x01,
				Nonce:       0x55667788,
				Version:     2,
				SignedData:  signedData,
			},
		},
		{
			name: "Message5_Probe",
			block: &PeerTestBlock{
				MessageCode: PeerTestProbe,
				StatusCode:  0x00,
				Nonce:       0xDEADBEEF,
				Timestamp:   1286608618,
				Version:     2,
				SignedData:  signedData,
			},
		},
		{
			name: "Message6_Reply",
			block: &PeerTestBlock{
				MessageCode: PeerTestReply,
				StatusCode:  0x02,
				Nonce:       0xCAFEBABE,
				Version:     2,
			},
		},
		{
			name: "Message7_Confirmation",
			block: &PeerTestBlock{
				MessageCode: PeerTestConfirmation,
				StatusCode:  0x00,
				Nonce:       0x99887766,
				Version:     2,
				SignedData:  signedData,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded, err := EncodePeerTestBlock(tt.block)
			require.NoError(t, err)
			require.NotNil(t, encoded)
			assert.Equal(t, BlockTypePeerTest, encoded.Type)

			// Verify fixed header layout
			assert.Equal(t, uint8(tt.block.MessageCode), encoded.Data[0])
			assert.Equal(t, tt.block.StatusCode, encoded.Data[1])
			nonce := binary.BigEndian.Uint32(encoded.Data[2:6])
			assert.Equal(t, tt.block.Nonce, nonce)
			timestamp := binary.BigEndian.Uint32(encoded.Data[6:10])
			assert.Equal(t, tt.block.Timestamp, timestamp)
			assert.Equal(t, tt.block.Version, encoded.Data[10])

			// Verify signed data
			if len(tt.block.SignedData) > 0 {
				assert.Equal(t, tt.block.SignedData, encoded.Data[11:])
				assert.Equal(t, 11+len(tt.block.SignedData), len(encoded.Data))
			} else {
				assert.Equal(t, 11, len(encoded.Data))
			}
		})
	}
}

// TestEncodePeerTestBlock_NilBlock tests error handling for nil block.
func TestEncodePeerTestBlock_NilBlock(t *testing.T) {
	_, err := EncodePeerTestBlock(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "PeerTestBlock is nil")
}

// TestEncodePeerTestBlock_InvalidMessageCode tests error handling for invalid message code.
func TestEncodePeerTestBlock_InvalidMessageCode(t *testing.T) {
	block := &PeerTestBlock{
		MessageCode: PeerTestMessageCode(99),
		Nonce:       0x12345678,
		Version:     2,
	}

	_, err := EncodePeerTestBlock(block)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid message code")
}

// TestDecodePeerTestBlock_AllMessages tests decoding each message type.
func TestDecodePeerTestBlock_AllMessages(t *testing.T) {
	signedData := make([]byte, 20)
	for i := range signedData {
		signedData[i] = byte(i + 100)
	}

	tests := []struct {
		name       string
		msg        uint8
		status     uint8
		nonce      uint32
		timestamp  uint32
		version    uint8
		signedData []byte
	}{
		{"Msg1_Request", 1, 0, 0x12345678, 0, 2, signedData},
		{"Msg2_Relay", 2, 0, 0xAABBCCDD, 1234567890, 2, signedData},
		{"Msg3_Response", 3, 0, 0x11223344, 0, 2, nil},
		{"Msg4_Result", 4, 1, 0x55667788, 0, 2, signedData},
		{"Msg5_Probe", 5, 0, 0xDEADBEEF, 1286608618, 2, signedData},
		{"Msg6_Reply", 6, 2, 0xCAFEBABE, 0, 2, nil},
		{"Msg7_Confirmation", 7, 0, 0x99887766, 0, 2, signedData},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := make([]byte, 11+len(tt.signedData))
			data[0] = tt.msg
			data[1] = tt.status
			binary.BigEndian.PutUint32(data[2:6], tt.nonce)
			binary.BigEndian.PutUint32(data[6:10], tt.timestamp)
			data[10] = tt.version
			if len(tt.signedData) > 0 {
				copy(data[11:], tt.signedData)
			}

			ssu2Block := NewSSU2Block(BlockTypePeerTest, data)
			decoded, err := DecodePeerTestBlock(ssu2Block)
			require.NoError(t, err)
			require.NotNil(t, decoded)

			assert.Equal(t, PeerTestMessageCode(tt.msg), decoded.MessageCode)
			assert.Equal(t, tt.status, decoded.StatusCode)
			assert.Equal(t, tt.nonce, decoded.Nonce)
			assert.Equal(t, tt.timestamp, decoded.Timestamp)
			assert.Equal(t, tt.version, decoded.Version)

			if len(tt.signedData) > 0 {
				assert.Equal(t, tt.signedData, decoded.SignedData)
			} else {
				assert.Nil(t, decoded.SignedData)
			}
		})
	}
}

// TestDecodePeerTestBlock_NilBlock tests error handling for nil block.
func TestDecodePeerTestBlock_NilBlock(t *testing.T) {
	_, err := DecodePeerTestBlock(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "block is nil")
}

// TestDecodePeerTestBlock_WrongBlockType tests error handling for wrong block type.
func TestDecodePeerTestBlock_WrongBlockType(t *testing.T) {
	ssu2Block := &SSU2Block{
		Type: BlockTypeRelayRequest,
		Data: make([]byte, 11),
	}

	_, err := DecodePeerTestBlock(ssu2Block)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid block type")
}

// TestDecodePeerTestBlock_TooShort tests error handling for insufficient data.
func TestDecodePeerTestBlock_TooShort(t *testing.T) {
	ssu2Block := &SSU2Block{
		Type: BlockTypePeerTest,
		Data: make([]byte, 5), // Need at least 11
	}

	_, err := DecodePeerTestBlock(ssu2Block)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "too short")
}

// TestDecodePeerTestBlock_InvalidMessageCode tests error handling for invalid message code.
func TestDecodePeerTestBlock_InvalidMessageCode(t *testing.T) {
	data := make([]byte, 11)
	data[0] = 99 // Invalid code

	ssu2Block := NewSSU2Block(BlockTypePeerTest, data)

	_, err := DecodePeerTestBlock(ssu2Block)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid message code")
}

// TestEncodeDecode_RoundTrip tests encode/decode round trip for all message types.
func TestEncodeDecode_RoundTrip(t *testing.T) {
	signedData := make([]byte, 48)
	for i := range signedData {
		signedData[i] = byte(i)
	}

	tests := []struct {
		name  string
		block *PeerTestBlock
	}{
		{
			name: "Message1",
			block: &PeerTestBlock{
				MessageCode: PeerTestRequest,
				Nonce:       0x12345678,
				Version:     2,
				SignedData:  signedData,
			},
		},
		{
			name: "Message2",
			block: &PeerTestBlock{
				MessageCode: PeerTestRelay,
				Nonce:       0xAABBCCDD,
				Timestamp:   1234567890,
				Version:     2,
				SignedData:  signedData,
			},
		},
		{
			name: "Message3",
			block: &PeerTestBlock{
				MessageCode: PeerTestResponse,
				Nonce:       0x11223344,
				Version:     2,
			},
		},
		{
			name: "Message4",
			block: &PeerTestBlock{
				MessageCode: PeerTestResult,
				StatusCode:  1,
				Nonce:       0x55667788,
				Version:     2,
				SignedData:  signedData,
			},
		},
		{
			name: "Message5",
			block: &PeerTestBlock{
				MessageCode: PeerTestProbe,
				Nonce:       0xDEADBEEF,
				Timestamp:   1286608618,
				Version:     2,
				SignedData:  signedData,
			},
		},
		{
			name: "Message6",
			block: &PeerTestBlock{
				MessageCode: PeerTestReply,
				StatusCode:  2,
				Nonce:       0xCAFEBABE,
				Version:     2,
			},
		},
		{
			name: "Message7",
			block: &PeerTestBlock{
				MessageCode: PeerTestConfirmation,
				Nonce:       0x99887766,
				Version:     2,
				SignedData:  signedData,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded, err := EncodePeerTestBlock(tt.block)
			require.NoError(t, err)

			decoded, err := DecodePeerTestBlock(encoded)
			require.NoError(t, err)

			assert.Equal(t, tt.block.MessageCode, decoded.MessageCode)
			assert.Equal(t, tt.block.StatusCode, decoded.StatusCode)
			assert.Equal(t, tt.block.Nonce, decoded.Nonce)
			assert.Equal(t, tt.block.Timestamp, decoded.Timestamp)
			assert.Equal(t, tt.block.Version, decoded.Version)

			if len(tt.block.SignedData) > 0 {
				assert.Equal(t, tt.block.SignedData, decoded.SignedData)
			} else {
				assert.Nil(t, decoded.SignedData)
			}
		})
	}
}

// TestDecodePeerTestBlock_HeaderOnly tests decoding with no signed data.
func TestDecodePeerTestBlock_HeaderOnly(t *testing.T) {
	data := make([]byte, 11)
	data[0] = uint8(PeerTestResponse)
	data[1] = 0 // status
	binary.BigEndian.PutUint32(data[2:6], 0x11223344)
	data[10] = 2 // version

	ssu2Block := NewSSU2Block(BlockTypePeerTest, data)
	decoded, err := DecodePeerTestBlock(ssu2Block)
	require.NoError(t, err)
	assert.Equal(t, PeerTestResponse, decoded.MessageCode)
	assert.Equal(t, uint32(0x11223344), decoded.Nonce)
	assert.Equal(t, uint8(2), decoded.Version)
	assert.Nil(t, decoded.SignedData)
}

// TestEncodePeerTestBlock_NoSignedData tests encoding with empty signed data.
func TestEncodePeerTestBlock_NoSignedData(t *testing.T) {
	block := &PeerTestBlock{
		MessageCode: PeerTestReply,
		StatusCode:  3,
		Nonce:       0xCAFEBABE,
		Version:     2,
	}

	encoded, err := EncodePeerTestBlock(block)
	require.NoError(t, err)
	assert.Equal(t, 11, len(encoded.Data))
}
