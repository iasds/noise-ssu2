package ssu2

import (
	"net"
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

// TestEncodePeerTestBlock_Message1_Request tests encoding message 1 (Request).
func TestEncodePeerTestBlock_Message1_Request(t *testing.T) {
	charlieHash := make([]byte, 32)
	for i := range charlieHash {
		charlieHash[i] = byte(i)
	}

	block := &PeerTestBlock{
		MessageCode:    PeerTestRequest,
		Nonce:          0x12345678,
		RouterHash:     charlieHash,
		CharlieAddress: &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 8080},
	}

	encoded, err := EncodePeerTestBlock(block)
	require.NoError(t, err)
	require.NotNil(t, encoded)

	assert.Equal(t, BlockTypePeerTest, encoded.Type)
	assert.Equal(t, uint8(PeerTestRequest), encoded.Data[0])
	assert.Equal(t, uint32(0x12345678), uint32(encoded.Data[1])<<24|uint32(encoded.Data[2])<<16|uint32(encoded.Data[3])<<8|uint32(encoded.Data[4]))

	// Verify router hash
	assert.Equal(t, charlieHash, encoded.Data[5:37])

	// Verify address encoding (type 4, port, IPv4)
	assert.Equal(t, uint8(4), encoded.Data[37])                                         // IPv4
	assert.Equal(t, uint16(8080), uint16(encoded.Data[38])<<8|uint16(encoded.Data[39])) // Port
	assert.Equal(t, []byte{192, 168, 1, 1}, encoded.Data[40:44])                        // IP
}

// TestEncodePeerTestBlock_Message2_Relay tests encoding message 2 (Relay).
func TestEncodePeerTestBlock_Message2_Relay(t *testing.T) {
	aliceHash := make([]byte, 32)
	for i := range aliceHash {
		aliceHash[i] = byte(i + 100)
	}

	block := &PeerTestBlock{
		MessageCode:  PeerTestRelay,
		Nonce:        0xAABBCCDD,
		RouterHash:   aliceHash,
		AliceAddress: &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 9999},
		Timestamp:    1234567890,
	}

	encoded, err := EncodePeerTestBlock(block)
	require.NoError(t, err)
	require.NotNil(t, encoded)

	assert.Equal(t, BlockTypePeerTest, encoded.Type)
	assert.Equal(t, uint8(PeerTestRelay), encoded.Data[0])

	// Verify nonce
	nonce := uint32(encoded.Data[1])<<24 | uint32(encoded.Data[2])<<16 | uint32(encoded.Data[3])<<8 | uint32(encoded.Data[4])
	assert.Equal(t, uint32(0xAABBCCDD), nonce)

	// Verify router hash
	assert.Equal(t, aliceHash, encoded.Data[5:37])

	// Verify address
	assert.Equal(t, uint8(4), encoded.Data[37])
	assert.Equal(t, uint16(9999), uint16(encoded.Data[38])<<8|uint16(encoded.Data[39]))
	assert.Equal(t, []byte{10, 0, 0, 1}, encoded.Data[40:44])

	// Verify timestamp
	timestamp := uint32(encoded.Data[44])<<24 | uint32(encoded.Data[45])<<16 | uint32(encoded.Data[46])<<8 | uint32(encoded.Data[47])
	assert.Equal(t, uint32(1234567890), timestamp)
}

// TestEncodePeerTestBlock_Message3_Response tests encoding message 3 (Response).
func TestEncodePeerTestBlock_Message3_Response(t *testing.T) {
	block := &PeerTestBlock{
		MessageCode: PeerTestResponse,
		Nonce:       0x11223344,
	}

	encoded, err := EncodePeerTestBlock(block)
	require.NoError(t, err)
	require.NotNil(t, encoded)

	assert.Equal(t, BlockTypePeerTest, encoded.Type)
	assert.Equal(t, 5, len(encoded.Data)) // Only code + nonce
	assert.Equal(t, uint8(PeerTestResponse), encoded.Data[0])

	nonce := uint32(encoded.Data[1])<<24 | uint32(encoded.Data[2])<<16 | uint32(encoded.Data[3])<<8 | uint32(encoded.Data[4])
	assert.Equal(t, uint32(0x11223344), nonce)
}

// TestEncodePeerTestBlock_Message4_Result tests encoding message 4 (Result).
func TestEncodePeerTestBlock_Message4_Result(t *testing.T) {
	block := &PeerTestBlock{
		MessageCode:    PeerTestResult,
		Nonce:          0x55667788,
		CharlieAddress: &net.UDPAddr{IP: net.ParseIP("172.16.0.1"), Port: 7777},
		AliceAddress:   &net.UDPAddr{IP: net.ParseIP("192.168.2.2"), Port: 8888},
	}

	encoded, err := EncodePeerTestBlock(block)
	require.NoError(t, err)
	require.NotNil(t, encoded)

	assert.Equal(t, BlockTypePeerTest, encoded.Type)
	assert.Equal(t, uint8(PeerTestResult), encoded.Data[0])

	// Verify nonce
	nonce := uint32(encoded.Data[1])<<24 | uint32(encoded.Data[2])<<16 | uint32(encoded.Data[3])<<8 | uint32(encoded.Data[4])
	assert.Equal(t, uint32(0x55667788), nonce)

	// Verify Charlie address
	assert.Equal(t, uint8(4), encoded.Data[5])
	assert.Equal(t, uint16(7777), uint16(encoded.Data[6])<<8|uint16(encoded.Data[7]))
	assert.Equal(t, []byte{172, 16, 0, 1}, encoded.Data[8:12])

	// Verify Alice address
	assert.Equal(t, uint8(4), encoded.Data[12])
	assert.Equal(t, uint16(8888), uint16(encoded.Data[13])<<8|uint16(encoded.Data[14]))
	assert.Equal(t, []byte{192, 168, 2, 2}, encoded.Data[15:19])
}

// TestEncodePeerTestBlock_Message5_Probe tests encoding message 5 (Probe).
func TestEncodePeerTestBlock_Message5_Probe(t *testing.T) {
	block := &PeerTestBlock{
		MessageCode:  PeerTestProbe,
		Nonce:        0xDEADBEEF,
		AliceAddress: &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 12345},
		Timestamp:    1286608618, // Fits in uint32
	}

	encoded, err := EncodePeerTestBlock(block)
	require.NoError(t, err)
	require.NotNil(t, encoded)

	assert.Equal(t, BlockTypePeerTest, encoded.Type)
	assert.Equal(t, uint8(PeerTestProbe), encoded.Data[0])

	// Verify nonce
	nonce := uint32(encoded.Data[1])<<24 | uint32(encoded.Data[2])<<16 | uint32(encoded.Data[3])<<8 | uint32(encoded.Data[4])
	assert.Equal(t, uint32(0xDEADBEEF), nonce)

	// Verify address
	assert.Equal(t, uint8(4), encoded.Data[5])
	assert.Equal(t, uint16(12345), uint16(encoded.Data[6])<<8|uint16(encoded.Data[7]))
	assert.Equal(t, []byte{203, 0, 113, 1}, encoded.Data[8:12])

	// Verify timestamp
	timestamp := uint32(encoded.Data[12])<<24 | uint32(encoded.Data[13])<<16 | uint32(encoded.Data[14])<<8 | uint32(encoded.Data[15])
	assert.Equal(t, uint32(1286608618), timestamp)
}

// TestEncodePeerTestBlock_Message6_Reply tests encoding message 6 (Reply).
func TestEncodePeerTestBlock_Message6_Reply(t *testing.T) {
	block := &PeerTestBlock{
		MessageCode: PeerTestReply,
		Nonce:       0xCAFEBABE,
	}

	encoded, err := EncodePeerTestBlock(block)
	require.NoError(t, err)
	require.NotNil(t, encoded)

	assert.Equal(t, BlockTypePeerTest, encoded.Type)
	assert.Equal(t, 5, len(encoded.Data)) // Only code + nonce
	assert.Equal(t, uint8(PeerTestReply), encoded.Data[0])

	nonce := uint32(encoded.Data[1])<<24 | uint32(encoded.Data[2])<<16 | uint32(encoded.Data[3])<<8 | uint32(encoded.Data[4])
	assert.Equal(t, uint32(0xCAFEBABE), nonce)
}

// TestEncodePeerTestBlock_Message7_Confirmation tests encoding message 7 (Confirmation).
func TestEncodePeerTestBlock_Message7_Confirmation(t *testing.T) {
	block := &PeerTestBlock{
		MessageCode: PeerTestConfirmation,
		Nonce:       0x99887766,
	}

	encoded, err := EncodePeerTestBlock(block)
	require.NoError(t, err)
	require.NotNil(t, encoded)

	assert.Equal(t, BlockTypePeerTest, encoded.Type)
	assert.Equal(t, 5, len(encoded.Data)) // Only code + nonce
	assert.Equal(t, uint8(PeerTestConfirmation), encoded.Data[0])

	nonce := uint32(encoded.Data[1])<<24 | uint32(encoded.Data[2])<<16 | uint32(encoded.Data[3])<<8 | uint32(encoded.Data[4])
	assert.Equal(t, uint32(0x99887766), nonce)
}

// TestEncodePeerTestBlock_IPv6 tests encoding with IPv6 addresses.
func TestEncodePeerTestBlock_IPv6(t *testing.T) {
	block := &PeerTestBlock{
		MessageCode:    PeerTestResult,
		Nonce:          0x12345678,
		CharlieAddress: &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 8080},
		AliceAddress:   &net.UDPAddr{IP: net.ParseIP("2001:db8::2"), Port: 9090},
	}

	encoded, err := EncodePeerTestBlock(block)
	require.NoError(t, err)
	require.NotNil(t, encoded)

	assert.Equal(t, BlockTypePeerTest, encoded.Type)

	// Check IPv6 marker (type 6)
	assert.Equal(t, uint8(6), encoded.Data[5])
	assert.Equal(t, uint8(6), encoded.Data[5+19]) // Second address
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
	}

	_, err := EncodePeerTestBlock(block)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid message code")
}

// TestEncodePeerTestBlock_Message1_MissingRouterHash tests validation for message 1.
func TestEncodePeerTestBlock_Message1_MissingRouterHash(t *testing.T) {
	block := &PeerTestBlock{
		MessageCode:    PeerTestRequest,
		Nonce:          0x12345678,
		RouterHash:     make([]byte, 16), // Wrong size
		CharlieAddress: &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 8080},
	}

	_, err := EncodePeerTestBlock(block)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires 32-byte RouterHash")
}

// TestEncodePeerTestBlock_Message1_MissingCharlieAddress tests validation for message 1.
func TestEncodePeerTestBlock_Message1_MissingCharlieAddress(t *testing.T) {
	block := &PeerTestBlock{
		MessageCode: PeerTestRequest,
		Nonce:       0x12345678,
		RouterHash:  make([]byte, 32),
		// Missing CharlieAddress
	}

	_, err := EncodePeerTestBlock(block)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires CharlieAddress")
}

// TestEncodePeerTestBlock_Message2_MissingAliceAddress tests validation for message 2.
func TestEncodePeerTestBlock_Message2_MissingAliceAddress(t *testing.T) {
	block := &PeerTestBlock{
		MessageCode: PeerTestRelay,
		Nonce:       0x12345678,
		RouterHash:  make([]byte, 32),
		// Missing AliceAddress
		Timestamp: 1234567890,
	}

	_, err := EncodePeerTestBlock(block)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires AliceAddress")
}

// TestEncodePeerTestBlock_Message4_MissingAddresses tests validation for message 4.
func TestEncodePeerTestBlock_Message4_MissingAddresses(t *testing.T) {
	// Missing CharlieAddress
	block1 := &PeerTestBlock{
		MessageCode:  PeerTestResult,
		Nonce:        0x12345678,
		AliceAddress: &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 8080},
	}

	_, err := EncodePeerTestBlock(block1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires CharlieAddress")

	// Missing AliceAddress
	block2 := &PeerTestBlock{
		MessageCode:    PeerTestResult,
		Nonce:          0x12345678,
		CharlieAddress: &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 8080},
	}

	_, err = EncodePeerTestBlock(block2)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires AliceAddress")
}

// TestEncodePeerTestBlock_Message5_MissingAliceAddress tests validation for message 5.
func TestEncodePeerTestBlock_Message5_MissingAliceAddress(t *testing.T) {
	block := &PeerTestBlock{
		MessageCode: PeerTestProbe,
		Nonce:       0x12345678,
		// Missing AliceAddress
		Timestamp: 1234567890,
	}

	_, err := EncodePeerTestBlock(block)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires AliceAddress")
}

// TestDecodePeerTestBlock_Message1_Request tests decoding message 1.
func TestDecodePeerTestBlock_Message1_Request(t *testing.T) {
	// Create encoded block manually
	charlieHash := make([]byte, 32)
	for i := range charlieHash {
		charlieHash[i] = byte(i)
	}

	data := make([]byte, 5+32+7) // code + nonce + hash + IPv4 address
	data[0] = uint8(PeerTestRequest)
	data[1] = 0x12
	data[2] = 0x34
	data[3] = 0x56
	data[4] = 0x78
	copy(data[5:37], charlieHash)
	data[37] = 4    // IPv4
	data[38] = 0x1F // Port high byte (8080)
	data[39] = 0x90 // Port low byte
	data[40] = 192  // IP
	data[41] = 168
	data[42] = 1
	data[43] = 1

	ssu2Block := NewSSU2Block(BlockTypePeerTest, data)

	decoded, err := DecodePeerTestBlock(ssu2Block)
	require.NoError(t, err)
	require.NotNil(t, decoded)

	assert.Equal(t, PeerTestRequest, decoded.MessageCode)
	assert.Equal(t, uint32(0x12345678), decoded.Nonce)
	assert.Equal(t, charlieHash, decoded.RouterHash)
	require.NotNil(t, decoded.CharlieAddress)
	assert.Equal(t, "192.168.1.1", decoded.CharlieAddress.IP.String())
	assert.Equal(t, 8080, decoded.CharlieAddress.Port)
}

// TestDecodePeerTestBlock_Message2_Relay tests decoding message 2.
func TestDecodePeerTestBlock_Message2_Relay(t *testing.T) {
	aliceHash := make([]byte, 32)
	for i := range aliceHash {
		aliceHash[i] = byte(i + 50)
	}

	data := make([]byte, 5+32+7+4) // code + nonce + hash + IPv4 address + timestamp
	data[0] = uint8(PeerTestRelay)
	data[1] = 0xAA
	data[2] = 0xBB
	data[3] = 0xCC
	data[4] = 0xDD
	copy(data[5:37], aliceHash)
	data[37] = 4    // IPv4
	data[38] = 0x27 // Port (9999)
	data[39] = 0x0F
	data[40] = 10
	data[41] = 0
	data[42] = 0
	data[43] = 1
	data[44] = 0x49 // Timestamp (1234567890)
	data[45] = 0x96
	data[46] = 0x02
	data[47] = 0xD2

	ssu2Block := NewSSU2Block(BlockTypePeerTest, data)

	decoded, err := DecodePeerTestBlock(ssu2Block)
	require.NoError(t, err)
	require.NotNil(t, decoded)

	assert.Equal(t, PeerTestRelay, decoded.MessageCode)
	assert.Equal(t, uint32(0xAABBCCDD), decoded.Nonce)
	assert.Equal(t, aliceHash, decoded.RouterHash)
	require.NotNil(t, decoded.AliceAddress)
	assert.Equal(t, "10.0.0.1", decoded.AliceAddress.IP.String())
	assert.Equal(t, 9999, decoded.AliceAddress.Port)
	assert.Equal(t, uint32(1234567890), decoded.Timestamp)
}

// TestDecodePeerTestBlock_Message3_Response tests decoding message 3.
func TestDecodePeerTestBlock_Message3_Response(t *testing.T) {
	data := make([]byte, 5)
	data[0] = uint8(PeerTestResponse)
	data[1] = 0x11
	data[2] = 0x22
	data[3] = 0x33
	data[4] = 0x44

	ssu2Block := NewSSU2Block(BlockTypePeerTest, data)

	decoded, err := DecodePeerTestBlock(ssu2Block)
	require.NoError(t, err)
	require.NotNil(t, decoded)

	assert.Equal(t, PeerTestResponse, decoded.MessageCode)
	assert.Equal(t, uint32(0x11223344), decoded.Nonce)
}

// TestDecodePeerTestBlock_Message4_Result tests decoding message 4.
func TestDecodePeerTestBlock_Message4_Result(t *testing.T) {
	data := make([]byte, 5+7+7) // code + nonce + 2 IPv4 addresses
	data[0] = uint8(PeerTestResult)
	data[1] = 0x55
	data[2] = 0x66
	data[3] = 0x77
	data[4] = 0x88
	// Charlie address
	data[5] = 4
	data[6] = 0x1E // Port 7777
	data[7] = 0x61
	data[8] = 172
	data[9] = 16
	data[10] = 0
	data[11] = 1
	// Alice address
	data[12] = 4
	data[13] = 0x22 // Port 8888
	data[14] = 0xB8
	data[15] = 192
	data[16] = 168
	data[17] = 2
	data[18] = 2

	ssu2Block := NewSSU2Block(BlockTypePeerTest, data)

	decoded, err := DecodePeerTestBlock(ssu2Block)
	require.NoError(t, err)
	require.NotNil(t, decoded)

	assert.Equal(t, PeerTestResult, decoded.MessageCode)
	assert.Equal(t, uint32(0x55667788), decoded.Nonce)
	require.NotNil(t, decoded.CharlieAddress)
	assert.Equal(t, "172.16.0.1", decoded.CharlieAddress.IP.String())
	assert.Equal(t, 7777, decoded.CharlieAddress.Port)
	require.NotNil(t, decoded.AliceAddress)
	assert.Equal(t, "192.168.2.2", decoded.AliceAddress.IP.String())
	assert.Equal(t, 8888, decoded.AliceAddress.Port)
}

// TestDecodePeerTestBlock_Message5_Probe tests decoding message 5.
func TestDecodePeerTestBlock_Message5_Probe(t *testing.T) {
	data := make([]byte, 5+7+4) // code + nonce + IPv4 address + timestamp
	data[0] = uint8(PeerTestProbe)
	data[1] = 0xDE
	data[2] = 0xAD
	data[3] = 0xBE
	data[4] = 0xEF
	// Alice address
	data[5] = 4
	data[6] = 0x30 // Port 12345
	data[7] = 0x39
	data[8] = 203
	data[9] = 0
	data[10] = 113
	data[11] = 1
	// Timestamp (1286608618)
	data[12] = 0x4C
	data[13] = 0xBE
	data[14] = 0xBC
	data[15] = 0xEA

	ssu2Block := NewSSU2Block(BlockTypePeerTest, data)

	decoded, err := DecodePeerTestBlock(ssu2Block)
	require.NoError(t, err)
	require.NotNil(t, decoded)

	assert.Equal(t, PeerTestProbe, decoded.MessageCode)
	assert.Equal(t, uint32(0xDEADBEEF), decoded.Nonce)
	require.NotNil(t, decoded.AliceAddress)
	assert.Equal(t, "203.0.113.1", decoded.AliceAddress.IP.String())
	assert.Equal(t, 12345, decoded.AliceAddress.Port)
	assert.Equal(t, uint32(0x4CBEBCEA), decoded.Timestamp)
}

// TestDecodePeerTestBlock_Message6_Reply tests decoding message 6.
func TestDecodePeerTestBlock_Message6_Reply(t *testing.T) {
	data := make([]byte, 5)
	data[0] = uint8(PeerTestReply)
	data[1] = 0xCA
	data[2] = 0xFE
	data[3] = 0xBA
	data[4] = 0xBE

	ssu2Block := NewSSU2Block(BlockTypePeerTest, data)

	decoded, err := DecodePeerTestBlock(ssu2Block)
	require.NoError(t, err)
	require.NotNil(t, decoded)

	assert.Equal(t, PeerTestReply, decoded.MessageCode)
	assert.Equal(t, uint32(0xCAFEBABE), decoded.Nonce)
}

// TestDecodePeerTestBlock_Message7_Confirmation tests decoding message 7.
func TestDecodePeerTestBlock_Message7_Confirmation(t *testing.T) {
	data := make([]byte, 5)
	data[0] = uint8(PeerTestConfirmation)
	data[1] = 0x99
	data[2] = 0x88
	data[3] = 0x77
	data[4] = 0x66

	ssu2Block := NewSSU2Block(BlockTypePeerTest, data)

	decoded, err := DecodePeerTestBlock(ssu2Block)
	require.NoError(t, err)
	require.NotNil(t, decoded)

	assert.Equal(t, PeerTestConfirmation, decoded.MessageCode)
	assert.Equal(t, uint32(0x99887766), decoded.Nonce)
}

// TestDecodePeerTestBlock_IPv6 tests decoding IPv6 addresses.
func TestDecodePeerTestBlock_IPv6(t *testing.T) {
	data := make([]byte, 5+19+19) // code + nonce + 2 IPv6 addresses
	data[0] = uint8(PeerTestResult)
	data[1] = 0x12
	data[2] = 0x34
	data[3] = 0x56
	data[4] = 0x78
	// Charlie address (2001:db8::1)
	data[5] = 6
	data[6] = 0x1F // Port 8080
	data[7] = 0x90
	copy(data[8:24], net.ParseIP("2001:db8::1").To16())
	// Alice address (2001:db8::2)
	data[24] = 6
	data[25] = 0x23 // Port 9090
	data[26] = 0x82
	copy(data[27:43], net.ParseIP("2001:db8::2").To16())

	ssu2Block := NewSSU2Block(BlockTypePeerTest, data)

	decoded, err := DecodePeerTestBlock(ssu2Block)
	require.NoError(t, err)
	require.NotNil(t, decoded)

	assert.Equal(t, PeerTestResult, decoded.MessageCode)
	assert.Equal(t, uint32(0x12345678), decoded.Nonce)
	require.NotNil(t, decoded.CharlieAddress)
	assert.Equal(t, "2001:db8::1", decoded.CharlieAddress.IP.String())
	assert.Equal(t, 8080, decoded.CharlieAddress.Port)
	require.NotNil(t, decoded.AliceAddress)
	assert.Equal(t, "2001:db8::2", decoded.AliceAddress.IP.String())
	assert.Equal(t, 9090, decoded.AliceAddress.Port)
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
		Type: BlockTypeRelayRequest, // Wrong type
		Data: make([]byte, 5),
	}

	_, err := DecodePeerTestBlock(ssu2Block)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid block type")
}

// TestDecodePeerTestBlock_TooShort tests error handling for insufficient data.
func TestDecodePeerTestBlock_TooShort(t *testing.T) {
	ssu2Block := &SSU2Block{
		Type: BlockTypePeerTest,
		Data: make([]byte, 3), // Need at least 5
	}

	_, err := DecodePeerTestBlock(ssu2Block)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "too short")
}

// TestDecodePeerTestBlock_InvalidMessageCode tests error handling for invalid message code.
func TestDecodePeerTestBlock_InvalidMessageCode(t *testing.T) {
	data := make([]byte, 5)
	data[0] = 99 // Invalid code

	ssu2Block := NewSSU2Block(BlockTypePeerTest, data)

	_, err := DecodePeerTestBlock(ssu2Block)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid message code")
}

// TestDecodePeerTestBlock_Message1_TooShort tests insufficient data for message 1.
func TestDecodePeerTestBlock_Message1_TooShort(t *testing.T) {
	data := make([]byte, 20) // Need at least 5 + 32 + 7
	data[0] = uint8(PeerTestRequest)

	ssu2Block := NewSSU2Block(BlockTypePeerTest, data)

	_, err := DecodePeerTestBlock(ssu2Block)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "too short for RouterHash")
}

// TestDecodePeerTestBlock_InvalidAddressType tests error handling for invalid address type.
func TestDecodePeerTestBlock_InvalidAddressType(t *testing.T) {
	data := make([]byte, 5+32+1) // code + nonce + hash + invalid address type
	data[0] = uint8(PeerTestRequest)
	data[37] = 99 // Invalid address type (not 4 or 6)

	ssu2Block := NewSSU2Block(BlockTypePeerTest, data)

	_, err := DecodePeerTestBlock(ssu2Block)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid address type")
}

// TestEncodeDecode_RoundTrip tests encode/decode round trip for all message types.
func TestEncodeDecode_RoundTrip(t *testing.T) {
	tests := []struct {
		name  string
		block *PeerTestBlock
	}{
		{
			name: "Message1",
			block: &PeerTestBlock{
				MessageCode:    PeerTestRequest,
				Nonce:          0x12345678,
				RouterHash:     make([]byte, 32),
				CharlieAddress: &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 8080},
			},
		},
		{
			name: "Message2",
			block: &PeerTestBlock{
				MessageCode:  PeerTestRelay,
				Nonce:        0xAABBCCDD,
				RouterHash:   make([]byte, 32),
				AliceAddress: &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 9999},
				Timestamp:    1234567890,
			},
		},
		{
			name: "Message3",
			block: &PeerTestBlock{
				MessageCode: PeerTestResponse,
				Nonce:       0x11223344,
			},
		},
		{
			name: "Message4",
			block: &PeerTestBlock{
				MessageCode:    PeerTestResult,
				Nonce:          0x55667788,
				CharlieAddress: &net.UDPAddr{IP: net.ParseIP("172.16.0.1"), Port: 7777},
				AliceAddress:   &net.UDPAddr{IP: net.ParseIP("192.168.2.2"), Port: 8888},
			},
		},
		{
			name: "Message5",
			block: &PeerTestBlock{
				MessageCode:  PeerTestProbe,
				Nonce:        0xDEADBEEF,
				AliceAddress: &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 12345},
				Timestamp:    1286608618,
			},
		},
		{
			name: "Message6",
			block: &PeerTestBlock{
				MessageCode: PeerTestReply,
				Nonce:       0xCAFEBABE,
			},
		},
		{
			name: "Message7",
			block: &PeerTestBlock{
				MessageCode: PeerTestConfirmation,
				Nonce:       0x99887766,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encode
			encoded, err := EncodePeerTestBlock(tt.block)
			require.NoError(t, err)

			// Decode
			decoded, err := DecodePeerTestBlock(encoded)
			require.NoError(t, err)

			// Verify
			assert.Equal(t, tt.block.MessageCode, decoded.MessageCode)
			assert.Equal(t, tt.block.Nonce, decoded.Nonce)

			if tt.block.RouterHash != nil {
				assert.Equal(t, tt.block.RouterHash, decoded.RouterHash)
			}

			if tt.block.AliceAddress != nil {
				require.NotNil(t, decoded.AliceAddress)
				assert.Equal(t, tt.block.AliceAddress.IP.String(), decoded.AliceAddress.IP.String())
				assert.Equal(t, tt.block.AliceAddress.Port, decoded.AliceAddress.Port)
			}

			if tt.block.CharlieAddress != nil {
				require.NotNil(t, decoded.CharlieAddress)
				assert.Equal(t, tt.block.CharlieAddress.IP.String(), decoded.CharlieAddress.IP.String())
				assert.Equal(t, tt.block.CharlieAddress.Port, decoded.CharlieAddress.Port)
			}

			if tt.block.Timestamp != 0 {
				assert.Equal(t, tt.block.Timestamp, decoded.Timestamp)
			}
		})
	}
}
