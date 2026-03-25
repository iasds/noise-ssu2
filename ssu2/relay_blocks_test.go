package ssu2

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// makeTestSignature returns a deterministic 64-byte Ed25519-size signature for tests.
func makeTestSignature() []byte {
	data := make([]byte, 64)
	for i := range data {
		data[i] = byte(i)
	}
	return data
}

// makeSignedData returns a deterministic 32-byte signed relay data blob for tests.
// Used by RelayResponse tests.
func makeSignedData() []byte {
	data := make([]byte, 32)
	for i := range data {
		data[i] = byte(i)
	}
	return data
}

// TestEncodeRelayRequest_Valid tests encoding a valid relay request.
func TestEncodeRelayRequest_Valid(t *testing.T) {
	req := &RelayRequestBlock{
		Flag:      0x00,
		Nonce:     12345,
		RelayTag:  99999,
		Timestamp: 1700000000,
		Version:   2,
		AlicePort: 9000,
		AliceIP:   net.IPv4(192, 168, 1, 1).To4(),
		Signature: makeTestSignature(),
	}

	block, err := EncodeRelayRequest(req)
	require.NoError(t, err)
	assert.NotNil(t, block)
	assert.Equal(t, BlockTypeRelayRequest, block.Type)
	// flag(1)+nonce(4)+relay_tag(4)+timestamp(4)+ver(1)+asz(1)+port(2)+ip(4)+sig(64) = 85
	assert.Equal(t, 85, len(block.Data))
}

// TestEncodeRelayRequest_IPv6 tests encoding relay request with IPv6.
func TestEncodeRelayRequest_IPv6(t *testing.T) {
	req := &RelayRequestBlock{
		Nonce:     12345,
		RelayTag:  99999,
		Timestamp: 1700000000,
		Version:   2,
		AlicePort: 9000,
		AliceIP:   net.ParseIP("2001:db8::1"),
		Signature: makeTestSignature(),
	}

	block, err := EncodeRelayRequest(req)
	require.NoError(t, err)
	// flag(1)+nonce(4)+relay_tag(4)+timestamp(4)+ver(1)+asz(1)+port(2)+ip(16)+sig(64) = 97
	assert.Equal(t, 97, len(block.Data))
}

// TestEncodeRelayRequest_NilBlock tests encoding nil request.
func TestEncodeRelayRequest_NilBlock(t *testing.T) {
	block, err := EncodeRelayRequest(nil)
	assert.Error(t, err)
	assert.Nil(t, block)
	assert.Contains(t, err.Error(), "nil")
}

// TestEncodeRelayRequest_WireFormat tests exact wire format bytes.
func TestEncodeRelayRequest_WireFormat(t *testing.T) {
	req := &RelayRequestBlock{
		Flag:      0x00,
		Nonce:     0x00003039, // 12345
		RelayTag:  0x0001869F, // 99999
		Timestamp: 0x6554F900, // 1700000000 (approximate)
		Version:   2,
		AlicePort: 9000,
		AliceIP:   net.IPv4(10, 0, 0, 1).To4(),
		Signature: []byte{0xAA, 0xBB},
	}

	block, err := EncodeRelayRequest(req)
	require.NoError(t, err)

	d := block.Data
	assert.Equal(t, byte(0x00), d[0])                                     // flag
	assert.Equal(t, uint32(0x00003039), binary.BigEndian.Uint32(d[1:5]))  // nonce
	assert.Equal(t, uint32(0x0001869F), binary.BigEndian.Uint32(d[5:9]))  // relay_tag
	assert.Equal(t, uint32(0x6554F900), binary.BigEndian.Uint32(d[9:13])) // timestamp
	assert.Equal(t, byte(2), d[13])                                       // ver
	assert.Equal(t, byte(6), d[14])                                       // asz (IPv4)
	assert.Equal(t, uint16(9000), binary.BigEndian.Uint16(d[15:17]))      // port
	assert.Equal(t, []byte{10, 0, 0, 1}, d[17:21])                        // IP
	assert.Equal(t, []byte{0xAA, 0xBB}, d[21:23])                         // signature
}

// TestDecodeRelayRequest_Valid tests decoding a valid relay request.
func TestDecodeRelayRequest_Valid(t *testing.T) {
	original := &RelayRequestBlock{
		Flag:      0x00,
		Nonce:     12345,
		RelayTag:  99999,
		Timestamp: 1700000000,
		Version:   2,
		AlicePort: 9000,
		AliceIP:   net.IPv4(192, 168, 1, 1).To4(),
		Signature: makeTestSignature(),
	}

	block, err := EncodeRelayRequest(original)
	require.NoError(t, err)

	decoded, err := DecodeRelayRequest(block)
	require.NoError(t, err)
	assert.Equal(t, original.Flag, decoded.Flag)
	assert.Equal(t, original.Nonce, decoded.Nonce)
	assert.Equal(t, original.RelayTag, decoded.RelayTag)
	assert.Equal(t, original.Timestamp, decoded.Timestamp)
	assert.Equal(t, original.Version, decoded.Version)
	assert.Equal(t, original.AlicePort, decoded.AlicePort)
	assert.True(t, original.AliceIP.Equal(decoded.AliceIP))
	assert.Equal(t, original.Signature, decoded.Signature)
}

// TestDecodeRelayRequest_NilBlock tests decoding nil block.
func TestDecodeRelayRequest_NilBlock(t *testing.T) {
	decoded, err := DecodeRelayRequest(nil)
	assert.Error(t, err)
	assert.Nil(t, decoded)
	assert.Contains(t, err.Error(), "nil")
}

// TestDecodeRelayRequest_WrongType tests decoding wrong block type.
func TestDecodeRelayRequest_WrongType(t *testing.T) {
	block := &SSU2Block{
		Type: BlockTypeRelayResponse,
		Data: make([]byte, 50),
	}

	decoded, err := DecodeRelayRequest(block)
	assert.Error(t, err)
	assert.Nil(t, decoded)
	assert.Contains(t, err.Error(), "invalid block type")
}

// TestDecodeRelayRequest_TooShort tests decoding truncated block.
func TestDecodeRelayRequest_TooShort(t *testing.T) {
	block := &SSU2Block{
		Type: BlockTypeRelayRequest,
		Data: make([]byte, 10), // Too short
	}

	decoded, err := DecodeRelayRequest(block)
	assert.Error(t, err)
	assert.Nil(t, decoded)
	assert.Contains(t, err.Error(), "too short")
}

// TestDecodeRelayRequest_InvalidAsz tests decoding with invalid asz value.
func TestDecodeRelayRequest_InvalidAsz(t *testing.T) {
	data := make([]byte, 30)
	data[14] = 10 // invalid asz (not 6 or 18)
	block := &SSU2Block{
		Type: BlockTypeRelayRequest,
		Data: data,
	}

	decoded, err := DecodeRelayRequest(block)
	assert.Error(t, err)
	assert.Nil(t, decoded)
	assert.Contains(t, err.Error(), "invalid asz")
}

// TestEncodeRelayResponse_Success tests encoding successful relay response.
func TestEncodeRelayResponse_Success(t *testing.T) {
	resp := &RelayResponseBlock{
		Flag:        0,
		Code:        0,
		Nonce:       12345,
		Timestamp:   1700000000,
		Version:     2,
		CharliePort: 9000,
		CharlieIP:   net.IPv4(10, 0, 0, 1).To4(),
		Signature:   makeTestSignature(), // 64 bytes
		Token:       []byte{1, 2, 3, 4, 5, 6, 7, 8},
	}

	block, err := EncodeRelayResponse(resp)
	require.NoError(t, err)
	assert.NotNil(t, block)
	assert.Equal(t, BlockTypeRelayResponse, block.Type)
	// flag(1)+code(1)+nonce(4)+ts(4)+ver(1)+csz(1)+port(2)+ip(4)+sig(64)+token(8) = 90
	assert.Equal(t, 90, len(block.Data))
}

// TestEncodeRelayResponse_SuccessIPv6 tests encoding accepted relay response with IPv6.
func TestEncodeRelayResponse_SuccessIPv6(t *testing.T) {
	resp := &RelayResponseBlock{
		Flag:        0,
		Code:        0,
		Nonce:       12345,
		Timestamp:   1700000000,
		Version:     2,
		CharliePort: 9000,
		CharlieIP:   net.ParseIP("2001:db8::1"),
		Signature:   makeTestSignature(),
		Token:       []byte{1, 2, 3, 4, 5, 6, 7, 8},
	}

	block, err := EncodeRelayResponse(resp)
	require.NoError(t, err)
	// flag(1)+code(1)+nonce(4)+ts(4)+ver(1)+csz(1)+port(2)+ip(16)+sig(64)+token(8) = 102
	assert.Equal(t, 102, len(block.Data))
}

// TestEncodeRelayResponse_BobRejection tests encoding Bob rejection response.
func TestEncodeRelayResponse_BobRejection(t *testing.T) {
	resp := &RelayResponseBlock{
		Flag:  0,
		Code:  1, // Bob rejection
		Nonce: 12345,
	}

	block, err := EncodeRelayResponse(resp)
	require.NoError(t, err)
	assert.Equal(t, 6, len(block.Data)) // flag(1)+code(1)+nonce(4)
}

// TestEncodeRelayResponse_CharlieRejection tests encoding Charlie rejection response.
func TestEncodeRelayResponse_CharlieRejection(t *testing.T) {
	resp := &RelayResponseBlock{
		Flag:        0,
		Code:        64, // Charlie rejection
		Nonce:       12345,
		Timestamp:   1700000000,
		Version:     2,
		CharliePort: 9000,
		CharlieIP:   net.IPv4(10, 0, 0, 1).To4(),
		Signature:   makeTestSignature(),
	}

	block, err := EncodeRelayResponse(resp)
	require.NoError(t, err)
	// flag(1)+code(1)+nonce(4)+ts(4)+ver(1)+csz(1)+port(2)+ip(4)+sig(64) = 82
	assert.Equal(t, 82, len(block.Data))
}

// TestEncodeRelayResponse_NilBlock tests encoding nil response.
func TestEncodeRelayResponse_NilBlock(t *testing.T) {
	block, err := EncodeRelayResponse(nil)
	assert.Error(t, err)
	assert.Nil(t, block)
	assert.Contains(t, err.Error(), "nil")
}

// TestDecodeRelayResponse_Success tests decoding successful relay response.
func TestDecodeRelayResponse_Success(t *testing.T) {
	original := &RelayResponseBlock{
		Flag:        0,
		Code:        0,
		Nonce:       12345,
		Timestamp:   1700000000,
		Version:     2,
		CharliePort: 9000,
		CharlieIP:   net.IPv4(10, 0, 0, 1).To4(),
		Signature:   makeTestSignature(),
		Token:       []byte{1, 2, 3, 4, 5, 6, 7, 8},
	}

	block, err := EncodeRelayResponse(original)
	require.NoError(t, err)

	decoded, err := DecodeRelayResponse(block)
	require.NoError(t, err)
	assert.Equal(t, original.Flag, decoded.Flag)
	assert.Equal(t, original.Code, decoded.Code)
	assert.Equal(t, original.Nonce, decoded.Nonce)
	assert.Equal(t, original.Timestamp, decoded.Timestamp)
	assert.Equal(t, original.Version, decoded.Version)
	assert.Equal(t, original.CharliePort, decoded.CharliePort)
	assert.True(t, original.CharlieIP.Equal(decoded.CharlieIP))
	assert.Equal(t, original.Signature, decoded.Signature)
	assert.Equal(t, original.Token, decoded.Token)
}

// TestDecodeRelayResponse_BobRejection tests decoding Bob rejection response.
func TestDecodeRelayResponse_BobRejection(t *testing.T) {
	original := &RelayResponseBlock{
		Flag:  0,
		Code:  1,
		Nonce: 12345,
	}

	block, err := EncodeRelayResponse(original)
	require.NoError(t, err)

	decoded, err := DecodeRelayResponse(block)
	require.NoError(t, err)
	assert.Equal(t, original.Nonce, decoded.Nonce)
	assert.Equal(t, original.Code, decoded.Code)
	assert.Nil(t, decoded.Token)
	assert.Nil(t, decoded.Signature)
}

// TestDecodeRelayResponse_CharlieRejection tests decoding Charlie rejection response.
func TestDecodeRelayResponse_CharlieRejection(t *testing.T) {
	original := &RelayResponseBlock{
		Flag:        0,
		Code:        64,
		Nonce:       12345,
		Timestamp:   1700000000,
		Version:     2,
		CharliePort: 9000,
		CharlieIP:   net.IPv4(10, 0, 0, 1).To4(),
		Signature:   makeTestSignature(),
	}

	block, err := EncodeRelayResponse(original)
	require.NoError(t, err)

	decoded, err := DecodeRelayResponse(block)
	require.NoError(t, err)
	assert.Equal(t, original.Code, decoded.Code)
	assert.Equal(t, original.Nonce, decoded.Nonce)
	assert.Equal(t, original.Timestamp, decoded.Timestamp)
	assert.Equal(t, original.Version, decoded.Version)
	assert.Equal(t, original.CharliePort, decoded.CharliePort)
	assert.True(t, original.CharlieIP.Equal(decoded.CharlieIP))
	assert.Equal(t, original.Signature, decoded.Signature)
	assert.Nil(t, decoded.Token)
}

// TestDecodeRelayResponse_NilBlock tests decoding nil block.
func TestDecodeRelayResponse_NilBlock(t *testing.T) {
	decoded, err := DecodeRelayResponse(nil)
	assert.Error(t, err)
	assert.Nil(t, decoded)
	assert.Contains(t, err.Error(), "nil")
}

// TestDecodeRelayResponse_WrongType tests decoding wrong block type.
func TestDecodeRelayResponse_WrongType(t *testing.T) {
	block := &SSU2Block{
		Type: BlockTypeRelayRequest,
		Data: make([]byte, 12),
	}

	decoded, err := DecodeRelayResponse(block)
	assert.Error(t, err)
	assert.Nil(t, decoded)
	assert.Contains(t, err.Error(), "invalid block type")
}

// TestDecodeRelayResponse_TooShort tests decoding truncated block.
func TestDecodeRelayResponse_TooShort(t *testing.T) {
	block := &SSU2Block{
		Type: BlockTypeRelayResponse,
		Data: make([]byte, 4), // Too short (minimum 6)
	}

	decoded, err := DecodeRelayResponse(block)
	assert.Error(t, err)
	assert.Nil(t, decoded)
	assert.Contains(t, err.Error(), "too short")
}

// TestEncodeRelayIntro_IPv4 tests encoding relay intro with IPv4.
func TestEncodeRelayIntro_IPv4(t *testing.T) {
	routerHash := make([]byte, 32)
	for i := range routerHash {
		routerHash[i] = byte(i)
	}
	sig := make([]byte, 64)

	intro := &RelayIntroBlock{
		Flag:            0,
		AliceRouterHash: routerHash,
		Nonce:           99,
		AliceRelayTag:   12345,
		Timestamp:       1234567890,
		Version:         2,
		AlicePort:       9000,
		AliceIP:         net.ParseIP("10.0.0.1"),
		Signature:       sig,
	}

	block, err := EncodeRelayIntro(intro)
	require.NoError(t, err)
	assert.NotNil(t, block)
	assert.Equal(t, BlockTypeRelayIntro, block.Type)
	// flag(1)+hash(32)+nonce(4)+tag(4)+ts(4)+ver(1)+asz(1)+port(2)+ip(4)+sig(64) = 117
	assert.Equal(t, 117, len(block.Data))
}

// TestEncodeRelayIntro_IPv6 tests encoding relay intro with IPv6.
func TestEncodeRelayIntro_IPv6(t *testing.T) {
	routerHash := make([]byte, 32)
	sig := make([]byte, 64)
	intro := &RelayIntroBlock{
		Flag:            0,
		AliceRouterHash: routerHash,
		Nonce:           99,
		AliceRelayTag:   12345,
		Timestamp:       1234567890,
		Version:         2,
		AlicePort:       9000,
		AliceIP:         net.ParseIP("2001:db8::1"),
		Signature:       sig,
	}

	block, err := EncodeRelayIntro(intro)
	require.NoError(t, err)
	// flag(1)+hash(32)+nonce(4)+tag(4)+ts(4)+ver(1)+asz(1)+port(2)+ip(16)+sig(64) = 129
	assert.Equal(t, 129, len(block.Data))
}

// TestEncodeRelayIntro_NilBlock tests encoding nil intro.
func TestEncodeRelayIntro_NilBlock(t *testing.T) {
	block, err := EncodeRelayIntro(nil)
	assert.Error(t, err)
	assert.Nil(t, block)
	assert.Contains(t, err.Error(), "nil")
}

// TestEncodeRelayIntro_InvalidRouterHash tests invalid router hash size.
func TestEncodeRelayIntro_InvalidRouterHash(t *testing.T) {
	intro := &RelayIntroBlock{
		AliceRouterHash: []byte{1, 2, 3}, // Wrong size
		AliceRelayTag:   12345,
		AlicePort:       9000,
		AliceIP:         net.ParseIP("10.0.0.1"),
		Timestamp:       1234567890,
	}

	block, err := EncodeRelayIntro(intro)
	assert.Error(t, err)
	assert.Nil(t, block)
	assert.Contains(t, err.Error(), "32 bytes")
}

// TestEncodeRelayIntro_NilIP tests encoding with nil IP.
func TestEncodeRelayIntro_NilIP(t *testing.T) {
	routerHash := make([]byte, 32)
	intro := &RelayIntroBlock{
		AliceRouterHash: routerHash,
		AliceRelayTag:   12345,
		AliceIP:         nil,
		Timestamp:       1234567890,
	}

	block, err := EncodeRelayIntro(intro)
	assert.Error(t, err)
	assert.Nil(t, block)
}

// TestDecodeRelayIntro_IPv4 tests decoding relay intro with IPv4.
func TestDecodeRelayIntro_IPv4(t *testing.T) {
	routerHash := make([]byte, 32)
	for i := range routerHash {
		routerHash[i] = byte(i)
	}
	sig := make([]byte, 64)
	for i := range sig {
		sig[i] = byte(i + 100)
	}

	original := &RelayIntroBlock{
		Flag:            0,
		AliceRouterHash: routerHash,
		Nonce:           42,
		AliceRelayTag:   12345,
		Timestamp:       1234567890,
		Version:         2,
		AlicePort:       9000,
		AliceIP:         net.ParseIP("10.0.0.1"),
		Signature:       sig,
	}

	block, err := EncodeRelayIntro(original)
	require.NoError(t, err)

	decoded, err := DecodeRelayIntro(block)
	require.NoError(t, err)
	assert.Equal(t, original.Flag, decoded.Flag)
	assert.Equal(t, original.AliceRouterHash, decoded.AliceRouterHash)
	assert.Equal(t, original.Nonce, decoded.Nonce)
	assert.Equal(t, original.AliceRelayTag, decoded.AliceRelayTag)
	assert.Equal(t, original.Timestamp, decoded.Timestamp)
	assert.Equal(t, original.Version, decoded.Version)
	assert.Equal(t, original.AlicePort, decoded.AlicePort)
	assert.True(t, original.AliceIP.Equal(decoded.AliceIP))
	assert.Equal(t, original.Signature, decoded.Signature)
}

// TestDecodeRelayIntro_IPv6 tests decoding relay intro with IPv6.
func TestDecodeRelayIntro_IPv6(t *testing.T) {
	routerHash := make([]byte, 32)
	sig := make([]byte, 64)
	original := &RelayIntroBlock{
		Flag:            0,
		AliceRouterHash: routerHash,
		Nonce:           42,
		AliceRelayTag:   12345,
		Timestamp:       1234567890,
		Version:         2,
		AlicePort:       9000,
		AliceIP:         net.ParseIP("2001:db8::1"),
		Signature:       sig,
	}

	block, err := EncodeRelayIntro(original)
	require.NoError(t, err)

	decoded, err := DecodeRelayIntro(block)
	require.NoError(t, err)
	assert.True(t, original.AliceIP.Equal(decoded.AliceIP))
	assert.Equal(t, original.AlicePort, decoded.AlicePort)
	assert.Equal(t, original.Nonce, decoded.Nonce)
	assert.Equal(t, original.Version, decoded.Version)
}

// TestDecodeRelayIntro_NilBlock tests decoding nil block.
func TestDecodeRelayIntro_NilBlock(t *testing.T) {
	decoded, err := DecodeRelayIntro(nil)
	assert.Error(t, err)
	assert.Nil(t, decoded)
	assert.Contains(t, err.Error(), "nil")
}

// TestDecodeRelayIntro_WrongType tests decoding wrong block type.
func TestDecodeRelayIntro_WrongType(t *testing.T) {
	block := &SSU2Block{
		Type: BlockTypeRelayRequest,
		Data: make([]byte, 60),
	}

	decoded, err := DecodeRelayIntro(block)
	assert.Error(t, err)
	assert.Nil(t, decoded)
	assert.Contains(t, err.Error(), "invalid block type")
}

// TestDecodeRelayIntro_TooShort tests decoding truncated block.
func TestDecodeRelayIntro_TooShort(t *testing.T) {
	block := &SSU2Block{
		Type: BlockTypeRelayIntro,
		Data: make([]byte, 30), // Too short
	}

	decoded, err := DecodeRelayIntro(block)
	assert.Error(t, err)
	assert.Nil(t, decoded)
	assert.Contains(t, err.Error(), "too short")
}

// TestDecodeRelayIntro_InvalidAsz tests invalid asz value.
func TestDecodeRelayIntro_InvalidAsz(t *testing.T) {
	data := make([]byte, 55)
	data[46] = 99 // Invalid asz

	block := &SSU2Block{
		Type: BlockTypeRelayIntro,
		Data: data,
	}

	decoded, err := DecodeRelayIntro(block)
	assert.Error(t, err)
	assert.Nil(t, decoded)
	assert.Contains(t, err.Error(), "invalid asz")
}

// TestEncodeRelayTagRequest_Valid tests encoding valid relay tag request.
func TestEncodeRelayTagRequest_Valid(t *testing.T) {
	req := &RelayTagRequestBlock{
		Nonce: 12345,
	}

	block, err := EncodeRelayTagRequest(req)
	require.NoError(t, err)
	assert.NotNil(t, block)
	assert.Equal(t, BlockTypeRelayTagRequest, block.Type)
	assert.Equal(t, 4, len(block.Data))
}

// TestEncodeRelayTagRequest_NilBlock tests encoding nil request.
func TestEncodeRelayTagRequest_NilBlock(t *testing.T) {
	block, err := EncodeRelayTagRequest(nil)
	assert.Error(t, err)
	assert.Nil(t, block)
	assert.Contains(t, err.Error(), "nil")
}

// TestDecodeRelayTagRequest_Valid tests decoding valid relay tag request.
func TestDecodeRelayTagRequest_Valid(t *testing.T) {
	original := &RelayTagRequestBlock{
		Nonce: 12345,
	}

	block, err := EncodeRelayTagRequest(original)
	require.NoError(t, err)

	decoded, err := DecodeRelayTagRequest(block)
	require.NoError(t, err)
	assert.Equal(t, original.Nonce, decoded.Nonce)
}

// TestDecodeRelayTagRequest_ThreeByte tests decoding 3-byte nonce.
func TestDecodeRelayTagRequest_ThreeByte(t *testing.T) {
	block := &SSU2Block{
		Type: BlockTypeRelayTagRequest,
		Data: []byte{0x12, 0x34, 0x56}, // 3-byte nonce
	}

	decoded, err := DecodeRelayTagRequest(block)
	require.NoError(t, err)
	assert.Equal(t, uint32(0x123456), decoded.Nonce)
}

// TestDecodeRelayTagRequest_NilBlock tests decoding nil block.
func TestDecodeRelayTagRequest_NilBlock(t *testing.T) {
	decoded, err := DecodeRelayTagRequest(nil)
	assert.Error(t, err)
	assert.Nil(t, decoded)
	assert.Contains(t, err.Error(), "nil")
}

// TestDecodeRelayTagRequest_WrongType tests decoding wrong block type.
func TestDecodeRelayTagRequest_WrongType(t *testing.T) {
	block := &SSU2Block{
		Type: BlockTypeRelayTag,
		Data: make([]byte, 4),
	}

	decoded, err := DecodeRelayTagRequest(block)
	assert.Error(t, err)
	assert.Nil(t, decoded)
	assert.Contains(t, err.Error(), "invalid block type")
}

// TestDecodeRelayTagRequest_TooShort tests decoding truncated block.
func TestDecodeRelayTagRequest_TooShort(t *testing.T) {
	block := &SSU2Block{
		Type: BlockTypeRelayTagRequest,
		Data: []byte{0x12}, // Too short
	}

	decoded, err := DecodeRelayTagRequest(block)
	assert.Error(t, err)
	assert.Nil(t, decoded)
	assert.Contains(t, err.Error(), "too short")
}

// TestEncodeRelayTag_Valid tests encoding valid relay tag.
func TestEncodeRelayTag_Valid(t *testing.T) {
	tag := &RelayTagBlock{
		RelayTag:   12345,
		Expiration: 3600,
	}

	block, err := EncodeRelayTag(tag)
	require.NoError(t, err)
	assert.NotNil(t, block)
	assert.Equal(t, BlockTypeRelayTag, block.Type)
	assert.Equal(t, 7, len(block.Data))
}

// TestEncodeRelayTag_MaxExpiration tests encoding maximum expiration.
func TestEncodeRelayTag_MaxExpiration(t *testing.T) {
	tag := &RelayTagBlock{
		RelayTag:   12345,
		Expiration: 0xFFFFFF, // Maximum 3-byte value
	}

	block, err := EncodeRelayTag(tag)
	require.NoError(t, err)
	assert.Equal(t, 7, len(block.Data))
}

// TestEncodeRelayTag_NilBlock tests encoding nil tag.
func TestEncodeRelayTag_NilBlock(t *testing.T) {
	block, err := EncodeRelayTag(nil)
	assert.Error(t, err)
	assert.Nil(t, block)
	assert.Contains(t, err.Error(), "nil")
}

// TestEncodeRelayTag_ExpirationTooLarge tests expiration overflow.
func TestEncodeRelayTag_ExpirationTooLarge(t *testing.T) {
	tag := &RelayTagBlock{
		RelayTag:   12345,
		Expiration: 0x1000000, // Too large for 3 bytes
	}

	block, err := EncodeRelayTag(tag)
	assert.Error(t, err)
	assert.Nil(t, block)
	assert.Contains(t, err.Error(), "too large")
}

// TestDecodeRelayTag_Valid tests decoding valid relay tag.
func TestDecodeRelayTag_Valid(t *testing.T) {
	original := &RelayTagBlock{
		RelayTag:   12345,
		Expiration: 3600,
	}

	block, err := EncodeRelayTag(original)
	require.NoError(t, err)

	decoded, err := DecodeRelayTag(block)
	require.NoError(t, err)
	assert.Equal(t, original.RelayTag, decoded.RelayTag)
	assert.Equal(t, original.Expiration, decoded.Expiration)
}

// TestDecodeRelayTag_NilBlock tests decoding nil block.
func TestDecodeRelayTag_NilBlock(t *testing.T) {
	decoded, err := DecodeRelayTag(nil)
	assert.Error(t, err)
	assert.Nil(t, decoded)
	assert.Contains(t, err.Error(), "nil")
}

// TestDecodeRelayTag_WrongType tests decoding wrong block type.
func TestDecodeRelayTag_WrongType(t *testing.T) {
	block := &SSU2Block{
		Type: BlockTypeRelayTagRequest,
		Data: make([]byte, 7),
	}

	decoded, err := DecodeRelayTag(block)
	assert.Error(t, err)
	assert.Nil(t, decoded)
	assert.Contains(t, err.Error(), "invalid block type")
}

// TestDecodeRelayTag_TooShort tests decoding truncated block.
func TestDecodeRelayTag_TooShort(t *testing.T) {
	block := &SSU2Block{
		Type: BlockTypeRelayTag,
		Data: make([]byte, 5), // Too short
	}

	decoded, err := DecodeRelayTag(block)
	assert.Error(t, err)
	assert.Nil(t, decoded)
	assert.Contains(t, err.Error(), "too short")
}

// TestRelayBlocks_RoundTrip tests complete encode/decode cycle for all relay blocks.
func TestRelayBlocks_RoundTrip(t *testing.T) {
	// Test RelayRequest
	t.Run("RelayRequest", func(t *testing.T) {
		req := &RelayRequestBlock{
			Flag:      0x00,
			Nonce:     99999,
			RelayTag:  55555,
			Timestamp: 1700000000,
			Version:   2,
			AlicePort: 9000,
			AliceIP:   net.IPv4(10, 0, 0, 1).To4(),
			Signature: makeTestSignature(),
		}

		block, err := EncodeRelayRequest(req)
		require.NoError(t, err)

		decoded, err := DecodeRelayRequest(block)
		require.NoError(t, err)

		assert.Equal(t, req.Nonce, decoded.Nonce)
		assert.Equal(t, req.RelayTag, decoded.RelayTag)
		assert.Equal(t, req.Timestamp, decoded.Timestamp)
		assert.Equal(t, req.Version, decoded.Version)
		assert.Equal(t, req.AlicePort, decoded.AlicePort)
		assert.True(t, req.AliceIP.Equal(decoded.AliceIP))
		assert.Equal(t, req.Signature, decoded.Signature)
	})

	// Test RelayResponse
	t.Run("RelayResponse", func(t *testing.T) {
		resp := &RelayResponseBlock{
			Flag:        0,
			Code:        0,
			Nonce:       11111,
			Timestamp:   1700000000,
			Version:     2,
			CharliePort: 9000,
			CharlieIP:   net.IPv4(10, 0, 0, 1).To4(),
			Signature:   makeTestSignature(),
			Token:       make([]byte, 8),
		}

		block, err := EncodeRelayResponse(resp)
		require.NoError(t, err)

		decoded, err := DecodeRelayResponse(block)
		require.NoError(t, err)

		assert.Equal(t, resp.Nonce, decoded.Nonce)
		assert.Equal(t, resp.Code, decoded.Code)
		assert.Equal(t, resp.Token, decoded.Token)
	})

	// Test RelayIntro
	t.Run("RelayIntro", func(t *testing.T) {
		routerHash := make([]byte, 32)
		sig := make([]byte, 64)
		intro := &RelayIntroBlock{
			AliceRouterHash: routerHash,
			AliceRelayTag:   55555,
			AlicePort:       54321,
			AliceIP:         net.ParseIP("192.168.100.50"),
			Timestamp:       1700000000,
			Version:         2,
			Signature:       sig,
		}

		block, err := EncodeRelayIntro(intro)
		require.NoError(t, err)

		decoded, err := DecodeRelayIntro(block)
		require.NoError(t, err)

		assert.Equal(t, intro.AliceRouterHash, decoded.AliceRouterHash)
		assert.Equal(t, intro.AliceRelayTag, decoded.AliceRelayTag)
		assert.Equal(t, intro.Timestamp, decoded.Timestamp)
		assert.True(t, intro.AliceIP.Equal(decoded.AliceIP))
		assert.Equal(t, intro.AlicePort, decoded.AlicePort)
	})

	// Test RelayTagRequest
	t.Run("RelayTagRequest", func(t *testing.T) {
		req := &RelayTagRequestBlock{
			Nonce: 77777,
		}

		block, err := EncodeRelayTagRequest(req)
		require.NoError(t, err)

		decoded, err := DecodeRelayTagRequest(block)
		require.NoError(t, err)

		assert.Equal(t, req.Nonce, decoded.Nonce)
	})

	// Test RelayTag
	t.Run("RelayTag", func(t *testing.T) {
		tag := &RelayTagBlock{
			RelayTag:   44444,
			Expiration: 7200,
		}

		block, err := EncodeRelayTag(tag)
		require.NoError(t, err)

		decoded, err := DecodeRelayTag(block)
		require.NoError(t, err)

		assert.Equal(t, tag.RelayTag, decoded.RelayTag)
		assert.Equal(t, tag.Expiration, decoded.Expiration)
	})
}
