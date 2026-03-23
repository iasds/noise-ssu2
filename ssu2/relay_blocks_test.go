package ssu2

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// makeSignedData returns a deterministic 32-byte signed relay data blob for tests.
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
		Nonce:              12345,
		SignedData:         makeSignedData(),
		Flag:               0x01,
		RouterInfoFragment: []byte{0xAA, 0xBB, 0xCC},
	}

	block, err := EncodeRelayRequest(req)
	require.NoError(t, err)
	assert.NotNil(t, block)
	assert.Equal(t, BlockTypeRelayRequest, block.Type)
	assert.Equal(t, 40, len(block.Data)) // 4+32+1+3
}

// TestEncodeRelayRequest_NoFragment tests encoding relay request without RI fragment.
func TestEncodeRelayRequest_NoFragment(t *testing.T) {
	req := &RelayRequestBlock{
		Nonce:      12345,
		SignedData: makeSignedData(),
		Flag:       0x00,
	}

	block, err := EncodeRelayRequest(req)
	require.NoError(t, err)
	assert.Equal(t, 37, len(block.Data)) // 4+32+1
}

// TestEncodeRelayRequest_NilBlock tests encoding nil request.
func TestEncodeRelayRequest_NilBlock(t *testing.T) {
	block, err := EncodeRelayRequest(nil)
	assert.Error(t, err)
	assert.Nil(t, block)
	assert.Contains(t, err.Error(), "nil")
}

// TestEncodeRelayRequest_InvalidSignedData tests invalid signed data size.
func TestEncodeRelayRequest_InvalidSignedData(t *testing.T) {
	req := &RelayRequestBlock{
		Nonce:      12345,
		SignedData: []byte{1, 2, 3}, // Wrong size
	}

	block, err := EncodeRelayRequest(req)
	assert.Error(t, err)
	assert.Nil(t, block)
	assert.Contains(t, err.Error(), "32 bytes")
}

// TestDecodeRelayRequest_Valid tests decoding a valid relay request.
func TestDecodeRelayRequest_Valid(t *testing.T) {
	original := &RelayRequestBlock{
		Nonce:              12345,
		SignedData:         makeSignedData(),
		Flag:               0x01,
		RouterInfoFragment: []byte{0xAA, 0xBB, 0xCC},
	}

	block, err := EncodeRelayRequest(original)
	require.NoError(t, err)

	decoded, err := DecodeRelayRequest(block)
	require.NoError(t, err)
	assert.Equal(t, original.Nonce, decoded.Nonce)
	assert.Equal(t, original.SignedData, decoded.SignedData)
	assert.Equal(t, original.Flag, decoded.Flag)
	assert.Equal(t, original.RouterInfoFragment, decoded.RouterInfoFragment)
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
		Data: make([]byte, 20), // Too short
	}

	decoded, err := DecodeRelayRequest(block)
	assert.Error(t, err)
	assert.Nil(t, decoded)
	assert.Contains(t, err.Error(), "too short")
}

// TestEncodeRelayResponse_Success tests encoding successful relay response.
func TestEncodeRelayResponse_Success(t *testing.T) {
	resp := &RelayResponseBlock{
		Nonce:      12345,
		StatusCode: 0,
		SignedData: []byte("charlie-signed-data-placeholder!"), // 32 bytes
	}

	block, err := EncodeRelayResponse(resp)
	require.NoError(t, err)
	assert.NotNil(t, block)
	assert.Equal(t, BlockTypeRelayResponse, block.Type)
	assert.Equal(t, 37, len(block.Data)) // 4+1+32
}

// TestEncodeRelayResponse_SuccessLargeSignedData tests encoding relay response with larger signed data.
func TestEncodeRelayResponse_SuccessLargeSignedData(t *testing.T) {
	signedData := make([]byte, 64)
	for i := range signedData {
		signedData[i] = byte(i)
	}

	resp := &RelayResponseBlock{
		Nonce:      12345,
		StatusCode: 0,
		SignedData: signedData,
	}

	block, err := EncodeRelayResponse(resp)
	require.NoError(t, err)
	assert.Equal(t, 69, len(block.Data)) // 4+1+64
}

// TestEncodeRelayResponse_Failure tests encoding failed relay response.
func TestEncodeRelayResponse_Failure(t *testing.T) {
	resp := &RelayResponseBlock{
		Nonce:      12345,
		StatusCode: 1, // Error
	}

	block, err := EncodeRelayResponse(resp)
	require.NoError(t, err)
	assert.Equal(t, 5, len(block.Data)) // 4+1 (no signed data)
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
		Nonce:      12345,
		StatusCode: 0,
		SignedData: []byte("charlie-signed-data-placeholder!"),
	}

	block, err := EncodeRelayResponse(original)
	require.NoError(t, err)

	decoded, err := DecodeRelayResponse(block)
	require.NoError(t, err)
	assert.Equal(t, original.Nonce, decoded.Nonce)
	assert.Equal(t, original.StatusCode, decoded.StatusCode)
	assert.Equal(t, original.SignedData, decoded.SignedData)
}

// TestDecodeRelayResponse_Failure tests decoding failed relay response.
func TestDecodeRelayResponse_Failure(t *testing.T) {
	original := &RelayResponseBlock{
		Nonce:      12345,
		StatusCode: 1,
	}

	block, err := EncodeRelayResponse(original)
	require.NoError(t, err)

	decoded, err := DecodeRelayResponse(block)
	require.NoError(t, err)
	assert.Equal(t, original.Nonce, decoded.Nonce)
	assert.Equal(t, original.StatusCode, decoded.StatusCode)
	assert.Nil(t, decoded.SignedData)
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
		Data: make([]byte, 3), // Too short
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

	intro := &RelayIntroBlock{
		AliceRouterHash: routerHash,
		AliceRelayTag:   12345,
		AliceAddress: &net.UDPAddr{
			IP:   net.ParseIP("10.0.0.1"),
			Port: 9000,
		},
		Timestamp: 1234567890,
	}

	block, err := EncodeRelayIntro(intro)
	require.NoError(t, err)
	assert.NotNil(t, block)
	assert.Equal(t, BlockTypeRelayIntro, block.Type)
	assert.Equal(t, 47, len(block.Data)) // 32+4+4+1+4+2
}

// TestEncodeRelayIntro_IPv6 tests encoding relay intro with IPv6.
func TestEncodeRelayIntro_IPv6(t *testing.T) {
	routerHash := make([]byte, 32)
	intro := &RelayIntroBlock{
		AliceRouterHash: routerHash,
		AliceRelayTag:   12345,
		AliceAddress: &net.UDPAddr{
			IP:   net.ParseIP("2001:db8::1"),
			Port: 9000,
		},
		Timestamp: 1234567890,
	}

	block, err := EncodeRelayIntro(intro)
	require.NoError(t, err)
	assert.Equal(t, 59, len(block.Data)) // 32+4+4+1+16+2
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
		AliceAddress: &net.UDPAddr{
			IP:   net.ParseIP("10.0.0.1"),
			Port: 9000,
		},
		Timestamp: 1234567890,
	}

	block, err := EncodeRelayIntro(intro)
	assert.Error(t, err)
	assert.Nil(t, block)
	assert.Contains(t, err.Error(), "32 bytes")
}

// TestEncodeRelayIntro_NilAddress tests encoding with nil address.
func TestEncodeRelayIntro_NilAddress(t *testing.T) {
	routerHash := make([]byte, 32)
	intro := &RelayIntroBlock{
		AliceRouterHash: routerHash,
		AliceRelayTag:   12345,
		AliceAddress:    nil, // Invalid
		Timestamp:       1234567890,
	}

	block, err := EncodeRelayIntro(intro)
	assert.Error(t, err)
	assert.Nil(t, block)
	assert.Contains(t, err.Error(), "nil")
}

// TestDecodeRelayIntro_IPv4 tests decoding relay intro with IPv4.
func TestDecodeRelayIntro_IPv4(t *testing.T) {
	routerHash := make([]byte, 32)
	for i := range routerHash {
		routerHash[i] = byte(i)
	}

	original := &RelayIntroBlock{
		AliceRouterHash: routerHash,
		AliceRelayTag:   12345,
		AliceAddress: &net.UDPAddr{
			IP:   net.ParseIP("10.0.0.1"),
			Port: 9000,
		},
		Timestamp: 1234567890,
	}

	block, err := EncodeRelayIntro(original)
	require.NoError(t, err)

	decoded, err := DecodeRelayIntro(block)
	require.NoError(t, err)
	assert.Equal(t, original.AliceRouterHash, decoded.AliceRouterHash)
	assert.Equal(t, original.AliceRelayTag, decoded.AliceRelayTag)
	assert.Equal(t, original.Timestamp, decoded.Timestamp)
	assert.NotNil(t, decoded.AliceAddress)
	assert.True(t, original.AliceAddress.IP.Equal(decoded.AliceAddress.IP))
	assert.Equal(t, original.AliceAddress.Port, decoded.AliceAddress.Port)
}

// TestDecodeRelayIntro_IPv6 tests decoding relay intro with IPv6.
func TestDecodeRelayIntro_IPv6(t *testing.T) {
	routerHash := make([]byte, 32)
	original := &RelayIntroBlock{
		AliceRouterHash: routerHash,
		AliceRelayTag:   12345,
		AliceAddress: &net.UDPAddr{
			IP:   net.ParseIP("2001:db8::1"),
			Port: 9000,
		},
		Timestamp: 1234567890,
	}

	block, err := EncodeRelayIntro(original)
	require.NoError(t, err)

	decoded, err := DecodeRelayIntro(block)
	require.NoError(t, err)
	assert.True(t, original.AliceAddress.IP.Equal(decoded.AliceAddress.IP))
	assert.Equal(t, original.AliceAddress.Port, decoded.AliceAddress.Port)
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
		Data: make([]byte, 50),
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

// TestDecodeRelayIntro_InvalidAddressType tests invalid address type.
func TestDecodeRelayIntro_InvalidAddressType(t *testing.T) {
	data := make([]byte, 47)
	data[40] = 99 // Invalid address type

	block := &SSU2Block{
		Type: BlockTypeRelayIntro,
		Data: data,
	}

	decoded, err := DecodeRelayIntro(block)
	assert.Error(t, err)
	assert.Nil(t, decoded)
	assert.Contains(t, err.Error(), "invalid address type")
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
			Nonce:              99999,
			SignedData:         makeSignedData(),
			Flag:               0x02,
			RouterInfoFragment: []byte{1, 2, 3, 4, 5},
		}

		block, err := EncodeRelayRequest(req)
		require.NoError(t, err)

		decoded, err := DecodeRelayRequest(block)
		require.NoError(t, err)

		assert.Equal(t, req.Nonce, decoded.Nonce)
		assert.Equal(t, req.SignedData, decoded.SignedData)
		assert.Equal(t, req.Flag, decoded.Flag)
		assert.Equal(t, req.RouterInfoFragment, decoded.RouterInfoFragment)
	})

	// Test RelayResponse
	t.Run("RelayResponse", func(t *testing.T) {
		resp := &RelayResponseBlock{
			Nonce:      11111,
			StatusCode: 0,
			SignedData: []byte("charlie-signed-data-placeholder!"),
		}

		block, err := EncodeRelayResponse(resp)
		require.NoError(t, err)

		decoded, err := DecodeRelayResponse(block)
		require.NoError(t, err)

		assert.Equal(t, resp.Nonce, decoded.Nonce)
		assert.Equal(t, resp.StatusCode, decoded.StatusCode)
		assert.Equal(t, resp.SignedData, decoded.SignedData)
	})

	// Test RelayIntro
	t.Run("RelayIntro", func(t *testing.T) {
		routerHash := make([]byte, 32)
		intro := &RelayIntroBlock{
			AliceRouterHash: routerHash,
			AliceRelayTag:   55555,
			AliceAddress: &net.UDPAddr{
				IP:   net.ParseIP("192.168.100.50"),
				Port: 54321,
			},
			Timestamp: 1700000000,
		}

		block, err := EncodeRelayIntro(intro)
		require.NoError(t, err)

		decoded, err := DecodeRelayIntro(block)
		require.NoError(t, err)

		assert.Equal(t, intro.AliceRouterHash, decoded.AliceRouterHash)
		assert.Equal(t, intro.AliceRelayTag, decoded.AliceRelayTag)
		assert.Equal(t, intro.Timestamp, decoded.Timestamp)
		assert.True(t, intro.AliceAddress.IP.Equal(decoded.AliceAddress.IP))
		assert.Equal(t, intro.AliceAddress.Port, decoded.AliceAddress.Port)
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
