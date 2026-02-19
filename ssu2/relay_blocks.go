package ssu2

import (
	"encoding/binary"
	"net"

	"github.com/samber/oops"
)

// Relay block-related structures and encoding/decoding functions for SSU2 protocol.
//
// SSU2 relay mechanism uses five block types:
// - Type 7: RelayRequest - Request relay service from introducer
// - Type 8: RelayResponse - Response to relay request
// - Type 9: RelayIntro - Introduction from Bob to Charlie
// - Type 15: RelayTagRequest - Request allocation of relay tag
// - Type 16: RelayTag - Relay tag assignment
//
// Design rationale:
// - Uses standard library encoding for wire format compatibility
// - Validates all field sizes per SSU2 specification
// - Defensive copies prevent mutation of shared data
// - Error handling provides context for debugging

// RelayRequestBlock represents a relay request (Type 7).
// Alice sends this to Bob to request relay through to Charlie.
type RelayRequestBlock struct {
	// Nonce uniquely identifies this relay request (4 bytes)
	Nonce uint32

	// RelayTag is the tag assigned by the introducer (4 bytes)
	RelayTag uint32

	// CharlieRouterHash is Charlie's 32-byte router identity hash
	CharlieRouterHash []byte

	// Token is an optional verification token (variable length)
	Token []byte
}

// RelayResponseBlock represents a relay response (Type 8).
// Bob sends this to Alice after processing relay request.
type RelayResponseBlock struct {
	// Nonce matches the nonce from RelayRequest (4 bytes)
	Nonce uint32

	// StatusCode indicates success or failure reason (1 byte)
	// 0 = success, non-zero = various error codes
	StatusCode uint8

	// CharlieAddress is Charlie's UDP address (optional)
	// Present when StatusCode is 0 (success)
	CharlieAddress *net.UDPAddr
}

// RelayIntroBlock represents a relay introduction (Type 9).
// Bob sends this to Charlie to introduce Alice.
type RelayIntroBlock struct {
	// AliceRouterHash is Alice's 32-byte router identity hash
	AliceRouterHash []byte

	// AliceRelayTag is the tag Alice will use (4 bytes)
	AliceRelayTag uint32

	// AliceAddress is Alice's UDP address as seen by Bob
	AliceAddress *net.UDPAddr

	// Timestamp is when the intro was created (4 bytes, seconds since epoch)
	Timestamp uint32
}

// RelayTagRequestBlock represents a relay tag request (Type 15).
// Request allocation of a relay tag from an introducer.
type RelayTagRequestBlock struct {
	// Nonce uniquely identifies this request (4 bytes)
	// Minimum 3 bytes per SSU2.md, we use 4 for alignment
	Nonce uint32
}

// RelayTagBlock represents a relay tag assignment (Type 16).
// Introducer assigns a relay tag to the requester.
type RelayTagBlock struct {
	// RelayTag is the assigned tag value (4 bytes)
	RelayTag uint32

	// Expiration is seconds until expiration (3 bytes)
	// Stored as uint32, but only 3 bytes encoded on wire
	Expiration uint32
}

// EncodeRelayRequest encodes a RelayRequest block to wire format.
//
// Wire format:
//
//	[Nonce:4][RelayTag:4][CharlieRouterHash:32][TokenLength:2][Token:variable]
//
// Parameters:
//   - req: RelayRequest data to encode
//
// Returns:
//   - *SSU2Block: Encoded block ready for transmission
//   - error: If validation fails
func EncodeRelayRequest(req *RelayRequestBlock) (*SSU2Block, error) {
	if req == nil {
		return nil, oops.Errorf("RelayRequestBlock is nil")
	}

	// Validate router hash
	if len(req.CharlieRouterHash) != 32 {
		return nil, oops.Errorf("CharlieRouterHash must be 32 bytes, got %d", len(req.CharlieRouterHash))
	}

	// Calculate size: nonce(4) + relayTag(4) + hash(32) + tokenLen(2) + token
	tokenLen := len(req.Token)
	dataSize := 4 + 4 + 32 + 2 + tokenLen
	data := make([]byte, dataSize)

	// Encode fields
	binary.BigEndian.PutUint32(data[0:4], req.Nonce)
	binary.BigEndian.PutUint32(data[4:8], req.RelayTag)
	copy(data[8:40], req.CharlieRouterHash)
	binary.BigEndian.PutUint16(data[40:42], uint16(tokenLen))
	if tokenLen > 0 {
		copy(data[42:], req.Token)
	}

	return NewSSU2Block(BlockTypeRelayRequest, data), nil
}

// DecodeRelayRequest decodes a RelayRequest block from wire format.
//
// Parameters:
//   - block: SSU2Block with Type 7
//
// Returns:
//   - *RelayRequestBlock: Decoded relay request
//   - error: If decoding fails or validation fails
func DecodeRelayRequest(block *SSU2Block) (*RelayRequestBlock, error) {
	if block == nil {
		return nil, oops.Errorf("block is nil")
	}

	if block.Type != BlockTypeRelayRequest {
		return nil, oops.Errorf("invalid block type: expected %d, got %d", BlockTypeRelayRequest, block.Type)
	}

	data := block.Data
	if len(data) < 42 {
		return nil, oops.Errorf("RelayRequest block too short: %d bytes (minimum 42)", len(data))
	}

	// Decode fixed fields
	nonce := binary.BigEndian.Uint32(data[0:4])
	relayTag := binary.BigEndian.Uint32(data[4:8])
	routerHash := make([]byte, 32)
	copy(routerHash, data[8:40])
	tokenLen := binary.BigEndian.Uint16(data[40:42])

	// Validate total length
	expectedLen := 42 + int(tokenLen)
	if len(data) < expectedLen {
		return nil, oops.Errorf("RelayRequest block truncated: %d bytes (expected %d)", len(data), expectedLen)
	}

	// Decode token if present
	var token []byte
	if tokenLen > 0 {
		token = make([]byte, tokenLen)
		copy(token, data[42:42+tokenLen])
	}

	return &RelayRequestBlock{
		Nonce:             nonce,
		RelayTag:          relayTag,
		CharlieRouterHash: routerHash,
		Token:             token,
	}, nil
}

// EncodeRelayResponse encodes a RelayResponse block to wire format.
//
// Wire format:
//
//	[Nonce:4][StatusCode:1][AddressPresent:1][Address:variable]
//
// Address encoding (if present):
//
//	IPv4: [IP:4][Port:2]
//	IPv6: [IP:16][Port:2]
//
// Parameters:
//   - resp: RelayResponse data to encode
//
// Returns:
//   - *SSU2Block: Encoded block ready for transmission
//   - error: If validation fails
func EncodeRelayResponse(resp *RelayResponseBlock) (*SSU2Block, error) {
	if resp == nil {
		return nil, oops.Errorf("RelayResponseBlock is nil")
	}

	// Calculate size
	dataSize := 6 // nonce(4) + statusCode(1) + addressPresent(1)
	hasAddress := resp.CharlieAddress != nil && resp.StatusCode == 0
	if hasAddress {
		if resp.CharlieAddress.IP.To4() != nil {
			dataSize += 6 // IPv4(4) + port(2)
		} else {
			dataSize += 18 // IPv6(16) + port(2)
		}
	}

	data := make([]byte, dataSize)

	// Encode fixed fields
	binary.BigEndian.PutUint32(data[0:4], resp.Nonce)
	data[4] = resp.StatusCode

	// Encode address flag and data
	if hasAddress {
		data[5] = 1 // Address present
		if ip4 := resp.CharlieAddress.IP.To4(); ip4 != nil {
			copy(data[6:10], ip4)
			binary.BigEndian.PutUint16(data[10:12], uint16(resp.CharlieAddress.Port))
		} else {
			copy(data[6:22], resp.CharlieAddress.IP.To16())
			binary.BigEndian.PutUint16(data[22:24], uint16(resp.CharlieAddress.Port))
		}
	} else {
		data[5] = 0 // No address
	}

	return NewSSU2Block(BlockTypeRelayResponse, data), nil
}

// DecodeRelayResponse decodes a RelayResponse block from wire format.
//
// Parameters:
//   - block: SSU2Block with Type 8
//
// Returns:
//   - *RelayResponseBlock: Decoded relay response
//   - error: If decoding fails or validation fails
func DecodeRelayResponse(block *SSU2Block) (*RelayResponseBlock, error) {
	if block == nil {
		return nil, oops.Errorf("block is nil")
	}

	if block.Type != BlockTypeRelayResponse {
		return nil, oops.Errorf("invalid block type: expected %d, got %d", BlockTypeRelayResponse, block.Type)
	}

	data := block.Data
	if len(data) < 6 {
		return nil, oops.Errorf("RelayResponse block too short: %d bytes (minimum 6)", len(data))
	}

	// Decode fixed fields
	nonce := binary.BigEndian.Uint32(data[0:4])
	statusCode := data[4]
	addressPresent := data[5]

	resp := &RelayResponseBlock{
		Nonce:      nonce,
		StatusCode: statusCode,
	}

	// Decode address if present
	if addressPresent == 1 {
		if len(data) >= 12 {
			// Could be IPv4 or IPv6
			if len(data) == 12 {
				// IPv4: 6 header + 4 IP + 2 port
				ip := net.IP(make([]byte, 4))
				copy(ip, data[6:10])
				port := binary.BigEndian.Uint16(data[10:12])
				resp.CharlieAddress = &net.UDPAddr{IP: ip, Port: int(port)}
			} else if len(data) == 24 {
				// IPv6: 6 header + 16 IP + 2 port
				ip := net.IP(make([]byte, 16))
				copy(ip, data[6:22])
				port := binary.BigEndian.Uint16(data[22:24])
				resp.CharlieAddress = &net.UDPAddr{IP: ip, Port: int(port)}
			} else {
				return nil, oops.Errorf("invalid RelayResponse address length: %d", len(data))
			}
		} else {
			return nil, oops.Errorf("RelayResponse claims address but data too short: %d bytes", len(data))
		}
	}

	return resp, nil
}

// EncodeRelayIntro encodes a RelayIntro block to wire format.
//
// Wire format:
//
//	[AliceRouterHash:32][AliceRelayTag:4][Timestamp:4][AddressType:1][Address:variable]
//
// Address encoding:
//
//	IPv4: [IP:4][Port:2]
//	IPv6: [IP:16][Port:2]
//
// Parameters:
//   - intro: RelayIntro data to encode
//
// Returns:
//   - *SSU2Block: Encoded block ready for transmission
//   - error: If validation fails
func EncodeRelayIntro(intro *RelayIntroBlock) (*SSU2Block, error) {
	if intro == nil {
		return nil, oops.Errorf("RelayIntroBlock is nil")
	}

	// Validate router hash
	if len(intro.AliceRouterHash) != 32 {
		return nil, oops.Errorf("AliceRouterHash must be 32 bytes, got %d", len(intro.AliceRouterHash))
	}

	// Validate address
	if intro.AliceAddress == nil {
		return nil, oops.Errorf("AliceAddress is nil")
	}

	// Calculate size
	dataSize := 32 + 4 + 4 + 1 // hash + tag + timestamp + addrType
	isIPv4 := intro.AliceAddress.IP.To4() != nil
	if isIPv4 {
		dataSize += 6 // IPv4(4) + port(2)
	} else {
		dataSize += 18 // IPv6(16) + port(2)
	}

	data := make([]byte, dataSize)

	// Encode fixed fields
	copy(data[0:32], intro.AliceRouterHash)
	binary.BigEndian.PutUint32(data[32:36], intro.AliceRelayTag)
	binary.BigEndian.PutUint32(data[36:40], intro.Timestamp)

	// Encode address
	if isIPv4 {
		data[40] = 4 // IPv4
		ip4 := intro.AliceAddress.IP.To4()
		copy(data[41:45], ip4)
		binary.BigEndian.PutUint16(data[45:47], uint16(intro.AliceAddress.Port))
	} else {
		data[40] = 6 // IPv6
		copy(data[41:57], intro.AliceAddress.IP.To16())
		binary.BigEndian.PutUint16(data[57:59], uint16(intro.AliceAddress.Port))
	}

	return NewSSU2Block(BlockTypeRelayIntro, data), nil
}

// DecodeRelayIntro decodes a RelayIntro block from wire format.
//
// Parameters:
//   - block: SSU2Block with Type 9
//
// Returns:
//   - *RelayIntroBlock: Decoded relay intro
//   - error: If decoding fails or validation fails
func DecodeRelayIntro(block *SSU2Block) (*RelayIntroBlock, error) {
	if block == nil {
		return nil, oops.Errorf("block is nil")
	}

	if block.Type != BlockTypeRelayIntro {
		return nil, oops.Errorf("invalid block type: expected %d, got %d", BlockTypeRelayIntro, block.Type)
	}

	data := block.Data
	if len(data) < 47 {
		return nil, oops.Errorf("RelayIntro block too short: %d bytes (minimum 47)", len(data))
	}

	// Decode fixed fields
	routerHash := make([]byte, 32)
	copy(routerHash, data[0:32])
	relayTag := binary.BigEndian.Uint32(data[32:36])
	timestamp := binary.BigEndian.Uint32(data[36:40])
	addrType := data[40]

	// Decode address based on type
	var addr *net.UDPAddr
	if addrType == 4 {
		// IPv4
		if len(data) < 47 {
			return nil, oops.Errorf("RelayIntro IPv4 block too short: %d bytes (expected 47)", len(data))
		}
		ip := net.IP(make([]byte, 4))
		copy(ip, data[41:45])
		port := binary.BigEndian.Uint16(data[45:47])
		addr = &net.UDPAddr{IP: ip, Port: int(port)}
	} else if addrType == 6 {
		// IPv6
		if len(data) < 59 {
			return nil, oops.Errorf("RelayIntro IPv6 block too short: %d bytes (expected 59)", len(data))
		}
		ip := net.IP(make([]byte, 16))
		copy(ip, data[41:57])
		port := binary.BigEndian.Uint16(data[57:59])
		addr = &net.UDPAddr{IP: ip, Port: int(port)}
	} else {
		return nil, oops.Errorf("invalid address type: %d (expected 4 or 6)", addrType)
	}

	return &RelayIntroBlock{
		AliceRouterHash: routerHash,
		AliceRelayTag:   relayTag,
		AliceAddress:    addr,
		Timestamp:       timestamp,
	}, nil
}

// EncodeRelayTagRequest encodes a RelayTagRequest block to wire format.
//
// Wire format: [Nonce:4]
//
// Parameters:
//   - req: RelayTagRequest data to encode
//
// Returns:
//   - *SSU2Block: Encoded block ready for transmission
//   - error: If validation fails
func EncodeRelayTagRequest(req *RelayTagRequestBlock) (*SSU2Block, error) {
	if req == nil {
		return nil, oops.Errorf("RelayTagRequestBlock is nil")
	}

	data := make([]byte, 4)
	binary.BigEndian.PutUint32(data[0:4], req.Nonce)

	return NewSSU2Block(BlockTypeRelayTagRequest, data), nil
}

// DecodeRelayTagRequest decodes a RelayTagRequest block from wire format.
//
// Parameters:
//   - block: SSU2Block with Type 15
//
// Returns:
//   - *RelayTagRequestBlock: Decoded relay tag request
//   - error: If decoding fails or validation fails
func DecodeRelayTagRequest(block *SSU2Block) (*RelayTagRequestBlock, error) {
	if block == nil {
		return nil, oops.Errorf("block is nil")
	}

	if block.Type != BlockTypeRelayTagRequest {
		return nil, oops.Errorf("invalid block type: expected %d, got %d", BlockTypeRelayTagRequest, block.Type)
	}

	data := block.Data
	if len(data) < 3 {
		return nil, oops.Errorf("RelayTagRequest block too short: %d bytes (minimum 3)", len(data))
	}

	// Support both 3-byte and 4-byte nonces
	var nonce uint32
	if len(data) >= 4 {
		nonce = binary.BigEndian.Uint32(data[0:4])
	} else {
		// 3-byte nonce: pad with zero byte
		nonce = uint32(data[0])<<16 | uint32(data[1])<<8 | uint32(data[2])
	}

	return &RelayTagRequestBlock{
		Nonce: nonce,
	}, nil
}

// EncodeRelayTag encodes a RelayTag block to wire format.
//
// Wire format: [RelayTag:4][Expiration:3]
//
// Parameters:
//   - tag: RelayTag data to encode
//
// Returns:
//   - *SSU2Block: Encoded block ready for transmission
//   - error: If validation fails
func EncodeRelayTag(tag *RelayTagBlock) (*SSU2Block, error) {
	if tag == nil {
		return nil, oops.Errorf("RelayTagBlock is nil")
	}

	// Validate expiration fits in 3 bytes (max ~194 days)
	if tag.Expiration > 0xFFFFFF {
		return nil, oops.Errorf("expiration too large: %d (maximum 16777215)", tag.Expiration)
	}

	data := make([]byte, 7)
	binary.BigEndian.PutUint32(data[0:4], tag.RelayTag)

	// Encode 3-byte expiration
	data[4] = byte(tag.Expiration >> 16)
	data[5] = byte(tag.Expiration >> 8)
	data[6] = byte(tag.Expiration)

	return NewSSU2Block(BlockTypeRelayTag, data), nil
}

// DecodeRelayTag decodes a RelayTag block from wire format.
//
// Parameters:
//   - block: SSU2Block with Type 16
//
// Returns:
//   - *RelayTagBlock: Decoded relay tag
//   - error: If decoding fails or validation fails
func DecodeRelayTag(block *SSU2Block) (*RelayTagBlock, error) {
	if block == nil {
		return nil, oops.Errorf("block is nil")
	}

	if block.Type != BlockTypeRelayTag {
		return nil, oops.Errorf("invalid block type: expected %d, got %d", BlockTypeRelayTag, block.Type)
	}

	data := block.Data
	if len(data) < 7 {
		return nil, oops.Errorf("RelayTag block too short: %d bytes (minimum 7)", len(data))
	}

	relayTag := binary.BigEndian.Uint32(data[0:4])

	// Decode 3-byte expiration
	expiration := uint32(data[4])<<16 | uint32(data[5])<<8 | uint32(data[6])

	return &RelayTagBlock{
		RelayTag:   relayTag,
		Expiration: expiration,
	}, nil
}
