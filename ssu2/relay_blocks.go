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
//
// Wire format per SSU2 spec:
//
//	[Flag:1][Nonce:4][RelayTag:4][Timestamp:4][Ver:1][Asz:1][AlicePort:2][AliceIP:asz-2][Signature:varies]
type RelayRequestBlock struct {
	// Flag is a 1-byte flag field (unused, set to 0)
	Flag uint8

	// Nonce uniquely identifies this relay request (4 bytes)
	Nonce uint32

	// RelayTag is the itag from Charlie's RI (4 bytes)
	RelayTag uint32

	// Timestamp is Unix timestamp in seconds (4 bytes)
	Timestamp uint32

	// Version is the SSU version for the introduction (1=SSU1, 2=SSU2)
	Version uint8

	// AlicePort is Alice's port number (2 bytes, big endian)
	AlicePort uint16

	// AliceIP is Alice's IP address (4 bytes IPv4 or 16 bytes IPv6)
	AliceIP net.IP

	// Signature is the variable-length signature (64 bytes for Ed25519)
	Signature []byte
}

// RelayResponseBlock represents a relay response (Type 8).
// Bob sends this to Alice after processing relay request.
//
// Wire format per SSU2 spec:
//
//	[Nonce:4][StatusCode:1][SignedData:variable]
type RelayResponseBlock struct {
	// Nonce matches the nonce from RelayRequest (4 bytes)
	Nonce uint32

	// StatusCode indicates success or failure reason (1 byte)
	// 0 = success, non-zero = various error codes
	StatusCode uint8

	// SignedData is Charlie's signed response data (variable length).
	// Present when StatusCode is 0 (success); contains Charlie's address
	// and signature.
	SignedData []byte
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
	// Minimum 3 bytes per ssu2.rst, we use 4 for alignment
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
// Wire format per SSU2 spec:
//
//	[Flag:1][Nonce:4][RelayTag:4][Timestamp:4][Ver:1][Asz:1][AlicePort:2][AliceIP:asz-2][Signature:varies]
func EncodeRelayRequest(req *RelayRequestBlock) (*SSU2Block, error) {
	if req == nil {
		return nil, oops.Errorf("RelayRequestBlock is nil")
	}

	ip4 := req.AliceIP.To4()
	var ipBytes []byte
	var asz uint8
	if ip4 != nil {
		ipBytes = ip4
		asz = 6 // port(2) + IPv4(4)
	} else {
		ip6 := req.AliceIP.To16()
		if ip6 == nil {
			return nil, oops.Errorf("invalid AliceIP")
		}
		ipBytes = ip6
		asz = 18 // port(2) + IPv6(16)
	}

	// flag(1) + nonce(4) + relay_tag(4) + timestamp(4) + ver(1) + asz(1) + port(2) + ip + signature
	dataSize := 1 + 4 + 4 + 4 + 1 + 1 + 2 + len(ipBytes) + len(req.Signature)
	data := make([]byte, dataSize)

	data[0] = req.Flag
	binary.BigEndian.PutUint32(data[1:5], req.Nonce)
	binary.BigEndian.PutUint32(data[5:9], req.RelayTag)
	binary.BigEndian.PutUint32(data[9:13], req.Timestamp)
	data[13] = req.Version
	data[14] = asz
	binary.BigEndian.PutUint16(data[15:17], req.AlicePort)
	copy(data[17:17+len(ipBytes)], ipBytes)
	copy(data[17+len(ipBytes):], req.Signature)

	return NewSSU2Block(BlockTypeRelayRequest, data), nil
}

// DecodeRelayRequest decodes a RelayRequest block from wire format.
//
// Wire format: [Flag:1][Nonce:4][RelayTag:4][Timestamp:4][Ver:1][Asz:1][AlicePort:2][AliceIP:asz-2][Signature:varies]
func DecodeRelayRequest(block *SSU2Block) (*RelayRequestBlock, error) {
	if block == nil {
		return nil, oops.Errorf("block is nil")
	}

	if block.Type != BlockTypeRelayRequest {
		return nil, oops.Errorf("invalid block type: expected %d, got %d", BlockTypeRelayRequest, block.Type)
	}

	data := block.Data
	// Minimum: flag(1)+nonce(4)+relay_tag(4)+timestamp(4)+ver(1)+asz(1)+port(2)+ip(4) = 21
	if len(data) < 21 {
		return nil, oops.Errorf("RelayRequest block too short: %d bytes (minimum 21)", len(data))
	}

	flag := data[0]
	nonce := binary.BigEndian.Uint32(data[1:5])
	relayTag := binary.BigEndian.Uint32(data[5:9])
	timestamp := binary.BigEndian.Uint32(data[9:13])
	ver := data[13]
	asz := data[14]
	port := binary.BigEndian.Uint16(data[15:17])

	if asz != 6 && asz != 18 {
		return nil, oops.Errorf("invalid asz: %d (expected 6 or 18)", asz)
	}

	ipLen := int(asz) - 2
	if len(data) < 17+ipLen {
		return nil, oops.Errorf("RelayRequest block too short for IP: need %d, have %d", 17+ipLen, len(data))
	}

	ip := make([]byte, ipLen)
	copy(ip, data[17:17+ipLen])

	var sig []byte
	if len(data) > 17+ipLen {
		sig = make([]byte, len(data)-(17+ipLen))
		copy(sig, data[17+ipLen:])
	}

	return &RelayRequestBlock{
		Flag:      flag,
		Nonce:     nonce,
		RelayTag:  relayTag,
		Timestamp: timestamp,
		Version:   ver,
		AlicePort: port,
		AliceIP:   net.IP(ip),
		Signature: sig,
	}, nil
}

// EncodeRelayResponse encodes a RelayResponse block to wire format.
//
// Wire format per SSU2 spec:
//
//	[Nonce:4][StatusCode:1][SignedData:variable]
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

	// Size: nonce(4) + statusCode(1) + signedData
	dataSize := 5 + len(resp.SignedData)
	data := make([]byte, dataSize)

	// Encode fields
	binary.BigEndian.PutUint32(data[0:4], resp.Nonce)
	data[4] = resp.StatusCode
	if len(resp.SignedData) > 0 {
		copy(data[5:], resp.SignedData)
	}

	return NewSSU2Block(BlockTypeRelayResponse, data), nil
}

// DecodeRelayResponse decodes a RelayResponse block from wire format.
//
// Wire format: [Nonce:4][StatusCode:1][SignedData:variable]
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
	if len(data) < 5 {
		return nil, oops.Errorf("RelayResponse block too short: %d bytes (minimum 5)", len(data))
	}

	nonce := binary.BigEndian.Uint32(data[0:4])
	statusCode := data[4]

	var signedData []byte
	if len(data) > 5 {
		signedData = make([]byte, len(data)-5)
		copy(signedData, data[5:])
	}

	return &RelayResponseBlock{
		Nonce:      nonce,
		StatusCode: statusCode,
		SignedData: signedData,
	}, nil
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
