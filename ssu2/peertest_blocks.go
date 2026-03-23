package ssu2

import (
	"encoding/binary"

	"github.com/samber/oops"
)

// PeerTest block structures and encoding/decoding for SSU2 protocol.
//
// SSU2 peer testing uses a seven-message protocol with message codes 1-7:
// 1. Alice -> Bob: Request (initiator requests test via relay)
// 2. Bob -> Charlie: Relay (relay forwards request to responder)
// 3. Charlie -> Bob: Response (responder acknowledges to relay)
// 4. Bob -> Alice: Result (relay sends result to initiator)
// 5. Charlie -> Alice: Probe (responder probes initiator directly)
// 6. Alice -> Charlie: Reply (initiator confirms probe received)
// 7. Charlie -> Alice: Confirmation (responder confirms successful test)
//
// These blocks use Type 10 (BlockTypePeerTest) with different message codes.
//
// Design rationale:
// - Seven message types encoded via message code field
// - Uses standard library encoding for wire format compatibility
// - Validates all field sizes per SSU2 specification
// - Defensive copies prevent mutation of shared data
// - Error handling provides context for debugging

// PeerTestMessageCode identifies the message type in the seven-message protocol.
type PeerTestMessageCode uint8

const (
	// PeerTestRequest (1): Alice -> Bob, request test via relay
	PeerTestRequest PeerTestMessageCode = 1

	// PeerTestRelay (2): Bob -> Charlie, relay request to responder
	PeerTestRelay PeerTestMessageCode = 2

	// PeerTestResponse (3): Charlie -> Bob, responder acknowledges
	PeerTestResponse PeerTestMessageCode = 3

	// PeerTestResult (4): Bob -> Alice, relay sends result
	PeerTestResult PeerTestMessageCode = 4

	// PeerTestProbe (5): Charlie -> Alice, responder probes directly
	PeerTestProbe PeerTestMessageCode = 5

	// PeerTestReply (6): Alice -> Charlie, initiator confirms probe
	PeerTestReply PeerTestMessageCode = 6

	// PeerTestConfirmation (7): Charlie -> Alice, responder confirms success
	PeerTestConfirmation PeerTestMessageCode = 7
)

// String returns string representation of the message code.
func (c PeerTestMessageCode) String() string {
	switch c {
	case PeerTestRequest:
		return "Request"
	case PeerTestRelay:
		return "Relay"
	case PeerTestResponse:
		return "Response"
	case PeerTestResult:
		return "Result"
	case PeerTestProbe:
		return "Probe"
	case PeerTestReply:
		return "Reply"
	case PeerTestConfirmation:
		return "Confirmation"
	default:
		return "Unknown"
	}
}

// PeerTestBlock represents a peer test message (Type 10, Block 10).
// Wire format per SSU2 spec:
//
//	Byte 0:       msg (message number 1-7)
//	Byte 1:       code (status/reason code)
//	Byte 2:       flag (unused, set to 0)
//	Bytes 3-34:   router hash (32 bytes, only for messages 2 and 4)
//	Next 1 byte:  ver (protocol version, should be 2)
//	Next 4 bytes: nonce (big-endian)
//	Next 4 bytes: timestamp (seconds since epoch, big-endian)
//	Next 1 byte:  asz (endpoint size: 6 for IPv4, 18 for IPv6)
//	Next 2 bytes: AlicePort (big-endian)
//	Next asz-2:   AliceIP (4 or 16 bytes)
//	Remaining:    signature (variable length; optional for messages 5-7)
type PeerTestBlock struct {
	// MessageCode identifies which of the 7 messages this is (1 byte)
	MessageCode PeerTestMessageCode

	// Code is the status/reason code (1 byte)
	Code uint8

	// Flag is reserved for future use (1 byte, must be 0)
	Flag uint8

	// RouterHash is the 32-byte hash (only for messages 2 and 4)
	RouterHash []byte

	// Version is the peer test protocol version (should be 2)
	Version uint8

	// Nonce uniquely identifies the test session (4 bytes)
	Nonce uint32

	// Timestamp is seconds since epoch (4 bytes)
	Timestamp uint32

	// AlicePort is Alice's port number
	AlicePort uint16

	// AliceIP is Alice's IP address (4 bytes IPv4 or 16 bytes IPv6)
	AliceIP []byte

	// Signature is the Ed25519 (or other) signature (variable length)
	// Optional for messages 5-7.
	Signature []byte
}

// hasRouterHash returns true if this message code includes a 32-byte router hash.
func (b *PeerTestBlock) hasRouterHash() bool {
	return b.MessageCode == PeerTestRelay || b.MessageCode == PeerTestResult
}

// EncodePeerTestBlock encodes a PeerTest block to wire format per the SSU2 spec.
func EncodePeerTestBlock(block *PeerTestBlock) (*SSU2Block, error) {
	if block == nil {
		return nil, oops.Errorf("PeerTestBlock is nil")
	}

	if block.MessageCode < 1 || block.MessageCode > 7 {
		return nil, oops.Errorf("invalid message code: %d (must be 1-7)", block.MessageCode)
	}

	ipLen := len(block.AliceIP)
	if ipLen != 4 && ipLen != 16 {
		return nil, oops.Errorf("invalid AliceIP length: %d (must be 4 or 16)", ipLen)
	}
	asz := uint8(2 + ipLen) // port(2) + IP

	// Calculate total size: msg(1)+code(1)+flag(1) + [hash(32)] + ver(1)+nonce(4)+timestamp(4)+asz(1)+port(2)+ip(ipLen)+sig
	dataSize := 3 // msg + code + flag
	if block.hasRouterHash() {
		dataSize += 32
	}
	dataSize += 1 + 4 + 4 + 1 + 2 + ipLen + len(block.Signature) // ver+nonce+ts+asz+port+ip+sig

	data := make([]byte, dataSize)
	off := 0

	data[off] = uint8(block.MessageCode)
	off++
	data[off] = block.Code
	off++
	data[off] = block.Flag
	off++

	if block.hasRouterHash() {
		if len(block.RouterHash) != 32 {
			return nil, oops.Errorf("RouterHash must be 32 bytes for message %d", block.MessageCode)
		}
		copy(data[off:off+32], block.RouterHash)
		off += 32
	}

	data[off] = block.Version
	off++
	binary.BigEndian.PutUint32(data[off:off+4], block.Nonce)
	off += 4
	binary.BigEndian.PutUint32(data[off:off+4], block.Timestamp)
	off += 4
	data[off] = asz
	off++
	binary.BigEndian.PutUint16(data[off:off+2], block.AlicePort)
	off += 2
	copy(data[off:off+ipLen], block.AliceIP)
	off += ipLen

	if len(block.Signature) > 0 {
		copy(data[off:], block.Signature)
	}

	return NewSSU2Block(BlockTypePeerTest, data), nil
}

// DecodePeerTestBlock decodes a PeerTest block from wire format per the SSU2 spec.
func DecodePeerTestBlock(ssu2Block *SSU2Block) (*PeerTestBlock, error) {
	if ssu2Block == nil {
		return nil, oops.Errorf("block is nil")
	}

	if ssu2Block.Type != BlockTypePeerTest {
		return nil, oops.Errorf("invalid block type: expected %d, got %d", BlockTypePeerTest, ssu2Block.Type)
	}

	data := ssu2Block.Data
	// Minimum: msg(1)+code(1)+flag(1)+ver(1)+nonce(4)+timestamp(4)+asz(1)+port(2)+ip(4) = 19
	if len(data) < 19 {
		return nil, oops.Errorf("PeerTest block too short: %d bytes (minimum 19)", len(data))
	}

	block := &PeerTestBlock{}
	off := 0

	block.MessageCode = PeerTestMessageCode(data[off])
	off++
	block.Code = data[off]
	off++
	block.Flag = data[off]
	off++

	if block.MessageCode < 1 || block.MessageCode > 7 {
		return nil, oops.Errorf("invalid message code: %d (must be 1-7)", block.MessageCode)
	}

	// Messages 2 and 4 include a 32-byte router hash
	if block.hasRouterHash() {
		if len(data) < off+32 {
			return nil, oops.Errorf("PeerTest block too short for router hash: %d bytes", len(data))
		}
		block.RouterHash = make([]byte, 32)
		copy(block.RouterHash, data[off:off+32])
		off += 32
	}

	// Remaining minimum: ver(1)+nonce(4)+timestamp(4)+asz(1)+port(2)+ip(4) = 16
	if len(data) < off+16 {
		return nil, oops.Errorf("PeerTest block too short for signed data: %d bytes at offset %d", len(data), off)
	}

	block.Version = data[off]
	off++
	block.Nonce = binary.BigEndian.Uint32(data[off : off+4])
	off += 4
	block.Timestamp = binary.BigEndian.Uint32(data[off : off+4])
	off += 4

	asz := data[off]
	off++
	if asz != 6 && asz != 18 {
		return nil, oops.Errorf("invalid asz: %d (must be 6 or 18)", asz)
	}

	ipLen := int(asz) - 2
	if len(data) < off+2+ipLen {
		return nil, oops.Errorf("PeerTest block too short for address: %d bytes", len(data))
	}

	block.AlicePort = binary.BigEndian.Uint16(data[off : off+2])
	off += 2
	block.AliceIP = make([]byte, ipLen)
	copy(block.AliceIP, data[off:off+ipLen])
	off += ipLen

	// Remaining bytes are signature (optional for messages 5-7)
	if off < len(data) {
		block.Signature = make([]byte, len(data)-off)
		copy(block.Signature, data[off:])
	}

	return block, nil
}
