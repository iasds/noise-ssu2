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
// The wire format is fixed for all message types per the SSU2 specification:
//
//	Byte 0:     msg (message number 1-7)
//	Byte 1:     status code (for msg 4, 5, 6, 7; 0 otherwise)
//	Bytes 2-5:  nonce (4 bytes)
//	Bytes 6-9:  timestamp (seconds since epoch; for msg 2, 5; 0 otherwise)
//	Byte 10:    version (2)
//	Bytes 11+:  signed data (varies by message number)
type PeerTestBlock struct {
	// MessageCode identifies which of the 7 messages this is (1 byte)
	MessageCode PeerTestMessageCode

	// StatusCode is the status/result code (for messages 4, 5, 6, 7)
	StatusCode uint8

	// Nonce uniquely identifies the test session (4 bytes)
	Nonce uint32

	// Timestamp is seconds since epoch (4 bytes)
	// Present in messages 2 and 5; 0 otherwise
	Timestamp uint32

	// Version is the peer test protocol version (should be 2)
	Version uint8

	// SignedData is the opaque signed data blob (varies by message number)
	SignedData []byte
}

// EncodePeerTestBlock encodes a PeerTest block to wire format.
//
// Wire format (fixed for all message types):
//
//	[Msg:1][StatusCode:1][Nonce:4][Timestamp:4][Version:1][SignedData:variable]
//
// Minimum encoded size is 11 bytes (header only, no signed data).
//
// Parameters:
//   - block: PeerTestBlock data to encode
//
// Returns:
//   - *SSU2Block: Encoded block ready for transmission
//   - error: If validation fails
func EncodePeerTestBlock(block *PeerTestBlock) (*SSU2Block, error) {
	if block == nil {
		return nil, oops.Errorf("PeerTestBlock is nil")
	}

	if block.MessageCode < 1 || block.MessageCode > 7 {
		return nil, oops.Errorf("invalid message code: %d (must be 1-7)", block.MessageCode)
	}

	// Fixed header: msg(1) + status(1) + nonce(4) + timestamp(4) + version(1) = 11
	dataSize := 11 + len(block.SignedData)
	data := make([]byte, dataSize)

	data[0] = uint8(block.MessageCode)
	data[1] = block.StatusCode
	binary.BigEndian.PutUint32(data[2:6], block.Nonce)
	binary.BigEndian.PutUint32(data[6:10], block.Timestamp)
	data[10] = block.Version

	if len(block.SignedData) > 0 {
		copy(data[11:], block.SignedData)
	}

	return NewSSU2Block(BlockTypePeerTest, data), nil
}

// DecodePeerTestBlock decodes a PeerTest block from wire format.
//
// Parameters:
//   - ssu2Block: SSU2Block with Type 10
//
// Returns:
//   - *PeerTestBlock: Decoded peer test message
//   - error: If decoding fails or validation fails
func DecodePeerTestBlock(ssu2Block *SSU2Block) (*PeerTestBlock, error) {
	if ssu2Block == nil {
		return nil, oops.Errorf("block is nil")
	}

	if ssu2Block.Type != BlockTypePeerTest {
		return nil, oops.Errorf("invalid block type: expected %d, got %d", BlockTypePeerTest, ssu2Block.Type)
	}

	data := ssu2Block.Data
	if len(data) < 11 {
		return nil, oops.Errorf("PeerTest block too short: %d bytes (minimum 11)", len(data))
	}

	block := &PeerTestBlock{
		MessageCode: PeerTestMessageCode(data[0]),
		StatusCode:  data[1],
		Nonce:       binary.BigEndian.Uint32(data[2:6]),
		Timestamp:   binary.BigEndian.Uint32(data[6:10]),
		Version:     data[10],
	}

	if block.MessageCode < 1 || block.MessageCode > 7 {
		return nil, oops.Errorf("invalid message code: %d (must be 1-7)", block.MessageCode)
	}

	if len(data) > 11 {
		block.SignedData = make([]byte, len(data)-11)
		copy(block.SignedData, data[11:])
	}

	return block, nil
}
