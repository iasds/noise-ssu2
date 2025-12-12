// Package ssu2 provides SSU2-specific implementations for the Noise Protocol Framework
// supporting I2P's SSU2 transport protocol with UDP-based connections and NAT traversal.
package ssu2

import (
	"crypto/rand"
	"encoding/binary"
	"net"
	"sync"
	"time"

	"github.com/samber/oops"
)

// PathValidator implements connection migration with path validation.
//
// Path validation allows an SSU2 connection to migrate to a new UDP path
// (different IP address or port) while maintaining security and preventing
// amplification attacks. This is useful for:
//  - IP address changes (network switch, VPN, mobile roaming)
//  - Port changes (NAT rebinding)
//  - Failover to backup paths
//  - Load balancing across multiple paths
//
// The validation protocol uses Path Challenge (Type 18) and Path Response (Type 19) blocks
// to verify bidirectional connectivity on the new path before migration.
//
// Design rationale:
// - Cryptographic challenge IDs prevent spoofing
// - Timeout-based cleanup prevents resource leaks
// - Thread-safe for concurrent path validations
// - Follows SSU2.md specification for path validation
type PathValidator struct {
	// conn is the SSU2 connection this validator belongs to
	conn PathValidationConn

	// challenges tracks active path validation attempts by challenge ID
	challenges map[uint64]*PathChallenge

	// mutex protects the challenges map
	mutex sync.RWMutex
}

// PathValidationConn defines the interface for sending path validation messages.
// This interface is implemented by SSU2Conn to allow testing with mocks.
type PathValidationConn interface {
	// SendToAddress sends a block to a specific UDP address
	SendToAddress(block *SSU2Block, addr *net.UDPAddr) error

	// GetRemoteAddr returns the current remote address
	GetRemoteAddr() *net.UDPAddr

	// SetRemoteAddr updates the remote address after successful validation
	SetRemoteAddr(addr *net.UDPAddr) error
}

// PathChallenge represents an active path validation attempt.
type PathChallenge struct {
	// ChallengeID uniquely identifies this validation (8 bytes)
	ChallengeID uint64

	// NewAddr is the new UDP address being validated
	NewAddr *net.UDPAddr

	// Timestamp is when the challenge was created
	Timestamp time.Time

	// State tracks the validation progress
	State PathChallengeState
}

// PathChallengeState represents the state of a path validation attempt.
type PathChallengeState int

const (
	// ChallengeSent indicates we sent a challenge, awaiting response
	ChallengeSent PathChallengeState = iota

	// ChallengeReceived indicates we received a challenge, need to respond
	ChallengeReceived

	// ChallengeValidated indicates successful bidirectional validation
	ChallengeValidated

	// ChallengeFailed indicates validation failed (timeout or error)
	ChallengeFailed
)

// String returns a human-readable representation of the challenge state.
func (s PathChallengeState) String() string {
	switch s {
	case ChallengeSent:
		return "ChallengeSent"
	case ChallengeReceived:
		return "ChallengeReceived"
	case ChallengeValidated:
		return "ChallengeValidated"
	case ChallengeFailed:
		return "ChallengeFailed"
	default:
		return "Unknown"
	}
}

// Path validation timeouts
const (
	// PathValidationTimeout is how long to wait for path response
	PathValidationTimeout = 10 * time.Second

	// PathValidationCleanupInterval is how often to clean up expired challenges
	PathValidationCleanupInterval = 30 * time.Second
)

// NewPathValidator creates a new path validator for a connection.
//
// Parameters:
//   - conn: The connection to manage path validation for
//
// Returns an initialized validator.
func NewPathValidator(conn PathValidationConn) *PathValidator {
	return &PathValidator{
		conn:       conn,
		challenges: make(map[uint64]*PathChallenge),
	}
}

// InitiatePathValidation starts path validation for a new address.
//
// This sends a Path Challenge (Type 18) block to the new address with a
// cryptographically random challenge ID. The peer must respond with a
// Path Response (Type 19) containing the same challenge ID.
//
// Parameters:
//   - newAddr: The new UDP address to validate
//
// Returns:
//   - uint64: The challenge ID for tracking this validation
//   - error: If challenge creation or sending fails
func (pv *PathValidator) InitiatePathValidation(newAddr *net.UDPAddr) (uint64, error) {
	if newAddr == nil {
		return 0, oops.Errorf("new address is nil")
	}

	// Generate cryptographic random challenge ID (8 bytes)
	challengeID, err := generateChallengeID()
	if err != nil {
		return 0, oops.Wrapf(err, "failed to generate challenge ID")
	}

	// Create challenge tracking entry
	challenge := &PathChallenge{
		ChallengeID: challengeID,
		NewAddr:     newAddr,
		Timestamp:   time.Now(),
		State:       ChallengeSent,
	}

	pv.mutex.Lock()
	pv.challenges[challengeID] = challenge
	pv.mutex.Unlock()

	// Send path challenge to new address
	if err := pv.SendPathChallenge(challengeID, newAddr); err != nil {
		pv.mutex.Lock()
		delete(pv.challenges, challengeID)
		pv.mutex.Unlock()
		return 0, oops.Wrapf(err, "failed to send path challenge")
	}

	return challengeID, nil
}

// SendPathChallenge sends a Path Challenge block to the specified address.
//
// Parameters:
//   - challengeID: The 8-byte challenge identifier
//   - addr: The UDP address to send to
//
// Returns error if encoding or sending fails.
func (pv *PathValidator) SendPathChallenge(challengeID uint64, addr *net.UDPAddr) error {
	block := EncodePathChallenge(challengeID)
	if err := pv.conn.SendToAddress(block, addr); err != nil {
		return oops.Wrapf(err, "failed to send path challenge to %v", addr)
	}
	return nil
}

// HandlePathChallenge processes a received Path Challenge block.
//
// When we receive a challenge, we:
//  1. Record it as ChallengeReceived
//  2. Send a Path Response with the same challenge ID
//
// Parameters:
//   - block: The received Path Challenge block
//   - fromAddr: The UDP address it came from
//
// Returns error if decoding or response fails.
func (pv *PathValidator) HandlePathChallenge(block *SSU2Block, fromAddr *net.UDPAddr) error {
	if block == nil {
		return oops.Errorf("block is nil")
	}
	if fromAddr == nil {
		return oops.Errorf("fromAddr is nil")
	}

	// Decode challenge ID
	challengeID, err := DecodePathChallenge(block)
	if err != nil {
		return oops.Wrapf(err, "failed to decode path challenge")
	}

	// Record challenge
	challenge := &PathChallenge{
		ChallengeID: challengeID,
		NewAddr:     fromAddr,
		Timestamp:   time.Now(),
		State:       ChallengeReceived,
	}

	pv.mutex.Lock()
	pv.challenges[challengeID] = challenge
	pv.mutex.Unlock()

	// Send response immediately
	return pv.SendPathResponse(challengeID, fromAddr)
}

// SendPathResponse sends a Path Response block to the specified address.
//
// Parameters:
//   - challengeID: The 8-byte challenge identifier from the Path Challenge
//   - addr: The UDP address to send to
//
// Returns error if encoding or sending fails.
func (pv *PathValidator) SendPathResponse(challengeID uint64, addr *net.UDPAddr) error {
	block := EncodePathResponse(challengeID)
	if err := pv.conn.SendToAddress(block, addr); err != nil {
		return oops.Wrapf(err, "failed to send path response to %v", addr)
	}
	return nil
}

// HandlePathResponse processes a received Path Response block.
//
// When we receive a response:
//  1. Verify it matches a pending challenge
//  2. Mark the challenge as validated
//  3. Complete the path migration if validation succeeds
//
// Parameters:
//   - block: The received Path Response block
//   - fromAddr: The UDP address it came from
//
// Returns error if validation fails.
func (pv *PathValidator) HandlePathResponse(block *SSU2Block, fromAddr *net.UDPAddr) error {
	if block == nil {
		return oops.Errorf("block is nil")
	}
	if fromAddr == nil {
		return oops.Errorf("fromAddr is nil")
	}

	// Decode response
	challengeID, err := DecodePathResponse(block)
	if err != nil {
		return oops.Wrapf(err, "failed to decode path response")
	}

	// Find matching challenge
	pv.mutex.Lock()
	challenge, exists := pv.challenges[challengeID]
	pv.mutex.Unlock()

	if !exists {
		return oops.Errorf("no matching challenge for ID %d", challengeID)
	}

	// Verify response came from expected address
	if challenge.NewAddr.String() != fromAddr.String() {
		return oops.Errorf("path response from unexpected address: expected %v, got %v",
			challenge.NewAddr, fromAddr)
	}

	// Mark as validated
	pv.mutex.Lock()
	challenge.State = ChallengeValidated
	pv.mutex.Unlock()

	// Complete path validation
	return pv.ValidatePath(challengeID)
}

// ValidatePath completes the path validation and migrates the connection.
//
// This should be called after receiving a valid Path Response.
// It updates the connection's remote address to the validated path.
//
// Parameters:
//   - challengeID: The challenge ID that was validated
//
// Returns error if migration fails.
func (pv *PathValidator) ValidatePath(challengeID uint64) error {
	pv.mutex.Lock()
	challenge, exists := pv.challenges[challengeID]
	pv.mutex.Unlock()

	if !exists {
		return oops.Errorf("no challenge found for ID %d", challengeID)
	}

	if challenge.State != ChallengeValidated {
		return oops.Errorf("challenge %d not validated (state: %v)", challengeID, challenge.State)
	}

	// Update connection remote address
	if err := pv.conn.SetRemoteAddr(challenge.NewAddr); err != nil {
		pv.FailPath(challengeID, err)
		return oops.Wrapf(err, "failed to set remote address")
	}

	// Clean up challenge
	pv.mutex.Lock()
	delete(pv.challenges, challengeID)
	pv.mutex.Unlock()

	return nil
}

// FailPath marks a path validation as failed.
//
// Parameters:
//   - challengeID: The challenge ID to fail
//   - reason: Error describing why validation failed
func (pv *PathValidator) FailPath(challengeID uint64, reason error) {
	pv.mutex.Lock()
	defer pv.mutex.Unlock()

	if challenge, exists := pv.challenges[challengeID]; exists {
		challenge.State = ChallengeFailed
	}
}

// GetChallenge returns information about a specific challenge.
//
// Parameters:
//   - challengeID: The challenge ID to look up
//
// Returns:
//   - *PathChallenge: Challenge information (defensive copy)
//   - bool: Whether the challenge exists
func (pv *PathValidator) GetChallenge(challengeID uint64) (*PathChallenge, bool) {
	pv.mutex.RLock()
	defer pv.mutex.RUnlock()

	challenge, exists := pv.challenges[challengeID]
	if !exists {
		return nil, false
	}

	// Return defensive copy
	return &PathChallenge{
		ChallengeID: challenge.ChallengeID,
		NewAddr:     challenge.NewAddr,
		Timestamp:   challenge.Timestamp,
		State:       challenge.State,
	}, true
}

// CleanupExpired removes expired path validation challenges.
//
// Challenges are expired if they're older than PathValidationTimeout
// and not in a terminal state (Validated or Failed).
//
// Returns the number of challenges cleaned up.
func (pv *PathValidator) CleanupExpired() int {
	pv.mutex.Lock()
	defer pv.mutex.Unlock()

	now := time.Now()
	cleaned := 0

	for id, challenge := range pv.challenges {
		// Skip terminal states
		if challenge.State == ChallengeValidated || challenge.State == ChallengeFailed {
			continue
		}

		// Check timeout
		if now.Sub(challenge.Timestamp) > PathValidationTimeout {
			challenge.State = ChallengeFailed
			delete(pv.challenges, id)
			cleaned++
		}
	}

	return cleaned
}

// generateChallengeID generates a cryptographically random 8-byte challenge ID.
func generateChallengeID() (uint64, error) {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return 0, oops.Wrapf(err, "failed to read random bytes")
	}
	return binary.BigEndian.Uint64(buf[:]), nil
}

// EncodePathChallenge encodes a Path Challenge block (Type 18).
//
// Wire format: [ChallengeID:8]
//
// Parameters:
//   - challengeID: 8-byte challenge identifier
//
// Returns encoded block.
func EncodePathChallenge(challengeID uint64) *SSU2Block {
	data := make([]byte, 8)
	binary.BigEndian.PutUint64(data, challengeID)
	return NewSSU2Block(BlockTypePathChallenge, data)
}

// DecodePathChallenge decodes a Path Challenge block.
//
// Parameters:
//   - block: SSU2Block with Type 18
//
// Returns:
//   - uint64: The challenge ID
//   - error: If decoding fails
func DecodePathChallenge(block *SSU2Block) (uint64, error) {
	if block == nil {
		return 0, oops.Errorf("block is nil")
	}

	if block.Type != BlockTypePathChallenge {
		return 0, oops.Errorf("invalid block type: expected %d, got %d",
			BlockTypePathChallenge, block.Type)
	}

	if len(block.Data) < 8 {
		return 0, oops.Errorf("PathChallenge block too short: %d bytes (minimum 8)",
			len(block.Data))
	}

	return binary.BigEndian.Uint64(block.Data[:8]), nil
}

// EncodePathResponse encodes a Path Response block (Type 19).
//
// Wire format: [ChallengeID:8]
//
// Parameters:
//   - challengeID: 8-byte challenge identifier from the Path Challenge
//
// Returns encoded block.
func EncodePathResponse(challengeID uint64) *SSU2Block {
	data := make([]byte, 8)
	binary.BigEndian.PutUint64(data, challengeID)
	return NewSSU2Block(BlockTypePathResponse, data)
}

// DecodePathResponse decodes a Path Response block.
//
// Parameters:
//   - block: SSU2Block with Type 19
//
// Returns:
//   - uint64: The challenge ID
//   - error: If decoding fails
func DecodePathResponse(block *SSU2Block) (uint64, error) {
	if block == nil {
		return 0, oops.Errorf("block is nil")
	}

	if block.Type != BlockTypePathResponse {
		return 0, oops.Errorf("invalid block type: expected %d, got %d",
			BlockTypePathResponse, block.Type)
	}

	if len(block.Data) < 8 {
		return 0, oops.Errorf("PathResponse block too short: %d bytes (minimum 8)",
			len(block.Data))
	}

	return binary.BigEndian.Uint64(block.Data[:8]), nil
}
