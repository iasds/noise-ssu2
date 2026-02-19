package ssu2

import (
	"crypto/rand"
	"encoding/binary"
	"net"
	"sync"
	"time"

	"github.com/samber/oops"
)

// HolePunchCoordinator coordinates UDP hole punching for NAT traversal.
// It manages hole punch attempts with state tracking, retries, and timeout handling.
//
// Design rationale:
// - Session IDs are cryptographically random 64-bit values for security
// - Maximum 3 retry attempts per I2P convention
// - 30-second timeout per attempt (I2P spec recommendation)
// - State machine: Requested → Sent → Waiting → Success/Failed
//
// Thread Safety: All public methods are thread-safe.
type HolePunchCoordinator struct {
	// manager is the parent RelayManager
	manager *RelayManager

	// attempts maps session ID to hole punch attempt
	attempts map[uint64]*HolePunchAttempt

	// mutex protects all fields
	mutex sync.RWMutex
}

// HolePunchAttempt represents an active hole punch operation.
type HolePunchAttempt struct {
	// SessionID uniquely identifies this attempt
	SessionID uint64

	// RemoteAddr is the target peer's UDP address
	RemoteAddr *net.UDPAddr

	// Introducer is the introducer facilitating the hole punch
	Introducer *net.UDPAddr

	// State is the current state of the attempt
	State HolePunchState

	// StartTime is when the attempt was initiated
	StartTime time.Time

	// Retries is the number of retry attempts made
	Retries int

	// RelayTag is the tag for relay communication
	RelayTag uint32
}

// HolePunchState represents the state of a hole punch attempt.
type HolePunchState int

const (
	// HolePunchRequested indicates hole punch has been requested
	HolePunchRequested HolePunchState = iota

	// HolePunchSent indicates hole punch packet has been sent
	HolePunchSent

	// HolePunchWaiting indicates waiting for response
	HolePunchWaiting

	// HolePunchSuccess indicates hole punch succeeded
	HolePunchSuccess

	// HolePunchFailed indicates hole punch failed
	HolePunchFailed
)

// String returns human-readable state name.
func (s HolePunchState) String() string {
	switch s {
	case HolePunchRequested:
		return "Requested"
	case HolePunchSent:
		return "Sent"
	case HolePunchWaiting:
		return "Waiting"
	case HolePunchSuccess:
		return "Success"
	case HolePunchFailed:
		return "Failed"
	default:
		return "Unknown"
	}
}

// NewHolePunchCoordinator creates a new HolePunchCoordinator.
//
// Parameters:
//   - manager: The RelayManager to coordinate with
//
// Returns a new HolePunchCoordinator with empty state.
func NewHolePunchCoordinator(manager *RelayManager) *HolePunchCoordinator {
	return &HolePunchCoordinator{
		manager:  manager,
		attempts: make(map[uint64]*HolePunchAttempt),
	}
}

// InitiateHolePunch starts a new hole punch attempt to reach a remote peer.
//
// Design rationale:
// - Uses introducer to coordinate hole punch with target peer
// - Generates cryptographically random session ID
// - Registers pending session with RelayManager
// - 30-second timeout per I2P spec
//
// Parameters:
//   - remoteAddr: Target peer's UDP address
//   - introducerAddr: Introducer's UDP address
//   - relayTag: Tag for relay communication
//
// Returns session ID on success, error otherwise.
func (hpc *HolePunchCoordinator) InitiateHolePunch(remoteAddr, introducerAddr *net.UDPAddr, relayTag uint32) (uint64, error) {
	if remoteAddr == nil {
		return 0, oops.
			Code("INVALID_ADDRESS").
			In("holepunch_coordinator").
			Errorf("remote address cannot be nil")
	}

	if introducerAddr == nil {
		return 0, oops.
			Code("INVALID_ADDRESS").
			In("holepunch_coordinator").
			Errorf("introducer address cannot be nil")
	}

	if relayTag == 0 {
		return 0, oops.
			Code("INVALID_RELAY_TAG").
			In("holepunch_coordinator").
			Errorf("relay tag cannot be zero")
	}

	// Generate cryptographically random session ID
	var sessionIDBytes [8]byte
	if _, err := rand.Read(sessionIDBytes[:]); err != nil {
		return 0, oops.
			Code("RANDOM_GENERATION_FAILED").
			In("holepunch_coordinator").
			With("error", err.Error()).
			Wrapf(err, "failed to generate session ID")
	}
	sessionID := binary.BigEndian.Uint64(sessionIDBytes[:])

	// Ensure non-zero
	if sessionID == 0 {
		sessionID = 1
	}

	hpc.mutex.Lock()
	defer hpc.mutex.Unlock()

	// Create attempt
	attempt := &HolePunchAttempt{
		SessionID:  sessionID,
		RemoteAddr: remoteAddr,
		Introducer: introducerAddr,
		State:      HolePunchRequested,
		StartTime:  time.Now(),
		Retries:    0,
		RelayTag:   relayTag,
	}

	hpc.attempts[sessionID] = attempt

	// Register with relay manager
	if err := hpc.manager.AddPendingSession(sessionID, remoteAddr, introducerAddr, relayTag); err != nil {
		delete(hpc.attempts, sessionID)
		return 0, oops.
			Code("PENDING_SESSION_FAILED").
			In("holepunch_coordinator").
			With("session_id", sessionID).
			Wrapf(err, "failed to register pending session")
	}

	return sessionID, nil
}

// SendHolePunch sends a hole punch packet to the target address.
//
// Parameters:
//   - sessionID: Session identifier
//   - targetAddr: Target peer's UDP address
//
// Returns error if session not found or send fails.
func (hpc *HolePunchCoordinator) SendHolePunch(sessionID uint64, targetAddr *net.UDPAddr) error {
	if sessionID == 0 {
		return oops.
			Code("INVALID_SESSION_ID").
			In("holepunch_coordinator").
			Errorf("session ID cannot be zero")
	}

	if targetAddr == nil {
		return oops.
			Code("INVALID_ADDRESS").
			In("holepunch_coordinator").
			Errorf("target address cannot be nil")
	}

	hpc.mutex.Lock()
	defer hpc.mutex.Unlock()

	attempt, exists := hpc.attempts[sessionID]
	if !exists {
		return oops.
			Code("SESSION_NOT_FOUND").
			In("holepunch_coordinator").
			With("session_id", sessionID).
			Errorf("hole punch session not found")
	}

	// Update state
	attempt.State = HolePunchSent

	// Note: Actual packet sending would be done by the listener
	// This method updates the state machine only

	return nil
}

// HandleHolePunch processes an incoming hole punch packet from a remote peer.
//
// Parameters:
//   - sessionID: Session identifier from the packet
//   - fromAddr: Address the packet came from
//
// Returns error if session not found.
func (hpc *HolePunchCoordinator) HandleHolePunch(sessionID uint64, fromAddr *net.UDPAddr) error {
	if sessionID == 0 {
		return oops.
			Code("INVALID_SESSION_ID").
			In("holepunch_coordinator").
			Errorf("session ID cannot be zero")
	}

	if fromAddr == nil {
		return oops.
			Code("INVALID_ADDRESS").
			In("holepunch_coordinator").
			Errorf("from address cannot be nil")
	}

	hpc.mutex.Lock()
	defer hpc.mutex.Unlock()

	attempt, exists := hpc.attempts[sessionID]
	if !exists {
		return oops.
			Code("SESSION_NOT_FOUND").
			In("holepunch_coordinator").
			With("session_id", sessionID).
			Errorf("hole punch session not found")
	}

	// Update state to waiting
	attempt.State = HolePunchWaiting

	return nil
}

// ProcessHolePunchResponse processes a response to a hole punch attempt.
//
// Parameters:
//   - sessionID: Session identifier
//   - addr: Address that responded
//
// Returns error if session not found.
func (hpc *HolePunchCoordinator) ProcessHolePunchResponse(sessionID uint64, addr *net.UDPAddr) error {
	if sessionID == 0 {
		return oops.
			Code("INVALID_SESSION_ID").
			In("holepunch_coordinator").
			Errorf("session ID cannot be zero")
	}

	if addr == nil {
		return oops.
			Code("INVALID_ADDRESS").
			In("holepunch_coordinator").
			Errorf("address cannot be nil")
	}

	hpc.mutex.Lock()
	defer hpc.mutex.Unlock()

	attempt, exists := hpc.attempts[sessionID]
	if !exists {
		return oops.
			Code("SESSION_NOT_FOUND").
			In("holepunch_coordinator").
			With("session_id", sessionID).
			Errorf("hole punch session not found")
	}

	// Verify address matches expected remote
	if attempt.RemoteAddr.String() != addr.String() {
		return oops.
			Code("ADDRESS_MISMATCH").
			In("holepunch_coordinator").
			With("session_id", sessionID).
			With("expected", attempt.RemoteAddr.String()).
			With("actual", addr.String()).
			Errorf("response address does not match expected remote")
	}

	// Mark as successful
	attempt.State = HolePunchSuccess

	return nil
}

// RetryHolePunch retries a failed hole punch attempt.
//
// Parameters:
//   - sessionID: Session identifier
//
// Returns error if session not found or max retries exceeded.
func (hpc *HolePunchCoordinator) RetryHolePunch(sessionID uint64) error {
	if sessionID == 0 {
		return oops.
			Code("INVALID_SESSION_ID").
			In("holepunch_coordinator").
			Errorf("session ID cannot be zero")
	}

	hpc.mutex.Lock()
	defer hpc.mutex.Unlock()

	attempt, exists := hpc.attempts[sessionID]
	if !exists {
		return oops.
			Code("SESSION_NOT_FOUND").
			In("holepunch_coordinator").
			With("session_id", sessionID).
			Errorf("hole punch session not found")
	}

	// Check max retries (3 per I2P convention)
	if attempt.Retries >= 3 {
		attempt.State = HolePunchFailed
		return oops.
			Code("MAX_RETRIES_EXCEEDED").
			In("holepunch_coordinator").
			With("session_id", sessionID).
			With("retries", attempt.Retries).
			Errorf("maximum retry attempts exceeded")
	}

	// Increment retry count
	attempt.Retries++

	// Increment in relay manager too
	hpc.manager.IncrementRetries(sessionID)

	// Reset state to requested
	attempt.State = HolePunchRequested

	return nil
}

// CompleteHolePunch marks a hole punch attempt as successfully completed.
//
// Parameters:
//   - sessionID: Session identifier
//
// Returns error if session not found.
func (hpc *HolePunchCoordinator) CompleteHolePunch(sessionID uint64) error {
	if sessionID == 0 {
		return oops.
			Code("INVALID_SESSION_ID").
			In("holepunch_coordinator").
			Errorf("session ID cannot be zero")
	}

	hpc.mutex.Lock()
	defer hpc.mutex.Unlock()

	attempt, exists := hpc.attempts[sessionID]
	if !exists {
		return oops.
			Code("SESSION_NOT_FOUND").
			In("holepunch_coordinator").
			With("session_id", sessionID).
			Errorf("hole punch session not found")
	}

	// Mark as successful
	attempt.State = HolePunchSuccess

	return nil
}

// FailHolePunch marks a hole punch attempt as failed with a reason.
//
// Parameters:
//   - sessionID: Session identifier
//   - reason: Error explaining failure
//
// Returns error if session not found.
func (hpc *HolePunchCoordinator) FailHolePunch(sessionID uint64, reason error) error {
	if sessionID == 0 {
		return oops.
			Code("INVALID_SESSION_ID").
			In("holepunch_coordinator").
			Errorf("session ID cannot be zero")
	}

	hpc.mutex.Lock()
	defer hpc.mutex.Unlock()

	attempt, exists := hpc.attempts[sessionID]
	if !exists {
		return oops.
			Code("SESSION_NOT_FOUND").
			In("holepunch_coordinator").
			With("session_id", sessionID).
			Errorf("hole punch session not found")
	}

	// Mark as failed
	attempt.State = HolePunchFailed

	return nil
}

// GetAttempt retrieves hole punch attempt information.
//
// Parameters:
//   - sessionID: Session identifier
//
// Returns attempt info, or nil if not found.
func (hpc *HolePunchCoordinator) GetAttempt(sessionID uint64) *HolePunchAttempt {
	if sessionID == 0 {
		return nil
	}

	hpc.mutex.RLock()
	defer hpc.mutex.RUnlock()

	attempt, exists := hpc.attempts[sessionID]
	if !exists {
		return nil
	}

	// Return defensive copy
	return &HolePunchAttempt{
		SessionID:  attempt.SessionID,
		RemoteAddr: attempt.RemoteAddr,
		Introducer: attempt.Introducer,
		State:      attempt.State,
		StartTime:  attempt.StartTime,
		Retries:    attempt.Retries,
		RelayTag:   attempt.RelayTag,
	}
}

// RemoveAttempt removes a hole punch attempt from tracking.
//
// Parameters:
//   - sessionID: Session identifier
func (hpc *HolePunchCoordinator) RemoveAttempt(sessionID uint64) {
	if sessionID == 0 {
		return
	}

	hpc.mutex.Lock()
	defer hpc.mutex.Unlock()

	delete(hpc.attempts, sessionID)

	// Remove from relay manager too
	hpc.manager.RemovePendingSession(sessionID)
}

// CleanupExpired removes expired hole punch attempts.
// Attempts are considered expired after 30 seconds per I2P spec.
func (hpc *HolePunchCoordinator) CleanupExpired() {
	hpc.mutex.Lock()
	defer hpc.mutex.Unlock()

	now := time.Now()
	timeout := 30 * time.Second

	for sessionID, attempt := range hpc.attempts {
		if now.Sub(attempt.StartTime) > timeout {
			delete(hpc.attempts, sessionID)
			hpc.manager.RemovePendingSession(sessionID)
		}
	}
}

// GetStats returns statistics about active hole punch attempts.
//
// Returns a map with attempt counts by state.
func (hpc *HolePunchCoordinator) GetStats() map[string]int {
	hpc.mutex.RLock()
	defer hpc.mutex.RUnlock()

	stats := map[string]int{
		"total":     len(hpc.attempts),
		"requested": 0,
		"sent":      0,
		"waiting":   0,
		"success":   0,
		"failed":    0,
	}

	for _, attempt := range hpc.attempts {
		switch attempt.State {
		case HolePunchRequested:
			stats["requested"]++
		case HolePunchSent:
			stats["sent"]++
		case HolePunchWaiting:
			stats["waiting"]++
		case HolePunchSuccess:
			stats["success"]++
		case HolePunchFailed:
			stats["failed"]++
		}
	}

	return stats
}
