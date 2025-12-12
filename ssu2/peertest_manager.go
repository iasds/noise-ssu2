package ssu2

import (
	"crypto/rand"
	"encoding/binary"
	"net"
	"sync"
	"time"

	"github.com/samber/oops"
)

// PeerTestManager manages the seven-message NAT traversal testing protocol.
// It coordinates peer tests to determine NAT type and external reachability.
//
// Design rationale:
// - Nonce generation uses crypto/rand for security
// - State machine tracks test progression through 7 messages
// - Results cached by remote address for efficiency
// - Thread-safe for concurrent test operations
//
// Protocol flow:
// 1. Alice → Bob: Request (InitiatePeerTest)
// 2. Bob → Charlie: Relay request
// 3. Charlie → Bob: Relay response
// 4. Bob → Alice: Result
// 5. Charlie → Alice: Probe
// 6. Alice → Charlie: Reply
// 7. Charlie → Alice: Confirmation
//
// Thread Safety: All public methods are thread-safe.
type PeerTestManager struct {
	// listener is the parent SSU2Listener
	listener *SSU2Listener

	// tests maps nonce to active peer test
	tests map[uint32]*PeerTest

	// results maps remote address to test result
	results map[string]*TestResult

	// mutex protects all fields
	mutex sync.RWMutex
}

// PeerTestRole represents the role of a peer in the test.
type PeerTestRole int

const (
	// RoleInitiator is Alice who initiates the test
	RoleInitiator PeerTestRole = iota

	// RoleRelay is Bob who relays messages
	RoleRelay

	// RoleResponder is Charlie who responds to test
	RoleResponder
)

// String returns human-readable role name.
func (r PeerTestRole) String() string {
	switch r {
	case RoleInitiator:
		return "Initiator"
	case RoleRelay:
		return "Relay"
	case RoleResponder:
		return "Responder"
	default:
		return "Unknown"
	}
}

// PeerTestState represents the current state of a peer test.
type PeerTestState int

const (
	// TestRequested indicates test has been requested
	TestRequested PeerTestState = iota

	// TestRelayed indicates test has been relayed to responder
	TestRelayed

	// TestProbed indicates probe has been sent
	TestProbed

	// TestComplete indicates test completed successfully
	TestComplete

	// TestFailed indicates test failed
	TestFailed
)

// String returns human-readable state name.
func (s PeerTestState) String() string {
	switch s {
	case TestRequested:
		return "Requested"
	case TestRelayed:
		return "Relayed"
	case TestProbed:
		return "Probed"
	case TestComplete:
		return "Complete"
	case TestFailed:
		return "Failed"
	default:
		return "Unknown"
	}
}

// PeerTest represents an active peer test operation.
type PeerTest struct {
	// Nonce uniquely identifies this test
	Nonce uint32

	// Role is this peer's role in the test
	Role PeerTestRole

	// State is the current test state
	State PeerTestState

	// AliceAddr is the initiator's address
	AliceAddr *net.UDPAddr

	// BobAddr is the relay's address
	BobAddr *net.UDPAddr

	// CharlieAddr is the responder's address
	CharlieAddr *net.UDPAddr

	// StartTime is when the test was initiated
	StartTime time.Time

	// Timeouts tracks timeout times for each message
	Timeouts []time.Time

	// NATType is the determined NAT type
	NATType NATType

	// Reachable indicates if peer is directly reachable
	Reachable bool

	// ExternalAddr is the detected external address
	ExternalAddr *net.UDPAddr
}

// NATType represents the type of NAT detected.
type NATType int

const (
	// NATUnknown indicates NAT type is not yet determined
	NATUnknown NATType = iota

	// NATNone indicates no NAT (public IP)
	NATNone

	// NATCone indicates full cone NAT
	NATCone

	// NATRestricted indicates restricted cone NAT
	NATRestricted

	// NATPortRestricted indicates port-restricted cone NAT
	NATPortRestricted

	// NATSymmetric indicates symmetric NAT
	NATSymmetric
)

// String returns human-readable NAT type name.
func (n NATType) String() string {
	switch n {
	case NATUnknown:
		return "Unknown"
	case NATNone:
		return "None"
	case NATCone:
		return "Full Cone"
	case NATRestricted:
		return "Restricted Cone"
	case NATPortRestricted:
		return "Port-Restricted Cone"
	case NATSymmetric:
		return "Symmetric"
	default:
		return "Unknown"
	}
}

// TestResult stores the results of a completed peer test.
type TestResult struct {
	// NATType is the determined NAT type
	NATType NATType

	// ExternalAddr is the detected external address
	ExternalAddr *net.UDPAddr

	// ExternalPort is the detected external port
	ExternalPort uint16

	// Reachable indicates if peer is directly reachable
	Reachable bool

	// TestTime is when the test completed
	TestTime time.Time

	// DirectProbeSuccess indicates if Charlie → Alice direct probe succeeded
	DirectProbeSuccess bool

	// RelayedProbeSuccess indicates if Charlie → Alice via Bob succeeded
	RelayedProbeSuccess bool

	// PortConsistent indicates if external port is consistent
	PortConsistent bool

	// IPConsistent indicates if external IP is consistent
	IPConsistent bool
}

// NewPeerTestManager creates a new PeerTestManager.
//
// Parameters:
//   - listener: The SSU2Listener to manage peer tests for
//
// Returns a new PeerTestManager with empty state.
func NewPeerTestManager(listener *SSU2Listener) *PeerTestManager {
	return &PeerTestManager{
		listener: listener,
		tests:    make(map[uint32]*PeerTest),
		results:  make(map[string]*TestResult),
	}
}

// InitiatePeerTest starts a new peer test as Alice (initiator).
//
// Design rationale:
// - Generates cryptographically random nonce for test identification
// - Creates test record with 60-second timeout per I2P spec
// - Returns nonce for tracking test progress
//
// Parameters:
//   - bobAddr: Address of Bob (relay peer)
//
// Returns nonce on success, error otherwise.
func (ptm *PeerTestManager) InitiatePeerTest(bobAddr *net.UDPAddr) (uint32, error) {
	if bobAddr == nil {
		return 0, oops.
			Code("INVALID_ADDRESS").
			In("peertest_manager").
			Errorf("bob address cannot be nil")
	}

	// Generate cryptographically random nonce
	var nonceBytes [4]byte
	if _, err := rand.Read(nonceBytes[:]); err != nil {
		return 0, oops.
			Code("RANDOM_GENERATION_FAILED").
			In("peertest_manager").
			With("error", err.Error()).
			Errorf("failed to generate nonce: %w", err)
	}
	nonce := binary.BigEndian.Uint32(nonceBytes[:])

	// Avoid zero nonce
	if nonce == 0 {
		nonce = 1
	}

	ptm.mutex.Lock()
	defer ptm.mutex.Unlock()

	// Check for duplicate nonce
	if _, exists := ptm.tests[nonce]; exists {
		return 0, oops.
			Code("DUPLICATE_NONCE").
			In("peertest_manager").
			With("nonce", nonce).
			Errorf("nonce already in use")
	}

	// Create peer test
	test := &PeerTest{
		Nonce:     nonce,
		Role:      RoleInitiator,
		State:     TestRequested,
		BobAddr:   bobAddr,
		StartTime: time.Now(),
		Timeouts:  make([]time.Time, 7), // 7 messages in protocol
	}

	// Set timeout for first message (60 seconds per I2P spec)
	test.Timeouts[0] = time.Now().Add(60 * time.Second)

	ptm.tests[nonce] = test

	return nonce, nil
}

// GetTest retrieves peer test information by nonce.
//
// Parameters:
//   - nonce: Test nonce
//
// Returns test copy, or nil if not found.
func (ptm *PeerTestManager) GetTest(nonce uint32) *PeerTest {
	if nonce == 0 {
		return nil
	}

	ptm.mutex.RLock()
	defer ptm.mutex.RUnlock()

	test, exists := ptm.tests[nonce]
	if !exists {
		return nil
	}

	// Return defensive copy
	testCopy := *test
	if test.AliceAddr != nil {
		addr := *test.AliceAddr
		testCopy.AliceAddr = &addr
	}
	if test.BobAddr != nil {
		addr := *test.BobAddr
		testCopy.BobAddr = &addr
	}
	if test.CharlieAddr != nil {
		addr := *test.CharlieAddr
		testCopy.CharlieAddr = &addr
	}
	if test.ExternalAddr != nil {
		addr := *test.ExternalAddr
		testCopy.ExternalAddr = &addr
	}

	return &testCopy
}

// UpdateState updates the state of a peer test.
//
// Parameters:
//   - nonce: Test nonce
//   - state: New state
//
// Returns error if test not found.
func (ptm *PeerTestManager) UpdateState(nonce uint32, state PeerTestState) error {
	if nonce == 0 {
		return oops.
			Code("INVALID_NONCE").
			In("peertest_manager").
			Errorf("nonce cannot be zero")
	}

	ptm.mutex.Lock()
	defer ptm.mutex.Unlock()

	test, exists := ptm.tests[nonce]
	if !exists {
		return oops.
			Code("TEST_NOT_FOUND").
			In("peertest_manager").
			With("nonce", nonce).
			Errorf("peer test not found")
	}

	test.State = state

	return nil
}

// CompleteTest marks a test as complete and stores the result.
//
// Parameters:
//   - nonce: Test nonce
//   - result: Test result to store
//
// Returns error if test not found.
func (ptm *PeerTestManager) CompleteTest(nonce uint32, result *TestResult) error {
	if nonce == 0 {
		return oops.
			Code("INVALID_NONCE").
			In("peertest_manager").
			Errorf("nonce cannot be zero")
	}

	if result == nil {
		return oops.
			Code("INVALID_RESULT").
			In("peertest_manager").
			Errorf("result cannot be nil")
	}

	ptm.mutex.Lock()
	defer ptm.mutex.Unlock()

	test, exists := ptm.tests[nonce]
	if !exists {
		return oops.
			Code("TEST_NOT_FOUND").
			In("peertest_manager").
			With("nonce", nonce).
			Errorf("peer test not found")
	}

	// Update test state
	test.State = TestComplete
	test.NATType = result.NATType
	test.Reachable = result.Reachable
	test.ExternalAddr = result.ExternalAddr

	// Store result by address (if available)
	if test.AliceAddr != nil {
		ptm.results[test.AliceAddr.String()] = result
	}

	return nil
}

// FailTest marks a test as failed.
//
// Parameters:
//   - nonce: Test nonce
//   - reason: Error explaining failure
//
// Returns error if test not found.
func (ptm *PeerTestManager) FailTest(nonce uint32, reason error) error {
	if nonce == 0 {
		return oops.
			Code("INVALID_NONCE").
			In("peertest_manager").
			Errorf("nonce cannot be zero")
	}

	ptm.mutex.Lock()
	defer ptm.mutex.Unlock()

	test, exists := ptm.tests[nonce]
	if !exists {
		return oops.
			Code("TEST_NOT_FOUND").
			In("peertest_manager").
			With("nonce", nonce).
			Errorf("peer test not found")
	}

	test.State = TestFailed

	return nil
}

// GetResult retrieves cached test result for an address.
//
// Parameters:
//   - addr: Remote address
//
// Returns result copy, or nil if not found.
func (ptm *PeerTestManager) GetResult(addr *net.UDPAddr) *TestResult {
	if addr == nil {
		return nil
	}

	ptm.mutex.RLock()
	defer ptm.mutex.RUnlock()

	result, exists := ptm.results[addr.String()]
	if !exists {
		return nil
	}

	// Return defensive copy
	resultCopy := *result
	if result.ExternalAddr != nil {
		addrCopy := *result.ExternalAddr
		resultCopy.ExternalAddr = &addrCopy
	}

	return &resultCopy
}

// RemoveTest removes a test from tracking.
//
// Parameters:
//   - nonce: Test nonce
func (ptm *PeerTestManager) RemoveTest(nonce uint32) {
	if nonce == 0 {
		return
	}

	ptm.mutex.Lock()
	defer ptm.mutex.Unlock()

	delete(ptm.tests, nonce)
}

// CleanupExpired removes tests that have exceeded their timeout.
func (ptm *PeerTestManager) CleanupExpired() {
	now := time.Now()

	ptm.mutex.Lock()
	defer ptm.mutex.Unlock()

	for nonce, test := range ptm.tests {
		// Check if test has timed out (60 seconds per I2P spec)
		if now.Sub(test.StartTime) > 60*time.Second {
			delete(ptm.tests, nonce)
		}
	}
}

// GetStats returns statistics about active tests.
func (ptm *PeerTestManager) GetStats() map[string]int {
	ptm.mutex.RLock()
	defer ptm.mutex.RUnlock()

	stats := make(map[string]int)
	stats["total_tests"] = len(ptm.tests)
	stats["cached_results"] = len(ptm.results)

	// Count by state
	for _, test := range ptm.tests {
		switch test.State {
		case TestRequested:
			stats["requested"]++
		case TestRelayed:
			stats["relayed"]++
		case TestProbed:
			stats["probed"]++
		case TestComplete:
			stats["complete"]++
		case TestFailed:
			stats["failed"]++
		}
	}

	// Count by role
	for _, test := range ptm.tests {
		switch test.Role {
		case RoleInitiator:
			stats["role_initiator"]++
		case RoleRelay:
			stats["role_relay"]++
		case RoleResponder:
			stats["role_responder"]++
		}
	}

	return stats
}

// DetermineNATType analyzes test results to determine NAT type.
//
// Logic per I2P specification:
// - Both probes succeed + consistent port/IP = No NAT or Full Cone
// - Direct fails + relayed succeeds = Symmetric or Port-Restricted
// - Port inconsistent = Symmetric NAT
// - IP inconsistent = Multiple NATs or proxy
//
// Parameters:
//   - result: Test result with probe outcomes
//
// Returns determined NAT type.
func (ptm *PeerTestManager) DetermineNATType(result *TestResult) NATType {
	if result == nil {
		return NATUnknown
	}

	// Both probes succeeded
	if result.DirectProbeSuccess && result.RelayedProbeSuccess {
		if result.PortConsistent && result.IPConsistent {
			// Likely no NAT or full cone NAT
			return NATCone
		}
		if !result.PortConsistent {
			// Port changes = symmetric or port-restricted
			return NATPortRestricted
		}
		if !result.IPConsistent {
			// IP changes = multiple NATs or proxies
			return NATRestricted
		}
	}

	// Only relayed probe succeeded
	if !result.DirectProbeSuccess && result.RelayedProbeSuccess {
		if result.PortConsistent {
			// Port stays same but direct fails = restricted cone
			return NATRestricted
		}
		// Port changes = symmetric NAT
		return NATSymmetric
	}

	// Neither probe succeeded
	if !result.DirectProbeSuccess && !result.RelayedProbeSuccess {
		return NATUnknown
	}

	// Only direct succeeded (unusual case)
	if result.DirectProbeSuccess && !result.RelayedProbeSuccess {
		return NATCone
	}

	return NATUnknown
}
