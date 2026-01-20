package ssu2

import (
	"sync"
	"time"
)

// Congestion control constants per SSU2 specification
const (
	// MinCongestionWindow is the minimum congestion window per SSU2 spec (1280 bytes)
	MinCongestionWindow = 1280

	// InitialCongestionWindow is the initial CWND (10 * MSS is common, using min MTU)
	InitialCongestionWindow = MinCongestionWindow * 10

	// MaxCongestionWindow is the maximum CWND to prevent memory exhaustion
	MaxCongestionWindow = 1024 * 1024 // 1 MB

	// SlowStartThreshold is the initial ssthresh (start in slow start mode)
	InitialSlowStartThreshold = MaxCongestionWindow
)

// CongestionState represents the current congestion control state
type CongestionState int

const (
	// SlowStart is the initial state where CWND increases exponentially
	SlowStart CongestionState = iota

	// CongestionAvoidance is the state where CWND increases linearly
	CongestionAvoidance

	// Recovery is the state during fast recovery after packet loss
	Recovery
)

// String returns a human-readable name for the congestion state
func (s CongestionState) String() string {
	switch s {
	case SlowStart:
		return "SlowStart"
	case CongestionAvoidance:
		return "CongestionAvoidance"
	case Recovery:
		return "Recovery"
	default:
		return "Unknown"
	}
}

// CongestionController manages congestion window for SSU2 connections.
// It implements a simplified TCP-style congestion control with:
//   - Slow Start: Exponential growth until ssthresh or loss
//   - Congestion Avoidance: Linear growth after ssthresh
//   - Fast Recovery: Quick recovery from packet loss
//
// The controller is thread-safe and can be used concurrently.
//
// Per SSU2 spec, the minimum congestion window is 1280 bytes to ensure
// at least one minimum-sized packet can always be sent.
type CongestionController struct {
	// cwnd is the congestion window in bytes
	cwnd int

	// ssthresh is the slow start threshold in bytes
	ssthresh int

	// state is the current congestion control state
	state CongestionState

	// bytesAcked tracks bytes acknowledged since last CWND increase
	// Used for linear increase in congestion avoidance
	bytesAcked int

	// rttEstimator provides RTT measurements for decisions
	rttEstimator *RTTEstimator

	// bytesInFlight tracks unacknowledged bytes currently sent
	bytesInFlight int

	// mutex protects all fields for concurrent access
	mutex sync.RWMutex
}

// NewCongestionController creates a new congestion controller.
// If rttEstimator is nil, congestion control will work without RTT-based decisions.
func NewCongestionController(rttEstimator *RTTEstimator) *CongestionController {
	return &CongestionController{
		cwnd:          InitialCongestionWindow,
		ssthresh:      InitialSlowStartThreshold,
		state:         SlowStart,
		bytesAcked:    0,
		bytesInFlight: 0,
		rttEstimator:  rttEstimator,
	}
}

// GetCWND returns the current congestion window in bytes.
func (cc *CongestionController) GetCWND() int {
	cc.mutex.RLock()
	defer cc.mutex.RUnlock()
	return cc.cwnd
}

// GetState returns the current congestion control state.
func (cc *CongestionController) GetState() CongestionState {
	cc.mutex.RLock()
	defer cc.mutex.RUnlock()
	return cc.state
}

// GetSSThresh returns the current slow start threshold.
func (cc *CongestionController) GetSSThresh() int {
	cc.mutex.RLock()
	defer cc.mutex.RUnlock()
	return cc.ssthresh
}

// GetBytesInFlight returns the current bytes in flight (unacknowledged).
func (cc *CongestionController) GetBytesInFlight() int {
	cc.mutex.RLock()
	defer cc.mutex.RUnlock()
	return cc.bytesInFlight
}

// CanSend returns true if more data can be sent given the congestion window.
// It compares bytes in flight against the current CWND.
func (cc *CongestionController) CanSend(packetSize int) bool {
	cc.mutex.RLock()
	defer cc.mutex.RUnlock()
	return cc.bytesInFlight+packetSize <= cc.cwnd
}

// AvailableWindow returns the number of bytes that can still be sent.
// This is CWND minus bytes currently in flight.
func (cc *CongestionController) AvailableWindow() int {
	cc.mutex.RLock()
	defer cc.mutex.RUnlock()

	available := cc.cwnd - cc.bytesInFlight
	if available < 0 {
		return 0
	}
	return available
}

// OnPacketSent records that a packet of the given size has been sent.
// This increases bytes in flight.
func (cc *CongestionController) OnPacketSent(packetSize int) {
	if packetSize <= 0 {
		return
	}

	cc.mutex.Lock()
	defer cc.mutex.Unlock()
	cc.bytesInFlight += packetSize
}

// OnAck processes an acknowledgment for the specified number of bytes.
// This implements CWND growth based on the current state:
//   - SlowStart: Increase CWND by ackedBytes (exponential growth)
//   - CongestionAvoidance: Increase CWND by MSS per RTT (linear growth)
//   - Recovery: Stay in recovery until all loss is recovered
func (cc *CongestionController) OnAck(ackedBytes int) {
	if ackedBytes <= 0 {
		return
	}

	cc.mutex.Lock()
	defer cc.mutex.Unlock()

	// Decrease bytes in flight
	cc.bytesInFlight -= ackedBytes
	if cc.bytesInFlight < 0 {
		cc.bytesInFlight = 0
	}

	switch cc.state {
	case SlowStart:
		cc.handleSlowStartAck(ackedBytes)
	case CongestionAvoidance:
		cc.handleCongestionAvoidanceAck(ackedBytes)
	case Recovery:
		// In recovery, just acknowledge bytes without CWND increase
		// Exit recovery when all lost packets are acknowledged
	}
}

// handleSlowStartAck processes ACK during slow start phase.
// CWND increases by ackedBytes for each ACK (exponential growth).
func (cc *CongestionController) handleSlowStartAck(ackedBytes int) {
	// Increase CWND by the number of bytes acknowledged
	cc.cwnd += ackedBytes

	// Cap at maximum
	if cc.cwnd > MaxCongestionWindow {
		cc.cwnd = MaxCongestionWindow
	}

	// Check if we should transition to congestion avoidance
	if cc.cwnd >= cc.ssthresh {
		cc.state = CongestionAvoidance
	}
}

// handleCongestionAvoidanceAck processes ACK during congestion avoidance.
// CWND increases by approximately MSS per RTT (linear growth).
// We track bytes acked and increase CWND when we've acked CWND bytes.
func (cc *CongestionController) handleCongestionAvoidanceAck(ackedBytes int) {
	// Accumulate acknowledged bytes
	cc.bytesAcked += ackedBytes

	// Increase CWND by MSS when we've acknowledged CWND bytes
	// This gives approximately one MSS increase per RTT
	if cc.bytesAcked >= cc.cwnd {
		cc.cwnd += MinCongestionWindow // Increase by one MSS
		cc.bytesAcked -= cc.cwnd       // Carry over excess
		if cc.bytesAcked < 0 {
			cc.bytesAcked = 0
		}
	}

	// Cap at maximum
	if cc.cwnd > MaxCongestionWindow {
		cc.cwnd = MaxCongestionWindow
	}
}

// OnPacketLoss handles a detected packet loss event.
// This implements multiplicative decrease:
//   - Set ssthresh to max(CWND/2, MinCWND)
//   - Set CWND to ssthresh (or MinCWND in severe cases)
//   - Enter recovery state
func (cc *CongestionController) OnPacketLoss() {
	cc.mutex.Lock()
	defer cc.mutex.Unlock()

	// Already in recovery, don't reduce further
	if cc.state == Recovery {
		return
	}

	// Multiplicative decrease: ssthresh = max(cwnd/2, min_cwnd)
	cc.ssthresh = cc.cwnd / 2
	if cc.ssthresh < MinCongestionWindow {
		cc.ssthresh = MinCongestionWindow
	}

	// Set CWND to ssthresh (standard Reno behavior)
	cc.cwnd = cc.ssthresh

	// Enter recovery state
	cc.state = Recovery
	cc.bytesAcked = 0
}

// OnRetransmissionTimeout handles an RTO event (more severe than packet loss).
// This resets to slow start with minimal CWND:
//   - Set ssthresh to max(CWND/2, MinCWND)
//   - Set CWND to MinCWND
//   - Enter slow start
func (cc *CongestionController) OnRetransmissionTimeout() {
	cc.mutex.Lock()
	defer cc.mutex.Unlock()

	// Multiplicative decrease for ssthresh
	cc.ssthresh = cc.cwnd / 2
	if cc.ssthresh < MinCongestionWindow {
		cc.ssthresh = MinCongestionWindow
	}

	// Reset CWND to minimum (restart slow start)
	cc.cwnd = MinCongestionWindow

	// Clear bytes in flight (they will be retransmitted)
	cc.bytesInFlight = 0

	// Enter slow start
	cc.state = SlowStart
	cc.bytesAcked = 0
}

// ExitRecovery transitions from recovery state to congestion avoidance.
// This should be called when all lost packets have been acknowledged.
func (cc *CongestionController) ExitRecovery() {
	cc.mutex.Lock()
	defer cc.mutex.Unlock()

	if cc.state == Recovery {
		cc.state = CongestionAvoidance
		cc.bytesAcked = 0
	}
}

// Reset returns the controller to initial state.
// This is useful after connection migration or significant path changes.
func (cc *CongestionController) Reset() {
	cc.mutex.Lock()
	defer cc.mutex.Unlock()

	cc.cwnd = InitialCongestionWindow
	cc.ssthresh = InitialSlowStartThreshold
	cc.state = SlowStart
	cc.bytesAcked = 0
	cc.bytesInFlight = 0
}

// GetStats returns current congestion control statistics.
func (cc *CongestionController) GetStats() CongestionStats {
	cc.mutex.RLock()
	defer cc.mutex.RUnlock()

	return CongestionStats{
		CWND:          cc.cwnd,
		SSThresh:      cc.ssthresh,
		State:         cc.state,
		BytesInFlight: cc.bytesInFlight,
	}
}

// CongestionStats contains a snapshot of congestion control state.
type CongestionStats struct {
	CWND          int
	SSThresh      int
	State         CongestionState
	BytesInFlight int
}

// UpdateRTTEstimator sets or replaces the RTT estimator.
// This can be used to attach an RTT estimator after creation.
func (cc *CongestionController) UpdateRTTEstimator(rtt *RTTEstimator) {
	cc.mutex.Lock()
	defer cc.mutex.Unlock()
	cc.rttEstimator = rtt
}

// ShouldProbe returns true if the controller recommends probing for more bandwidth.
// This is useful for implementing bandwidth probing during idle periods.
func (cc *CongestionController) ShouldProbe() bool {
	cc.mutex.RLock()
	defer cc.mutex.RUnlock()

	// Probe if CWND is less than half of max and we have capacity
	return cc.cwnd < MaxCongestionWindow/2 && cc.bytesInFlight < cc.cwnd/2
}

// SetCWND manually sets the congestion window (for testing or special cases).
// The value is clamped to [MinCongestionWindow, MaxCongestionWindow].
func (cc *CongestionController) SetCWND(cwnd int) {
	cc.mutex.Lock()
	defer cc.mutex.Unlock()

	if cwnd < MinCongestionWindow {
		cwnd = MinCongestionWindow
	} else if cwnd > MaxCongestionWindow {
		cwnd = MaxCongestionWindow
	}
	cc.cwnd = cwnd
}

// TimeSinceLastAck can be used for idle timeout detection.
// If no RTT estimator is set or it's not initialized, returns 0.
func (cc *CongestionController) GetRTO() time.Duration {
	cc.mutex.RLock()
	defer cc.mutex.RUnlock()

	if cc.rttEstimator == nil {
		return time.Second // Default RTO
	}
	return cc.rttEstimator.GetRTO()
}
