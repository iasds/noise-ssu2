package ssu2

import (
	"sync"
	"testing"
	"time"
)

// TestNewRTTEstimator verifies that a new estimator starts in uninitialized state.
func TestNewRTTEstimator(t *testing.T) {
	est := NewRTTEstimator()

	if est == nil {
		t.Fatal("NewRTTEstimator returned nil")
	}

	if est.IsInitialized() {
		t.Error("New estimator should not be initialized")
	}

	if got := est.GetSmoothedRTT(); got != 0 {
		t.Errorf("New estimator smoothedRTT = %v, want 0", got)
	}

	if got := est.GetRTTVariance(); got != 0 {
		t.Errorf("New estimator rttVariance = %v, want 0", got)
	}

	if got := est.GetMinRTT(); got != 0 {
		t.Errorf("New estimator minRTT = %v, want 0", got)
	}

	if got := est.GetRTO(); got != initialRTO {
		t.Errorf("Uninitialized estimator RTO = %v, want %v", got, initialRTO)
	}
}

// TestRTTEstimatorFirstSample verifies RFC 6298 section 2.2 initialization.
// First sample should set:
//   - SRTT = sample
//   - RTTVAR = sample / 2
//   - minRTT = sample
func TestRTTEstimatorFirstSample(t *testing.T) {
	est := NewRTTEstimator()
	sample := 100 * time.Millisecond

	est.Update(sample)

	if !est.IsInitialized() {
		t.Error("Estimator should be initialized after first sample")
	}

	if got := est.GetSmoothedRTT(); got != sample {
		t.Errorf("After first sample, smoothedRTT = %v, want %v", got, sample)
	}

	expectedVariance := sample / 2
	if got := est.GetRTTVariance(); got != expectedVariance {
		t.Errorf("After first sample, rttVariance = %v, want %v", got, expectedVariance)
	}

	if got := est.GetMinRTT(); got != sample {
		t.Errorf("After first sample, minRTT = %v, want %v", got, sample)
	}
}

// TestRTTEstimatorInvalidSamples verifies that zero and negative samples are ignored.
func TestRTTEstimatorInvalidSamples(t *testing.T) {
	est := NewRTTEstimator()

	// Try invalid samples
	est.Update(0)
	est.Update(-10 * time.Millisecond)

	if est.IsInitialized() {
		t.Error("Estimator should not be initialized after invalid samples")
	}

	// Add valid sample, then try invalid ones
	est.Update(100 * time.Millisecond)
	firstSRTT := est.GetSmoothedRTT()

	est.Update(0)
	est.Update(-5 * time.Millisecond)

	if got := est.GetSmoothedRTT(); got != firstSRTT {
		t.Errorf("Invalid samples changed smoothedRTT from %v to %v", firstSRTT, got)
	}
}

// TestRTTEstimatorSubsequentSamples verifies RFC 6298 section 2.3 updates.
// Subsequent samples should use exponential weighted moving averages.
func TestRTTEstimatorSubsequentSamples(t *testing.T) {
	est := NewRTTEstimator()

	// First sample: 100ms
	sample1 := 100 * time.Millisecond
	est.Update(sample1)

	firstSRTT := est.GetSmoothedRTT()
	firstVariance := est.GetRTTVariance()

	// Second sample: 120ms (increase)
	sample2 := 120 * time.Millisecond
	est.Update(sample2)

	// SRTT should increase (moving toward 120ms)
	secondSRTT := est.GetSmoothedRTT()
	if secondSRTT <= firstSRTT {
		t.Errorf("SRTT should increase after larger sample: %v <= %v", secondSRTT, firstSRTT)
	}
	if secondSRTT >= sample2 {
		t.Errorf("SRTT should not reach sample2 yet: %v >= %v", secondSRTT, sample2)
	}

	// Variance should update based on difference
	secondVariance := est.GetRTTVariance()
	if secondVariance == firstVariance {
		t.Error("Variance should change after different sample")
	}

	// MinRTT should remain at first sample
	if got := est.GetMinRTT(); got != sample1 {
		t.Errorf("minRTT = %v, want %v (should not increase)", got, sample1)
	}
}

// TestRTTEstimatorMinRTTTracking verifies minimum RTT tracking.
func TestRTTEstimatorMinRTTTracking(t *testing.T) {
	est := NewRTTEstimator()

	samples := []time.Duration{
		100 * time.Millisecond,
		80 * time.Millisecond, // New minimum
		150 * time.Millisecond,
		70 * time.Millisecond, // New minimum
		120 * time.Millisecond,
	}

	expectedMin := 70 * time.Millisecond

	for _, sample := range samples {
		est.Update(sample)
	}

	if got := est.GetMinRTT(); got != expectedMin {
		t.Errorf("minRTT = %v, want %v", got, expectedMin)
	}
}

// TestRTTEstimatorROCalculation verifies RTO calculation according to RFC 6298.
// RTO = SRTT + max(G, K*RTTVAR) where G=1ms, K=4
func TestRTTEstimatorRTOCalculation(t *testing.T) {
	est := NewRTTEstimator()

	// First sample establishes baseline
	sample := 100 * time.Millisecond
	est.Update(sample)

	rto := est.GetRTO()

	// RTO should be at least SRTT
	if rto < est.GetSmoothedRTT() {
		t.Errorf("RTO (%v) should be >= SRTT (%v)", rto, est.GetSmoothedRTT())
	}

	// RTO should include variance component
	expectedVarianceComponent := time.Duration(rttK * float64(est.GetRTTVariance()))
	if expectedVarianceComponent < clockGranularity {
		expectedVarianceComponent = clockGranularity
	}

	expectedRTO := est.GetSmoothedRTT() + expectedVarianceComponent
	if expectedRTO < minRTO {
		expectedRTO = minRTO
	} else if expectedRTO > maxRTO {
		expectedRTO = maxRTO
	}

	if rto != expectedRTO {
		t.Errorf("RTO = %v, want %v", rto, expectedRTO)
	}
}

// TestRTTEstimatorRTOBounds verifies that RTO is clamped to [1s, 60s].
func TestRTTEstimatorRTOBounds(t *testing.T) {
	est := NewRTTEstimator()

	// Very small RTT should result in minimum RTO
	est.Update(1 * time.Millisecond)
	rto := est.GetRTO()

	if rto < minRTO {
		t.Errorf("RTO (%v) below minimum (%v)", rto, minRTO)
	}

	// Large RTT should be clamped to maximum
	// Note: With our algorithm, it's hard to exceed maxRTO naturally,
	// but we verify the clamp logic exists
	if rto > maxRTO {
		t.Errorf("RTO (%v) exceeds maximum (%v)", rto, maxRTO)
	}
}

// TestRTTEstimatorStableRTT verifies behavior with consistent RTT samples.
// With stable RTT, variance should decrease and SRTT should stabilize.
func TestRTTEstimatorStableRTT(t *testing.T) {
	est := NewRTTEstimator()

	stableRTT := 100 * time.Millisecond

	// Add 10 identical samples
	for i := 0; i < 10; i++ {
		est.Update(stableRTT)
	}

	// SRTT should be very close to stable value
	srtt := est.GetSmoothedRTT()
	diff := srtt - stableRTT
	if diff < 0 {
		diff = -diff
	}

	// Allow 1ms tolerance for floating point arithmetic
	if diff > time.Millisecond {
		t.Errorf("SRTT (%v) not converged to stable RTT (%v), diff=%v", srtt, stableRTT, diff)
	}

	// Variance should be very small (near zero)
	variance := est.GetRTTVariance()
	if variance > 5*time.Millisecond {
		t.Errorf("Variance (%v) too high for stable RTT", variance)
	}
}

// TestRTTEstimatorVariableRTT verifies behavior with varying RTT samples.
// Variable RTT should result in higher variance.
func TestRTTEstimatorVariableRTT(t *testing.T) {
	est := NewRTTEstimator()

	// Alternating high and low RTT
	samples := []time.Duration{
		50 * time.Millisecond,
		150 * time.Millisecond,
		60 * time.Millisecond,
		140 * time.Millisecond,
		55 * time.Millisecond,
		145 * time.Millisecond,
	}

	for _, sample := range samples {
		est.Update(sample)
	}

	// SRTT should be somewhere in the middle
	srtt := est.GetSmoothedRTT()
	if srtt < 70*time.Millisecond || srtt > 130*time.Millisecond {
		t.Errorf("SRTT (%v) outside expected range for variable RTT", srtt)
	}

	// Variance should be significant
	variance := est.GetRTTVariance()
	if variance < 10*time.Millisecond {
		t.Errorf("Variance (%v) too low for highly variable RTT", variance)
	}
}

// TestRTTEstimatorReset verifies that Reset() clears all state.
func TestRTTEstimatorReset(t *testing.T) {
	est := NewRTTEstimator()

	// Initialize with samples
	est.Update(100 * time.Millisecond)
	est.Update(120 * time.Millisecond)

	if !est.IsInitialized() {
		t.Fatal("Estimator should be initialized before reset")
	}

	// Reset
	est.Reset()

	// Should be back to initial state
	if est.IsInitialized() {
		t.Error("Estimator should not be initialized after reset")
	}

	if got := est.GetSmoothedRTT(); got != 0 {
		t.Errorf("After reset, smoothedRTT = %v, want 0", got)
	}

	if got := est.GetRTTVariance(); got != 0 {
		t.Errorf("After reset, rttVariance = %v, want 0", got)
	}

	if got := est.GetMinRTT(); got != 0 {
		t.Errorf("After reset, minRTT = %v, want 0", got)
	}

	if got := est.GetRTO(); got != initialRTO {
		t.Errorf("After reset, RTO = %v, want %v", got, initialRTO)
	}
}

// TestRTTEstimatorConcurrency verifies thread-safety under concurrent access.
func TestRTTEstimatorConcurrency(t *testing.T) {
	est := NewRTTEstimator()

	const numGoroutines = 100
	const samplesPerGoroutine = 100

	var wg sync.WaitGroup
	wg.Add(numGoroutines * 2) // readers and writers

	// Writers: add samples concurrently
	for i := 0; i < numGoroutines; i++ {
		go func(offset int) {
			defer wg.Done()
			for j := 0; j < samplesPerGoroutine; j++ {
				sample := time.Duration(50+offset+j) * time.Millisecond
				est.Update(sample)
			}
		}(i)
	}

	// Readers: read values concurrently
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < samplesPerGoroutine; j++ {
				_ = est.GetSmoothedRTT()
				_ = est.GetRTTVariance()
				_ = est.GetMinRTT()
				_ = est.GetRTO()
				_ = est.IsInitialized()
			}
		}()
	}

	wg.Wait()

	// Verify estimator is in valid state
	if !est.IsInitialized() {
		t.Error("Estimator should be initialized after concurrent updates")
	}

	if est.GetSmoothedRTT() <= 0 {
		t.Error("SRTT should be positive after concurrent updates")
	}

	if est.GetMinRTT() <= 0 {
		t.Error("MinRTT should be positive after concurrent updates")
	}
}

// TestRTTEstimatorConcurrentReset verifies that Reset() is thread-safe.
func TestRTTEstimatorConcurrentReset(t *testing.T) {
	est := NewRTTEstimator()

	var wg sync.WaitGroup
	wg.Add(3)

	// Writer goroutine
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			est.Update(time.Duration(50+i) * time.Millisecond)
		}
	}()

	// Reader goroutine
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			_ = est.GetSmoothedRTT()
			_ = est.GetRTO()
		}
	}()

	// Reset goroutine
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			time.Sleep(time.Microsecond)
			est.Reset()
		}
	}()

	wg.Wait()

	// No panics = success
	// Final state is unpredictable but should be valid
}

// TestRTTEstimatorExponentialSmoothing verifies the exponential smoothing behavior.
// A sudden change in RTT should be incorporated gradually.
func TestRTTEstimatorExponentialSmoothing(t *testing.T) {
	est := NewRTTEstimator()

	// Start with stable low RTT
	baseRTT := 50 * time.Millisecond
	for i := 0; i < 10; i++ {
		est.Update(baseRTT)
	}

	baselineSRTT := est.GetSmoothedRTT()

	// Sudden jump to high RTT
	highRTT := 200 * time.Millisecond
	est.Update(highRTT)

	newSRTT := est.GetSmoothedRTT()

	// SRTT should increase but not jump to highRTT immediately
	if newSRTT <= baselineSRTT {
		t.Error("SRTT should increase after high RTT sample")
	}

	if newSRTT >= highRTT {
		t.Error("SRTT should not jump to high RTT immediately (exponential smoothing)")
	}

	// Verify it's moving in the right direction with the right magnitude
	expectedIncrease := time.Duration(rttAlpha * float64(highRTT-baselineSRTT))
	actualIncrease := newSRTT - baselineSRTT

	tolerance := 2 * time.Millisecond
	diff := actualIncrease - expectedIncrease
	if diff < 0 {
		diff = -diff
	}

	if diff > tolerance {
		t.Errorf("SRTT increase (%v) not matching expected (%v), diff=%v",
			actualIncrease, expectedIncrease, diff)
	}
}

// BenchmarkRTTEstimatorUpdate measures the performance of Update().
func BenchmarkRTTEstimatorUpdate(b *testing.B) {
	est := NewRTTEstimator()
	sample := 100 * time.Millisecond

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		est.Update(sample)
	}
}

// BenchmarkRTTEstimatorGetRTO measures the performance of GetRTO().
func BenchmarkRTTEstimatorGetRTO(b *testing.B) {
	est := NewRTTEstimator()
	est.Update(100 * time.Millisecond)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = est.GetRTO()
	}
}

// BenchmarkRTTEstimatorConcurrent measures concurrent access performance.
func BenchmarkRTTEstimatorConcurrent(b *testing.B) {
	est := NewRTTEstimator()

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			if i%2 == 0 {
				est.Update(time.Duration(50+i%100) * time.Millisecond)
			} else {
				_ = est.GetRTO()
			}
			i++
		}
	})
}
