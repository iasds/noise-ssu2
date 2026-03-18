package ssu2

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockSendReceiver implements SendReceiver for testing.
type mockSendReceiver struct {
	sendKeepaliveCalled int
	sendKeepaliveError  error
	mutex               sync.Mutex
}

func (m *mockSendReceiver) SendKeepalive() error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.sendKeepaliveCalled++
	return m.sendKeepaliveError
}

func (m *mockSendReceiver) getCallCount() int {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	return m.sendKeepaliveCalled
}

func (m *mockSendReceiver) resetCallCount() {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.sendKeepaliveCalled = 0
}

// TestNewKeepaliveManager tests manager creation with various parameters.
func TestNewKeepaliveManager(t *testing.T) {
	conn := &mockSendReceiver{}

	// Test with explicit values
	km := NewKeepaliveManager(conn, 10*time.Second, 30*time.Second)
	require.NotNil(t, km)
	assert.Equal(t, 10*time.Second, km.interval)
	assert.Equal(t, 30*time.Second, km.timeout)
	assert.False(t, km.started)
	assert.NotNil(t, km.stopChan)

	// Verify initial timestamps are recent
	now := time.Now()
	assert.WithinDuration(t, now, km.lastSent, time.Second)
	assert.WithinDuration(t, now, km.lastRecv, time.Second)
}

// TestNewKeepaliveManager_DefaultValues tests default parameter handling.
func TestNewKeepaliveManager_DefaultValues(t *testing.T) {
	conn := &mockSendReceiver{}

	// Test with zero values (should use defaults)
	km := NewKeepaliveManager(conn, 0, 0)
	require.NotNil(t, km)
	assert.Equal(t, 15*time.Second, km.interval) // SSU2.md default
	assert.Equal(t, 45*time.Second, km.timeout)  // 3x interval
}

// TestKeepaliveManager_StartStop tests lifecycle management.
func TestKeepaliveManager_StartStop(t *testing.T) {
	conn := &mockSendReceiver{}
	km := NewKeepaliveManager(conn, 100*time.Millisecond, 300*time.Millisecond)

	// Verify not started initially
	assert.False(t, km.started)

	// Start the manager
	km.Start()
	assert.True(t, km.started)
	assert.NotNil(t, km.ticker)

	// Starting again should be idempotent
	km.Start()
	assert.True(t, km.started)

	// Stop the manager
	km.Stop()

	// Stopping again should be safe
	km.Stop()
}

// TestKeepaliveManager_UpdateTimestamps tests timestamp update methods.
func TestKeepaliveManager_UpdateTimestamps(t *testing.T) {
	conn := &mockSendReceiver{}
	km := NewKeepaliveManager(conn, 15*time.Second, 45*time.Second)

	// Record initial timestamps
	initialSent := km.lastSent
	initialRecv := km.lastRecv

	// Wait a bit to ensure time difference
	time.Sleep(10 * time.Millisecond)

	// Update sent timestamp
	km.UpdateLastSent()
	assert.True(t, km.lastSent.After(initialSent))
	assert.Equal(t, initialRecv, km.lastRecv) // Recv unchanged

	// Update recv timestamp
	time.Sleep(10 * time.Millisecond)
	km.UpdateLastRecv()
	assert.True(t, km.lastRecv.After(initialRecv))
}

// TestKeepaliveManager_IsAlive tests connection liveness detection.
func TestKeepaliveManager_IsAlive(t *testing.T) {
	conn := &mockSendReceiver{}
	km := NewKeepaliveManager(conn, 10*time.Millisecond, 50*time.Millisecond)

	// Should be alive initially (just created)
	assert.True(t, km.IsAlive())

	// Update recv to reset the timer
	km.UpdateLastRecv()
	assert.True(t, km.IsAlive())

	// Wait less than timeout - should still be alive
	time.Sleep(30 * time.Millisecond)
	assert.True(t, km.IsAlive())

	// Wait past timeout - should be dead
	time.Sleep(30 * time.Millisecond)
	assert.False(t, km.IsAlive())

	// Receiving a packet should bring it back alive
	km.UpdateLastRecv()
	assert.True(t, km.IsAlive())
}

// TestKeepaliveManager_GetIdleTime tests idle time calculation.
func TestKeepaliveManager_GetIdleTime(t *testing.T) {
	conn := &mockSendReceiver{}
	km := NewKeepaliveManager(conn, 15*time.Second, 45*time.Second)

	// Initial idle time should be near zero
	idleTime := km.GetIdleTime()
	assert.Less(t, idleTime, 100*time.Millisecond)

	// Wait and check idle time increases
	time.Sleep(50 * time.Millisecond)
	idleTime = km.GetIdleTime()
	assert.GreaterOrEqual(t, idleTime, 50*time.Millisecond)
	assert.Less(t, idleTime, 150*time.Millisecond)

	// Reset with received packet
	km.UpdateLastRecv()
	idleTime = km.GetIdleTime()
	assert.Less(t, idleTime, 10*time.Millisecond)
}

// TestKeepaliveManager_GetTimeSinceLastSent tests sent time calculation.
func TestKeepaliveManager_GetTimeSinceLastSent(t *testing.T) {
	conn := &mockSendReceiver{}
	km := NewKeepaliveManager(conn, 15*time.Second, 45*time.Second)

	// Initial time since sent should be near zero
	timeSinceSent := km.GetTimeSinceLastSent()
	assert.Less(t, timeSinceSent, 100*time.Millisecond)

	// Wait and check time increases
	time.Sleep(50 * time.Millisecond)
	timeSinceSent = km.GetTimeSinceLastSent()
	assert.GreaterOrEqual(t, timeSinceSent, 50*time.Millisecond)

	// Reset with sent packet
	km.UpdateLastSent()
	timeSinceSent = km.GetTimeSinceLastSent()
	assert.Less(t, timeSinceSent, 10*time.Millisecond)
}

// TestKeepaliveManager_SendsKeepalive tests automatic keepalive sending.
func TestKeepaliveManager_SendsKeepalive(t *testing.T) {
	conn := &mockSendReceiver{}
	interval := 100 * time.Millisecond
	km := NewKeepaliveManager(conn, interval, 300*time.Millisecond)

	// Start the manager
	km.Start()
	defer km.Stop()

	// Wait for first keepalive (should happen after interval since no sent packets)
	time.Sleep(interval + 50*time.Millisecond)

	// Verify SendKeepalive was called
	callCount := conn.getCallCount()
	assert.GreaterOrEqual(t, callCount, 1, "Expected at least one keepalive call")
}

// TestKeepaliveManager_NoKeepaliveWhenActive tests piggyback optimization.
func TestKeepaliveManager_NoKeepaliveWhenActive(t *testing.T) {
	conn := &mockSendReceiver{}
	interval := 100 * time.Millisecond
	km := NewKeepaliveManager(conn, interval, 300*time.Millisecond)

	// Start the manager
	km.Start()
	defer km.Stop()

	// Continuously update sent timestamp to simulate active sending
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(30 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				km.UpdateLastSent()
			case <-done:
				return
			}
		}
	}()

	// Wait for what would be multiple keepalive intervals
	time.Sleep(250 * time.Millisecond)
	close(done)

	// Verify minimal or no keepalives were sent (piggyback optimization)
	callCount := conn.getCallCount()
	assert.LessOrEqual(t, callCount, 1, "Expected few/no keepalives when actively sending")
}

// TestKeepaliveManager_MultipleIntervals tests keepalive over time.
func TestKeepaliveManager_MultipleIntervals(t *testing.T) {
	conn := &mockSendReceiver{}
	interval := 50 * time.Millisecond
	km := NewKeepaliveManager(conn, interval, 150*time.Millisecond)

	// Start the manager
	km.Start()
	defer km.Stop()

	// Wait for multiple intervals
	time.Sleep(200 * time.Millisecond)

	// Should have sent multiple keepalives
	callCount := conn.getCallCount()
	assert.GreaterOrEqual(t, callCount, 3, "Expected multiple keepalive calls")
}

// TestKeepaliveManager_ErrorHandling tests behavior when SendKeepalive fails.
func TestKeepaliveManager_ErrorHandling(t *testing.T) {
	conn := &mockSendReceiver{
		sendKeepaliveError: assert.AnError,
	}
	interval := 50 * time.Millisecond
	km := NewKeepaliveManager(conn, interval, 150*time.Millisecond)

	// Start the manager
	km.Start()
	defer km.Stop()

	// Wait for keepalive attempts
	time.Sleep(100 * time.Millisecond)

	// Should have attempted despite errors (continues trying)
	callCount := conn.getCallCount()
	assert.GreaterOrEqual(t, callCount, 1, "Expected keepalive attempts despite errors")
}

// TestKeepaliveManager_ConcurrentUpdates tests thread-safety.
func TestKeepaliveManager_ConcurrentUpdates(t *testing.T) {
	conn := &mockSendReceiver{}
	km := NewKeepaliveManager(conn, 10*time.Millisecond, 30*time.Millisecond)

	// Start the manager
	km.Start()
	defer km.Stop()

	// Spawn multiple goroutines updating timestamps
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				km.UpdateLastSent()
				km.UpdateLastRecv()
				km.IsAlive()
				km.GetIdleTime()
				km.GetTimeSinceLastSent()
				time.Sleep(time.Millisecond)
			}
		}()
	}

	// Wait for all goroutines
	wg.Wait()

	// If we got here without data races, test passes
}

// TestKeepaliveManager_StopWhileRunning tests stopping during active keepalive.
func TestKeepaliveManager_StopWhileRunning(t *testing.T) {
	conn := &mockSendReceiver{}
	km := NewKeepaliveManager(conn, 20*time.Millisecond, 60*time.Millisecond)

	// Start the manager
	km.Start()

	// Let it run a bit
	time.Sleep(50 * time.Millisecond)

	// Stop should complete without hanging
	done := make(chan struct{})
	go func() {
		km.Stop()
		close(done)
	}()

	select {
	case <-done:
		// Success
	case <-time.After(1 * time.Second):
		t.Fatal("Stop() hung")
	}
}

// TestKeepaliveManager_RepeatedStartStop tests multiple start/stop cycles.
func TestKeepaliveManager_RepeatedStartStop(t *testing.T) {
	conn := &mockSendReceiver{}
	km := NewKeepaliveManager(conn, 20*time.Millisecond, 60*time.Millisecond)

	// Multiple start/stop cycles
	for i := 0; i < 5; i++ {
		km.Start()
		assert.True(t, km.started)

		time.Sleep(30 * time.Millisecond)

		km.Stop()

		// Reset for next cycle (would need new manager in real usage)
		km.stopChan = make(chan struct{})
		km.started = false
	}
}

// TestKeepaliveManager_DefaultIntervalBehavior tests SSU2.md recommended 15s interval.
func TestKeepaliveManager_DefaultIntervalBehavior(t *testing.T) {
	conn := &mockSendReceiver{}

	// Use defaults (15s interval per SSU2.md)
	km := NewKeepaliveManager(conn, 0, 0)
	assert.Equal(t, 15*time.Second, km.interval)
	assert.Equal(t, 45*time.Second, km.timeout) // 3x interval

	// Verify timeout is exactly 3x interval
	assert.Equal(t, km.interval*3, km.timeout)
}

// TestKeepaliveManager_ImmediateKeepalive tests keepalive fires if no recent activity.
func TestKeepaliveManager_ImmediateKeepalive(t *testing.T) {
	conn := &mockSendReceiver{}
	interval := 50 * time.Millisecond
	km := NewKeepaliveManager(conn, interval, 150*time.Millisecond)

	// Manually set lastSent to past (simulate idle connection)
	km.mutex.Lock()
	km.lastSent = time.Now().Add(-100 * time.Millisecond)
	km.mutex.Unlock()

	// Start the manager
	km.Start()
	defer km.Stop()

	// Should send keepalive quickly since lastSent is old
	time.Sleep(interval + 30*time.Millisecond)

	callCount := conn.getCallCount()
	assert.GreaterOrEqual(t, callCount, 1, "Expected keepalive for idle connection")
}

// TestKeepaliveManager_UpdatesLastSentAfterKeepalive tests timestamp update after send.
func TestKeepaliveManager_UpdatesLastSentAfterKeepalive(t *testing.T) {
	conn := &mockSendReceiver{}
	interval := 50 * time.Millisecond
	km := NewKeepaliveManager(conn, interval, 150*time.Millisecond)

	// Record initial sent time
	initialSent := km.lastSent

	// Manually set to trigger immediate keepalive
	km.mutex.Lock()
	km.lastSent = time.Now().Add(-100 * time.Millisecond)
	km.mutex.Unlock()

	// Start and wait for keepalive
	km.Start()
	defer km.Stop()
	time.Sleep(interval + 30*time.Millisecond)

	// Verify lastSent was updated
	km.mutex.RLock()
	currentSent := km.lastSent
	km.mutex.RUnlock()

	assert.True(t, currentSent.After(initialSent), "Expected lastSent to be updated after keepalive")
}
