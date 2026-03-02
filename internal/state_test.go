package internal

import (
	"sync"
	"testing"
	"time"
)

// --- ConnState tests ---

func TestConnState_String_AllValues(t *testing.T) {
	tests := []struct {
		state    ConnState
		expected string
	}{
		{StateInit, "init"},
		{StateHandshaking, "handshaking"},
		{StateEstablished, "established"},
		{StateClosed, "closed"},
	}
	for _, tt := range tests {
		if got := tt.state.String(); got != tt.expected {
			t.Errorf("ConnState(%d).String() = %q, want %q", tt.state, got, tt.expected)
		}
	}
}

func TestConnState_String_Unknown(t *testing.T) {
	unknown := ConnState(99)
	if got := unknown.String(); got != "unknown" {
		t.Errorf("ConnState(99).String() = %q, want %q", got, "unknown")
	}
}

// --- ConnectionMetrics tests ---

func TestNewConnectionMetrics(t *testing.T) {
	before := time.Now()
	m := NewConnectionMetrics()
	after := time.Now()

	if m.Created.Before(before) || m.Created.After(after) {
		t.Errorf("Created time %v not in range [%v, %v]", m.Created, before, after)
	}
}

func TestConnectionMetrics_HandshakeDuration_NotStarted(t *testing.T) {
	m := NewConnectionMetrics()
	if d := m.HandshakeDuration(); d != 0 {
		t.Errorf("HandshakeDuration() = %v, want 0 (not started)", d)
	}
}

func TestConnectionMetrics_HandshakeDuration_StartedNotEnded(t *testing.T) {
	m := NewConnectionMetrics()
	m.SetHandshakeStart()
	if d := m.HandshakeDuration(); d != 0 {
		t.Errorf("HandshakeDuration() = %v, want 0 (not ended)", d)
	}
}

func TestConnectionMetrics_HandshakeDuration_Complete(t *testing.T) {
	m := NewConnectionMetrics()
	m.SetHandshakeStart()
	time.Sleep(10 * time.Millisecond)
	m.SetHandshakeEnd()

	d := m.HandshakeDuration()
	if d < 10*time.Millisecond {
		t.Errorf("HandshakeDuration() = %v, want >= 10ms", d)
	}
}

func TestConnectionMetrics_AddBytesRead(t *testing.T) {
	m := NewConnectionMetrics()
	m.AddBytesRead(100)
	m.AddBytesRead(50)

	br, _, _ := m.GetStats()
	if br != 150 {
		t.Errorf("BytesRead = %d, want 150", br)
	}
}

func TestConnectionMetrics_AddBytesWritten(t *testing.T) {
	m := NewConnectionMetrics()
	m.AddBytesWritten(200)
	m.AddBytesWritten(75)

	_, bw, _ := m.GetStats()
	if bw != 275 {
		t.Errorf("BytesWritten = %d, want 275", bw)
	}
}

func TestConnectionMetrics_GetStats_AllFields(t *testing.T) {
	m := NewConnectionMetrics()
	m.SetHandshakeStart()
	time.Sleep(5 * time.Millisecond)
	m.SetHandshakeEnd()
	m.AddBytesRead(42)
	m.AddBytesWritten(84)

	br, bw, d := m.GetStats()
	if br != 42 {
		t.Errorf("BytesRead = %d, want 42", br)
	}
	if bw != 84 {
		t.Errorf("BytesWritten = %d, want 84", bw)
	}
	if d < 5*time.Millisecond {
		t.Errorf("Duration = %v, want >= 5ms", d)
	}
}

func TestConnectionMetrics_GetStats_NoDeadlock(t *testing.T) {
	// This test verifies the critical fix: GetStats() must not deadlock
	// when called concurrently with write operations (AddBytesRead,
	// AddBytesWritten, SetHandshakeStart, SetHandshakeEnd).
	//
	// Before the fix, GetStats() called HandshakeDuration() while holding
	// RLock, causing a nested RLock that deadlocks under write contention
	// due to Go's RWMutex write-priority fairness rules.
	m := NewConnectionMetrics()
	m.SetHandshakeStart()
	m.SetHandshakeEnd()

	const goroutines = 20
	const iterations = 500

	var wg sync.WaitGroup
	wg.Add(goroutines)

	// Half the goroutines continuously call write operations (Lock)
	for i := 0; i < goroutines/2; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				switch id % 4 {
				case 0:
					m.AddBytesRead(1)
				case 1:
					m.AddBytesWritten(1)
				case 2:
					m.SetHandshakeStart()
				case 3:
					m.SetHandshakeEnd()
				}
			}
		}(i)
	}

	// Other half continuously call GetStats (RLock -> nested RLock before fix)
	for i := goroutines / 2; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				m.GetStats()
			}
		}()
	}

	// If there's a deadlock, this will hang and the test will time out
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Success — no deadlock
	case <-time.After(5 * time.Second):
		t.Fatal("DEADLOCK: GetStats() deadlocked under concurrent write contention")
	}
}

func TestConnectionMetrics_HandshakeDuration_Concurrent(t *testing.T) {
	// Verify HandshakeDuration() itself is also safe under contention
	m := NewConnectionMetrics()
	m.SetHandshakeStart()
	m.SetHandshakeEnd()

	var wg sync.WaitGroup
	wg.Add(10)
	for i := 0; i < 5; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				m.AddBytesRead(1)
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				_ = m.HandshakeDuration()
			}
		}()
	}
	wg.Wait()
}
