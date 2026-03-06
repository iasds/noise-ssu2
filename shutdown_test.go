package noise

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewShutdownManager(t *testing.T) {
	tests := []struct {
		name            string
		timeout         time.Duration
		expectedTimeout time.Duration
	}{
		{
			name:            "with custom timeout",
			timeout:         10 * time.Second,
			expectedTimeout: 10 * time.Second,
		},
		{
			name:            "with zero timeout uses default",
			timeout:         0,
			expectedTimeout: 30 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sm := NewShutdownManager(tt.timeout)

			assert.NotNil(t, sm)
			assert.Equal(t, tt.expectedTimeout, sm.shutdownTimeout)
			assert.NotNil(t, sm.ctx)
			assert.NotNil(t, sm.done)
			assert.NotNil(t, sm.connections)
			assert.NotNil(t, sm.listeners)
			assert.NotNil(t, sm.logger)
		})
	}
}

func TestShutdownManagerContext(t *testing.T) {
	sm := NewShutdownManager(5 * time.Second)

	ctx := sm.Context()
	assert.NotNil(t, ctx)

	// Context should not be cancelled initially
	select {
	case <-ctx.Done():
		t.Fatal("context should not be cancelled initially")
	default:
		// expected
	}

	// Start shutdown
	go func() {
		sm.Shutdown()
	}()

	// Context should be cancelled after shutdown
	select {
	case <-ctx.Done():
		// expected
	case <-time.After(1 * time.Second):
		t.Fatal("context should be cancelled after shutdown")
	}
}

func TestGlobalShutdownFunctions(t *testing.T) {
	// Test setting and getting global shutdown manager
	originalSM := GetGlobalShutdownManager()
	assert.NotNil(t, originalSM)

	newSM := NewShutdownManager(10 * time.Second)
	SetGlobalShutdownManager(newSM)

	assert.Equal(t, newSM, GetGlobalShutdownManager())

	// Test graceful shutdown
	err := GracefulShutdown()
	assert.NoError(t, err)

	// Restore original for other tests
	SetGlobalShutdownManager(originalSM)
}

func TestNoiseConnShutdownManagerIntegration(t *testing.T) {
	sm := NewShutdownManager(5 * time.Second)

	mockConn := &mockNetConn{}
	config := NewConnConfig("NN", true)
	noiseConn, err := NewNoiseConn(mockConn, config)
	require.NoError(t, err)

	noiseConn.SetShutdownManager(sm)
	assertShutdownRegistered(t, sm, noiseConn, true)

	err = noiseConn.Close()
	assert.NoError(t, err)
	assertShutdownRegistered(t, sm, noiseConn, false)
}

func TestNoiseListenerShutdownManagerIntegration(t *testing.T) {
	sm := NewShutdownManager(5 * time.Second)

	ml := &mockListener{
		addr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080},
	}
	config := NewListenerConfig("NN")
	noiseListener, err := NewNoiseListener(ml, config)
	require.NoError(t, err)

	noiseListener.SetShutdownManager(sm)
	assertShutdownRegistered(t, sm, noiseListener, true)

	err = noiseListener.Close()
	assert.NoError(t, err)
	assertShutdownRegistered(t, sm, noiseListener, false)
}

// assertShutdownRegistered checks whether a resource (conn or listener) is
// present in (or absent from) the shutdown manager's tracked set.
func assertShutdownRegistered(t *testing.T, sm *ShutdownManager, resource interface{}, expected bool) {
	t.Helper()
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	switch v := resource.(type) {
	case *NoiseConn:
		if expected {
			assert.Contains(t, sm.connections, v)
		} else {
			assert.NotContains(t, sm.connections, v)
		}
	case *NoiseListener:
		if expected {
			assert.Contains(t, sm.listeners, v)
		} else {
			assert.NotContains(t, sm.listeners, v)
		}
	default:
		t.Fatalf("unsupported resource type: %T", resource)
	}
}
