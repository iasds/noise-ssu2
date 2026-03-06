package noise

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/go-i2p/crypto/rand"
	"github.com/go-i2p/go-noise/handshake"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestNoiseListenerFromTCP creates a NoiseListener backed by a real TCP listener
// with a random static key and the given pattern. Caller must close the returned listener.
func newTestNoiseListenerFromTCP(t *testing.T, pattern string) *NoiseListener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	staticKey := make([]byte, 32)
	_, err = rand.Read(staticKey)
	require.NoError(t, err)
	config := NewListenerConfig(pattern).WithStaticKey(staticKey)
	noiseListener, err := NewNoiseListener(listener, config)
	require.NoError(t, err)
	return noiseListener
}

// newTestNoiseListenerFromMock creates a NoiseListener backed by a mockListener
// with a random static key and the given pattern.
func newTestNoiseListenerFromMock(t *testing.T, pattern string, ml *mockListener) *NoiseListener {
	t.Helper()
	staticKey := make([]byte, 32)
	_, err := rand.Read(staticKey)
	require.NoError(t, err)
	config := NewListenerConfig(pattern).WithStaticKey(staticKey)
	noiseListener, err := NewNoiseListener(ml, config)
	require.NoError(t, err)
	return noiseListener
}

func TestNewListenerConfig(t *testing.T) {
	config := NewListenerConfig("XX")

	assert.Equal(t, "XX", config.Pattern)
	assert.Equal(t, 30*time.Second, config.HandshakeTimeout)
	assert.Equal(t, time.Duration(0), config.ReadTimeout)
	assert.Equal(t, time.Duration(0), config.WriteTimeout)
}

func TestListenerConfigBuilder(t *testing.T) {
	staticKey := make([]byte, 32)
	_, err := rand.Read(staticKey)
	require.NoError(t, err)

	config := NewListenerConfig("XX").
		WithStaticKey(staticKey).
		WithHandshakeTimeout(10 * time.Second).
		WithReadTimeout(5 * time.Second).
		WithWriteTimeout(5 * time.Second)

	assert.Equal(t, "XX", config.Pattern)
	assert.Equal(t, staticKey, config.StaticKey)
	assert.Equal(t, 10*time.Second, config.HandshakeTimeout)
	assert.Equal(t, 5*time.Second, config.ReadTimeout)
	assert.Equal(t, 5*time.Second, config.WriteTimeout)
}

func TestListenerConfigValidation(t *testing.T) {
	tests := []struct {
		name        string
		setupConfig func() *ListenerConfig
		expectError bool
		errorCode   string
	}{
		{
			name: "valid config",
			setupConfig: func() *ListenerConfig {
				staticKey := make([]byte, 32)
				return NewListenerConfig("XX").WithStaticKey(staticKey)
			},
			expectError: false,
		},
		{
			name: "valid config without static key",
			setupConfig: func() *ListenerConfig {
				return NewListenerConfig("NN") // No static key - should be valid
			},
			expectError: false,
		},
		{
			name: "empty pattern",
			setupConfig: func() *ListenerConfig {
				staticKey := make([]byte, 32)
				return NewListenerConfig("").WithStaticKey(staticKey)
			},
			expectError: true,
			errorCode:   "noise pattern is required",
		},
		{
			name: "invalid pattern",
			setupConfig: func() *ListenerConfig {
				staticKey := make([]byte, 32)
				return NewListenerConfig("INVALID").WithStaticKey(staticKey)
			},
			expectError: true,
			errorCode:   "invalid noise pattern",
		},
		{
			name: "invalid key length",
			setupConfig: func() *ListenerConfig {
				staticKey := make([]byte, 16) // Wrong length
				return NewListenerConfig("XX").WithStaticKey(staticKey)
			},
			expectError: true,
			errorCode:   "static key must be 32 bytes",
		},
		{
			name: "invalid timeout",
			setupConfig: func() *ListenerConfig {
				staticKey := make([]byte, 32)
				return NewListenerConfig("XX").
					WithStaticKey(staticKey).
					WithHandshakeTimeout(-1 * time.Second)
			},
			expectError: true,
			errorCode:   "handshake timeout must be positive",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := tt.setupConfig()
			err := config.Validate()

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorCode != "" {
					assert.Contains(t, err.Error(), tt.errorCode)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestNewNoiseListener(t *testing.T) {
	tests := []struct {
		name            string
		setupUnderlying func() net.Listener
		setupConfig     func() *ListenerConfig
		expectError     bool
		errorType       string
	}{
		{
			name: "valid listener creation",
			setupUnderlying: func() net.Listener {
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				require.NoError(t, err)
				return listener
			},
			setupConfig: func() *ListenerConfig {
				staticKey := make([]byte, 32)
				_, err := rand.Read(staticKey)
				require.NoError(t, err)
				return NewListenerConfig("XX").WithStaticKey(staticKey)
			},
			expectError: false,
		},
		{
			name: "nil underlying listener",
			setupUnderlying: func() net.Listener {
				return nil
			},
			setupConfig: func() *ListenerConfig {
				staticKey := make([]byte, 32)
				return NewListenerConfig("XX").WithStaticKey(staticKey)
			},
			expectError: true,
			errorType:   "underlying listener cannot be nil",
		},
		{
			name: "nil config",
			setupUnderlying: func() net.Listener {
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				require.NoError(t, err)
				return listener
			},
			setupConfig: func() *ListenerConfig {
				return nil
			},
			expectError: true,
			errorType:   "listener config cannot be nil",
		},
		{
			name: "invalid config",
			setupUnderlying: func() net.Listener {
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				require.NoError(t, err)
				return listener
			},
			setupConfig: func() *ListenerConfig {
				return NewListenerConfig("") // Invalid pattern
			},
			expectError: true,
			errorType:   "invalid listener configuration",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			underlying := tt.setupUnderlying()
			if underlying != nil {
				defer underlying.Close()
			}
			config := tt.setupConfig()

			listener, err := NewNoiseListener(underlying, config)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, listener)
				if tt.errorType != "" {
					assert.Contains(t, err.Error(), tt.errorType)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, listener)
				assert.Equal(t, underlying.Addr().Network(), listener.Addr().(*NoiseAddr).underlying.Network())
				listener.Close()
			}
		})
	}
}

func TestNoiseListenerAddr(t *testing.T) {
	noiseListener := newTestNoiseListenerFromTCP(t, "XX")
	defer noiseListener.Close()

	addr := noiseListener.Addr()
	noiseAddr, ok := addr.(*NoiseAddr)
	require.True(t, ok)

	assert.Equal(t, "noise+tcp", noiseAddr.Network())
	assert.Contains(t, noiseAddr.String(), "XX")
	assert.Contains(t, noiseAddr.String(), "responder")
	assert.Contains(t, noiseAddr.String(), "127.0.0.1")
}

func TestNoiseListenerClose(t *testing.T) {
	noiseListener := newTestNoiseListenerFromTCP(t, "XX")

	// Close should succeed
	err := noiseListener.Close()
	assert.NoError(t, err)

	// Second close should also succeed (idempotent)
	err = noiseListener.Close()
	assert.NoError(t, err)

	// Accept should fail after close
	_, err = noiseListener.Accept()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "listener is closed")
}

func TestNoiseListenerAcceptAfterClose(t *testing.T) {
	noiseListener := newTestNoiseListenerFromTCP(t, "XX")

	// Close the listener
	err := noiseListener.Close()
	require.NoError(t, err)

	// Accept should return error
	conn, err := noiseListener.Accept()
	assert.Error(t, err)
	assert.Nil(t, conn)
	assert.Contains(t, err.Error(), "listener is closed")
}

// mockListener implements net.Listener for testing
type mockListener struct {
	addr       net.Addr
	acceptFunc func() (net.Conn, error)
	closeFunc  func() error
	closed     bool
	mu         sync.Mutex
}

func (ml *mockListener) Accept() (net.Conn, error) {
	ml.mu.Lock()
	defer ml.mu.Unlock()
	if ml.closed {
		return nil, net.ErrClosed
	}
	if ml.acceptFunc != nil {
		return ml.acceptFunc()
	}
	return nil, assert.AnError
}

func (ml *mockListener) Close() error {
	ml.mu.Lock()
	defer ml.mu.Unlock()
	ml.closed = true
	if ml.closeFunc != nil {
		return ml.closeFunc()
	}
	return nil
}

func (ml *mockListener) Addr() net.Addr {
	return ml.addr
}

func TestNoiseListenerAcceptError(t *testing.T) {
	addr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080}
	ml := &mockListener{
		addr: addr,
		acceptFunc: func() (net.Conn, error) {
			return nil, assert.AnError
		},
	}
	noiseListener := newTestNoiseListenerFromMock(t, "XX", ml)
	defer noiseListener.Close()

	conn, err := noiseListener.Accept()
	assert.Error(t, err)
	assert.Nil(t, conn)
	assert.Contains(t, err.Error(), "failed to accept underlying connection")
}

func TestNoiseListenerConcurrentOperations(t *testing.T) {
	noiseListener := newTestNoiseListenerFromTCP(t, "XX")

	// Test concurrent close operations
	var wg sync.WaitGroup
	closeErrors := make([]error, 10)

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			closeErrors[index] = noiseListener.Close()
		}(i)
	}

	wg.Wait()

	// All close operations should succeed (idempotent)
	for i, err := range closeErrors {
		assert.NoError(t, err, "Close operation %d should succeed", i)
	}
}

func TestNoiseListenerNetworkInterface(t *testing.T) {
	// Verify NoiseListener implements net.Listener interface
	noiseListener := newTestNoiseListenerFromTCP(t, "XX")
	defer noiseListener.Close()

	// Verify it implements net.Listener
	var _ net.Listener = noiseListener

	// Test interface methods
	addr := noiseListener.Addr()
	assert.NotNil(t, addr)

	// Accept should work (but we won't wait for connections)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	go func() {
		<-ctx.Done()
		noiseListener.Close()
	}()

	_, err := noiseListener.Accept()
	// Should get an error due to timeout/close, but that's expected
	assert.Error(t, err)
}

func TestListenerConfigAllPatterns(t *testing.T) {
	patterns := []string{
		"NN", "NK", "NX", "XN", "XK", "XX",
		"KN", "KK", "KX", "IN", "IK", "IX",
		"N", "K", "X",
		"Noise_NN_25519_AESGCM_SHA256",
		"Noise_XX_25519_AESGCM_SHA256",
	}

	staticKey := make([]byte, 32)
	_, err := rand.Read(staticKey)
	require.NoError(t, err)

	for _, pattern := range patterns {
		t.Run(pattern, func(t *testing.T) {
			config := NewListenerConfig(pattern).WithStaticKey(staticKey)
			err := config.Validate()
			assert.NoError(t, err, "Pattern %s should be valid", pattern)
		})
	}
}

// Benchmark the listener creation and basic operations
func BenchmarkNoiseListenerCreation(b *testing.B) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(b, err)
	defer listener.Close()

	staticKey := make([]byte, 32)
	_, err = rand.Read(staticKey)
	require.NoError(b, err)

	config := NewListenerConfig("XX").WithStaticKey(staticKey)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		noiseListener, err := NewNoiseListener(listener, config)
		if err != nil {
			b.Fatal(err)
		}
		noiseListener.Close()
	}
}

func BenchmarkListenerConfigValidation(b *testing.B) {
	staticKey := make([]byte, 32)
	_, err := rand.Read(staticKey)
	require.NoError(b, err)

	config := NewListenerConfig("XX").WithStaticKey(staticKey)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := config.Validate()
		if err != nil {
			b.Fatal(err)
		}
	}
}

// --- Tests for ListenerConfig Modifiers, PostHandshakeHook, AdditionalSymmetricKeyLabels ---

// testModifier is a minimal HandshakeModifier for testing.
type testModifier struct {
	name string
}

func (m *testModifier) ModifyOutbound(_ handshake.HandshakePhase, data []byte) ([]byte, error) {
	return data, nil
}
func (m *testModifier) ModifyInbound(_ handshake.HandshakePhase, data []byte) ([]byte, error) {
	return data, nil
}
func (m *testModifier) Name() string { return m.name }
func (m *testModifier) Close() error { return nil }

func TestListenerConfigWithModifiers(t *testing.T) {
	mod1 := &testModifier{name: "mod1"}
	mod2 := &testModifier{name: "mod2"}

	config := NewListenerConfig("XX").
		WithModifiers(mod1, mod2)

	require.Len(t, config.Modifiers, 2)
	assert.Equal(t, "mod1", config.Modifiers[0].Name())
	assert.Equal(t, "mod2", config.Modifiers[1].Name())
}

func TestListenerConfigWithModifiers_DefensiveCopy(t *testing.T) {
	mod1 := &testModifier{name: "mod1"}
	mods := []handshake.HandshakeModifier{mod1}

	config := NewListenerConfig("XX").WithModifiers(mods...)

	// Mutating the original slice should not affect the config
	mods[0] = &testModifier{name: "replaced"}
	assert.Equal(t, "mod1", config.Modifiers[0].Name())
}

func TestListenerConfigWithPostHandshakeHook(t *testing.T) {
	hookCalled := false
	hook := func(nc *NoiseConn) error {
		hookCalled = true
		return nil
	}

	config := NewListenerConfig("XX").
		WithPostHandshakeHook(hook)

	require.NotNil(t, config.PostHandshakeHook)

	// Verify hook is callable
	err := config.PostHandshakeHook(nil)
	assert.NoError(t, err)
	assert.True(t, hookCalled)
}

func TestListenerConfigWithAdditionalSymmetricKeyLabels(t *testing.T) {
	labels := [][]byte{[]byte("ask"), []byte("extra")}

	config := NewListenerConfig("XX").
		WithAdditionalSymmetricKeyLabels(labels)

	require.Len(t, config.AdditionalSymmetricKeyLabels, 2)
	assert.Equal(t, []byte("ask"), config.AdditionalSymmetricKeyLabels[0])
	assert.Equal(t, []byte("extra"), config.AdditionalSymmetricKeyLabels[1])
}

func TestListenerConfigBuilderChain_AllFields(t *testing.T) {
	staticKey := make([]byte, 32)
	_, err := rand.Read(staticKey)
	require.NoError(t, err)

	mod := &testModifier{name: "test-mod"}
	hookCalled := false
	hook := func(nc *NoiseConn) error {
		hookCalled = true
		return nil
	}
	labels := [][]byte{[]byte("ask")}

	config := NewListenerConfig("XX").
		WithStaticKey(staticKey).
		WithHandshakeTimeout(10 * time.Second).
		WithReadTimeout(5 * time.Second).
		WithWriteTimeout(5 * time.Second).
		WithModifiers(mod).
		WithPostHandshakeHook(hook).
		WithAdditionalSymmetricKeyLabels(labels)

	assert.Equal(t, "XX", config.Pattern)
	assert.Equal(t, staticKey, config.StaticKey)
	assert.Equal(t, 10*time.Second, config.HandshakeTimeout)
	assert.Len(t, config.Modifiers, 1)
	assert.Equal(t, "test-mod", config.Modifiers[0].Name())
	assert.NotNil(t, config.PostHandshakeHook)
	assert.Len(t, config.AdditionalSymmetricKeyLabels, 1)

	// Verify hook works
	_ = config.PostHandshakeHook(nil)
	assert.True(t, hookCalled)
}

// --- Test that Accept() propagates Modifiers/Hook/ASKLabels to ConnConfig ---

func TestNoiseListenerAcceptPropagatesModifiers(t *testing.T) {
	// Use a mock listener that returns a mock conn on Accept
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	addr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9090}
	ml := &mockListener{
		addr: addr,
		acceptFunc: func() (net.Conn, error) {
			return serverConn, nil
		},
	}

	staticKey := make([]byte, 32)
	_, err := rand.Read(staticKey)
	require.NoError(t, err)

	mod := &testModifier{name: "propagated-mod"}
	hookCalled := false
	hook := func(nc *NoiseConn) error {
		hookCalled = true
		return nil
	}
	labels := [][]byte{[]byte("ask")}

	config := NewListenerConfig("XX").
		WithStaticKey(staticKey).
		WithModifiers(mod).
		WithPostHandshakeHook(hook).
		WithAdditionalSymmetricKeyLabels(labels)

	noiseListener, err := NewNoiseListener(ml, config)
	require.NoError(t, err)
	defer noiseListener.Close()

	conn, err := noiseListener.Accept()
	require.NoError(t, err)
	require.NotNil(t, conn)

	noiseConn, ok := conn.(*NoiseConn)
	require.True(t, ok)
	defer noiseConn.Close()

	// Verify modifiers were propagated
	require.Len(t, noiseConn.config.Modifiers, 1)
	assert.Equal(t, "propagated-mod", noiseConn.config.Modifiers[0].Name())

	// Verify PostHandshakeHook was propagated
	require.NotNil(t, noiseConn.config.PostHandshakeHook)

	// Verify ASK labels were propagated
	require.Len(t, noiseConn.config.AdditionalSymmetricKeyLabels, 1)
	assert.Equal(t, []byte("ask"), noiseConn.config.AdditionalSymmetricKeyLabels[0])

	// Verify hook is functional
	_ = noiseConn.config.PostHandshakeHook(nil)
	assert.True(t, hookCalled)
}

func TestNoiseListenerAcceptNoModifiers(t *testing.T) {
	// Verify Accept works correctly when no modifiers are configured (no regression)
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	addr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9091}
	ml := &mockListener{
		addr: addr,
		acceptFunc: func() (net.Conn, error) {
			return serverConn, nil
		},
	}

	staticKey := make([]byte, 32)
	_, err := rand.Read(staticKey)
	require.NoError(t, err)

	config := NewListenerConfig("XX").WithStaticKey(staticKey)
	noiseListener, err := NewNoiseListener(ml, config)
	require.NoError(t, err)
	defer noiseListener.Close()

	conn, err := noiseListener.Accept()
	require.NoError(t, err)
	require.NotNil(t, conn)

	noiseConn := conn.(*NoiseConn)
	defer noiseConn.Close()

	assert.Empty(t, noiseConn.config.Modifiers)
	assert.Nil(t, noiseConn.config.PostHandshakeHook)
	assert.Empty(t, noiseConn.config.AdditionalSymmetricKeyLabels)
}

// --- Test isClosed() is thread-safe ---

func TestNoiseListenerIsClosedThreadSafe(t *testing.T) {
	noiseListener := newTestNoiseListenerFromTCP(t, "XX")

	// Concurrent readers calling isClosed() while a writer calls Close()
	// should not deadlock or panic.
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Call isClosed() repeatedly — this is the method that previously
			// had a misleading doc comment saying it was NOT thread-safe.
			for j := 0; j < 100; j++ {
				_ = noiseListener.isClosed()
			}
		}()
	}

	// Close from another goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(1 * time.Millisecond)
		noiseListener.Close()
	}()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Success — no deadlock
	case <-time.After(5 * time.Second):
		t.Fatal("deadlock detected: isClosed() is not thread-safe")
	}
}

// --- Test concurrent Accept without acceptMutex serialization ---

func TestNoiseListenerConcurrentAccepts(t *testing.T) {
	noiseListener := newTestNoiseListenerFromTCP(t, "XX")
	defer noiseListener.Close()

	const numAcceptors = 3
	const numConnections = 3

	// Spawn multiple concurrent acceptors
	accepted := make(chan net.Conn, numConnections)
	acceptErrs := make(chan error, numAcceptors)

	for i := 0; i < numAcceptors; i++ {
		go func() {
			conn, err := noiseListener.Accept()
			if err != nil {
				acceptErrs <- err
				return
			}
			accepted <- conn
		}()
	}

	// Give acceptors time to all block on Accept()
	time.Sleep(50 * time.Millisecond)

	// Connect clients
	listenAddr := noiseListener.Addr().(*NoiseAddr).Underlying().String()
	for i := 0; i < numConnections; i++ {
		go func() {
			conn, err := net.Dial("tcp", listenAddr)
			if err == nil {
				defer conn.Close()
				time.Sleep(200 * time.Millisecond)
			}
		}()
	}

	// Collect accepted connections
	var conns []net.Conn
	timeout := time.After(5 * time.Second)
	for i := 0; i < numConnections; i++ {
		select {
		case conn := <-accepted:
			conns = append(conns, conn)
		case <-timeout:
			// Some may not be accepted due to timing; that's fine
			break
		}
	}

	// Clean up
	noiseListener.Close()
	for _, c := range conns {
		c.Close()
	}

	// At least one concurrent accept should have succeeded
	assert.GreaterOrEqual(t, len(conns), 1,
		"at least one concurrent accept should succeed without acceptMutex serialization")
}
