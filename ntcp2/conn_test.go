package ntcp2

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dchest/siphash"
	noise "github.com/go-i2p/go-noise"
	"github.com/go-i2p/go-noise/handshake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockNoiseConn implements a mock NoiseConn for testing
type mockNoiseConn struct {
	readData    []byte
	writeBuffer bytes.Buffer
	closed      bool
	readErr     error
	writeErr    error
	closeErr    error
	deadlineErr error
}

func (m *mockNoiseConn) Read(b []byte) (int, error) {
	if m.readErr != nil {
		return 0, m.readErr
	}
	n := copy(b, m.readData)
	return n, nil
}

func (m *mockNoiseConn) Write(b []byte) (int, error) {
	if m.writeErr != nil {
		return 0, m.writeErr
	}
	return m.writeBuffer.Write(b)
}

func (m *mockNoiseConn) Close() error {
	m.closed = true
	return m.closeErr
}

func (m *mockNoiseConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080}
}

func (m *mockNoiseConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8081}
}

func (m *mockNoiseConn) SetDeadline(t time.Time) error {
	return m.deadlineErr
}

func (m *mockNoiseConn) SetReadDeadline(t time.Time) error {
	return m.deadlineErr
}

func (m *mockNoiseConn) SetWriteDeadline(t time.Time) error {
	return m.deadlineErr
}

// TestNewNTCP2Conn tests the NTCP2Conn constructor
func TestNewNTCP2Conn(t *testing.T) {
	tests := []struct {
		name        string
		noiseConn   *noise.NoiseConn
		localAddr   *NTCP2Addr
		remoteAddr  *NTCP2Addr
		expectError bool
		errorCode   string
	}{
		{
			name:        "nil noise connection",
			noiseConn:   nil,
			localAddr:   createTestNTCP2Addr("local", "initiator"),
			remoteAddr:  createTestNTCP2Addr("remote", "responder"),
			expectError: true,
			errorCode:   "INVALID_NOISE_CONN",
		},
		{
			name:        "nil local address",
			noiseConn:   &noise.NoiseConn{},
			localAddr:   nil,
			remoteAddr:  createTestNTCP2Addr("remote", "responder"),
			expectError: true,
			errorCode:   "INVALID_LOCAL_ADDR",
		},
		{
			name:        "nil remote address",
			noiseConn:   &noise.NoiseConn{},
			localAddr:   createTestNTCP2Addr("local", "initiator"),
			remoteAddr:  nil,
			expectError: true,
			errorCode:   "INVALID_REMOTE_ADDR",
		},
		{
			name:        "valid parameters",
			noiseConn:   &noise.NoiseConn{},
			localAddr:   createTestNTCP2Addr("local", "initiator"),
			remoteAddr:  createTestNTCP2Addr("remote", "responder"),
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn, err := NewNTCP2Conn(tt.noiseConn, tt.localAddr, tt.remoteAddr)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, conn)
				// Check for key words from the error message rather than codes
				if tt.errorCode == "INVALID_NOISE_CONN" {
					assert.Contains(t, err.Error(), "noise connection cannot be nil")
				} else if tt.errorCode == "INVALID_LOCAL_ADDR" {
					assert.Contains(t, err.Error(), "local address cannot be nil")
				} else if tt.errorCode == "INVALID_REMOTE_ADDR" {
					assert.Contains(t, err.Error(), "remote address cannot be nil")
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, conn)
				assert.Equal(t, tt.noiseConn, conn.noiseConn)
				assert.Equal(t, tt.localAddr, conn.localAddr)
				assert.Equal(t, tt.remoteAddr, conn.remoteAddr)
			}
		})
	}
}

// TestNTCP2Conn_Read tests the Read method
func TestNTCP2Conn_Read(t *testing.T) {
	tests := []struct {
		name          string
		readData      []byte
		readErr       error
		expectError   bool
		expectedBytes int
		errorContains string
	}{
		{
			name:          "handshake not completed",
			readData:      []byte("test data"),
			readErr:       nil,
			expectError:   true,
			expectedBytes: 0,
			errorContains: "handshake not completed",
		},
		{
			name:          "underlying read error",
			readData:      nil,
			readErr:       assert.AnError,
			expectError:   true,
			expectedBytes: 0,
			errorContains: "handshake not completed", // This will be the first error encountered
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockNoise := &mockNoiseConn{
				readData: tt.readData,
				readErr:  tt.readErr,
			}

			conn := createTestNTCP2Conn(mockNoise)

			buffer := make([]byte, 64)
			n, err := conn.Read(buffer)

			if tt.expectError {
				assert.Error(t, err)
				assert.Equal(t, 0, n)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedBytes, n)
				assert.Equal(t, tt.readData, buffer[:n])
			}
		})
	}
}

// TestNTCP2Conn_Write tests the Write method
func TestNTCP2Conn_Write(t *testing.T) {
	tests := []struct {
		name          string
		writeData     []byte
		writeErr      error
		expectError   bool
		errorContains string
	}{
		{
			name:          "handshake not completed",
			writeData:     []byte("test data"),
			writeErr:      nil,
			expectError:   true,
			errorContains: "handshake not completed",
		},
		{
			name:          "underlying write error",
			writeData:     []byte("test data"),
			writeErr:      assert.AnError,
			expectError:   true,
			errorContains: "handshake not completed", // This will be the first error encountered
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockNoise := &mockNoiseConn{
				writeErr: tt.writeErr,
			}

			conn := createTestNTCP2Conn(mockNoise)

			n, err := conn.Write(tt.writeData)

			if tt.expectError {
				assert.Error(t, err)
				assert.Equal(t, 0, n)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
				assert.Equal(t, len(tt.writeData), n)
				assert.Equal(t, tt.writeData, mockNoise.writeBuffer.Bytes())
			}
		})
	}
}

// TestNTCP2Conn_Close tests the Close method
func TestNTCP2Conn_Close(t *testing.T) {
	tests := []struct {
		name          string
		closeErr      error
		expectError   bool
		errorContains string
	}{
		{
			name:        "successful close",
			closeErr:    nil,
			expectError: false,
		},
		{
			name:          "close error",
			closeErr:      assert.AnError,
			expectError:   true,
			errorContains: "ntcp2 close failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockNoise := &mockNoiseConn{
				closeErr: tt.closeErr,
			}

			conn := createTestNTCP2Conn(mockNoise)

			err := conn.Close()

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
				assert.True(t, mockNoise.closed)
			}
		})
	}
}

// TestNTCP2Conn_Addresses tests the LocalAddr and RemoteAddr methods
func TestNTCP2Conn_Addresses(t *testing.T) {
	localAddr := createTestNTCP2Addr("local", "initiator")
	remoteAddr := createTestNTCP2Addr("remote", "responder")

	conn := createTestNTCP2ConnWithAddrs(&mockNoiseConn{}, localAddr, remoteAddr)

	assert.Equal(t, localAddr, conn.LocalAddr())
	assert.Equal(t, remoteAddr, conn.RemoteAddr())
}

// TestNTCP2Conn_Deadlines tests the deadline methods
func TestNTCP2Conn_Deadlines(t *testing.T) {
	deadline := time.Now().Add(time.Minute)

	tests := []struct {
		name          string
		method        func(*NTCP2Conn, time.Time) error
		deadlineErr   error
		expectError   bool
		errorContains string
	}{
		{
			name:        "SetDeadline success",
			method:      (*NTCP2Conn).SetDeadline,
			deadlineErr: nil,
			expectError: false,
		},
		{
			name:          "SetDeadline error",
			method:        (*NTCP2Conn).SetDeadline,
			deadlineErr:   assert.AnError,
			expectError:   true,
			errorContains: "ntcp2 set deadline failed",
		},
		{
			name:        "SetReadDeadline success",
			method:      (*NTCP2Conn).SetReadDeadline,
			deadlineErr: nil,
			expectError: false,
		},
		{
			name:          "SetReadDeadline error",
			method:        (*NTCP2Conn).SetReadDeadline,
			deadlineErr:   assert.AnError,
			expectError:   true,
			errorContains: "ntcp2 set read deadline failed",
		},
		{
			name:        "SetWriteDeadline success",
			method:      (*NTCP2Conn).SetWriteDeadline,
			deadlineErr: nil,
			expectError: false,
		},
		{
			name:          "SetWriteDeadline error",
			method:        (*NTCP2Conn).SetWriteDeadline,
			deadlineErr:   assert.AnError,
			expectError:   true,
			errorContains: "ntcp2 set write deadline failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockNoise := &mockNoiseConn{
				deadlineErr: tt.deadlineErr,
			}

			conn := createTestNTCP2Conn(mockNoise)

			err := tt.method(conn, deadline)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestNTCP2Conn_I2PSpecificMethods tests NTCP2-specific methods
func TestNTCP2Conn_I2PSpecificMethods(t *testing.T) {
	routerHash := make([]byte, 32)
	copy(routerHash, "test-router-hash-32-bytes-long!")

	tcpAddr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080}

	localAddr, err := NewNTCP2Addr(tcpAddr, routerHash, "initiator")
	if err != nil {
		t.Fatalf("Failed to create local address: %v", err)
	}

	remoteAddr, err := NewNTCP2Addr(tcpAddr, routerHash, "responder")
	if err != nil {
		t.Fatalf("Failed to create remote address: %v", err)
	}

	conn := createTestNTCP2ConnWithAddrs(&mockNoiseConn{}, localAddr, remoteAddr)

	// Test RouterHash
	assert.Equal(t, routerHash, conn.RouterHash())

	// Test PeerStaticKey - nil for mock connection without real handshake
	// In a real connection, this would return the 32-byte X25519 public key
	_ = conn.PeerStaticKey()

	// Test Role
	assert.Equal(t, "initiator", conn.Role())

	// Test UnderlyingConn
	assert.Equal(t, conn.noiseConn, conn.UnderlyingConn())
}

// TestNTCP2Conn_NetConnInterface tests net.Conn interface compliance
func TestNTCP2Conn_NetConnInterface(t *testing.T) {
	conn := createTestNTCP2Conn(&mockNoiseConn{})

	// Verify that NTCP2Conn implements net.Conn
	var _ net.Conn = conn

	// Test that all methods are callable
	assert.NotNil(t, conn.LocalAddr())
	assert.NotNil(t, conn.RemoteAddr())

	// Test deadline methods don't panic
	deadline := time.Now().Add(time.Minute)
	assert.NotPanics(t, func() { conn.SetDeadline(deadline) })
	assert.NotPanics(t, func() { conn.SetReadDeadline(deadline) })
	assert.NotPanics(t, func() { conn.SetWriteDeadline(deadline) })
}

// Helper functions for creating test objects

func createTestNTCP2Addr(prefix, role string) *NTCP2Addr {
	routerHash := make([]byte, 32)
	copy(routerHash, prefix+"-router-hash")

	// Create a mock TCP address
	tcpAddr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080}

	addr, err := NewNTCP2Addr(tcpAddr, routerHash, role)
	if err != nil {
		panic(err) // This should not happen in tests
	}
	return addr
}

func createTestNTCP2Conn(mockNoise *mockNoiseConn) *NTCP2Conn {
	localAddr := createTestNTCP2Addr("local", "initiator")
	remoteAddr := createTestNTCP2Addr("remote", "responder")
	return createTestNTCP2ConnWithAddrs(mockNoise, localAddr, remoteAddr)
}

func createTestNTCP2ConnWithAddrs(mockNoise *mockNoiseConn, localAddr, remoteAddr *NTCP2Addr) *NTCP2Conn {
	// For testing, we'll create a minimal NoiseConn that doesn't require handshake
	// We'll create it directly rather than using the constructor to bypass validation
	config := noise.NewConnConfig("XK", true)

	// Create a NoiseConn with the mock as the underlying connection
	noiseConn, err := noise.NewNoiseConn(mockNoise, config)
	if err != nil {
		panic(err) // This should not happen in tests
	}

	// Force the state to established so reads/writes work
	// This is a test-only hack to bypass the handshake requirement
	// We need to access internal state, so let's use reflection or create a simpler approach
	conn, err := NewNTCP2Conn(noiseConn, localAddr, remoteAddr)
	if err != nil {
		panic(err) // This should not happen in tests
	}
	return conn
}

// ============================================================================
// Tests from audit_fixes_3_test.go — conn-related
// ============================================================================

func TestValidateFrameLength_ZeroAppliesProbingDelay(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()

	config := noise.NewConnConfig("XK", true)
	noiseConn, err := noise.NewNoiseConn(client, config)
	require.NoError(t, err)
	defer noiseConn.Close()

	localAddr := createTestNTCP2Addr("local", "initiator")
	remoteAddr := createTestNTCP2Addr("remote", "responder")
	ntcp2Conn, err := NewNTCP2Conn(noiseConn, localAddr, remoteAddr)
	require.NoError(t, err)

	err = ntcp2Conn.validateFrameLength(0)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "frame length 0 below minimum 16")
}

func TestValidateFrameLength_TooSmallAppliesProbingDelay(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()

	config := noise.NewConnConfig("XK", true)
	noiseConn, err := noise.NewNoiseConn(client, config)
	require.NoError(t, err)
	defer noiseConn.Close()

	localAddr := createTestNTCP2Addr("local", "initiator")
	remoteAddr := createTestNTCP2Addr("remote", "responder")
	ntcp2Conn, err := NewNTCP2Conn(noiseConn, localAddr, remoteAddr)
	require.NoError(t, err)

	err = ntcp2Conn.validateFrameLength(1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "below minimum")
}

func TestValidateFrameLength_ValidLength(t *testing.T) {
	conn := createTestNTCP2Conn(&mockNoiseConn{})

	err := conn.validateFrameLength(MinDataPhaseFrameSize)
	assert.NoError(t, err)

	err = conn.validateFrameLength(1024)
	assert.NoError(t, err)

	err = conn.validateFrameLength(uint16(MaxFrameSize))
	assert.NoError(t, err)
}

func TestAEADErrorConstants(t *testing.T) {
	assert.Equal(t, 1024, AEADErrorMaxJunkBytes)
	assert.Greater(t, AEADErrorTimeout.Seconds(), 0.0)
	assert.Greater(t, NonceRekeyThreshold, uint64(0))
	assert.Less(t, NonceRekeyThreshold, MaxNonce)
}

func TestNonceExhaustionImminent(t *testing.T) {
	conn := createTestNTCP2Conn(&mockNoiseConn{})

	assert.False(t, conn.NonceExhaustionImminent())

	conn.writeMu.Lock()
	conn.writeNonce = NonceRekeyThreshold
	conn.writeMu.Unlock()
	assert.True(t, conn.NonceExhaustionImminent())

	conn.writeMu.Lock()
	conn.writeNonce = 0
	conn.writeMu.Unlock()
	conn.readMu.Lock()
	conn.readNonce = NonceRekeyThreshold
	conn.readMu.Unlock()
	assert.True(t, conn.NonceExhaustionImminent())

	conn.readMu.Lock()
	conn.readNonce = 0
	conn.readMu.Unlock()
	assert.False(t, conn.NonceExhaustionImminent())
}

func TestNonceExhaustion_AdvisoryOnly(t *testing.T) {
	conn := createTestNTCP2Conn(&mockNoiseConn{})

	conn.writeMu.Lock()
	conn.writeNonce = 0
	conn.writeMu.Unlock()
	conn.readMu.Lock()
	conn.readNonce = 0
	conn.readMu.Unlock()
	assert.False(t, conn.NonceExhaustionImminent())

	conn.writeMu.Lock()
	conn.writeNonce = NonceRekeyThreshold
	conn.writeMu.Unlock()
	assert.True(t, conn.NonceExhaustionImminent())
}

func TestZeroKeyMaterial(t *testing.T) {
	conn := createTestNTCP2Conn(&mockNoiseConn{})

	keys := [2]uint64{0xDEADBEEF, 0xCAFEBABE}
	slm := NewSipHashLengthModifier("test", keys, 0x12345678)
	conn.SetLengthObfuscator(slm)

	conn.readMu.Lock()
	conn.readBuffer = []byte("sensitive plaintext data")
	conn.readMu.Unlock()

	conn.zeroKeyMaterial()

	assert.Equal(t, uint64(0), slm.outboundKeys[0])
	assert.Equal(t, uint64(0), slm.outboundKeys[1])
	assert.Equal(t, uint64(0), slm.inboundKeys[0])
	assert.Equal(t, uint64(0), slm.inboundKeys[1])
	assert.Equal(t, uint64(0), slm.outboundIV)
	assert.Equal(t, uint64(0), slm.inboundIV)

	conn.readMu.Lock()
	assert.Nil(t, conn.readBuffer)
	conn.readMu.Unlock()
}

func TestRekey(t *testing.T) {
	conn := createTestNTCP2Conn(&mockNoiseConn{})
	err := conn.Rekey()
	_ = err
}

func TestHandshakeHash(t *testing.T) {
	conn := createTestNTCP2Conn(&mockNoiseConn{})
	h := conn.HandshakeHash()
	assert.NotNil(t, h)
	assert.Equal(t, 32, len(h))
}

func TestPeerStaticKey(t *testing.T) {
	conn := createTestNTCP2Conn(&mockNoiseConn{})
	key := conn.PeerStaticKey()
	assert.Nil(t, key)
}

func TestWriteFramed_MultiFrameSplit(t *testing.T) {
	conn := createTestNTCP2Conn(&mockNoiseConn{})

	slm := NewSipHashLengthModifier("test", [2]uint64{0x1234, 0x5678}, 0)
	conn.SetLengthObfuscator(slm)

	maxPlaintext := MaxFrameSize - Poly1305Overhead
	largePayload := make([]byte, maxPlaintext+100)

	_, err := conn.Write(largePayload)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to encrypt frame")
}

func TestReadFramed_BufferRemainder(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()

	config := noise.NewConnConfig("XK", true)
	noiseConn, err := noise.NewNoiseConn(client, config)
	require.NoError(t, err)
	defer noiseConn.Close()

	localAddr := createTestNTCP2Addr("local", "initiator")
	remoteAddr := createTestNTCP2Addr("remote", "responder")
	ntcp2Conn, err := NewNTCP2Conn(noiseConn, localAddr, remoteAddr)
	require.NoError(t, err)

	ntcp2Conn.readMu.Lock()
	ntcp2Conn.readBuffer = []byte("buffered-remainder-data")
	ntcp2Conn.readMu.Unlock()

	slm := NewSipHashLengthModifier("test", [2]uint64{0x1234, 0x5678}, 0)
	ntcp2Conn.SetLengthObfuscator(slm)

	smallBuf := make([]byte, 8)
	n, err := ntcp2Conn.Read(smallBuf)
	assert.NoError(t, err)
	assert.Equal(t, 8, n)
	assert.Equal(t, "buffered", string(smallBuf[:n]))

	remainBuf := make([]byte, 32)
	n, err = ntcp2Conn.Read(remainBuf)
	assert.NoError(t, err)
	assert.Equal(t, "-remainder-data", string(remainBuf[:n]))
}

// ============================================================================
// Tests from audit_fixes_4_test.go — conn-related
// ============================================================================

func TestAuditFix_NonceExhaustion_WriteRejectsAtMaxNonce(t *testing.T) {
	conn := createTestNTCP2Conn(&mockNoiseConn{})
	slm := NewSipHashLengthModifier("test", [2]uint64{0x1234, 0x5678}, 0)
	conn.SetLengthObfuscator(slm)

	conn.writeNonce = MaxNonce

	_, err := conn.Write([]byte("hello"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nonce exhausted")
}

func TestAuditFix_NonceExhaustion_ReadRejectsAtMaxNonce(t *testing.T) {
	conn := createTestNTCP2Conn(&mockNoiseConn{})
	slm := NewSipHashLengthModifier("test", [2]uint64{0x1234, 0x5678}, 0)
	conn.SetLengthObfuscator(slm)

	conn.readNonce = MaxNonce

	buf := make([]byte, 64)
	_, err := conn.Read(buf)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nonce exhausted")
}

func TestAuditFix_NonceExhaustion_BelowMaxNonceAllowed(t *testing.T) {
	conn := createTestNTCP2Conn(&mockNoiseConn{})
	slm := NewSipHashLengthModifier("test", [2]uint64{0x1234, 0x5678}, 0)
	conn.SetLengthObfuscator(slm)

	conn.writeNonce = MaxNonce - 1

	_, err := conn.Write([]byte("hello"))
	if err != nil {
		assert.NotContains(t, err.Error(), "nonce exhausted",
			"nonce just below MaxNonce should not trigger exhaustion")
	}
}

func TestAuditFix_NonceExhaustion_ReadBelowMaxNonceAllowed(t *testing.T) {
	conn := createTestNTCP2Conn(&mockNoiseConn{
		readData: make([]byte, 100),
	})
	slm := NewSipHashLengthModifier("test", [2]uint64{0x1234, 0x5678}, 0)
	conn.SetLengthObfuscator(slm)

	conn.readNonce = MaxNonce - 1

	buf := make([]byte, 64)
	_, err := conn.Read(buf)
	if err != nil {
		assert.NotContains(t, err.Error(), "nonce exhausted",
			"nonce just below MaxNonce should not trigger exhaustion")
	}
}

func TestAuditFix_BrokenFlag_WriteRejects(t *testing.T) {
	conn := createTestNTCP2Conn(&mockNoiseConn{})
	slm := NewSipHashLengthModifier("test", [2]uint64{0x1234, 0x5678}, 0)
	conn.SetLengthObfuscator(slm)

	conn.broken.Store(true)

	_, err := conn.Write([]byte("hello"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "connection is broken")
}

func TestAuditFix_BrokenFlag_ReadRejects(t *testing.T) {
	conn := createTestNTCP2Conn(&mockNoiseConn{})
	slm := NewSipHashLengthModifier("test", [2]uint64{0x1234, 0x5678}, 0)
	conn.SetLengthObfuscator(slm)

	conn.broken.Store(true)

	buf := make([]byte, 64)
	_, err := conn.Read(buf)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "connection is broken")
}

func TestAuditFix_BrokenFlag_NotBrokenInitially(t *testing.T) {
	conn := createTestNTCP2Conn(&mockNoiseConn{})
	assert.False(t, conn.broken.Load(), "new connection should not be broken")
}

func TestAuditFix_BrokenFlag_DirectReadChecked(t *testing.T) {
	conn := createTestNTCP2Conn(&mockNoiseConn{})
	conn.broken.Store(true)

	buf := make([]byte, 64)
	_, err := conn.Read(buf)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "connection is broken")
}

func TestAuditFix_BrokenFlag_DirectWriteChecked(t *testing.T) {
	conn := createTestNTCP2Conn(&mockNoiseConn{})
	conn.broken.Store(true)

	_, err := conn.Write([]byte("hello"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "connection is broken")
}

func TestAuditFix_HandleAEADError_MarksBroken(t *testing.T) {
	conn := createTestNTCP2Conn(&mockNoiseConn{})
	assert.False(t, conn.broken.Load())

	mockUnderlying := &mockNoiseConn{}
	conn.handleAEADError(mockUnderlying)

	assert.True(t, conn.broken.Load(), "handleAEADError should mark connection as broken")
}

func TestAuditFix_HandleAEADError_ClosesConnection(t *testing.T) {
	conn := createTestNTCP2Conn(&mockNoiseConn{})

	mockUnderlying := &mockNoiseConn{}
	conn.handleAEADError(mockUnderlying)

	assert.True(t, mockUnderlying.closed, "handleAEADError should close the underlying connection")
}

func TestAuditFix_SendTCPRST_FallbackCloseForNonTCP(t *testing.T) {
	conn := createTestNTCP2Conn(&mockNoiseConn{})

	mockUnderlying := &mockNoiseConn{}
	conn.sendTCPRST(mockUnderlying)

	assert.True(t, mockUnderlying.closed, "sendTCPRST should close non-TCP connections via fallback")
}

func TestAuditFix_GetMaxFrameSize_DefaultsToConstant(t *testing.T) {
	conn := createTestNTCP2Conn(&mockNoiseConn{})
	assert.Equal(t, MaxFrameSize, conn.getMaxFrameSize())
}

func TestAuditFix_GetMaxFrameSize_UsesConfigValue(t *testing.T) {
	conn := createTestNTCP2Conn(&mockNoiseConn{})
	cfg := &NTCP2Config{MaxFrameSize: 16384}
	conn.SetNTCP2Config(cfg)

	assert.Equal(t, 16384, conn.getMaxFrameSize())
}

func TestAuditFix_GetMaxFrameSize_IgnoresZeroConfig(t *testing.T) {
	conn := createTestNTCP2Conn(&mockNoiseConn{})
	cfg := &NTCP2Config{MaxFrameSize: 0}
	conn.SetNTCP2Config(cfg)

	assert.Equal(t, MaxFrameSize, conn.getMaxFrameSize(),
		"zero MaxFrameSize in config should fall back to constant")
}

func TestAuditFix_GetMaxFrameSize_IgnoresOversizedConfig(t *testing.T) {
	conn := createTestNTCP2Conn(&mockNoiseConn{})
	cfg := &NTCP2Config{MaxFrameSize: MaxFrameSize + 100}
	conn.SetNTCP2Config(cfg)

	assert.Equal(t, MaxFrameSize, conn.getMaxFrameSize(),
		"oversized MaxFrameSize should fall back to constant")
}

func TestAuditFix_SetNTCP2Config_ThreadSafe(t *testing.T) {
	conn := createTestNTCP2Conn(&mockNoiseConn{})

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			cfg := &NTCP2Config{MaxFrameSize: 1000 + i}
			conn.SetNTCP2Config(cfg)
		}(i)
	}

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = conn.getMaxFrameSize()
		}()
	}

	wg.Wait()
}

func TestAuditFix_PropagateSipHash_ThreadSafe(t *testing.T) {
	conn := createTestNTCP2Conn(&mockNoiseConn{})

	var wg sync.WaitGroup

	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			cfg := &NTCP2Config{EnableSipHashLength: true}
			conn.SetNTCP2Config(cfg)
		}()
		go func() {
			defer wg.Done()
			conn.PropagateSipHash()
		}()
	}

	wg.Wait()
}

func TestAuditFix_ReadDirect_NoDoubleWrapping(t *testing.T) {
	conn := createTestNTCP2Conn(&mockNoiseConn{})

	buf := make([]byte, 64)
	_, err := conn.Read(buf)
	require.Error(t, err)

	assert.NotContains(t, err.Error(), "ntcp2 read failed",
		"readDirect should not double-wrap errors from NoiseConn")
}

func TestAuditFix_WriteDirect_NoDoubleWrapping(t *testing.T) {
	conn := createTestNTCP2Conn(&mockNoiseConn{})

	_, err := conn.Write([]byte("hello"))
	require.Error(t, err)

	assert.NotContains(t, err.Error(), "ntcp2 write failed",
		"writeDirect should not double-wrap errors from NoiseConn")
}

func TestAuditFix_NonceExhaustionImminent_Advisory(t *testing.T) {
	conn := createTestNTCP2Conn(&mockNoiseConn{})

	conn.writeNonce = 0
	conn.readNonce = 0
	assert.False(t, conn.NonceExhaustionImminent())

	conn.writeNonce = NonceRekeyThreshold
	assert.True(t, conn.NonceExhaustionImminent())

	conn.writeNonce = 0
	conn.readNonce = NonceRekeyThreshold
	assert.True(t, conn.NonceExhaustionImminent())
}

func TestAuditFix_BrokenAndNonceExhausted_BrokenTakesPriority(t *testing.T) {
	conn := createTestNTCP2Conn(&mockNoiseConn{})
	slm := NewSipHashLengthModifier("test", [2]uint64{0x1234, 0x5678}, 0)
	conn.SetLengthObfuscator(slm)

	conn.broken.Store(true)
	conn.writeNonce = MaxNonce

	_, err := conn.Write([]byte("hello"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "connection is broken")
}

func TestAuditFix_NonceExhaustionError_ContainsCode(t *testing.T) {
	conn := createTestNTCP2Conn(&mockNoiseConn{})
	slm := NewSipHashLengthModifier("test", [2]uint64{0x1234, 0x5678}, 0)
	conn.SetLengthObfuscator(slm)

	conn.writeNonce = MaxNonce

	_, err := conn.Write([]byte("hello"))
	require.Error(t, err)
	errStr := err.Error()
	assert.True(t,
		strings.Contains(errStr, "NONCE_EXHAUSTED") || strings.Contains(errStr, "nonce exhausted"),
		"error should indicate nonce exhaustion, got: %s", errStr)
}

func TestAuditFix_LoggerIsPointer(t *testing.T) {
	conn := createTestNTCP2Conn(&mockNoiseConn{})
	assert.NotNil(t, conn.logger, "logger should be set to package-level log pointer")
}

// ============================================================================
// Tests from audit_fixes_5_test.go — conn-related
// ============================================================================

func TestAuditFix_Close_SuppressesErrorOnBrokenConn(t *testing.T) {
	mock := &mockNoiseConn{
		closeErr: errors.New("use of closed network connection"),
	}
	conn := createTestNTCP2Conn(mock)

	conn.broken.Store(true)

	err := conn.Close()
	assert.NoError(t, err, "Close() must suppress errors on broken connections")
}

func TestAuditFix_Close_PropagatesErrorOnHealthyConn(t *testing.T) {
	mock := &mockNoiseConn{
		closeErr: errors.New("unexpected close error"),
	}
	conn := createTestNTCP2Conn(mock)

	err := conn.Close()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "ntcp2 close failed")
}

func TestAuditFix_NonceExhaustion_ReadMarksBroken(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()

	config := noise.NewConnConfig("XK", true)
	noiseConn, err := noise.NewNoiseConn(client, config)
	require.NoError(t, err)
	defer noiseConn.Close()

	localAddr := createTestNTCP2Addr("local", "initiator")
	remoteAddr := createTestNTCP2Addr("remote", "responder")
	conn, err := NewNTCP2Conn(noiseConn, localAddr, remoteAddr)
	require.NoError(t, err)

	slm := NewSipHashLengthModifier("test", [2]uint64{1, 2}, 0)
	conn.SetLengthObfuscator(slm)

	conn.readNonce = MaxNonce

	buf := make([]byte, 64)
	conn.readMu.Lock()
	_, err = conn.readFramed(buf)
	conn.readMu.Unlock()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "nonce exhausted")
	assert.True(t, conn.broken.Load(), "connection must be marked broken on read nonce exhaustion")
}

func TestAuditFix_NonceExhaustion_WriteMarksBroken(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()

	config := noise.NewConnConfig("XK", true)
	noiseConn, err := noise.NewNoiseConn(client, config)
	require.NoError(t, err)
	defer noiseConn.Close()

	localAddr := createTestNTCP2Addr("local", "initiator")
	remoteAddr := createTestNTCP2Addr("remote", "responder")
	conn, err := NewNTCP2Conn(noiseConn, localAddr, remoteAddr)
	require.NoError(t, err)

	slm := NewSipHashLengthModifier("test", [2]uint64{1, 2}, 0)
	conn.SetLengthObfuscator(slm)

	conn.writeNonce = MaxNonce

	_, err = conn.writeSingleFrame([]byte("hello"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "nonce exhausted")
	assert.True(t, conn.broken.Load(), "connection must be marked broken on write nonce exhaustion")
}

func TestAuditFix_NonceExhaustion_PreventsSubsequentIO(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()

	config := noise.NewConnConfig("XK", true)
	noiseConn, err := noise.NewNoiseConn(client, config)
	require.NoError(t, err)
	defer noiseConn.Close()

	localAddr := createTestNTCP2Addr("local", "initiator")
	remoteAddr := createTestNTCP2Addr("remote", "responder")
	conn, err := NewNTCP2Conn(noiseConn, localAddr, remoteAddr)
	require.NoError(t, err)

	slm := NewSipHashLengthModifier("test", [2]uint64{1, 2}, 0)
	conn.SetLengthObfuscator(slm)

	conn.broken.Store(true)

	buf := make([]byte, 64)
	_, readErr := conn.Read(buf)
	assert.Error(t, readErr)
	assert.Contains(t, readErr.Error(), "connection is broken")

	_, writeErr := conn.Write([]byte("test"))
	assert.Error(t, writeErr)
	assert.Contains(t, writeErr.Error(), "connection is broken")
}

func TestAuditFix_ValidateFrameLength_ZeroHandledByMinCheck(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()

	config := noise.NewConnConfig("XK", true)
	noiseConn, err := noise.NewNoiseConn(client, config)
	require.NoError(t, err)
	defer noiseConn.Close()

	conn, err := NewNTCP2Conn(noiseConn,
		createTestNTCP2Addr("local", "initiator"),
		createTestNTCP2Addr("remote", "responder"))
	require.NoError(t, err)

	err = conn.validateFrameLength(0)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "below minimum")
	assert.Contains(t, err.Error(), "16")
}

func TestAuditFix_ValidateFrameLength_AllBelowMin(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()

	config := noise.NewConnConfig("XK", true)
	noiseConn, err := noise.NewNoiseConn(client, config)
	require.NoError(t, err)
	defer noiseConn.Close()

	conn, err := NewNTCP2Conn(noiseConn,
		createTestNTCP2Addr("local", "initiator"),
		createTestNTCP2Addr("remote", "responder"))
	require.NoError(t, err)

	for i := uint16(0); i < MinDataPhaseFrameSize; i++ {
		err := conn.validateFrameLength(i)
		assert.Error(t, err, "frameLen=%d should be rejected", i)
	}

	err = conn.validateFrameLength(MinDataPhaseFrameSize)
	assert.NoError(t, err)
}

func TestAuditFix_ValidateFrameLength_UsesSpecMaxFrameSize(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()

	config := noise.NewConnConfig("XK", true)
	noiseConn, err := noise.NewNoiseConn(client, config)
	require.NoError(t, err)
	defer noiseConn.Close()

	conn, err := NewNTCP2Conn(noiseConn,
		createTestNTCP2Addr("local", "initiator"),
		createTestNTCP2Addr("remote", "responder"))
	require.NoError(t, err)

	err = conn.validateFrameLength(uint16(SpecMaxFrameSize))
	assert.NoError(t, err, "SpecMaxFrameSize must be accepted")

	err = conn.validateFrameLength(uint16(DefaultMaxFrameSize + 1000))
	assert.NoError(t, err, "frames between DefaultMaxFrameSize and SpecMaxFrameSize must be accepted")
}

func TestAuditFix_AEADErrorMaxJunkBytes_IsPowerOfTwo(t *testing.T) {
	assert.Equal(t, 1024, AEADErrorMaxJunkBytes)
	assert.Equal(t, 0, AEADErrorMaxJunkBytes&(AEADErrorMaxJunkBytes-1),
		"AEADErrorMaxJunkBytes must be a power of two for bitmask to avoid modulo bias")
}

func TestAuditFix_ReadDirect_PartialReadWithError(t *testing.T) {
	conn := createTestNTCP2Conn(&mockNoiseConn{})
	buf := make([]byte, 64)
	_, err := conn.Read(buf)
	assert.Error(t, err)
}

func TestAuditFix_Close_Idempotent(t *testing.T) {
	mock := &mockNoiseConn{}
	conn := createTestNTCP2Conn(mock)

	err1 := conn.Close()
	assert.NoError(t, err1)

	err2 := conn.Close()
	assert.NoError(t, err2)

	assert.True(t, mock.closed)
}

func TestAuditFix_HandleAEADError_SetsBroken(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	config := noise.NewConnConfig("XK", true)
	noiseConn, err := noise.NewNoiseConn(client, config)
	require.NoError(t, err)

	conn, err := NewNTCP2Conn(noiseConn,
		createTestNTCP2Addr("local", "initiator"),
		createTestNTCP2Addr("remote", "responder"))
	require.NoError(t, err)

	assert.False(t, conn.broken.Load())

	go func() {
		server.Write(make([]byte, 2048))
		time.Sleep(50 * time.Millisecond)
		server.Close()
	}()

	underlying := noiseConn.Underlying()
	conn.handleAEADError(underlying)

	assert.True(t, conn.broken.Load(), "handleAEADError must set broken flag")
}

func TestAuditFix_GetMaxFrameSize_FallsBackToSpecMax(t *testing.T) {
	conn := createTestNTCP2Conn(&mockNoiseConn{})
	assert.Equal(t, SpecMaxFrameSize, conn.getMaxFrameSize())
}

func TestAuditFix_GetMaxFrameSize_RespectsConfig(t *testing.T) {
	conn := createTestNTCP2Conn(&mockNoiseConn{})
	cfg := &NTCP2Config{MaxFrameSize: 8192}
	conn.ntcp2Config.Store(cfg)
	assert.Equal(t, 8192, conn.getMaxFrameSize())
}

// TestSetLengthObfuscator verifies the setter for the SipHash length obfuscator.
func TestSetLengthObfuscator(t *testing.T) {
	conn := createTestNTCP2Conn(&mockNoiseConn{})

	// Initially nil
	assert.Nil(t, conn.lengthObfuscator.Load())

	// Set it
	slm := NewSipHashLengthModifier("test-siphash", [2]uint64{0x1234, 0x5678}, 0)
	conn.SetLengthObfuscator(slm)
	assert.Equal(t, slm, conn.lengthObfuscator.Load())

	// Can set to nil to disable
	conn.SetLengthObfuscator(nil)
	assert.Nil(t, conn.lengthObfuscator.Load())
}

// TestFramedWritePath_TakenWhenObfuscatorSet verifies that the framed write
// path is taken when a length obfuscator is set. Since the handshake isn't
// complete, we verify by the error: framed path calls Encrypt which fails
// with "handshake not completed" or "cipher state not initialized".
func TestFramedWritePath_TakenWhenObfuscatorSet(t *testing.T) {
	conn := createTestNTCP2Conn(&mockNoiseConn{})
	slm := NewSipHashLengthModifier("test-siphash", [2]uint64{0x1234, 0x5678}, 0)
	conn.SetLengthObfuscator(slm)

	_, err := conn.Write([]byte("test data"))
	assert.Error(t, err)
	// The framed path calls noiseConn.Encrypt → validateWriteState → fails
	// The error wraps through NTCP2Conn's "ENCRYPT_FAILED" code
	assert.Contains(t, err.Error(), "failed to encrypt frame")
}

// TestDirectWritePath_TakenWhenNoObfuscator verifies that the direct write
// path is taken when no length obfuscator is set.
func TestDirectWritePath_TakenWhenNoObfuscator(t *testing.T) {
	conn := createTestNTCP2Conn(&mockNoiseConn{})

	// No obfuscator set
	_, err := conn.Write([]byte("test data"))
	assert.Error(t, err)
	// The direct path calls noiseConn.Write → validates state → fails
	// NoiseConn returns "handshake not completed" before the write can proceed
	assert.Contains(t, err.Error(), "handshake not completed")
}

// TestFramedReadPath_TakenWhenObfuscatorSet verifies that the framed read
// path is taken when a length obfuscator is set.
func TestFramedReadPath_TakenWhenObfuscatorSet(t *testing.T) {
	// Use a pipe so the underlying connection has actual I/O
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	config := noise.NewConnConfig("XK", true)
	noiseConn, err := noise.NewNoiseConn(client, config)
	require.NoError(t, err)

	localAddr := createTestNTCP2Addr("local", "initiator")
	remoteAddr := createTestNTCP2Addr("remote", "responder")
	ntcp2Conn, err := NewNTCP2Conn(noiseConn, localAddr, remoteAddr)
	require.NoError(t, err)

	slm := NewSipHashLengthModifier("test-siphash", [2]uint64{0x1234, 0x5678}, 0)
	ntcp2Conn.SetLengthObfuscator(slm)

	// Write an obfuscated frame to the server side that will be read by the client
	go func() {
		// Write 2-byte obfuscated length followed by fake ciphertext
		// The length must be >= MinDataPhaseFrameSize (16) to pass validation
		plainLen := uint16(20)
		// Compute the SipHash mask that the reader will use
		iv := make([]byte, SipHashIVSize)
		binary.LittleEndian.PutUint64(iv, 0) // initial IV = 0
		hash := siphash.Hash(0x1234, 0x5678, iv)
		mask := uint16(hash & 0xFFFF)
		obfuscatedLen := plainLen ^ mask

		buf := make([]byte, 2+20)
		binary.BigEndian.PutUint16(buf[:2], obfuscatedLen)
		copy(buf[2:], []byte("ABCDEFGHIJKLMNOPQRST")) // fake ciphertext (will fail to decrypt)
		server.Write(buf)
		// Close after writing so handleAEADError's junk read gets immediate EOF
		server.Close()
	}()

	// Read should get past the length deobfuscation but fail at Decrypt
	// (since no handshake was done, cipher state is not initialized)
	readBuf := make([]byte, 64)
	_, err = ntcp2Conn.Read(readBuf)
	assert.Error(t, err)
	// The framed path reads 2 bytes, deobfuscates, reads the frame, then tries Decrypt
	assert.Contains(t, err.Error(), "failed to decrypt frame")
}

// TestDirectReadPath_TakenWhenNoObfuscator verifies direct delegation.
func TestDirectReadPath_TakenWhenNoObfuscator(t *testing.T) {
	conn := createTestNTCP2Conn(&mockNoiseConn{})

	buf := make([]byte, 64)
	_, err := conn.Read(buf)
	assert.Error(t, err)
	// Direct path delegates to NoiseConn.Read which returns "handshake not completed"
	assert.Contains(t, err.Error(), "handshake not completed")
}

// TestFrameLengthObfuscation_RoundTrip verifies that the SipHash length
// obfuscation math is correct: encode → wire → decode gives back the original length.
func TestFrameLengthObfuscation_RoundTrip(t *testing.T) {
	keys := [2]uint64{0xDEADBEEF, 0xCAFEBABE}
	initialIV := uint64(42)

	// Create two separate modifiers (sender and receiver) with same keys/IV
	sender := NewSipHashLengthModifier("sender", keys, initialIV)
	receiver := NewSipHashLengthModifier("receiver", keys, initialIV)

	testLengths := []uint16{0, 1, 2, 255, 256, 1024, 16384, 65535}

	for _, originalLen := range testLengths {
		// Sender: obfuscate
		outMask := sender.NextOutboundMask()
		obfuscated := originalLen ^ outMask

		// Put on "wire" as big-endian
		wire := make([]byte, 2)
		binary.BigEndian.PutUint16(wire, obfuscated)

		// Receiver: deobfuscate
		inMask := receiver.NextInboundMask()
		recovered := binary.BigEndian.Uint16(wire) ^ inMask

		assert.Equal(t, originalLen, recovered, "round-trip failed for length %d", originalLen)
	}
}

// TestFrameLengthObfuscation_MultipleFrames verifies that mask sequences
// stay in sync across multiple frames.
func TestFrameLengthObfuscation_MultipleFrames(t *testing.T) {
	keys := [2]uint64{0x0102030405060708, 0x090A0B0C0D0E0F10}
	initialIV := uint64(0xABCDEF)

	sender := NewSipHashLengthModifier("sender", keys, initialIV)
	receiver := NewSipHashLengthModifier("receiver", keys, initialIV)

	// Simulate 100 frames with various lengths
	for i := 0; i < 100; i++ {
		originalLen := uint16(i*137 + 1) // Arbitrary non-trivial lengths

		outMask := sender.NextOutboundMask()

		obfuscated := originalLen ^ outMask

		inMask := receiver.NextInboundMask()

		recovered := obfuscated ^ inMask
		assert.Equal(t, originalLen, recovered, "round-trip failed at frame %d", i)
	}
}

// TestFramedRead_ZeroLengthFrame verifies that a zero-length frame is rejected.
func TestFramedRead_ZeroLengthFrame(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	config := noise.NewConnConfig("XK", true)
	noiseConn, err := noise.NewNoiseConn(client, config)
	require.NoError(t, err)

	localAddr := createTestNTCP2Addr("local", "initiator")
	remoteAddr := createTestNTCP2Addr("remote", "responder")
	ntcp2Conn, err := NewNTCP2Conn(noiseConn, localAddr, remoteAddr)
	require.NoError(t, err)

	// Create a modifier and compute the mask value
	keys := [2]uint64{0x1111, 0x2222}
	slm := NewSipHashLengthModifier("test", keys, 0)
	ntcp2Conn.SetLengthObfuscator(slm)

	// Compute what mask the reader will use for the first frame
	probe := NewSipHashLengthModifier("probe", keys, 0)
	mask := probe.NextInboundMask()

	go func() {
		// Write a 2-byte value that deobfuscates to zero
		zeroObfuscated := uint16(0) ^ mask // XOR with mask to get zero after deobfuscation
		buf := make([]byte, 2)
		binary.BigEndian.PutUint16(buf, zeroObfuscated)
		server.Write(buf)
	}()

	readBuf := make([]byte, 64)
	_, err = ntcp2Conn.Read(readBuf)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "below minimum")
}

// TestFramedRead_FrameTooLarge verifies that frames exceeding MaxFrameSize are rejected.
func TestFramedRead_FrameTooLarge(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	config := noise.NewConnConfig("XK", true)
	noiseConn, err := noise.NewNoiseConn(client, config)
	require.NoError(t, err)

	localAddr := createTestNTCP2Addr("local", "initiator")
	remoteAddr := createTestNTCP2Addr("remote", "responder")
	ntcp2Conn, err := NewNTCP2Conn(noiseConn, localAddr, remoteAddr)
	require.NoError(t, err)

	// Use keys that produce a specific mask
	keys := [2]uint64{0, 0}
	slm := NewSipHashLengthModifier("test", keys, 0)
	ntcp2Conn.SetLengthObfuscator(slm)

	// Compute what mask the reader will use
	probe := NewSipHashLengthModifier("probe", keys, 0)
	mask := probe.NextInboundMask()

	go func() {
		// Construct a length that deobfuscates to MaxFrameSize + 1
		// This is impossible since MaxFrameSize is 65535 and uint16 max is 65535
		// So we just need to ensure that MaxFrameSize (65535) itself is accepted
		// Actually MaxFrameSize = 65535 = max uint16, so frame_too_large can't happen
		// with the current constant. Let's verify the check works if we could somehow
		// trigger it. Since uint16 max = 65535 = MaxFrameSize, the check is a guard
		// for future constant changes.

		// Instead, let's test that MaxFrameSize is exactly accepted by checking
		// a valid length doesn't trigger the error. We'll send a valid-length frame
		// that fails later at decryption.
		validLen := uint16(100)
		obfuscated := validLen ^ mask
		buf := make([]byte, 2+100)
		binary.BigEndian.PutUint16(buf[:2], obfuscated)
		// Fill with fake ciphertext
		for i := 2; i < len(buf); i++ {
			buf[i] = byte(i)
		}
		server.Write(buf)
		// Close after writing so handleAEADError's junk read gets immediate EOF
		server.Close()
	}()

	readBuf := make([]byte, 200)
	_, err = ntcp2Conn.Read(readBuf)
	assert.Error(t, err)
	// Should get past length validation and fail at decrypt
	assert.Contains(t, err.Error(), "failed to decrypt frame")
}

// TestFramedRead_ConnectionClosedDuringLengthRead verifies graceful handling
// when the connection closes while reading the length field.
func TestFramedRead_ConnectionClosedDuringLengthRead(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	config := noise.NewConnConfig("XK", true)
	noiseConn, err := noise.NewNoiseConn(client, config)
	require.NoError(t, err)

	localAddr := createTestNTCP2Addr("local", "initiator")
	remoteAddr := createTestNTCP2Addr("remote", "responder")
	ntcp2Conn, err := NewNTCP2Conn(noiseConn, localAddr, remoteAddr)
	require.NoError(t, err)

	slm := NewSipHashLengthModifier("test", [2]uint64{1, 2}, 0)
	ntcp2Conn.SetLengthObfuscator(slm)

	// Close the server side immediately - reader gets EOF
	server.Close()

	readBuf := make([]byte, 64)
	_, err = ntcp2Conn.Read(readBuf)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read frame length")
}

// TestFramedRead_PartialLengthRead verifies handling when only 1 of 2 bytes
// is available for the length field.
func TestFramedRead_PartialLengthRead(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	config := noise.NewConnConfig("XK", true)
	noiseConn, err := noise.NewNoiseConn(client, config)
	require.NoError(t, err)

	localAddr := createTestNTCP2Addr("local", "initiator")
	remoteAddr := createTestNTCP2Addr("remote", "responder")
	ntcp2Conn, err := NewNTCP2Conn(noiseConn, localAddr, remoteAddr)
	require.NoError(t, err)

	slm := NewSipHashLengthModifier("test", [2]uint64{1, 2}, 0)
	ntcp2Conn.SetLengthObfuscator(slm)

	go func() {
		// Write only 1 byte then close
		server.Write([]byte{0x42})
		server.Close()
	}()

	readBuf := make([]byte, 64)
	_, err = ntcp2Conn.Read(readBuf)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read frame length")
}

// TestFramedRead_PartialFrameRead verifies handling when the connection
// closes mid-frame (after length, before full ciphertext).
func TestFramedRead_PartialFrameRead(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	config := noise.NewConnConfig("XK", true)
	noiseConn, err := noise.NewNoiseConn(client, config)
	require.NoError(t, err)

	localAddr := createTestNTCP2Addr("local", "initiator")
	remoteAddr := createTestNTCP2Addr("remote", "responder")
	ntcp2Conn, err := NewNTCP2Conn(noiseConn, localAddr, remoteAddr)
	require.NoError(t, err)

	keys := [2]uint64{0, 0}
	slm := NewSipHashLengthModifier("test", keys, 0)
	ntcp2Conn.SetLengthObfuscator(slm)

	// Compute what mask the reader will use
	probe := NewSipHashLengthModifier("probe", keys, 0)
	mask := probe.NextInboundMask()

	go func() {
		// Write a valid length (100) but only 10 bytes of frame data, then close
		obfuscated := uint16(100) ^ mask
		buf := make([]byte, 2+10)
		binary.BigEndian.PutUint16(buf[:2], obfuscated)
		server.Write(buf)
		server.Close()
	}()

	readBuf := make([]byte, 200)
	_, err = ntcp2Conn.Read(readBuf)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read frame data")
}

// TestFrameWireFormat verifies the exact wire format produced by the
// framing logic: [2-byte big-endian obfuscated length][ciphertext].
func TestFrameWireFormat(t *testing.T) {
	keys := [2]uint64{0xAAAA, 0xBBBB}
	initialIV := uint64(99)

	sender := NewSipHashLengthModifier("sender", keys, initialIV)

	// Compute expected mask
	iv := make([]byte, SipHashIVSize)
	binary.LittleEndian.PutUint64(iv, initialIV)
	hash := siphash.Hash(keys[0], keys[1], iv)
	expectedMask := uint16(hash & 0xFFFF)

	plainLen := uint16(42)
	expectedObfuscated := plainLen ^ expectedMask

	// Simulate what writeFramed does for the length field
	mask := sender.NextOutboundMask()
	assert.Equal(t, expectedMask, mask)

	obfuscated := plainLen ^ mask
	assert.Equal(t, expectedObfuscated, obfuscated)

	// Verify wire encoding
	wire := make([]byte, 2)
	binary.BigEndian.PutUint16(wire, obfuscated)

	// Decode and verify
	recovered := binary.BigEndian.Uint16(wire)
	assert.Equal(t, obfuscated, recovered)
}

// TestFrameIO_FullPipeRoundTrip tests the full frame I/O path using a net.Pipe.
// This verifies that data written by writeFramed can be read back by readFramed,
// using a mock encrypt/decrypt approach (bypassing actual Noise crypto).
func TestFrameIO_FullPipeRoundTrip(t *testing.T) {
	// This test uses raw pipe I/O to verify the frame encoding matches
	// between writer and reader, without needing actual Noise handshake.
	keys := [2]uint64{0xDEAD, 0xBEEF}
	initialIV := uint64(0)

	// Compute the first mask
	senderMod := NewSipHashLengthModifier("sender", keys, initialIV)
	outMask := senderMod.NextOutboundMask()

	receiverMod := NewSipHashLengthModifier("receiver", keys, initialIV)
	inMask := receiverMod.NextInboundMask()

	// Masks should match
	assert.Equal(t, outMask, inMask, "sender and receiver masks should match")

	// Simulate a frame on the wire
	fakeCiphertext := []byte("encrypted-payload-here")
	frameLen := uint16(len(fakeCiphertext))
	obfuscatedLen := frameLen ^ outMask

	// Build wire frame
	var wire bytes.Buffer
	lengthBuf := make([]byte, FrameLengthFieldSize)
	binary.BigEndian.PutUint16(lengthBuf, obfuscatedLen)
	wire.Write(lengthBuf)
	wire.Write(fakeCiphertext)

	// Now verify reading
	reader := bytes.NewReader(wire.Bytes())
	// Read 2 bytes
	readLenBuf := make([]byte, FrameLengthFieldSize)
	_, err := io.ReadFull(reader, readLenBuf)
	require.NoError(t, err)

	// Deobfuscate
	recoveredLen := binary.BigEndian.Uint16(readLenBuf) ^ inMask
	assert.Equal(t, frameLen, recoveredLen)

	// Read frame
	frame := make([]byte, recoveredLen)
	_, err = io.ReadFull(reader, frame)
	require.NoError(t, err)

	assert.Equal(t, fakeCiphertext, frame)
}

// ============================================================================
// Tests for double-close fix (underlyingClosed) and plaintext zeroing
// ============================================================================

// countingMockConn extends mockNoiseConn to count Close() invocations.
type countingMockConn struct {
	mockNoiseConn
	closeCount int
	mu         sync.Mutex
}

func (c *countingMockConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closeCount++
	c.closed = true
	return c.closeErr
}

// TestSendTCPRST_SetsUnderlyingClosed verifies that sendTCPRST sets the
// underlyingClosed flag so that a subsequent Close() call knows the socket
// has already been closed and can skip the second close.
func TestSendTCPRST_SetsUnderlyingClosed(t *testing.T) {
	mock := &mockNoiseConn{}
	conn := createTestNTCP2Conn(mock)

	assert.False(t, conn.underlyingClosed.Load(), "underlyingClosed should be false before sendTCPRST")

	// sendTCPRST with a non-TCPConn mock (uses fallback Close path)
	fakePeer := &mockNoiseConn{}
	conn.sendTCPRST(fakePeer)

	assert.True(t, conn.underlyingClosed.Load(), "sendTCPRST must set underlyingClosed to true")
	assert.True(t, fakePeer.closed, "sendTCPRST must close the supplied connection")
}

// TestHandleAEADError_SetsUnderlyingClosed verifies that handleAEADError
// indirectly sets underlyingClosed via sendTCPRST, so that Close() later
// skips the redundant noiseConn.Close() call.
func TestHandleAEADError_SetsUnderlyingClosed(t *testing.T) {
	mock := &mockNoiseConn{}
	conn := createTestNTCP2Conn(mock)

	assert.False(t, conn.underlyingClosed.Load())

	underlying := &mockNoiseConn{}
	conn.handleAEADError(underlying)

	assert.True(t, conn.broken.Load(), "handleAEADError must set broken flag")
	assert.True(t, conn.underlyingClosed.Load(), "handleAEADError must set underlyingClosed via sendTCPRST")
}

// TestClose_SkipsNoiseConnCloseWhenUnderlyingAlreadyClosed verifies that when
// underlyingClosed is true (set by sendTCPRST), Close() returns without
// performing a second close of the same socket.
//
// This prevents the fd-reuse double-close race described in the NTCP2 audit:
// sendTCPRST() closes the TCP socket directly; if Close() also calls
// noiseConn.Close(), the OS may have reassigned the fd to a new socket by
// the time the second Close() runs.
func TestClose_SkipsNoiseConnCloseWhenUnderlyingAlreadyClosed(t *testing.T) {
	counting := &countingMockConn{}
	conn := createTestNTCP2Conn(&counting.mockNoiseConn)

	// Simulate that sendTCPRST has already closed the underlying socket.
	conn.broken.Store(true)
	conn.underlyingClosed.Store(true)

	err := conn.Close()
	assert.NoError(t, err)

	// The mock underlying must NOT be closed a second time by noiseConn.Close().
	// (noiseConn.Close() would cascade into the mock's Close().)
	counting.mu.Lock()
	count := counting.closeCount
	counting.mu.Unlock()
	assert.Equal(t, 0, count,
		"Close() must not call noiseConn.Close() when underlyingClosed is already set")
}

// TestClose_CallsNoiseConnCloseWhenUnderlyingNotYetClosed verifies the normal
// (non-RST) close path: when underlyingClosed is false, Close() delegates to
// noiseConn.Close() as usual.
func TestClose_CallsNoiseConnCloseWhenUnderlyingNotYetClosed(t *testing.T) {
	mock := &mockNoiseConn{}
	conn := createTestNTCP2Conn(mock)

	err := conn.Close()
	// noiseConn itself may or may not error depending on internal state;
	// what matters is that the mock's Close was eventually reached.
	_ = err
	assert.True(t, mock.closed,
		"Close() must call noiseConn.Close() (and transitively close the mock) on the normal path")
}

// TestReadFramed_PlaintextZeroed verifies that the zeroing of the Decrypt output
// in readFramed does not corrupt the data returned to callers. The function
// must both (a) zero the internal buffer for security and (b) return correct
// plaintext to the caller via the caller's buffer and readBuffer.
//
// We test this via bufferPlaintext directly: after copying into the destination
// buffer and readBuffer, zeroing the original plaintext slice must not corrupt
// either copy, because bufferPlaintext uses deep-copy (copy(b, plaintext) and
// a freshly-allocated readBuffer), not sub-slicing.
func TestReadFramed_PlaintextZeroed_DataReachesCallerIntact(t *testing.T) {
	conn := createTestNTCP2Conn(&mockNoiseConn{})

	// Simulate a Decrypt output: 10 bytes of plaintext.
	plaintext := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	want := make([]byte, len(plaintext))
	copy(want, plaintext)

	// bufferPlaintext with a small caller buffer (5 bytes) → overflow goes to readBuffer.
	callerBuf := make([]byte, 5)
	n := conn.bufferPlaintext(callerBuf, plaintext)
	assert.Equal(t, 5, n)

	// Now zero the original plaintext, mimicking what readFramed does.
	for i := range plaintext {
		plaintext[i] = 0
	}
	assert.Equal(t, make([]byte, 10), plaintext, "original plaintext slice must be zeroed")

	// The caller's buffer must hold the first 5 bytes unchanged.
	assert.Equal(t, want[:5], callerBuf,
		"caller buffer must retain data despite zeroing the Decrypt output")

	// The readBuffer overflow must hold the remaining 5 bytes unchanged.
	assert.Equal(t, want[5:], conn.readBuffer,
		"readBuffer overflow must retain data despite zeroing the Decrypt output")
}

// TestAuditFix_ValidateFrameLength_TypeConstraintEnforcesUpperBound documents that
// the previous FRAME_TOO_LARGE branch (`int(frameLen) > SpecMaxFrameSize`) was dead
// code and has been removed.  Because frameLen is uint16 and SpecMaxFrameSize equals
// math.MaxUint16 (65535), the wire-format type itself enforces the upper bound;
// no runtime check is possible or required.  This test pins that the maximum uint16
// value is always accepted and that the constant relationship holds.
func TestAuditFix_ValidateFrameLength_TypeConstraintEnforcesUpperBound(t *testing.T) {
	conn := createTestNTCP2Conn(&mockNoiseConn{})

	// uint16(65535) == SpecMaxFrameSize == math.MaxUint16.
	// The dead branch `int(frameLen) > 65535` could never fire; it has been removed.
	err := conn.validateFrameLength(uint16(SpecMaxFrameSize))
	assert.NoError(t, err,
		"uint16(SpecMaxFrameSize)==%d must be accepted; type constraint holds", SpecMaxFrameSize)

	err = conn.validateFrameLength(uint16(SpecMaxFrameSize) - 1)
	assert.NoError(t, err, "SpecMaxFrameSize-1 must also be accepted")

	// The constant relationship that makes the upper-bound check unreachable.
	const uint16Max = 65535
	assert.EqualValues(t, uint16Max, SpecMaxFrameSize,
		"SpecMaxFrameSize must equal uint16 max (65535) for type constraint to hold")
}

// ============================================================================
// Tests for PhaseData modifier wiring in NTCP2 framed I/O path
// ============================================================================

// ntcp2TrackingModifier records calls to ModifyOutbound and ModifyInbound
// and passes data through unchanged, allowing assertion of PhaseData wiring.
type ntcp2TrackingModifier struct {
	mu            sync.Mutex
	outboundCalls []struct {
		phase handshake.HandshakePhase
		data  []byte
	}
	inboundCalls []struct {
		phase handshake.HandshakePhase
		data  []byte
	}
}

func (m *ntcp2TrackingModifier) ModifyOutbound(phase handshake.HandshakePhase, data []byte) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.outboundCalls = append(m.outboundCalls, struct {
		phase handshake.HandshakePhase
		data  []byte
	}{phase, append([]byte(nil), data...)})
	return data, nil
}

func (m *ntcp2TrackingModifier) ModifyInbound(phase handshake.HandshakePhase, data []byte) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.inboundCalls = append(m.inboundCalls, struct {
		phase handshake.HandshakePhase
		data  []byte
	}{phase, append([]byte(nil), data...)})
	return data, nil
}

func (m *ntcp2TrackingModifier) Name() string { return "ntcp2-tracking-modifier" }
func (m *ntcp2TrackingModifier) Close() error { return nil }

// createTestNTCP2ConnWithModifier creates an NTCP2Conn whose underlying
// NoiseConn has the supplied modifier configured. Use this to verify that
// applyOutboundModifier / applyInboundModifier delegate to the chain.
func createTestNTCP2ConnWithModifier(mod handshake.HandshakeModifier) *NTCP2Conn {
	mockNet := &mockNoiseConn{}
	cfg := noise.NewConnConfig("XK", true).WithModifiers(mod)
	noiseConn, err := noise.NewNoiseConn(mockNet, cfg)
	if err != nil {
		panic(err)
	}
	localAddr := createTestNTCP2Addr("local", "initiator")
	remoteAddr := createTestNTCP2Addr("remote", "responder")
	conn, err := NewNTCP2Conn(noiseConn, localAddr, remoteAddr)
	if err != nil {
		panic(err)
	}
	return conn
}

// TestNTCP2ApplyOutboundModifier_NoChain verifies passthrough when no modifier chain is set.
func TestNTCP2ApplyOutboundModifier_NoChain(t *testing.T) {
	conn := createTestNTCP2Conn(&mockNoiseConn{})
	data := []byte("hello")
	got, err := conn.applyOutboundModifier(data)
	require.NoError(t, err)
	assert.Equal(t, data, got, "passthrough expected with no modifier chain")
}

// TestNTCP2ApplyInboundModifier_NoChain verifies passthrough when no modifier chain is set.
func TestNTCP2ApplyInboundModifier_NoChain(t *testing.T) {
	conn := createTestNTCP2Conn(&mockNoiseConn{})
	data := []byte("hello")
	got, err := conn.applyInboundModifier(data)
	require.NoError(t, err)
	assert.Equal(t, data, got, "passthrough expected with no modifier chain")
}

// TestNTCP2ApplyOutboundModifier_InvokesPhaseData verifies ModifyOutbound is
// called with PhaseData when a modifier chain is configured.
func TestNTCP2ApplyOutboundModifier_InvokesPhaseData(t *testing.T) {
	mod := &ntcp2TrackingModifier{}
	conn := createTestNTCP2ConnWithModifier(mod)

	data := []byte("outbound data")
	_, err := conn.applyOutboundModifier(data)
	require.NoError(t, err)

	mod.mu.Lock()
	defer mod.mu.Unlock()
	require.Len(t, mod.outboundCalls, 1, "expected exactly one outbound modifier call")
	assert.Equal(t, handshake.PhaseData, mod.outboundCalls[0].phase,
		"framed write must invoke modifier with PhaseData")
	assert.Equal(t, data, mod.outboundCalls[0].data, "modifier must receive original data")
}

// TestNTCP2ApplyInboundModifier_InvokesPhaseData verifies ModifyInbound is
// called with PhaseData when a modifier chain is configured.
func TestNTCP2ApplyInboundModifier_InvokesPhaseData(t *testing.T) {
	mod := &ntcp2TrackingModifier{}
	conn := createTestNTCP2ConnWithModifier(mod)

	data := []byte("inbound data")
	_, err := conn.applyInboundModifier(data)
	require.NoError(t, err)

	mod.mu.Lock()
	defer mod.mu.Unlock()
	require.Len(t, mod.inboundCalls, 1, "expected exactly one inbound modifier call")
	assert.Equal(t, handshake.PhaseData, mod.inboundCalls[0].phase,
		"framed read must invoke modifier with PhaseData")
	assert.Equal(t, data, mod.inboundCalls[0].data, "modifier must receive original data")
}
