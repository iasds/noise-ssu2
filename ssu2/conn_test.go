package ssu2

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/go-i2p/noise"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test helpers

// createTestConfig creates a test SSU2Config with sensible defaults.
func createTestConfig(t *testing.T) *SSU2Config {
	t.Helper()
	routerHash := make([]byte, 32)
	remoteHash := make([]byte, 32)
	for i := range remoteHash {
		remoteHash[i] = byte(i + 1) // Different from routerHash
	}
	config, err := NewSSU2Config(routerHash, true)
	require.NoError(t, err)
	config.RemoteRouterHash = remoteHash
	config.ConnectionID = 123456 // Non-zero connection ID
	return config
}

// mockPacketConn implements net.PacketConn for testing.
type mockPacketConn struct {
	readChan     chan mockPacket
	writeChan    chan mockPacket
	localAddr    net.Addr
	closed       bool
	readDeadline time.Time
}

type mockPacket struct {
	data []byte
	addr net.Addr
	err  error
}

// timeoutError implements net.Error for timeout conditions.
type timeoutError struct{}

func (e *timeoutError) Error() string   { return "i/o timeout" }
func (e *timeoutError) Timeout() bool   { return true }
func (e *timeoutError) Temporary() bool { return true }

func newMockPacketConn(localAddr net.Addr) *mockPacketConn {
	return &mockPacketConn{
		readChan:  make(chan mockPacket, 10),
		writeChan: make(chan mockPacket, 10),
		localAddr: localAddr,
	}
}

func (m *mockPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	if m.closed {
		return 0, nil, net.ErrClosed
	}

	// Respect read deadline
	var timer *time.Timer
	var timerChan <-chan time.Time
	if !m.readDeadline.IsZero() {
		timeout := time.Until(m.readDeadline)
		if timeout <= 0 {
			return 0, nil, &net.OpError{Op: "read", Net: "udp", Err: &timeoutError{}}
		}
		timer = time.NewTimer(timeout)
		timerChan = timer.C
		defer timer.Stop()
	}

	select {
	case packet, ok := <-m.readChan:
		if !ok {
			return 0, nil, net.ErrClosed
		}
		if packet.err != nil {
			return 0, nil, packet.err
		}
		n = copy(p, packet.data)
		return n, packet.addr, nil
	case <-timerChan:
		return 0, nil, &net.OpError{Op: "read", Net: "udp", Err: &timeoutError{}}
	}
}

func (m *mockPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if m.closed {
		return 0, net.ErrClosed
	}
	data := make([]byte, len(p))
	copy(data, p)
	m.writeChan <- mockPacket{data: data, addr: addr}
	return len(p), nil
}

func (m *mockPacketConn) Close() error {
	m.closed = true
	close(m.readChan)
	close(m.writeChan)
	return nil
}

func (m *mockPacketConn) LocalAddr() net.Addr {
	return m.localAddr
}

func (m *mockPacketConn) SetDeadline(t time.Time) error {
	return nil
}

func (m *mockPacketConn) SetReadDeadline(t time.Time) error {
	m.readDeadline = t
	return nil
}

func (m *mockPacketConn) SetWriteDeadline(t time.Time) error {
	return nil
}

// setupConnPair creates a pair of mock connections for testing.
func setupConnPair(t *testing.T) (*mockPacketConn, *mockPacketConn, []byte, []byte, []byte, []byte) {
	t.Helper()

	// Generate keypairs
	initDH, err := noise.DH25519.GenerateKeypair(nil)
	require.NoError(t, err)
	respDH, err := noise.DH25519.GenerateKeypair(nil)
	require.NoError(t, err)

	// Create mock packet connections
	initLocalAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9000}
	respLocalAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9001}

	initConn := newMockPacketConn(initLocalAddr)
	respConn := newMockPacketConn(respLocalAddr)

	return initConn, respConn, initDH.Private, initDH.Public, respDH.Private, respDH.Public
}

// NewSSU2Conn tests

func TestNewSSU2Conn_ValidInitiator(t *testing.T) {
	initConn, _, initPriv, _, _, respPub := setupConnPair(t)
	defer initConn.Close()

	remoteAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9001}
	routerHash := make([]byte, 32)
	remoteHash := make([]byte, 32)
	for i := range remoteHash {
		remoteHash[i] = byte(i + 1)
	}
	config, err := NewSSU2Config(routerHash, true)
	require.NoError(t, err)
	config.RemoteRouterHash = remoteHash // Required for initiator
	config.ConnectionID = 12345
	config.MTU = 1500

	conn, err := NewSSU2Conn(initConn, remoteAddr, config, true, initPriv, respPub)
	require.NoError(t, err)
	require.NotNil(t, conn)
	assert.Equal(t, StateInit, conn.GetState())
	assert.NotNil(t, conn.handshakeHandler)
	assert.NotNil(t, conn.dataHandler)
	assert.NotNil(t, conn.ackHandler)

	// Cleanup
	_ = conn.Close()
}

func TestNewSSU2Conn_ValidResponder(t *testing.T) {
	_, respConn, _, _, respPriv, _ := setupConnPair(t)
	defer respConn.Close()

	remoteAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9000}
	config := createTestConfig(t)
	config.ConnectionID = 54321
	config.MTU = 1500

	conn, err := NewSSU2Conn(respConn, remoteAddr, config, false, respPriv, nil)
	require.NoError(t, err)
	require.NotNil(t, conn)
	assert.Equal(t, StateInit, conn.GetState())

	// Cleanup
	_ = conn.Close()
}

func TestNewSSU2Conn_NilUnderlyingConn(t *testing.T) {
	remoteAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9001}
	config := createTestConfig(t)
	staticKey := make([]byte, 32)

	conn, err := NewSSU2Conn(nil, remoteAddr, config, true, staticKey, staticKey)
	assert.Error(t, err)
	assert.Nil(t, conn)
	assert.Contains(t, err.Error(), "underlying PacketConn is nil")
}

func TestNewSSU2Conn_NilRemoteAddr(t *testing.T) {
	initConn, _, _, _, _, _ := setupConnPair(t)
	defer initConn.Close()

	config := createTestConfig(t)
	staticKey := make([]byte, 32)

	conn, err := NewSSU2Conn(initConn, nil, config, true, staticKey, staticKey)
	assert.Error(t, err)
	assert.Nil(t, conn)
	assert.Contains(t, err.Error(), "remoteAddr is nil")
}

func TestNewSSU2Conn_NilConfig(t *testing.T) {
	initConn, _, _, _, _, _ := setupConnPair(t)
	defer initConn.Close()

	remoteAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9001}
	staticKey := make([]byte, 32)

	conn, err := NewSSU2Conn(initConn, remoteAddr, nil, true, staticKey, staticKey)
	assert.Error(t, err)
	assert.Nil(t, conn)
	assert.Contains(t, err.Error(), "config is nil")
}

func TestNewSSU2Conn_InvalidStaticKey(t *testing.T) {
	initConn, _, _, _, _, _ := setupConnPair(t)
	defer initConn.Close()

	remoteAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9001}
	config := createTestConfig(t)
	invalidKey := make([]byte, 16) // Wrong size

	conn, err := NewSSU2Conn(initConn, remoteAddr, config, true, invalidKey, make([]byte, 32))
	assert.Error(t, err)
	assert.Nil(t, conn)
	assert.Contains(t, err.Error(), "static key")
}

// State management tests

func TestSSU2Conn_GetState(t *testing.T) {
	initConn, _, initPriv, _, _, respPub := setupConnPair(t)
	defer initConn.Close()

	remoteAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9001}
	config := createTestConfig(t)

	conn, err := NewSSU2Conn(initConn, remoteAddr, config, true, initPriv, respPub)
	require.NoError(t, err)
	defer conn.Close()

	assert.Equal(t, StateInit, conn.GetState())
}

func TestSSU2Conn_StateTransitions(t *testing.T) {
	initConn, _, initPriv, _, _, respPub := setupConnPair(t)
	defer initConn.Close()

	remoteAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9001}
	config := createTestConfig(t)

	conn, err := NewSSU2Conn(initConn, remoteAddr, config, true, initPriv, respPub)
	require.NoError(t, err)
	defer conn.Close()

	// Initial state
	assert.Equal(t, StateInit, conn.GetState())

	// Transition to handshaking (will fail without peer, but state should change)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_ = conn.Handshake(ctx) // Expected to fail

	// Close should transition to closed
	err = conn.Close()
	assert.NoError(t, err)
	assert.Equal(t, StateClosed, conn.GetState())
}

// net.Conn interface tests

func TestSSU2Conn_LocalAddr(t *testing.T) {
	initConn, _, initPriv, _, _, respPub := setupConnPair(t)
	defer initConn.Close()

	remoteAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9001}
	config := createTestConfig(t)
	config.ConnectionID = 12345

	conn, err := NewSSU2Conn(initConn, remoteAddr, config, true, initPriv, respPub)
	require.NoError(t, err)
	defer conn.Close()

	localAddr := conn.LocalAddr()
	require.NotNil(t, localAddr)

	ssu2Addr, ok := localAddr.(*SSU2Addr)
	require.True(t, ok)
	assert.Equal(t, uint64(12345), ssu2Addr.ConnectionID())
}

func TestSSU2Conn_RemoteAddr(t *testing.T) {
	initConn, _, initPriv, _, _, respPub := setupConnPair(t)
	defer initConn.Close()

	remoteAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9001}
	config := createTestConfig(t)

	conn, err := NewSSU2Conn(initConn, remoteAddr, config, true, initPriv, respPub)
	require.NoError(t, err)
	defer conn.Close()

	remote := conn.RemoteAddr()
	require.NotNil(t, remote)

	ssu2Addr, ok := remote.(*SSU2Addr)
	require.True(t, ok)
	assert.Equal(t, remoteAddr.Port, ssu2Addr.UnderlyingAddr().(*net.UDPAddr).Port)
}

func TestSSU2Conn_SetDeadline(t *testing.T) {
	initConn, _, initPriv, _, _, respPub := setupConnPair(t)
	defer initConn.Close()

	remoteAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9001}
	config := createTestConfig(t)

	conn, err := NewSSU2Conn(initConn, remoteAddr, config, true, initPriv, respPub)
	require.NoError(t, err)
	defer conn.Close()

	deadline := time.Now().Add(1 * time.Second)
	err = conn.SetDeadline(deadline)
	assert.NoError(t, err)

	conn.deadlineMutex.RLock()
	assert.Equal(t, deadline, conn.readDeadline)
	assert.Equal(t, deadline, conn.writeDeadline)
	conn.deadlineMutex.RUnlock()
}

func TestSSU2Conn_SetReadDeadline(t *testing.T) {
	initConn, _, initPriv, _, _, respPub := setupConnPair(t)
	defer initConn.Close()

	remoteAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9001}
	config := createTestConfig(t)

	conn, err := NewSSU2Conn(initConn, remoteAddr, config, true, initPriv, respPub)
	require.NoError(t, err)
	defer conn.Close()

	deadline := time.Now().Add(1 * time.Second)
	err = conn.SetReadDeadline(deadline)
	assert.NoError(t, err)

	conn.deadlineMutex.RLock()
	assert.Equal(t, deadline, conn.readDeadline)
	conn.deadlineMutex.RUnlock()
}

func TestSSU2Conn_SetWriteDeadline(t *testing.T) {
	initConn, _, initPriv, _, _, respPub := setupConnPair(t)
	defer initConn.Close()

	remoteAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9001}
	config := createTestConfig(t)

	conn, err := NewSSU2Conn(initConn, remoteAddr, config, true, initPriv, respPub)
	require.NoError(t, err)
	defer conn.Close()

	deadline := time.Now().Add(1 * time.Second)
	err = conn.SetWriteDeadline(deadline)
	assert.NoError(t, err)

	conn.deadlineMutex.RLock()
	assert.Equal(t, deadline, conn.writeDeadline)
	conn.deadlineMutex.RUnlock()
}

func TestSSU2Conn_Close(t *testing.T) {
	initConn, _, initPriv, _, _, respPub := setupConnPair(t)
	defer initConn.Close()

	remoteAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9001}
	config := createTestConfig(t)

	conn, err := NewSSU2Conn(initConn, remoteAddr, config, true, initPriv, respPub)
	require.NoError(t, err)

	// Close should succeed
	err = conn.Close()
	assert.NoError(t, err)
	assert.Equal(t, StateClosed, conn.GetState())

	// Second close should also succeed (idempotent)
	err = conn.Close()
	assert.NoError(t, err)
}

func TestSSU2Conn_CloseMultipleGoroutines(t *testing.T) {
	initConn, _, initPriv, _, _, respPub := setupConnPair(t)
	defer initConn.Close()

	remoteAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9001}
	config := createTestConfig(t)

	conn, err := NewSSU2Conn(initConn, remoteAddr, config, true, initPriv, respPub)
	require.NoError(t, err)

	// Close from multiple goroutines
	const numGoroutines = 10
	done := make(chan bool, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			_ = conn.Close()
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < numGoroutines; i++ {
		<-done
	}

	assert.Equal(t, StateClosed, conn.GetState())
}

// Read/Write tests

func TestSSU2Conn_ReadWriteNotEstablished(t *testing.T) {
	initConn, _, initPriv, _, _, respPub := setupConnPair(t)
	defer initConn.Close()

	remoteAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9001}
	config := createTestConfig(t)

	conn, err := NewSSU2Conn(initConn, remoteAddr, config, true, initPriv, respPub)
	require.NoError(t, err)
	defer conn.Close()

	// Read should fail (not established)
	buf := make([]byte, 100)
	_, err = conn.Read(buf)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not established")

	// Write should fail (not established)
	_, err = conn.Write([]byte("test"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not established")
}

// Handshake tests

func TestSSU2Conn_HandshakeInvalidState(t *testing.T) {
	initConn, _, initPriv, _, _, respPub := setupConnPair(t)
	defer initConn.Close()

	remoteAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9001}
	config := createTestConfig(t)

	conn, err := NewSSU2Conn(initConn, remoteAddr, config, true, initPriv, respPub)
	require.NoError(t, err)
	defer conn.Close()

	// Manually set state to established
	conn.stateMutex.Lock()
	conn.state = StateEstablished
	conn.stateMutex.Unlock()

	// Handshake should fail
	ctx := context.Background()
	err = conn.Handshake(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid state")
}

func TestSSU2Conn_HandshakeTimeout(t *testing.T) {
	initConn, _, initPriv, _, _, respPub := setupConnPair(t)
	defer initConn.Close()

	remoteAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9001}
	config := createTestConfig(t)
	config.HandshakeTimeout = 100 * time.Millisecond

	conn, err := NewSSU2Conn(initConn, remoteAddr, config, true, initPriv, respPub)
	require.NoError(t, err)
	defer conn.Close()

	ctx := context.Background()
	err = conn.Handshake(ctx)
	assert.Error(t, err)
	// Should timeout waiting for SessionCreated
}

// Activity tracking tests

func TestSSU2Conn_UpdateActivity(t *testing.T) {
	initConn, _, initPriv, _, _, respPub := setupConnPair(t)
	defer initConn.Close()

	remoteAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9001}
	config := createTestConfig(t)

	conn, err := NewSSU2Conn(initConn, remoteAddr, config, true, initPriv, respPub)
	require.NoError(t, err)
	defer conn.Close()

	// Get initial activity time
	conn.lastActivityLock.RLock()
	initial := conn.lastActivity
	conn.lastActivityLock.RUnlock()

	// Wait a bit
	time.Sleep(10 * time.Millisecond)

	// Update activity
	conn.updateActivity()

	// Check that activity time was updated
	conn.lastActivityLock.RLock()
	updated := conn.lastActivity
	conn.lastActivityLock.RUnlock()

	assert.True(t, updated.After(initial))
}

// Sequence number tests

func TestSSU2Conn_NextSendSequence(t *testing.T) {
	initConn, _, initPriv, _, _, respPub := setupConnPair(t)
	defer initConn.Close()

	remoteAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9001}
	config := createTestConfig(t)

	conn, err := NewSSU2Conn(initConn, remoteAddr, config, true, initPriv, respPub)
	require.NoError(t, err)
	defer conn.Close()

	// Get sequence numbers
	seq1 := conn.nextSendSequence()
	seq2 := conn.nextSendSequence()
	seq3 := conn.nextSendSequence()

	assert.Equal(t, uint32(0), seq1)
	assert.Equal(t, uint32(1), seq2)
	assert.Equal(t, uint32(2), seq3)
}

func TestSSU2Conn_NextSendSequenceThreadSafe(t *testing.T) {
	initConn, _, initPriv, _, _, respPub := setupConnPair(t)
	defer initConn.Close()

	remoteAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9001}
	config := createTestConfig(t)

	conn, err := NewSSU2Conn(initConn, remoteAddr, config, true, initPriv, respPub)
	require.NoError(t, err)
	defer conn.Close()

	// Call from multiple goroutines
	const numGoroutines = 100
	sequences := make(chan uint32, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			sequences <- conn.nextSendSequence()
		}()
	}

	// Collect all sequences
	seqMap := make(map[uint32]bool)
	for i := 0; i < numGoroutines; i++ {
		seq := <-sequences
		seqMap[seq] = true
	}

	// Should have unique sequences
	assert.Equal(t, numGoroutines, len(seqMap))
}

// ConnState string tests

func TestConnState_String(t *testing.T) {
	tests := []struct {
		state    ConnState
		expected string
	}{
		{StateInit, "Init"},
		{StateHandshaking, "Handshaking"},
		{StateEstablished, "Established"},
		{StateClosing, "Closing"},
		{StateClosed, "Closed"},
		{ConnState(99), "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.state.String())
		})
	}
}

// Helper function tests

func TestCopyBytes(t *testing.T) {
	// Test nil
	assert.Nil(t, copyBytes(nil))

	// Test empty slice
	empty := []byte{}
	copied := copyBytes(empty)
	assert.NotNil(t, copied)
	assert.Equal(t, 0, len(copied))

	// Test with data
	data := []byte{1, 2, 3, 4, 5}
	copied = copyBytes(data)
	assert.Equal(t, data, copied)

	// Verify it's a copy (not same backing array)
	copied[0] = 99
	assert.Equal(t, byte(1), data[0])
	assert.Equal(t, byte(99), copied[0])
}
