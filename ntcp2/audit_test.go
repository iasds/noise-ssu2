package ntcp2

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── Close() tests for all three modifiers ────────────────────────────

// TestAESObfuscationModifier_Close verifies that Close() zeroes key material.
func TestAESObfuscationModifier_Close(t *testing.T) {
	routerHash := make([]byte, RouterHashSize)
	copy(routerHash, "test-router-hash-32-bytes-long!!")
	iv := make([]byte, IVSize)
	copy(iv, "1234567890123456")

	mod, err := NewAESObfuscationModifier("test-aes", routerHash, iv)
	require.NoError(t, err)

	// Encrypt something so aesState is populated
	data := make([]byte, StaticKeySize)
	copy(data, "test-data-32-bytes-long-padding!")
	_, err = mod.ModifyOutbound(0, data) // PhaseInitial
	require.NoError(t, err)
	require.NotNil(t, mod.aesState, "aesState should be set after PhaseInitial encrypt")

	// Close should zero everything
	err = mod.Close()
	require.NoError(t, err)

	// Verify key material is zeroed
	for _, b := range mod.routerHash {
		assert.Equal(t, byte(0), b, "routerHash should be zeroed after Close")
	}
	for _, b := range mod.iv {
		assert.Equal(t, byte(0), b, "iv should be zeroed after Close")
	}
	for _, b := range mod.aesState {
		assert.Equal(t, byte(0), b, "aesState should be zeroed after Close")
	}
	assert.Nil(t, mod.block, "AES cipher block should be nil after Close")
}

// TestAESObfuscationModifier_Close_Idempotent verifies Close can be called twice.
func TestAESObfuscationModifier_Close_Idempotent(t *testing.T) {
	routerHash := make([]byte, RouterHashSize)
	copy(routerHash, "test-router-hash-32-bytes-long!!")
	iv := make([]byte, IVSize)
	copy(iv, "1234567890123456")

	mod, err := NewAESObfuscationModifier("test-aes", routerHash, iv)
	require.NoError(t, err)

	require.NoError(t, mod.Close())
	require.NoError(t, mod.Close()) // second Close should not panic
}

// TestSipHashLengthModifier_Close verifies that Close() zeroes all keys and IVs.
func TestSipHashLengthModifier_Close(t *testing.T) {
	sipKeys := [2]uint64{0xDEADBEEFCAFE0001, 0xC0FFEE0102030405}
	mod := NewSipHashLengthModifier("test-siphash", sipKeys, 0xA1B2C3D4E5F60708)

	// Advance the IV state to confirm Close zeroes the updated state
	mod.NextOutboundMask()
	mod.NextInboundMask()

	err := mod.Close()
	require.NoError(t, err)

	assert.Equal(t, uint64(0), mod.outboundKeys[0], "outbound k1 should be zeroed")
	assert.Equal(t, uint64(0), mod.outboundKeys[1], "outbound k2 should be zeroed")
	assert.Equal(t, uint64(0), mod.inboundKeys[0], "inbound k1 should be zeroed")
	assert.Equal(t, uint64(0), mod.inboundKeys[1], "inbound k2 should be zeroed")
	assert.Equal(t, uint64(0), mod.outboundIV, "outbound IV should be zeroed")
	assert.Equal(t, uint64(0), mod.inboundIV, "inbound IV should be zeroed")
}

// TestSipHashLengthModifier_Close_Idempotent verifies Close can be called twice.
func TestSipHashLengthModifier_Close_Idempotent(t *testing.T) {
	sipKeys := [2]uint64{0xDEAD, 0xBEEF}
	mod := NewSipHashLengthModifier("test", sipKeys, 42)

	require.NoError(t, mod.Close())
	require.NoError(t, mod.Close()) // second Close should not panic
}

// TestNTCP2PaddingModifier_Close verifies that Close() returns nil (no-op).
func TestNTCP2PaddingModifier_Close(t *testing.T) {
	mod, err := NewNTCP2PaddingModifier("test-padding", 0, 64, false)
	require.NoError(t, err)

	err = mod.Close()
	assert.NoError(t, err, "Close should return nil for padding modifier")
}

// TestNTCP2PaddingModifier_Close_Idempotent verifies Close can be called twice.
func TestNTCP2PaddingModifier_Close_Idempotent(t *testing.T) {
	mod, err := NewNTCP2PaddingModifier("test-padding", 0, 64, true)
	require.NoError(t, err)

	require.NoError(t, mod.Close())
	require.NoError(t, mod.Close())
}

// ── acceptMutex removal verification ─────────────────────────────────

// TestNTCP2Listener_ConcurrentAccepts verifies that multiple goroutines can
// call Accept() concurrently without serialization after the acceptMutex
// was removed. This mirrors the root package's TestNoiseListenerConcurrentAccepts.
func TestNTCP2Listener_ConcurrentAccepts(t *testing.T) {
	responderHash := make([]byte, RouterHashSize)
	copy(responderHash, "responder-hash-32-bytes-long!!!!")

	config, err := NewNTCP2Config(responderHash, false)
	require.NoError(t, err)
	config, err = config.WithAESObfuscation(false, nil)
	require.NoError(t, err)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	ntcp2Ln, err := NewNTCP2Listener(ln, config)
	require.NoError(t, err)
	defer ntcp2Ln.Close()

	const numAcceptors = 3
	var wg sync.WaitGroup
	accepted := make(chan net.Conn, numAcceptors)
	errors := make(chan error, numAcceptors)

	// Launch multiple concurrent acceptors
	for i := 0; i < numAcceptors; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := ntcp2Ln.Accept()
			if err != nil {
				errors <- err
				return
			}
			accepted <- conn
		}()
	}

	// Give acceptors time to start and block
	time.Sleep(50 * time.Millisecond)

	// Dial connections to unblock acceptors
	for i := 0; i < numAcceptors; i++ {
		conn, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
		if err != nil {
			t.Logf("dial %d failed: %v", i, err)
			continue
		}
		defer conn.Close()
	}

	// Wait with timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// All acceptors completed
	case <-time.After(5 * time.Second):
		t.Fatal("concurrent accepts timed out — possible serialization bug")
	}

	// At least one should have succeeded
	close(accepted)
	count := 0
	for conn := range accepted {
		conn.Close()
		count++
	}
	assert.GreaterOrEqual(t, count, 1, "at least one concurrent accept should succeed")
}

// ── AcceptWithHandshake test ─────────────────────────────────────────

// TestAcceptWithHandshake_FullE2E exercises the AcceptWithHandshake convenience
// method by performing a full XK handshake between a dialing initiator and
// an NTCP2Listener that calls AcceptWithHandshake.
func TestAcceptWithHandshake_FullE2E(t *testing.T) {
	p := newTestXKConfigPair(t)
	responderConfig := p.responderConfig
	initiatorConfig := p.initiatorConfig
	initiatorHash := p.initiatorHash
	responderHash := p.responderHash

	// Start TCP listener
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer tcpLn.Close()

	ntcp2Ln, err := NewNTCP2Listener(tcpLn, responderConfig)
	require.NoError(t, err)
	defer ntcp2Ln.Close()

	// Responder goroutine using AcceptWithHandshake
	var wg sync.WaitGroup
	var responderConn *NTCP2Conn
	var responderErr error

	wg.Add(1)
	go func() {
		defer wg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		responderConn, responderErr = ntcp2Ln.AcceptWithHandshake(ctx)
	}()

	// Initiator side: manual dial + handshake
	initiatorNTCP2 := dialAndHandshakeInitiator(t, tcpLn.Addr().String(), initiatorConfig, initiatorHash, responderHash, &wg, &responderErr)

	// Wait for responder
	wg.Wait()
	require.NoError(t, responderErr, "AcceptWithHandshake should succeed")
	require.NotNil(t, responderConn, "responder conn should not be nil")
	defer initiatorNTCP2.Close()
	defer responderConn.Close()

	// Verify SipHash is active on both sides
	assert.NotNil(t, initiatorNTCP2.lengthObfuscator.Load(),
		"initiator should have SipHash obfuscator")
	assert.NotNil(t, responderConn.lengthObfuscator.Load(),
		"responder should have SipHash obfuscator via AcceptWithHandshake")

	// Verify bidirectional data exchange
	testMsg := []byte("AcceptWithHandshake works!")
	_, err = initiatorNTCP2.Write(testMsg)
	require.NoError(t, err)

	buf := make([]byte, 1024)
	n, err := responderConn.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, testMsg, buf[:n], "responder should receive initiator's message")
}

// TestAcceptWithHandshake_ClosedListener verifies AcceptWithHandshake
// returns an error when the listener is already closed.
func TestAcceptWithHandshake_ClosedListener(t *testing.T) {
	responderHash := make([]byte, RouterHashSize)
	copy(responderHash, "responder-hash-32-bytes-long!!!!")

	config, err := NewNTCP2Config(responderHash, false)
	require.NoError(t, err)
	config, err = config.WithAESObfuscation(false, nil)
	require.NoError(t, err)

	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	ntcp2Ln, err := NewNTCP2Listener(tcpLn, config)
	require.NoError(t, err)
	ntcp2Ln.Close()

	ctx := context.Background()
	_, err = ntcp2Ln.AcceptWithHandshake(ctx)
	assert.Error(t, err, "AcceptWithHandshake on closed listener should fail")
}
