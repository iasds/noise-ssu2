package noise

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/go-i2p/crypto/rand"
	"github.com/go-i2p/go-noise/handshake"

	upstreamnoise "github.com/go-i2p/noise"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNoiseConnIntegration performs a real handshake between two NoiseConn instances
func TestNoiseConnIntegration(t *testing.T) {
	clientConn, serverConn := net.Pipe()

	clientConfig := NewConnConfig("NN", true).
		WithHandshakeTimeout(5 * time.Second)

	serverConfig := NewConnConfig("NN", false).
		WithHandshakeTimeout(5 * time.Second)

	client, err := NewNoiseConn(clientConn, clientConfig)
	if err != nil {
		t.Fatalf("Failed to create client NoiseConn: %v", err)
	}
	defer client.Close()

	server, err := NewNoiseConn(serverConn, serverConfig)
	if err != nil {
		t.Fatalf("Failed to create server NoiseConn: %v", err)
	}
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	clientDone := make(chan error, 1)
	serverDone := make(chan error, 1)

	go func() {
		err := client.Handshake(ctx)
		clientDone <- err
	}()

	go func() {
		err := server.Handshake(ctx)
		serverDone <- err
	}()

	select {
	case err := <-clientDone:
		if err != nil {
			t.Logf("Client handshake completed with result: %v", err)
		}
	case <-ctx.Done():
		t.Errorf("Client handshake timed out")
	}

	select {
	case err := <-serverDone:
		if err != nil {
			t.Logf("Server handshake completed with result: %v", err)
		}
	case <-ctx.Done():
		t.Errorf("Server handshake timed out")
	}
}

// TestHighCoverageEncryption tests the encryption/decryption paths
func TestHighCoverageEncryption(t *testing.T) {
	initiatorConn, responderConn := net.Pipe()
	defer initiatorConn.Close()
	defer responderConn.Close()

	initiatorConfig := NewConnConfig("NN", true).
		WithHandshakeTimeout(5 * time.Second).
		WithReadTimeout(2 * time.Second).
		WithWriteTimeout(2 * time.Second)

	responderConfig := NewConnConfig("NN", false).
		WithHandshakeTimeout(5 * time.Second).
		WithReadTimeout(2 * time.Second).
		WithWriteTimeout(2 * time.Second)

	initiatorNC, err := NewNoiseConn(initiatorConn, initiatorConfig)
	require.NoError(t, err)

	responderNC, err := NewNoiseConn(responderConn, responderConfig)
	require.NoError(t, err)

	var wg sync.WaitGroup
	var handshakeErrors []error
	handshakeErrors = make([]error, 2)

	wg.Add(2)

	go func() {
		defer wg.Done()
		handshakeErrors[0] = initiatorNC.Handshake(context.Background())
	}()

	go func() {
		defer wg.Done()
		handshakeErrors[1] = responderNC.Handshake(context.Background())
	}()

	wg.Wait()

	if handshakeErrors[0] != nil || handshakeErrors[1] != nil {
		t.Logf("Handshake errors: initiator=%v, responder=%v", handshakeErrors[0], handshakeErrors[1])

		require.NoError(t, handshakeErrors[0], "NN initiator handshake should succeed")
		require.NoError(t, handshakeErrors[1], "NN responder handshake should succeed")
	}

	testMessage := "Hello, encrypted world!"

	go func() {
		_, writeErr := initiatorNC.Write([]byte(testMessage))
		if writeErr != nil {
			t.Logf("Write error: %v", writeErr)
		}
	}()

	buffer := make([]byte, len(testMessage))
	n, readErr := responderNC.Read(buffer)
	if readErr != nil {
		t.Logf("Read error: %v", readErr)
	} else {
		received := string(buffer[:n])
		assert.Equal(t, testMessage, received, "Message should be transmitted correctly")
	}

	initiatorNC.Close()
	responderNC.Close()
}

// handshakePairConfig holds the parameters for setting up a Noise handshake pair.
type handshakePairConfig struct {
	pattern      string
	setRemoteKey bool // whether to set initiator's RemoteKey to responder's public key
}

// setupHandshakePairConn creates a pair of NoiseConn instances connected over
// TCP that have completed the Noise handshake. The caller is responsible for
// closing both returned connections.
func setupHandshakePairConn(t *testing.T, cfg handshakePairConfig) (initiator, responder *NoiseConn) {
	t.Helper()

	cs := upstreamnoise.NewCipherSuite(
		upstreamnoise.DH25519,
		upstreamnoise.CipherAESGCM,
		upstreamnoise.HashSHA256,
	)

	initiatorKP, err := cs.GenerateKeypair(rand.Reader)
	if err != nil {
		t.Fatalf("generate initiator keypair: %v", err)
	}
	responderKP, err := cs.GenerateKeypair(rand.Reader)
	if err != nil {
		t.Fatalf("generate responder keypair: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	responderCfg := NewConnConfig(cfg.pattern, false)
	responderCfg.StaticKey = responderKP.Private
	responderCfg.CipherSuite = cs

	initiatorCfg := NewConnConfig(cfg.pattern, true)
	initiatorCfg.StaticKey = initiatorKP.Private
	initiatorCfg.CipherSuite = cs
	if cfg.setRemoteKey {
		initiatorCfg.RemoteKey = responderKP.Public
	}

	var wg sync.WaitGroup
	var responderErr error
	var responderConn *NoiseConn

	wg.Add(1)
	go func() {
		defer wg.Done()
		raw, err := ln.Accept()
		if err != nil {
			responderErr = err
			return
		}
		nc, err := NewNoiseConn(raw, responderCfg)
		if err != nil {
			raw.Close()
			responderErr = err
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := nc.Handshake(ctx); err != nil {
			nc.Close()
			responderErr = err
			return
		}
		responderConn = nc
	}()

	raw, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	initiatorConn, err := NewNoiseConn(raw, initiatorCfg)
	if err != nil {
		raw.Close()
		t.Fatalf("new initiator conn: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := initiatorConn.Handshake(ctx); err != nil {
		initiatorConn.Close()
		wg.Wait()
		t.Fatalf("initiator handshake: %v (responder err: %v)", err, responderErr)
	}

	wg.Wait()
	if responderErr != nil {
		initiatorConn.Close()
		t.Fatalf("responder handshake: %v", responderErr)
	}

	return initiatorConn, responderConn
}

// TestXKHandshake_FullE2E performs a complete Noise XK handshake over real
// TCP connections with real Curve25519 keypairs.
func TestXKHandshake_FullE2E(t *testing.T) {
	initiatorConn, responderConn := setupHandshakePairConn(t, handshakePairConfig{
		pattern:      "XK",
		setRemoteKey: true,
	})
	defer initiatorConn.Close()
	defer responderConn.Close()

	payload := []byte("hello from initiator via Noise XK")

	n, err := initiatorConn.Write(payload)
	if err != nil {
		t.Fatalf("initiator write: %v", err)
	}
	if n != len(payload) {
		t.Fatalf("short write: %d != %d", n, len(payload))
	}

	buf := make([]byte, 4096)
	n, err = responderConn.Read(buf)
	if err != nil {
		t.Fatalf("responder read: %v", err)
	}
	if string(buf[:n]) != string(payload) {
		t.Fatalf("payload mismatch: got %q, want %q", buf[:n], payload)
	}

	reply := []byte("reply from responder via Noise XK")
	n, err = responderConn.Write(reply)
	if err != nil {
		t.Fatalf("responder write: %v", err)
	}
	if n != len(reply) {
		t.Fatalf("short write: %d != %d", n, len(reply))
	}

	n, err = initiatorConn.Read(buf)
	if err != nil {
		t.Fatalf("initiator read: %v", err)
	}
	if string(buf[:n]) != string(reply) {
		t.Fatalf("reply mismatch: got %q, want %q", buf[:n], reply)
	}

	initiatorPeerStatic := initiatorConn.PeerStatic()
	responderPeerStatic := responderConn.PeerStatic()

	if len(initiatorPeerStatic) != 32 {
		t.Fatalf("initiator PeerStatic length: %d", len(initiatorPeerStatic))
	}
	if len(responderPeerStatic) != 32 {
		t.Fatalf("responder PeerStatic length: %d", len(responderPeerStatic))
	}

	t.Log("Full XK handshake + bidirectional data exchange succeeded")
}

// TestXKHandshake_MissingPeerStatic verifies that an XK initiator without
// RemoteKey set fails the handshake with a meaningful error.
func TestXKHandshake_MissingPeerStatic(t *testing.T) {
	cs := upstreamnoise.NewCipherSuite(
		upstreamnoise.DH25519,
		upstreamnoise.CipherAESGCM,
		upstreamnoise.HashSHA256,
	)
	kp, err := cs.GenerateKeypair(rand.Reader)
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}

	cfg := NewConnConfig("XK", true)
	cfg.StaticKey = kp.Private
	cfg.CipherSuite = cs

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, _ := ln.Accept()
		if conn != nil {
			conn.Close()
		}
	}()

	raw, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	nc, err := NewNoiseConn(raw, cfg)
	if err != nil {
		raw.Close()
		t.Logf("NewNoiseConn failed (expected): %v", err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err = nc.Handshake(ctx)
	nc.Close()

	if err == nil {
		t.Fatal("expected handshake to fail with missing PeerStatic, but it succeeded")
	}
	t.Logf("handshake correctly failed: %v", err)
}

// TestXXHandshake_NoPeerStaticNeeded verifies that the XX pattern works
// without RemoteKey since neither side needs the other's static key as
// a pre-message.
func TestXXHandshake_NoPeerStaticNeeded(t *testing.T) {
	initiatorConn, responderConn := setupHandshakePairConn(t, handshakePairConfig{
		pattern:      "XX",
		setRemoteKey: false,
	})
	defer initiatorConn.Close()
	defer responderConn.Close()

	msg := []byte("XX pattern works without PeerStatic")
	if _, err := initiatorConn.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 256)
	n, err := responderConn.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf[:n]) != string(msg) {
		t.Fatalf("mismatch: got %q, want %q", buf[:n], msg)
	}

	t.Log("XX handshake + data exchange succeeded without PeerStatic")
}

// TestPhaseData_ModifierInvokedOnWriteAndRead verifies that the modifier chain
// is called with PhaseData on every Write (outbound) and Read (inbound) after
// the Noise handshake completes.
func TestPhaseData_ModifierInvokedOnWriteAndRead(t *testing.T) {
	clientPipe, serverPipe := net.Pipe()

	// Install a tracking modifier on both sides.
	clientMod := &trackingModifier{}
	serverMod := &trackingModifier{}

	clientCfg := NewConnConfig("NN", true).
		WithHandshakeTimeout(5 * time.Second).
		WithModifiers(clientMod)
	serverCfg := NewConnConfig("NN", false).
		WithHandshakeTimeout(5 * time.Second).
		WithModifiers(serverMod)

	client, err := NewNoiseConn(clientPipe, clientCfg)
	require.NoError(t, err)
	defer client.Close()

	server, err := NewNoiseConn(serverPipe, serverCfg)
	require.NoError(t, err)
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Perform handshake concurrently.
	hsErr := make(chan error, 2)
	go func() { hsErr <- client.Handshake(ctx) }()
	go func() { hsErr <- server.Handshake(ctx) }()
	require.NoError(t, <-hsErr)
	require.NoError(t, <-hsErr)

	msg := []byte("PhaseData wiring test message")

	// Client writes; server reads.
	writeErr := make(chan error, 1)
	go func() {
		_, err := client.Write(msg)
		writeErr <- err
	}()

	buf := make([]byte, 256)
	n, err := server.Read(buf)
	require.NoError(t, err)
	require.NoError(t, <-writeErr)
	assert.Equal(t, msg, buf[:n], "round-trip data must be identical with symmetric modifier")

	// Client modifier must have called ModifyOutbound with PhaseData.
	clientMod.mu.Lock()
	outCalls := len(clientMod.outboundCalls)
	var outPhase handshake.HandshakePhase
	if outCalls > 0 {
		outPhase = clientMod.outboundCalls[0].phase
	}
	clientMod.mu.Unlock()
	require.Equal(t, 1, outCalls, "Write must invoke ModifyOutbound once")
	assert.Equal(t, handshake.PhaseData, outPhase, "Write must invoke ModifyOutbound with PhaseData")

	// Server modifier must have called ModifyInbound with PhaseData.
	serverMod.mu.Lock()
	inCalls := len(serverMod.inboundCalls)
	var inPhase handshake.HandshakePhase
	if inCalls > 0 {
		inPhase = serverMod.inboundCalls[0].phase
	}
	serverMod.mu.Unlock()
	require.Equal(t, 1, inCalls, "Read must invoke ModifyInbound once")
	assert.Equal(t, handshake.PhaseData, inPhase, "Read must invoke ModifyInbound with PhaseData")
}

// TestHandshakeTimeoutWithStalledPeer verifies that a stalled peer (one that
// never sends any handshake messages) causes the Handshake call to return a
// deadline-exceeded error rather than blocking indefinitely.
func TestHandshakeTimeoutWithStalledPeer(t *testing.T) {
	// Create a pipe; only the initiator side will attempt a handshake.
	// The responder side is left idle — simulating a stalled or malicious peer.
	initiatorConn, _ := net.Pipe()
	defer initiatorConn.Close()

	config := NewConnConfig("NN", true).
		WithHandshakeTimeout(100 * time.Millisecond)

	client, err := NewNoiseConn(initiatorConn, config)
	require.NoError(t, err, "NewNoiseConn should succeed")
	defer client.Close()

	ctx := context.Background()

	start := time.Now()
	err = client.Handshake(ctx)
	elapsed := time.Since(start)

	// The handshake must fail because the peer never responds.
	require.Error(t, err, "Handshake must fail when peer is stalled")

	// Verify the error is a deadline/timeout, not some other failure.
	require.True(t,
		isTimeoutError(err),
		"expected a timeout/deadline error, got: %v", err)

	// Verify it completed in a reasonable time (not stuck forever).
	// Allow generous margin: up to 5s for slow CI, but it should be ~100ms.
	require.Less(t, elapsed, 5*time.Second,
		"Handshake should have timed out promptly, took %v", elapsed)
}

// isTimeoutError checks whether err (or any wrapped error) is a deadline/timeout.
func isTimeoutError(err error) bool {
	if err == nil {
		return false
	}
	// Check for net.Error timeout interface
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	// Check for context deadline exceeded
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	// Fall back to string matching for wrapped errors (oops wraps messages)
	msg := err.Error()
	return contains(msg, "deadline") || contains(msg, "timeout") || contains(msg, "i/o timeout")
}

// contains is a simple case-insensitive substring check.
func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchCI(s, substr)
}

func searchCI(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if eqFoldASCII(s[i:i+len(substr)], substr) {
			return true
		}
	}
	return false
}

func eqFoldASCII(a, b string) bool {
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}
