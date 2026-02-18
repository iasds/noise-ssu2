package noise

import (
	"context"
	"crypto/rand"
	"net"
	"sync"
	"testing"
	"time"

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

// TestXKHandshake_FullE2E performs a complete Noise XK handshake over real
// TCP connections with real Curve25519 keypairs.
func TestXKHandshake_FullE2E(t *testing.T) {
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

	responderCfg := NewConnConfig("XK", false)
	responderCfg.StaticKey = responderKP.Private
	responderCfg.CipherSuite = cs

	initiatorCfg := NewConnConfig("XK", true)
	initiatorCfg.StaticKey = initiatorKP.Private
	initiatorCfg.RemoteKey = responderKP.Public
	initiatorCfg.CipherSuite = cs

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

	for i := range initiatorPeerStatic {
		if initiatorPeerStatic[i] != responderKP.Public[i] {
			t.Fatalf("initiator PeerStatic mismatch at byte %d", i)
		}
	}
	for i := range responderPeerStatic {
		if responderPeerStatic[i] != initiatorKP.Public[i] {
			t.Fatalf("responder PeerStatic mismatch at byte %d", i)
		}
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

	responderCfg := NewConnConfig("XX", false)
	responderCfg.StaticKey = responderKP.Private
	responderCfg.CipherSuite = cs

	initiatorCfg := NewConnConfig("XX", true)
	initiatorCfg.StaticKey = initiatorKP.Private
	initiatorCfg.CipherSuite = cs

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
		t.Fatalf("initiator handshake: %v", err)
	}

	wg.Wait()
	if responderErr != nil {
		initiatorConn.Close()
		t.Fatalf("responder handshake: %v", responderErr)
	}
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
