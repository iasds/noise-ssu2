package noise

import (
	"context"
	"crypto/rand"
	"net"
	"sync"
	"testing"
	"time"

	upstreamnoise "github.com/go-i2p/noise"
)

// TestXKHandshake_FullE2E performs a complete Noise XK handshake over real
// TCP connections with real Curve25519 keypairs.  This test verifies the
// PeerStatic plumbing: the initiator supplies the responder's static
// public key as RemoteKey, and createHandshakeState passes it through to
// noise.Config.PeerStatic so that the XK pre-message (← s) is correctly
// processed.  After the handshake, both sides exchange encrypted data.
func TestXKHandshake_FullE2E(t *testing.T) {
	cs := upstreamnoise.NewCipherSuite(
		upstreamnoise.DH25519,
		upstreamnoise.CipherAESGCM,
		upstreamnoise.HashSHA256,
	)

	// Generate real keypairs.
	initiatorKP, err := cs.GenerateKeypair(rand.Reader)
	if err != nil {
		t.Fatalf("generate initiator keypair: %v", err)
	}
	responderKP, err := cs.GenerateKeypair(rand.Reader)
	if err != nil {
		t.Fatalf("generate responder keypair: %v", err)
	}

	// Bind a TCP listener.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	// --- responder config ---
	responderCfg := NewConnConfig("XK", false)
	responderCfg.StaticKey = responderKP.Private
	responderCfg.CipherSuite = cs

	// --- initiator config ---
	// The XK pattern requires the initiator to know the responder's static
	// public key as a pre-message (← s).  This is the field that was
	// previously never plumbed through to noise.Config.PeerStatic.
	initiatorCfg := NewConnConfig("XK", true)
	initiatorCfg.StaticKey = initiatorKP.Private
	initiatorCfg.RemoteKey = responderKP.Public // ← THE FIX
	initiatorCfg.CipherSuite = cs

	// Channel for any error from the responder goroutine.
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

	// --- initiator side ---
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

	// Wait for responder.
	wg.Wait()
	if responderErr != nil {
		initiatorConn.Close()
		t.Fatalf("responder handshake: %v", responderErr)
	}
	defer initiatorConn.Close()
	defer responderConn.Close()

	// --- data exchange ---
	payload := []byte("hello from initiator via Noise XK")

	// Initiator writes, responder reads.
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

	// Responder writes, initiator reads.
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

	// Verify PeerStatic was correctly exchanged.
	// After XK, the initiator already knew the responder's static key,
	// and the responder learned the initiator's static key.
	initiatorPeerStatic := initiatorConn.PeerStatic()
	responderPeerStatic := responderConn.PeerStatic()

	if len(initiatorPeerStatic) != 32 {
		t.Fatalf("initiator PeerStatic length: %d", len(initiatorPeerStatic))
	}
	if len(responderPeerStatic) != 32 {
		t.Fatalf("responder PeerStatic length: %d", len(responderPeerStatic))
	}

	// The initiator's PeerStatic should be the responder's public key.
	for i := range initiatorPeerStatic {
		if initiatorPeerStatic[i] != responderKP.Public[i] {
			t.Fatalf("initiator PeerStatic mismatch at byte %d", i)
		}
	}
	// The responder's PeerStatic should be the initiator's public key.
	for i := range responderPeerStatic {
		if responderPeerStatic[i] != initiatorKP.Public[i] {
			t.Fatalf("responder PeerStatic mismatch at byte %d", i)
		}
	}

	t.Log("Full XK handshake + bidirectional data exchange succeeded")
}

// TestXKHandshake_MissingPeerStatic verifies that an XK initiator without
// RemoteKey set fails the handshake with a meaningful error rather than
// silently producing a broken session.
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

	// No RemoteKey — for XK the pre-message requires it.
	cfg := NewConnConfig("XK", true)
	cfg.StaticKey = kp.Private
	cfg.CipherSuite = cs
	// cfg.RemoteKey intentionally omitted

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
		// If NewNoiseConn itself fails due to nil PeerStatic, that's acceptable.
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
// a pre-message.  This confirms that our PeerStatic plumbing doesn't
// break patterns that don't use pre-messages.
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

	// XX pattern — no pre-message, no RemoteKey needed.
	responderCfg := NewConnConfig("XX", false)
	responderCfg.StaticKey = responderKP.Private
	responderCfg.CipherSuite = cs

	initiatorCfg := NewConnConfig("XX", true)
	initiatorCfg.StaticKey = initiatorKP.Private
	initiatorCfg.CipherSuite = cs
	// No RemoteKey — XX doesn't need it.

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

	// Quick data exchange to confirm the session is functional.
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
