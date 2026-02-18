package ntcp2

import (
	"context"
	"crypto/rand"
	"net"
	"sync"
	"testing"
	"time"

	noise "github.com/go-i2p/go-noise"
	upstreamnoise "github.com/go-i2p/noise"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestXKHandshake_NTCP2_FullE2E exercises the complete NTCP2 pipeline:
//
//  1. Generate Curve25519 keypairs for initiator and responder
//  2. Set up NTCP2Config for both sides with SipHash enabled
//  3. TCP connection via localhost
//  4. XK handshake (initiator ↔ responder)
//  5. PostHandshakeHook derives per-direction SipHash keys
//  6. PropagateSipHash() installs SipHash-obfuscated framing
//  7. Bidirectional data exchange over framed I/O
//  8. Verify PeerStatic, ChannelBinding, NonceExhaustionImminent
//
// This test is the "most critical test gap" from AUDIT.md — without it,
// interoperability bugs between go-noise and other I2P implementations
// would not be caught.
func TestXKHandshake_NTCP2_FullE2E(t *testing.T) {
	cs := upstreamnoise.NewCipherSuite(
		upstreamnoise.DH25519,
		upstreamnoise.CipherChaChaPoly, // NTCP2 mandates ChaChaPoly
		upstreamnoise.HashSHA256,
	)

	// ── Step 1: Generate real Curve25519 keypairs ──────────────────────
	initiatorKP, err := cs.GenerateKeypair(rand.Reader)
	require.NoError(t, err, "generate initiator keypair")

	responderKP, err := cs.GenerateKeypair(rand.Reader)
	require.NoError(t, err, "generate responder keypair")

	// ── Step 2: Create test router hashes (SHA-256 of RouterIdentity) ─
	initiatorHash := make([]byte, RouterHashSize)
	copy(initiatorHash, "initiator-hash-32-bytes-long!!!!")

	responderHash := make([]byte, RouterHashSize)
	copy(responderHash, "responder-hash-32-bytes-long!!!!")

	// ── Step 3: Build NTCP2Config for responder ───────────────────────
	responderConfig, err := NewNTCP2Config(responderHash, false)
	require.NoError(t, err, "create responder NTCP2Config")

	responderConfig, err = responderConfig.WithStaticKey(responderKP.Private)
	require.NoError(t, err, "set responder static key")

	// Disable AES obfuscation for this test (avoids needing a published IV).
	// AES obfuscation is a handshake-phase modifier that doesn't affect
	// the data-phase framing pipeline we're testing.
	responderConfig, err = responderConfig.WithAESObfuscation(false, nil)
	require.NoError(t, err, "disable responder AES obfuscation")

	// SipHash is enabled by default — this is what we want to test.

	// ── Step 4: Build NTCP2Config for initiator ───────────────────────
	initiatorConfig, err := NewNTCP2Config(initiatorHash, true)
	require.NoError(t, err, "create initiator NTCP2Config")

	initiatorConfig, err = initiatorConfig.WithStaticKey(initiatorKP.Private)
	require.NoError(t, err, "set initiator static key")

	initiatorConfig, err = initiatorConfig.WithRemoteRouterHash(responderHash)
	require.NoError(t, err, "set initiator remote router hash")

	// XK requires the initiator to know the responder's static public key
	// as a pre-message (← s).
	initiatorConfig, err = initiatorConfig.WithRemoteStaticKey(responderKP.Public)
	require.NoError(t, err, "set initiator remote static key")

	initiatorConfig, err = initiatorConfig.WithAESObfuscation(false, nil)
	require.NoError(t, err, "disable initiator AES obfuscation")

	// ── Step 5: Start TCP listener ────────────────────────────────────
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err, "start TCP listener")
	defer ln.Close()

	// ── Step 6: Responder goroutine ───────────────────────────────────
	var wg sync.WaitGroup
	var responderErr error
	var responderNTCP2 *NTCP2Conn

	wg.Add(1)
	go func() {
		defer wg.Done()

		// Accept raw TCP connection
		rawConn, err := ln.Accept()
		if err != nil {
			responderErr = err
			return
		}

		// Create per-connection config (clone for isolation)
		perConnConfig := responderConfig.Clone()
		perConnConfig.Initiator = false

		// Convert to Noise ConnConfig
		connConfig, err := perConnConfig.ToConnConfig()
		if err != nil {
			rawConn.Close()
			responderErr = err
			return
		}

		// Create NoiseConn
		noiseConn, err := noise.NewNoiseConn(rawConn, connConfig)
		if err != nil {
			rawConn.Close()
			responderErr = err
			return
		}

		// Create NTCP2Conn
		responderAddr, _ := NewNTCP2Addr(rawConn.LocalAddr(), responderHash, "responder")
		remoteAddr, _ := NewNTCP2Addr(rawConn.RemoteAddr(), initiatorHash, "initiator")
		ntcp2Conn, err := NewNTCP2Conn(noiseConn, responderAddr, remoteAddr)
		if err != nil {
			noiseConn.Close()
			responderErr = err
			return
		}
		ntcp2Conn.SetNTCP2Config(perConnConfig)

		// Perform XK handshake (responder side)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := noiseConn.Handshake(ctx); err != nil {
			ntcp2Conn.Close()
			responderErr = err
			return
		}

		// Propagate SipHash keys derived by PostHandshakeHook
		ntcp2Conn.PropagateSipHash()

		responderNTCP2 = ntcp2Conn
	}()

	// ── Step 7: Initiator side ────────────────────────────────────────
	rawConn, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	require.NoError(t, err, "dial TCP")

	connConfig, err := initiatorConfig.ToConnConfig()
	require.NoError(t, err, "initiator ToConnConfig")

	noiseConn, err := noise.NewNoiseConn(rawConn, connConfig)
	require.NoError(t, err, "create initiator NoiseConn")

	initiatorAddr, err := NewNTCP2Addr(rawConn.LocalAddr(), initiatorHash, "initiator")
	require.NoError(t, err, "create initiator addr")

	remoteAddr, err := NewNTCP2Addr(rawConn.RemoteAddr(), responderHash, "responder")
	require.NoError(t, err, "create remote addr")

	initiatorNTCP2, err := NewNTCP2Conn(noiseConn, initiatorAddr, remoteAddr)
	require.NoError(t, err, "create initiator NTCP2Conn")
	initiatorNTCP2.SetNTCP2Config(initiatorConfig)

	// Perform XK handshake (initiator side)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = noiseConn.Handshake(ctx)
	if err != nil {
		initiatorNTCP2.Close()
		wg.Wait()
		t.Fatalf("initiator handshake: %v (responder err: %v)", err, responderErr)
	}

	// Propagate SipHash keys derived by PostHandshakeHook
	initiatorNTCP2.PropagateSipHash()

	// Wait for responder to complete handshake
	wg.Wait()
	if responderErr != nil {
		initiatorNTCP2.Close()
		t.Fatalf("responder handshake: %v", responderErr)
	}
	defer initiatorNTCP2.Close()
	defer responderNTCP2.Close()

	// ── Step 8: Verify SipHash obfuscation is active ──────────────────
	assert.NotNil(t, initiatorNTCP2.lengthObfuscator.Load(),
		"initiator should have SipHash obfuscator after PropagateSipHash")
	assert.NotNil(t, responderNTCP2.lengthObfuscator.Load(),
		"responder should have SipHash obfuscator after PropagateSipHash")

	// ── Step 9: Bidirectional framed data exchange ─────────────────────
	// Initiator → Responder
	payload1 := []byte("hello from initiator via NTCP2 XK framed I/O")
	n, err := initiatorNTCP2.Write(payload1)
	require.NoError(t, err, "initiator write")
	assert.Equal(t, len(payload1), n, "initiator write byte count")

	buf := make([]byte, 4096)
	n, err = responderNTCP2.Read(buf)
	require.NoError(t, err, "responder read")
	assert.Equal(t, string(payload1), string(buf[:n]),
		"responder should receive initiator's message intact")

	// Responder → Initiator
	payload2 := []byte("reply from responder via NTCP2 XK framed I/O")
	n, err = responderNTCP2.Write(payload2)
	require.NoError(t, err, "responder write")
	assert.Equal(t, len(payload2), n, "responder write byte count")

	n, err = initiatorNTCP2.Read(buf)
	require.NoError(t, err, "initiator read")
	assert.Equal(t, string(payload2), string(buf[:n]),
		"initiator should receive responder's reply intact")

	// ── Step 10: Verify handshake metadata ────────────────────────────
	// PeerStatic: initiator sees responder's public key, responder sees initiator's
	assert.Equal(t, responderKP.Public[:], initiatorNTCP2.PeerStaticKey(),
		"initiator PeerStatic should be responder's public key")
	assert.Equal(t, initiatorKP.Public[:], responderNTCP2.PeerStaticKey(),
		"responder PeerStatic should be initiator's public key")

	// HandshakeHash: both sides should have the same channel binding
	assert.NotNil(t, initiatorNTCP2.HandshakeHash(), "initiator should have handshake hash")
	assert.NotNil(t, responderNTCP2.HandshakeHash(), "responder should have handshake hash")
	assert.Equal(t, initiatorNTCP2.HandshakeHash(), responderNTCP2.HandshakeHash(),
		"both sides should share the same handshake hash")

	// Nonce counters should reflect the frames sent
	assert.False(t, initiatorNTCP2.NonceExhaustionImminent(),
		"nonce exhaustion should not be imminent after a few frames")
	assert.False(t, responderNTCP2.NonceExhaustionImminent(),
		"nonce exhaustion should not be imminent after a few frames")

	t.Log("Full NTCP2 XK handshake + SipHash key derivation + framed I/O succeeded")
}

// TestXKHandshake_NTCP2_MultipleMessages exercises framed I/O with multiple
// messages to verify nonce counter advancement and SipHash mask sequencing.
func TestXKHandshake_NTCP2_MultipleMessages(t *testing.T) {
	initiatorConn, responderConn := setupHandshakedPair(t)
	defer initiatorConn.Close()
	defer responderConn.Close()

	buf := make([]byte, 4096)

	// Send 10 messages in each direction to exercise nonce advancement
	for i := 0; i < 10; i++ {
		// Initiator → Responder
		msg := []byte("message from initiator #" + string(rune('0'+i)))
		n, err := initiatorConn.Write(msg)
		require.NoError(t, err, "initiator write %d", i)
		assert.Equal(t, len(msg), n)

		n, err = responderConn.Read(buf)
		require.NoError(t, err, "responder read %d", i)
		assert.Equal(t, string(msg), string(buf[:n]))

		// Responder → Initiator
		reply := []byte("reply from responder #" + string(rune('0'+i)))
		n, err = responderConn.Write(reply)
		require.NoError(t, err, "responder write %d", i)
		assert.Equal(t, len(reply), n)

		n, err = initiatorConn.Read(buf)
		require.NoError(t, err, "initiator read %d", i)
		assert.Equal(t, string(reply), string(buf[:n]))
	}

	t.Log("10 bidirectional NTCP2 framed messages exchanged successfully")
}

// TestXKHandshake_NTCP2_LargePayload verifies frame splitting works with
// the config's MaxFrameSize by sending a payload larger than one frame.
func TestXKHandshake_NTCP2_LargePayload(t *testing.T) {
	initiatorConn, responderConn := setupHandshakedPair(t)
	defer initiatorConn.Close()
	defer responderConn.Close()

	// Create a payload larger than DefaultMaxFrameSize (16384).
	// This should trigger frame splitting in writeFramed.
	largePayload := make([]byte, 32768)
	for i := range largePayload {
		largePayload[i] = byte(i % 256)
	}

	// Initiator sends large payload
	n, err := initiatorConn.Write(largePayload)
	require.NoError(t, err, "write large payload")
	assert.Equal(t, len(largePayload), n, "should write full payload")

	// Responder reads — may need multiple Read calls to get all data
	received := make([]byte, 0, len(largePayload))
	buf := make([]byte, 4096)
	for len(received) < len(largePayload) {
		n, err = responderConn.Read(buf)
		require.NoError(t, err, "read large payload chunk")
		received = append(received, buf[:n]...)
	}

	assert.Equal(t, largePayload, received, "large payload should be received intact")

	t.Log("Large payload (32KB) frame splitting + reassembly succeeded")
}

// TestXKHandshake_NTCP2_ConfigMaxFrameSize verifies that the config's
// MaxFrameSize is respected in frame splitting after handshake.
func TestXKHandshake_NTCP2_ConfigMaxFrameSize(t *testing.T) {
	initiatorConn, responderConn := setupHandshakedPair(t)
	defer initiatorConn.Close()
	defer responderConn.Close()

	// getMaxFrameSize should return the config value (DefaultMaxFrameSize=16384)
	assert.Equal(t, DefaultMaxFrameSize, initiatorConn.getMaxFrameSize(),
		"initiator should use config MaxFrameSize")
	assert.Equal(t, DefaultMaxFrameSize, responderConn.getMaxFrameSize(),
		"responder should use config MaxFrameSize")
}

// TestXKHandshake_NTCP2_CloseAfterHandshake verifies clean connection teardown.
func TestXKHandshake_NTCP2_CloseAfterHandshake(t *testing.T) {
	initiatorConn, responderConn := setupHandshakedPair(t)

	// Close initiator
	err := initiatorConn.Close()
	assert.NoError(t, err, "initiator close")

	// Close responder
	err = responderConn.Close()
	assert.NoError(t, err, "responder close")

	// Verify broken flag is NOT set (clean close)
	assert.False(t, initiatorConn.broken.Load(), "initiator should not be broken after clean close")
	assert.False(t, responderConn.broken.Load(), "responder should not be broken after clean close")
}

// ============================================================================
// Test helper: creates a fully handshaked initiator↔responder NTCP2 pair
// ============================================================================

func setupHandshakedPair(t *testing.T) (initiator *NTCP2Conn, responder *NTCP2Conn) {
	t.Helper()

	cs := upstreamnoise.NewCipherSuite(
		upstreamnoise.DH25519,
		upstreamnoise.CipherChaChaPoly,
		upstreamnoise.HashSHA256,
	)

	initiatorKP, err := cs.GenerateKeypair(rand.Reader)
	require.NoError(t, err)

	responderKP, err := cs.GenerateKeypair(rand.Reader)
	require.NoError(t, err)

	initiatorHash := make([]byte, RouterHashSize)
	copy(initiatorHash, "initiator-hash-32-bytes-long!!!!")

	responderHash := make([]byte, RouterHashSize)
	copy(responderHash, "responder-hash-32-bytes-long!!!!")

	// Responder config
	responderConfig, err := NewNTCP2Config(responderHash, false)
	require.NoError(t, err)
	responderConfig, err = responderConfig.WithStaticKey(responderKP.Private)
	require.NoError(t, err)
	responderConfig, err = responderConfig.WithAESObfuscation(false, nil)
	require.NoError(t, err)

	// Initiator config
	initiatorConfig, err := NewNTCP2Config(initiatorHash, true)
	require.NoError(t, err)
	initiatorConfig, err = initiatorConfig.WithStaticKey(initiatorKP.Private)
	require.NoError(t, err)
	initiatorConfig, err = initiatorConfig.WithRemoteRouterHash(responderHash)
	require.NoError(t, err)
	initiatorConfig, err = initiatorConfig.WithRemoteStaticKey(responderKP.Public)
	require.NoError(t, err)
	initiatorConfig, err = initiatorConfig.WithAESObfuscation(false, nil)
	require.NoError(t, err)

	// TCP listener
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	// Responder goroutine
	var wg sync.WaitGroup
	var responderErr error
	var responderNTCP2 *NTCP2Conn

	wg.Add(1)
	go func() {
		defer wg.Done()

		rawConn, err := ln.Accept()
		if err != nil {
			responderErr = err
			return
		}

		perConnConfig := responderConfig.Clone()
		perConnConfig.Initiator = false
		connConfig, err := perConnConfig.ToConnConfig()
		if err != nil {
			rawConn.Close()
			responderErr = err
			return
		}

		noiseConn, err := noise.NewNoiseConn(rawConn, connConfig)
		if err != nil {
			rawConn.Close()
			responderErr = err
			return
		}

		rAddr, _ := NewNTCP2Addr(rawConn.LocalAddr(), responderHash, "responder")
		iAddr, _ := NewNTCP2Addr(rawConn.RemoteAddr(), initiatorHash, "initiator")
		ntcp2Conn, err := NewNTCP2Conn(noiseConn, rAddr, iAddr)
		if err != nil {
			noiseConn.Close()
			responderErr = err
			return
		}
		ntcp2Conn.SetNTCP2Config(perConnConfig)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := noiseConn.Handshake(ctx); err != nil {
			ntcp2Conn.Close()
			responderErr = err
			return
		}

		ntcp2Conn.PropagateSipHash()
		responderNTCP2 = ntcp2Conn
	}()

	// Initiator side
	rawConn, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	require.NoError(t, err)

	connConfig, err := initiatorConfig.ToConnConfig()
	require.NoError(t, err)

	noiseConn, err := noise.NewNoiseConn(rawConn, connConfig)
	require.NoError(t, err)

	iAddr, err := NewNTCP2Addr(rawConn.LocalAddr(), initiatorHash, "initiator")
	require.NoError(t, err)
	rAddr, err := NewNTCP2Addr(rawConn.RemoteAddr(), responderHash, "responder")
	require.NoError(t, err)

	initiatorNTCP2, err := NewNTCP2Conn(noiseConn, iAddr, rAddr)
	require.NoError(t, err)
	initiatorNTCP2.SetNTCP2Config(initiatorConfig)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = noiseConn.Handshake(ctx)
	if err != nil {
		initiatorNTCP2.Close()
		wg.Wait()
		t.Fatalf("initiator handshake: %v (responder err: %v)", err, responderErr)
	}

	initiatorNTCP2.PropagateSipHash()

	wg.Wait()
	if responderErr != nil {
		initiatorNTCP2.Close()
		t.Fatalf("responder handshake: %v", responderErr)
	}

	return initiatorNTCP2, responderNTCP2
}
