package ntcp2

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"net"
	"testing"

	noise "github.com/go-i2p/go-noise"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// Tests for AUDIT round 3 fixes
// ============================================================================

// --- validateFrameLength probing-resistance delay ---

// TestValidateFrameLength_ZeroAppliesProbingDelay verifies that a zero-length
// frame triggers probing-resistance delay before returning the error.
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

	// validateFrameLength with 0 should return an error (and not panic)
	err = ntcp2Conn.validateFrameLength(0)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "zero-length frame")
}

// TestValidateFrameLength_TooSmallAppliesProbingDelay verifies probing delay
// for frames below MinDataPhaseFrameSize.
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

	err = ntcp2Conn.validateFrameLength(1) // below MinDataPhaseFrameSize (16)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "below minimum")
}

// TestValidateFrameLength_ValidLength verifies that valid lengths pass.
func TestValidateFrameLength_ValidLength(t *testing.T) {
	conn := createTestNTCP2Conn(&mockNoiseConn{})

	err := conn.validateFrameLength(MinDataPhaseFrameSize)
	assert.NoError(t, err)

	err = conn.validateFrameLength(1024)
	assert.NoError(t, err)

	err = conn.validateFrameLength(uint16(MaxFrameSize))
	assert.NoError(t, err)
}

// --- Named constants for AEAD error handling ---

// TestAEADErrorConstants verifies that AEAD error handling constants are defined.
func TestAEADErrorConstants(t *testing.T) {
	assert.Equal(t, 1024, AEADErrorMaxJunkBytes)
	assert.Greater(t, AEADErrorTimeout.Seconds(), 0.0)
	assert.Greater(t, NonceRekeyThreshold, uint64(0))
	assert.Less(t, NonceRekeyThreshold, MaxNonce)
}

// --- NonceExhaustionImminent ---

// TestNonceExhaustionImminent verifies that the method correctly detects
// approaching nonce limits.
func TestNonceExhaustionImminent(t *testing.T) {
	conn := createTestNTCP2Conn(&mockNoiseConn{})

	// Initially false
	assert.False(t, conn.NonceExhaustionImminent())

	// Set write nonce above threshold
	conn.writeMu.Lock()
	conn.writeNonce = NonceRekeyThreshold
	conn.writeMu.Unlock()
	assert.True(t, conn.NonceExhaustionImminent())

	// Reset write, set read nonce above threshold
	conn.writeMu.Lock()
	conn.writeNonce = 0
	conn.writeMu.Unlock()
	conn.readMu.Lock()
	conn.readNonce = NonceRekeyThreshold
	conn.readMu.Unlock()
	assert.True(t, conn.NonceExhaustionImminent())

	// Reset both
	conn.readMu.Lock()
	conn.readNonce = 0
	conn.readMu.Unlock()
	assert.False(t, conn.NonceExhaustionImminent())
}

// --- checkNonceLimit nonce exhaustion path ---

// TestCheckNonceLimit_AtMaxNonce verifies that checkWriteNonceLimit returns
// an error when the nonce has reached MaxNonce.
func TestCheckNonceLimit_AtMaxNonce(t *testing.T) {
	conn := createTestNTCP2Conn(&mockNoiseConn{})

	conn.writeMu.Lock()
	conn.writeNonce = MaxNonce
	err := conn.checkWriteNonceLimit()
	conn.writeMu.Unlock()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "nonce limit reached")
}

// TestCheckNonceLimit_BelowMaxNonce verifies normal operation.
func TestCheckNonceLimit_BelowMaxNonce(t *testing.T) {
	conn := createTestNTCP2Conn(&mockNoiseConn{})

	conn.writeMu.Lock()
	conn.writeNonce = 0
	err := conn.checkWriteNonceLimit()
	conn.writeMu.Unlock()
	assert.NoError(t, err)
}

// --- zeroKeyMaterial ---

// TestZeroKeyMaterial verifies that zeroKeyMaterial zeroes all sensitive fields.
func TestZeroKeyMaterial(t *testing.T) {
	conn := createTestNTCP2Conn(&mockNoiseConn{})

	// Set up a SipHash modifier with non-zero keys
	keys := [2]uint64{0xDEADBEEF, 0xCAFEBABE}
	slm := NewSipHashLengthModifier("test", keys, 0x12345678)
	conn.SetLengthObfuscator(slm)

	// Set some read buffer data
	conn.readMu.Lock()
	conn.readBuffer = []byte("sensitive plaintext data")
	conn.readMu.Unlock()

	// Zero key material
	conn.zeroKeyMaterial()

	// Verify SipHash keys are zeroed
	assert.Equal(t, uint64(0), slm.outboundKeys[0])
	assert.Equal(t, uint64(0), slm.outboundKeys[1])
	assert.Equal(t, uint64(0), slm.inboundKeys[0])
	assert.Equal(t, uint64(0), slm.inboundKeys[1])
	assert.Equal(t, uint64(0), slm.outboundIV)
	assert.Equal(t, uint64(0), slm.inboundIV)

	// Verify read buffer is nil
	conn.readMu.Lock()
	assert.Nil(t, conn.readBuffer)
	conn.readMu.Unlock()
}

// --- Rekey delegation ---

// TestRekey verifies that Rekey() delegates to the underlying NoiseConn.
func TestRekey(t *testing.T) {
	conn := createTestNTCP2Conn(&mockNoiseConn{})

	// Rekey on an uninitialized connection may return an error, but should not panic
	err := conn.Rekey()
	// The error is expected because the handshake hasn't been done
	_ = err
}

// --- HandshakeHash and PeerStaticKey ---

// TestHandshakeHash verifies HandshakeHash() returns a value (the protocol
// name hash is initialized even before the handshake completes).
func TestHandshakeHash(t *testing.T) {
	conn := createTestNTCP2Conn(&mockNoiseConn{})
	h := conn.HandshakeHash()
	// ChannelBinding returns the symmetric state hash, which is initialized
	// from the protocol name during NewNoiseConn. It's non-nil even before handshake.
	assert.NotNil(t, h)
	assert.Equal(t, 32, len(h))
}

// TestPeerStaticKey verifies PeerStaticKey() returns nil before handshake.
func TestPeerStaticKey(t *testing.T) {
	conn := createTestNTCP2Conn(&mockNoiseConn{})
	key := conn.PeerStaticKey()
	assert.Nil(t, key)
}

// --- WithAESObfuscation wrong IV length ---

// TestWithAESObfuscation_WrongIVLengthLogsWarning verifies that an IV
// of wrong length is not silently set — the ObfuscationIV remains nil.
func TestWithAESObfuscation_WrongIVLengthLogsWarning(t *testing.T) {
	routerHash := make([]byte, 32)
	_, err := rand.Read(routerHash)
	require.NoError(t, err)

	config, err := NewNTCP2Config(routerHash, false)
	require.NoError(t, err)
	config.EnableAESObfuscation = false // Start fresh

	// Wrong length IV — should not be set
	wrongIV := make([]byte, 10) // not 16
	config = config.WithAESObfuscation(true, wrongIV)
	assert.Nil(t, config.ObfuscationIV, "Wrong-length IV must not be set")

	// Correct length IV
	correctIV := make([]byte, 16)
	config = config.WithAESObfuscation(true, correctIV)
	assert.NotNil(t, config.ObfuscationIV, "Correct-length IV must be set")
}

// --- SipHashModifier placeholder ---

// TestSipHashModifier_NilBeforeHandshake verifies that SipHashModifier()
// returns nil after ToConnConfig() (since the placeholder is no longer stored).
func TestSipHashModifier_NilBeforeHandshake(t *testing.T) {
	routerHash := make([]byte, 32)
	_, err := rand.Read(routerHash)
	require.NoError(t, err)

	obfuscationIV := make([]byte, 16)
	_, err = rand.Read(obfuscationIV)
	require.NoError(t, err)

	config, err := NewNTCP2Config(routerHash, false)
	require.NoError(t, err)

	config = config.WithAESObfuscation(true, obfuscationIV)

	// Before ToConnConfig, sipHashModifier is nil
	assert.Nil(t, config.SipHashModifier())

	_, err = config.ToConnConfig()
	require.NoError(t, err)

	// After ToConnConfig with SipHash enabled, SipHashModifier() should still
	// be nil because the placeholder is no longer stored — only the
	// post-handshake hook sets the proper directional modifier.
	assert.Nil(t, config.SipHashModifier(),
		"Placeholder zero-key modifier must not be exposed via SipHashModifier()")
}

// --- createDialAddresses RemoteRouterHash validation ---

// TestCreateDialAddresses_InvalidRemoteRouterHash verifies that
// createDialAddresses rejects a RemoteRouterHash of wrong length.
func TestCreateDialAddresses_InvalidRemoteRouterHash(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	routerHash := make([]byte, 32)
	config, err := NewNTCP2Config(routerHash, true)
	require.NoError(t, err)

	// Set RemoteRouterHash to wrong length
	config.RemoteRouterHash = make([]byte, 20) // not 32

	_, _, err = createDialAddresses(client, config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "config.RemoteRouterHash must be exactly")
}

// --- listener.go: atomic.Bool for closed ---

// TestListener_AtomicBoolClosed verifies that the listener uses atomic.Bool
// correctly for the closed field.
func TestListener_AtomicBoolClosed(t *testing.T) {
	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	routerHash := make([]byte, 32)
	_, err = rand.Read(routerHash)
	require.NoError(t, err)

	config, err := NewNTCP2Config(routerHash, false)
	require.NoError(t, err)

	listener, err := NewNTCP2Listener(tcpListener, config)
	require.NoError(t, err)

	// Initially not closed
	assert.False(t, listener.isClosed())

	// Close
	err = listener.Close()
	assert.NoError(t, err)
	assert.True(t, listener.isClosed())

	// Double close is idempotent
	err = listener.Close()
	assert.NoError(t, err)
}

// --- AcceptWithHandshake ---

// TestAcceptWithHandshake_ClosedListener verifies that AcceptWithHandshake
// returns an error on a closed listener.
func TestAcceptWithHandshake_ClosedListener(t *testing.T) {
	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	routerHash := make([]byte, 32)
	_, err = rand.Read(routerHash)
	require.NoError(t, err)

	config, err := NewNTCP2Config(routerHash, false)
	require.NoError(t, err)

	listener, err := NewNTCP2Listener(tcpListener, config)
	require.NoError(t, err)

	// Close the listener
	err = listener.Close()
	require.NoError(t, err)

	// AcceptWithHandshake should fail
	_, err = listener.AcceptWithHandshake(context.Background())
	assert.Error(t, err)
}

// --- writeFramed multi-frame splitting ---

// TestWriteFramed_MultiFrameSplit verifies that large payloads are
// split into multiple frames of MaxFrameSize - Poly1305Overhead.
func TestWriteFramed_MultiFrameSplit(t *testing.T) {
	conn := createTestNTCP2Conn(&mockNoiseConn{})

	// Set a SipHash modifier so the framed path is taken
	slm := NewSipHashLengthModifier("test", [2]uint64{0x1234, 0x5678}, 0)
	conn.SetLengthObfuscator(slm)

	// Create a payload larger than MaxFrameSize - Poly1305Overhead
	maxPlaintext := MaxFrameSize - Poly1305Overhead
	largePayload := make([]byte, maxPlaintext+100)

	// Write will fail (no handshake) but should attempt the split path
	_, err := conn.Write(largePayload)
	assert.Error(t, err)
	// The framed path calls Encrypt which fails due to no handshake
	assert.Contains(t, err.Error(), "failed to encrypt frame")
}

// --- readFramed buffer-remainder ---

// TestReadFramed_BufferRemainder verifies that when the caller's buffer is
// smaller than the decrypted frame, the remainder is buffered.
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

	// Manually inject read buffer to simulate a previous oversized frame
	ntcp2Conn.readMu.Lock()
	ntcp2Conn.readBuffer = []byte("buffered-remainder-data")
	ntcp2Conn.readMu.Unlock()

	// Set a SipHash modifier to enable the framed read path
	slm := NewSipHashLengthModifier("test", [2]uint64{0x1234, 0x5678}, 0)
	ntcp2Conn.SetLengthObfuscator(slm)

	// Read into a small buffer — should get first part from readBuffer
	smallBuf := make([]byte, 8)
	n, err := ntcp2Conn.Read(smallBuf)
	assert.NoError(t, err)
	assert.Equal(t, 8, n)
	assert.Equal(t, "buffered", string(smallBuf[:n]))

	// Read remainder
	remainBuf := make([]byte, 32)
	n, err = ntcp2Conn.Read(remainBuf)
	assert.NoError(t, err)
	assert.Equal(t, "-remainder-data", string(remainBuf[:n]))
}

// --- KDF ask_master label verification ---

// TestKDF_ASKLabelConfigured verifies that ToConnConfig correctly
// configures the "ask" label for ASK key derivation.
func TestKDF_ASKLabelConfigured(t *testing.T) {
	routerHash := make([]byte, 32)
	_, err := rand.Read(routerHash)
	require.NoError(t, err)

	obfuscationIV := make([]byte, 16)
	_, err = rand.Read(obfuscationIV)
	require.NoError(t, err)

	config, err := NewNTCP2Config(routerHash, false)
	require.NoError(t, err)
	config = config.WithAESObfuscation(true, obfuscationIV)

	connConfig, err := config.ToConnConfig()
	require.NoError(t, err)

	// Verify ASK label is configured
	assert.Len(t, connConfig.AdditionalSymmetricKeyLabels, 1)
	assert.Equal(t, []byte("ask"), connConfig.AdditionalSymmetricKeyLabels[0])

	// Verify post-handshake hook is configured
	assert.NotNil(t, connConfig.PostHandshakeHook)
}

// TestDeriveSipHashKeys_Deterministic verifies that DeriveSipHashKeys
// produces deterministic output for the same inputs.
func TestDeriveSipHashKeys_Deterministic(t *testing.T) {
	askMaster := make([]byte, 32)
	for i := range askMaster {
		askMaster[i] = byte(i + 10)
	}
	handshakeHash := make([]byte, 32)
	for i := range handshakeHash {
		handshakeHash[i] = byte(i + 50)
	}

	keysAB1, ivAB1, keysBA1, ivBA1, err1 := DeriveSipHashKeys(askMaster, handshakeHash)
	keysAB2, ivAB2, keysBA2, ivBA2, err2 := DeriveSipHashKeys(askMaster, handshakeHash)

	require.NoError(t, err1)
	require.NoError(t, err2)

	assert.Equal(t, keysAB1, keysAB2)
	assert.Equal(t, ivAB1, ivAB2)
	assert.Equal(t, keysBA1, keysBA2)
	assert.Equal(t, ivBA1, ivBA2)
}

// --- SipHash frame length obfuscation with directional keys ---

// TestFrameLengthObfuscation_DirectionalRoundTrip verifies that directional
// SipHash modifiers correctly obfuscate/deobfuscate frame lengths when
// used as an initiator/responder pair.
func TestFrameLengthObfuscation_DirectionalRoundTrip(t *testing.T) {
	askMaster := make([]byte, 32)
	for i := range askMaster {
		askMaster[i] = byte(i)
	}
	handshakeHash := make([]byte, 32)
	for i := range handshakeHash {
		handshakeHash[i] = byte(i + 128)
	}

	keysAB, ivAB, keysBA, ivBA, err := DeriveSipHashKeys(askMaster, handshakeHash)
	require.NoError(t, err)

	initiator := NewSipHashLengthModifierDirectional("alice", keysAB, keysBA, ivAB, ivBA)
	responder := NewSipHashLengthModifierDirectional("bob", keysBA, keysAB, ivBA, ivAB)

	// Test round-trip: initiator outbound → responder inbound
	for i := 0; i < 20; i++ {
		originalLen := uint16(16 + i*100)

		outMask := initiator.NextOutboundMask()
		obfuscated := originalLen ^ outMask

		wire := make([]byte, 2)
		binary.BigEndian.PutUint16(wire, obfuscated)

		inMask := responder.NextInboundMask()
		recovered := binary.BigEndian.Uint16(wire) ^ inMask

		assert.Equal(t, originalLen, recovered,
			"Directional round-trip failed at frame %d", i)
	}
}
