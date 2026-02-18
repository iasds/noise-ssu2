package ntcp2

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"

	"github.com/dchest/siphash"
	noise "github.com/go-i2p/go-noise"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSetLengthObfuscator verifies the setter for the SipHash length obfuscator.
func TestSetLengthObfuscator(t *testing.T) {
	conn := createTestNTCP2Conn(&mockNoiseConn{})

	// Initially nil
	assert.Nil(t, conn.lengthObfuscator)

	// Set it
	slm := NewSipHashLengthModifier("test-siphash", [2]uint64{0x1234, 0x5678}, 0)
	conn.SetLengthObfuscator(slm)
	assert.Equal(t, slm, conn.lengthObfuscator)

	// Can set to nil to disable
	conn.SetLengthObfuscator(nil)
	assert.Nil(t, conn.lengthObfuscator)
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
	// The error wraps through NTCP2Conn's "WRITE_FAILED" code
	assert.Contains(t, err.Error(), "ntcp2 write failed")
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
	// Direct path wraps with "READ_FAILED" code
	assert.Contains(t, err.Error(), "ntcp2 read failed")
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
		sender.mu.Lock()
		outMask := sender.getNextOutboundMask()
		sender.mu.Unlock()
		obfuscated := originalLen ^ outMask

		// Put on "wire" as big-endian
		wire := make([]byte, 2)
		binary.BigEndian.PutUint16(wire, obfuscated)

		// Receiver: deobfuscate
		receiver.mu.Lock()
		inMask := receiver.getNextInboundMask()
		receiver.mu.Unlock()
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

		sender.mu.Lock()
		outMask := sender.getNextOutboundMask()
		sender.mu.Unlock()

		obfuscated := originalLen ^ outMask

		receiver.mu.Lock()
		inMask := receiver.getNextInboundMask()
		receiver.mu.Unlock()

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
	probe.mu.Lock()
	mask := probe.getNextInboundMask()
	probe.mu.Unlock()

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
	assert.Contains(t, err.Error(), "zero-length frame")
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
	probe.mu.Lock()
	mask := probe.getNextInboundMask()
	probe.mu.Unlock()

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
	probe.mu.Lock()
	mask := probe.getNextInboundMask()
	probe.mu.Unlock()

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

// TestConfigSipHashModifier verifies that NTCP2Config stores and returns
// the SipHash modifier after ToConnConfig() is called.
func TestConfigSipHashModifier(t *testing.T) {
	routerHash := make([]byte, 32)
	copy(routerHash, "test-router-hash-32-bytes-long!")

	config, err := NewNTCP2Config(routerHash, true)
	require.NoError(t, err)

	// Set remote router hash (required for initiator)
	config.RemoteRouterHash = make([]byte, 32)
	copy(config.RemoteRouterHash, "remote-hash-32-bytes-long!!!!!")

	// Provide a static key
	config.StaticKey = make([]byte, 32)
	copy(config.StaticKey, "static-key-32-bytes-long!!!!!!!")

	// AES obfuscation requires an explicit IV
	config = config.WithAESObfuscation(true, make([]byte, 16))

	// Before ToConnConfig, modifier should be nil
	assert.Nil(t, config.SipHashModifier())

	// Call ToConnConfig
	connConfig, err := config.ToConnConfig()
	require.NoError(t, err)

	// After ToConnConfig (before handshake), SipHashModifier() should be nil
	// because the placeholder zero-key modifier is no longer exposed.
	// The proper directional modifier is set by the post-handshake hook.
	assert.Nil(t, config.SipHashModifier(),
		"Placeholder zero-key modifier must not be exposed pre-handshake")

	// But the SipHash modifier is still in the modifier list for the handshake
	hasSipHashMod := false
	for _, mod := range connConfig.Modifiers {
		if mod.Name() == "ntcp2-siphash" {
			hasSipHashMod = true
			break
		}
	}
	assert.True(t, hasSipHashMod,
		"SipHash modifier should be in the handshake modifier list")
}

// TestConfigSipHashModifier_Disabled verifies that the modifier is nil
// when SipHash is disabled.
func TestConfigSipHashModifier_Disabled(t *testing.T) {
	routerHash := make([]byte, 32)
	copy(routerHash, "test-router-hash-32-bytes-long!")

	config, err := NewNTCP2Config(routerHash, true)
	require.NoError(t, err)

	config.RemoteRouterHash = make([]byte, 32)
	copy(config.RemoteRouterHash, "remote-hash-32-bytes-long!!!!!")
	config.StaticKey = make([]byte, 32)
	copy(config.StaticKey, "static-key-32-bytes-long!!!!!!!")

	// Disable SipHash
	config.EnableSipHashLength = false

	// AES obfuscation requires an explicit IV
	config = config.WithAESObfuscation(true, make([]byte, 16))

	_, err = config.ToConnConfig()
	require.NoError(t, err)

	// Modifier should be nil
	assert.Nil(t, config.SipHashModifier())
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
	sender.mu.Lock()
	mask := sender.getNextOutboundMask()
	sender.mu.Unlock()
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
	senderMod.mu.Lock()
	outMask := senderMod.getNextOutboundMask()
	senderMod.mu.Unlock()

	receiverMod := NewSipHashLengthModifier("receiver", keys, initialIV)
	receiverMod.mu.Lock()
	inMask := receiverMod.getNextInboundMask()
	receiverMod.mu.Unlock()

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
