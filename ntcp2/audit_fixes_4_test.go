package ntcp2

import (
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// Fix 1: Nonce exhaustion enforcement
// Verify that readFramed/writeSingleFrame reject operations at MaxNonce.
// ============================================================================

func TestAuditFix_NonceExhaustion_WriteRejectsAtMaxNonce(t *testing.T) {
	conn := createTestNTCP2Conn(&mockNoiseConn{})
	slm := NewSipHashLengthModifier("test", [2]uint64{0x1234, 0x5678}, 0)
	conn.SetLengthObfuscator(slm)

	// Set writeNonce to MaxNonce to simulate exhaustion.
	conn.writeNonce = MaxNonce

	// writeFramed acquires writeMu and calls writeSingleFrame which should
	// check nonce exhaustion before encrypting.
	_, err := conn.Write([]byte("hello"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nonce exhausted")
}

func TestAuditFix_NonceExhaustion_ReadRejectsAtMaxNonce(t *testing.T) {
	conn := createTestNTCP2Conn(&mockNoiseConn{})
	slm := NewSipHashLengthModifier("test", [2]uint64{0x1234, 0x5678}, 0)
	conn.SetLengthObfuscator(slm)

	// Set readNonce to MaxNonce to simulate exhaustion.
	conn.readNonce = MaxNonce

	// Read with framing enabled should fail before any I/O.
	buf := make([]byte, 64)
	_, err := conn.Read(buf)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nonce exhausted")
}

func TestAuditFix_NonceExhaustion_BelowMaxNonceAllowed(t *testing.T) {
	// A nonce just below MaxNonce should still be allowed (the guard
	// only rejects at >= MaxNonce).
	conn := createTestNTCP2Conn(&mockNoiseConn{})
	slm := NewSipHashLengthModifier("test", [2]uint64{0x1234, 0x5678}, 0)
	conn.SetLengthObfuscator(slm)

	conn.writeNonce = MaxNonce - 1

	// This will fail for other reasons (no real Noise state), but it
	// should NOT fail with NONCE_EXHAUSTED.
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

// ============================================================================
// Fix 2: SipHash desync — broken flag
// Verify that the broken flag is checked on Read/Write.
// ============================================================================

func TestAuditFix_BrokenFlag_WriteRejects(t *testing.T) {
	conn := createTestNTCP2Conn(&mockNoiseConn{})
	slm := NewSipHashLengthModifier("test", [2]uint64{0x1234, 0x5678}, 0)
	conn.SetLengthObfuscator(slm)

	// Simulate a broken connection
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
	// When no length obfuscator is set, Read delegates to readDirect
	// but the broken check at the top of Read() should still fire.
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

// ============================================================================
// Fix 3: AEAD error handling — TCP RST
// Verify handleAEADError marks connection broken and closes underlying.
// ============================================================================

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

// ============================================================================
// Fix 4: writeFramed uses config MaxFrameSize
// Verify getMaxFrameSize returns config value when set.
// ============================================================================

func TestAuditFix_GetMaxFrameSize_DefaultsToConstant(t *testing.T) {
	conn := createTestNTCP2Conn(&mockNoiseConn{})
	// No config set
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

// ============================================================================
// Fix 5: SetNTCP2Config thread safety
// Verify atomic.Pointer access is race-free.
// ============================================================================

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

	// Concurrently read
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = conn.getMaxFrameSize()
		}()
	}

	wg.Wait()
	// No data race should be detected (run with -race)
}

func TestAuditFix_PropagateSipHash_ThreadSafe(t *testing.T) {
	conn := createTestNTCP2Conn(&mockNoiseConn{})

	var wg sync.WaitGroup

	// Concurrently set config and propagate
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

// ============================================================================
// Fix 6: Quality items
// ============================================================================

func TestAuditFix_ReadDirect_NoDoubleWrapping(t *testing.T) {
	conn := createTestNTCP2Conn(&mockNoiseConn{})

	buf := make([]byte, 64)
	_, err := conn.Read(buf)
	require.Error(t, err)

	// Should NOT contain "ntcp2 read failed" (old double-wrap message)
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

	// Well below threshold
	conn.writeNonce = 0
	conn.readNonce = 0
	assert.False(t, conn.NonceExhaustionImminent())

	// At threshold
	conn.writeNonce = NonceRekeyThreshold
	assert.True(t, conn.NonceExhaustionImminent())

	// Read nonce at threshold
	conn.writeNonce = 0
	conn.readNonce = NonceRekeyThreshold
	assert.True(t, conn.NonceExhaustionImminent())
}

// ============================================================================
// Fix 7: Clone() produces independent config
// ============================================================================

func TestAuditFix_Clone_IndependentConfig(t *testing.T) {
	original := &NTCP2Config{
		Pattern:       "XK",
		MaxFrameSize:  16384,
		BobRouterHash: []byte("original-hash-32-bytes-long!!!!!"),
	}

	clone := original.Clone()

	// Modify clone should not affect original
	clone.MaxFrameSize = 8192
	clone.BobRouterHash[0] = 0xFF

	assert.Equal(t, 16384, original.MaxFrameSize, "clone modification should not affect original")
	assert.NotEqual(t, byte(0xFF), original.BobRouterHash[0], "clone byte slice modification should not affect original")
}

// ============================================================================
// Fix: removeTrailingPaddingBlock bounded by maxPadding
// ============================================================================

func TestAuditFix_RemoveTrailingPaddingBlock_BoundedByMaxPadding(t *testing.T) {
	// Create a modifier with small maxPadding
	modifier, err := NewNTCP2PaddingModifier("test", 0, 16, false)
	require.NoError(t, err)

	// Create data with a large "padding" block that exceeds maxPadding.
	// Block: type=254, size=100 (big-endian), followed by 100 bytes.
	paddingSize := 100
	payload := []byte("real data here and some more data to fill it up!!")
	data := make([]byte, len(payload)+3+paddingSize)
	copy(data[:len(payload)], payload)
	data[len(payload)] = PaddingBlockType         // type=254
	data[len(payload)+1] = byte(paddingSize >> 8) // size high byte
	data[len(payload)+2] = byte(paddingSize)      // size low byte
	// paddingSize bytes of padding follow (already zeroed)

	result, err := modifier.removeTrailingPaddingBlock(data)
	require.NoError(t, err)

	// Since the padding block is 100 bytes > maxPadding=16, it should NOT be removed.
	assert.Equal(t, len(data), len(result),
		"padding block exceeding maxPadding should not be removed")
}

func TestAuditFix_RemoveTrailingPaddingBlock_WithinMaxPadding(t *testing.T) {
	modifier, err := NewNTCP2PaddingModifier("test", 0, 64, false)
	require.NoError(t, err)

	// Create data with a small padding block (10 bytes) within maxPadding.
	payloadStr := "real data"
	payload := []byte(payloadStr)
	paddingSize := 10
	data := make([]byte, len(payload)+3+paddingSize)
	copy(data, payload)
	data[len(payload)] = PaddingBlockType
	data[len(payload)+1] = 0
	data[len(payload)+2] = byte(paddingSize)

	result, err := modifier.removeTrailingPaddingBlock(data)
	require.NoError(t, err)

	assert.Equal(t, len(payload), len(result),
		"padding block within maxPadding should be removed")
	assert.Equal(t, payloadStr, string(result))
}

// ============================================================================
// Logger pointer type verification
// ============================================================================

func TestAuditFix_LoggerIsPointer(t *testing.T) {
	conn := createTestNTCP2Conn(&mockNoiseConn{})
	assert.NotNil(t, conn.logger, "logger should be set to package-level log pointer")
}

// ============================================================================
// Integration: multiple fixes working together
// ============================================================================

func TestAuditFix_BrokenAndNonceExhausted_BrokenTakesPriority(t *testing.T) {
	conn := createTestNTCP2Conn(&mockNoiseConn{})
	slm := NewSipHashLengthModifier("test", [2]uint64{0x1234, 0x5678}, 0)
	conn.SetLengthObfuscator(slm)

	// Set both broken and nonce exhausted
	conn.broken.Store(true)
	conn.writeNonce = MaxNonce

	_, err := conn.Write([]byte("hello"))
	require.Error(t, err)
	// Broken check happens first (in Write), before nonce check (in writeSingleFrame)
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
