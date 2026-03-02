package handshake

import (
	"errors"
	"fmt"
	"io"
	"sync"
	"testing"
)

func TestXORModifier(t *testing.T) {
	t.Run("NewXORModifier with key", func(t *testing.T) {
		key := []byte{0xAA, 0xBB, 0xCC}
		modifier := NewXORModifier("test-xor", key)

		if modifier.Name() != "test-xor" {
			t.Errorf("Name() = %v, want %v", modifier.Name(), "test-xor")
		}

		if len(modifier.xorKey) != 3 {
			t.Errorf("Key length = %v, want %v", len(modifier.xorKey), 3)
		}

		// Verify key independence
		key[0] = 0xFF
		if modifier.xorKey[0] != 0xAA {
			t.Error("XOR key was affected by external modification")
		}
	})

	t.Run("NewXORModifier with empty key generates random key", func(t *testing.T) {
		mod1 := NewXORModifier("empty-key-1", []byte{})
		mod2 := NewXORModifier("empty-key-2", []byte{})

		// The random default should be 32 bytes long
		if len(mod1.xorKey) != 32 {
			t.Errorf("Empty-key default key length = %v, want 32", len(mod1.xorKey))
		}
		if len(mod2.xorKey) != 32 {
			t.Errorf("Empty-key default key length = %v, want 32", len(mod2.xorKey))
		}

		// Two separate calls should produce different keys (probabilistic: P(collision) ≈ 2^-256)
		sameKey := true
		for i := range mod1.xorKey {
			if mod1.xorKey[i] != mod2.xorKey[i] {
				sameKey = false
				break
			}
		}
		if sameKey {
			t.Error("Two NewXORModifier(empty) calls produced the same key (astronomically unlikely unless broken)")
		}
	})

	t.Run("XOR round-trip", func(t *testing.T) {
		key := []byte{0xAA, 0xBB}
		modifier := NewXORModifier("roundtrip", key)
		originalData := []byte("Hello, Noise Protocol!")

		// Apply XOR transformation
		outbound, err := modifier.ModifyOutbound(PhaseInitial, originalData)
		if err != nil {
			t.Errorf("ModifyOutbound() error = %v", err)
		}

		// Data should be different
		if string(outbound) == string(originalData) {
			t.Error("XOR should transform data, but it's unchanged")
		}

		// Apply XOR again to reverse
		recovered, err := modifier.ModifyInbound(PhaseInitial, outbound)
		if err != nil {
			t.Errorf("ModifyInbound() error = %v", err)
		}

		// Should get back original data
		if string(recovered) != string(originalData) {
			t.Errorf("XOR round-trip failed: got %v, want %v", string(recovered), string(originalData))
		}
	})

	t.Run("XOR with different phases including PhaseData", func(t *testing.T) {
		modifier := NewXORModifier("phase-test", []byte{0x42})
		testData := []byte("test")

		// XOR should work the same regardless of phase, including PhaseData
		phases := []HandshakePhase{PhaseInitial, PhaseExchange, PhaseFinal, PhaseData}
		for _, phase := range phases {
			result, err := modifier.ModifyOutbound(phase, testData)
			if err != nil {
				t.Errorf("ModifyOutbound() phase %v error = %v", phase, err)
			}

			// Verify consistent transformation
			expected := make([]byte, len(testData))
			for i, b := range testData {
				expected[i] = b ^ 0x42
			}

			if string(result) != string(expected) {
				t.Errorf("Phase %v: got %v, want %v", phase, result, expected)
			}

			// Verify round-trip for PhaseData specifically
			recovered, err := modifier.ModifyInbound(phase, result)
			if err != nil {
				t.Errorf("ModifyInbound() phase %v error = %v", phase, err)
			}
			if string(recovered) != string(testData) {
				t.Errorf("Round-trip failed for phase %v", phase)
			}
		}
	})

	t.Run("XOR with empty data", func(t *testing.T) {
		modifier := NewXORModifier("empty-data", []byte{0xFF})

		result, err := modifier.ModifyOutbound(PhaseInitial, []byte{})
		if err != nil {
			t.Errorf("ModifyOutbound() error = %v", err)
		}

		if len(result) != 0 {
			t.Errorf("Empty data should remain empty, got %v", result)
		}
	})

	t.Run("XOR key cycling", func(t *testing.T) {
		key := []byte{0x01, 0x02}
		modifier := NewXORModifier("cycling", key)
		data := []byte{0x10, 0x20, 0x30, 0x40, 0x50}

		result, err := modifier.ModifyOutbound(PhaseExchange, data)
		if err != nil {
			t.Errorf("ModifyOutbound() error = %v", err)
		}

		expected := []byte{
			0x10 ^ 0x01, // data[0] ^ key[0]
			0x20 ^ 0x02, // data[1] ^ key[1]
			0x30 ^ 0x01, // data[2] ^ key[0] (cycle)
			0x40 ^ 0x02, // data[3] ^ key[1] (cycle)
			0x50 ^ 0x01, // data[4] ^ key[0] (cycle)
		}

		for i, b := range result {
			if b != expected[i] {
				t.Errorf("Byte %d: got %v, want %v", i, b, expected[i])
			}
		}
	})

	t.Run("Close zeroes key material", func(t *testing.T) {
		key := []byte{0x11, 0x22, 0x33}
		modifier := NewXORModifier("close-test", key)

		if err := modifier.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}

		for i, b := range modifier.xorKey {
			if b != 0 {
				t.Errorf("xorKey[%d] = %02x after Close(), want 0x00", i, b)
			}
		}
	})

	t.Run("Concurrent ModifyOutbound and ModifyInbound", func(t *testing.T) {
		modifier := NewXORModifier("concurrent-xor", []byte{0x5A, 0xA5})
		testData := []byte("concurrent test data for XOR modifier")

		const goroutines = 16
		var wg sync.WaitGroup
		errs := make(chan error, goroutines*2)

		for i := 0; i < goroutines; i++ {
			wg.Add(2)
			go func() {
				defer wg.Done()
				out, err := modifier.ModifyOutbound(PhaseData, testData)
				if err != nil {
					errs <- err
					return
				}
				recovered, err := modifier.ModifyInbound(PhaseData, out)
				if err != nil {
					errs <- err
					return
				}
				if string(recovered) != string(testData) {
					errs <- fmt.Errorf("concurrent round-trip mismatch")
				}
			}()
			go func() {
				defer wg.Done()
				out, err := modifier.ModifyOutbound(PhaseFinal, testData)
				if err != nil {
					errs <- err
					return
				}
				recovered, err := modifier.ModifyInbound(PhaseFinal, out)
				if err != nil {
					errs <- err
					return
				}
				if string(recovered) != string(testData) {
					errs <- fmt.Errorf("concurrent round-trip mismatch (PhaseFinal)")
				}
			}()
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Error(err)
		}
	})
}

// failingReader is an io.Reader that always returns an error, used to test
// the NewXORModifier entropy-failure fallback path.
type failingReader struct{}

func (failingReader) Read([]byte) (int, error) {
	return 0, errors.New("simulated entropy failure")
}

// TestNewXORModifier_EntropyFailureFallback verifies that when the random
// source fails, NewXORModifier produces a modifier with the degraded 1-byte
// fallback key {0x01} instead of panicking. This covers the otherwise-
// unreachable path in production (crypto/rand.Read only fails if the OS
// entropy source is broken).
func TestNewXORModifier_EntropyFailureFallback(t *testing.T) {
	// Save and restore the package-level randReader
	originalReader := randReader
	t.Cleanup(func() { randReader = originalReader })

	// Inject a failing reader
	randReader = io.Reader(failingReader{})

	mod := NewXORModifier("entropy-fail", nil)

	// The fallback key should be the well-known degraded value
	if len(mod.xorKey) != 1 {
		t.Fatalf("Fallback key length = %d, want 1", len(mod.xorKey))
	}
	if mod.xorKey[0] != 0x01 {
		t.Errorf("Fallback key = %#x, want 0x01", mod.xorKey[0])
	}

	// The modifier should still function (XOR with 0x01)
	data := []byte{0x10, 0x20, 0x30}
	out, err := mod.ModifyOutbound(PhaseInitial, data)
	if err != nil {
		t.Fatalf("ModifyOutbound() error = %v", err)
	}
	expected := []byte{0x11, 0x21, 0x31}
	for i, b := range out {
		if b != expected[i] {
			t.Errorf("ModifyOutbound byte %d = %#x, want %#x", i, b, expected[i])
		}
	}

	// Round-trip should still work
	recovered, err := mod.ModifyInbound(PhaseInitial, out)
	if err != nil {
		t.Fatalf("ModifyInbound() error = %v", err)
	}
	for i, b := range recovered {
		if b != data[i] {
			t.Errorf("Round-trip byte %d = %#x, want %#x", i, b, data[i])
		}
	}
}

// TestNewXORModifier_NormalRandReaderRestored verifies that the injected
// reader does not leak across tests (basic sanity check).
func TestNewXORModifier_NormalRandReaderRestored(t *testing.T) {
	mod := NewXORModifier("after-restore", nil)
	if len(mod.xorKey) != 32 {
		t.Errorf("Expected 32-byte random key after reader restore, got %d bytes", len(mod.xorKey))
	}
}

// TestXORModifier_UseAfterClose verifies that ModifyOutbound and ModifyInbound
// return errors after Close() has been called, preventing silent security
// degradation where zeroed key material would cause XOR to become a no-op.
func TestXORModifier_UseAfterClose(t *testing.T) {
	key := []byte{0xAA, 0xBB, 0xCC}
	modifier := NewXORModifier("use-after-close", key)
	testData := []byte("hello noise")

	// Verify it works before Close
	out, err := modifier.ModifyOutbound(PhaseInitial, testData)
	if err != nil {
		t.Fatalf("ModifyOutbound() before Close error = %v", err)
	}
	if string(out) == string(testData) {
		t.Fatal("ModifyOutbound() should transform data before Close")
	}

	// Close the modifier
	if err := modifier.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	// ModifyOutbound after Close should return error
	_, err = modifier.ModifyOutbound(PhaseInitial, testData)
	if err == nil {
		t.Error("ModifyOutbound() after Close() should return error")
	}

	// ModifyInbound after Close should return error
	_, err = modifier.ModifyInbound(PhaseInitial, testData)
	if err == nil {
		t.Error("ModifyInbound() after Close() should return error")
	}

	// Empty data after Close should also return error
	_, err = modifier.ModifyOutbound(PhaseInitial, []byte{})
	if err == nil {
		t.Error("ModifyOutbound() with empty data after Close() should return error")
	}

	// All phases should return error after Close
	for _, phase := range []HandshakePhase{PhaseInitial, PhaseExchange, PhaseFinal, PhaseData} {
		_, err = modifier.ModifyOutbound(phase, testData)
		if err == nil {
			t.Errorf("ModifyOutbound(phase=%v) after Close() should return error", phase)
		}
		_, err = modifier.ModifyInbound(phase, testData)
		if err == nil {
			t.Errorf("ModifyInbound(phase=%v) after Close() should return error", phase)
		}
	}
}
