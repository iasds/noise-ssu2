package handshake

import (
	"strings"
	"testing"
)

func TestPaddingModifier(t *testing.T) {
	t.Run("NewPaddingModifier valid parameters", func(t *testing.T) {
		modifier, err := NewPaddingModifier("test-padding", 5, 10)
		if err != nil {
			t.Errorf("NewPaddingModifier() error = %v", err)
		}

		if modifier.Name() != "test-padding" {
			t.Errorf("Name() = %v, want %v", modifier.Name(), "test-padding")
		}

		if modifier.minPadding != 5 {
			t.Errorf("minPadding = %v, want %v", modifier.minPadding, 5)
		}

		if modifier.maxPadding != 10 {
			t.Errorf("maxPadding = %v, want %v", modifier.maxPadding, 10)
		}
	})

	t.Run("NewPaddingModifier negative minimum", func(t *testing.T) {
		_, err := NewPaddingModifier("negative", -1, 5)
		if err == nil {
			t.Error("NewPaddingModifier() expected error for negative minimum")
		}

		if !strings.Contains(err.Error(), "minimum padding cannot be negative") {
			t.Errorf("Error message = %v, want minimum padding error", err.Error())
		}
	})

	t.Run("NewPaddingModifier max less than min", func(t *testing.T) {
		_, err := NewPaddingModifier("invalid", 10, 5)
		if err == nil {
			t.Error("NewPaddingModifier() expected error for max < min")
		}

		if !strings.Contains(err.Error(), "maximum padding cannot be less than minimum padding") {
			t.Errorf("Error message = %v, want max < min error", err.Error())
		}
	})

	t.Run("Padding round-trip", func(t *testing.T) {
		modifier, err := NewPaddingModifier("roundtrip", 4, 4)
		if err != nil {
			t.Errorf("NewPaddingModifier() error = %v", err)
		}

		originalData := []byte("Hello, World!")

		// Apply padding
		padded, err := modifier.ModifyOutbound(PhaseInitial, originalData)
		if err != nil {
			t.Errorf("ModifyOutbound() error = %v", err)
		}

		// Padded data should be longer
		expectedLen := 4 + len(originalData) + 4 // length prefix + data + padding
		if len(padded) != expectedLen {
			t.Errorf("Padded length = %v, want %v", len(padded), expectedLen)
		}

		// Remove padding
		recovered, err := modifier.ModifyInbound(PhaseInitial, padded)
		if err != nil {
			t.Errorf("ModifyInbound() error = %v", err)
		}

		// Should get back original data
		if string(recovered) != string(originalData) {
			t.Errorf("Padding round-trip failed: got %v, want %v", string(recovered), string(originalData))
		}
	})

	t.Run("No padding configuration", func(t *testing.T) {
		modifier, err := NewPaddingModifier("no-padding", 0, 0)
		if err != nil {
			t.Errorf("NewPaddingModifier() error = %v", err)
		}

		testData := []byte("test data")

		result, err := modifier.ModifyOutbound(PhaseExchange, testData)
		if err != nil {
			t.Errorf("ModifyOutbound() error = %v", err)
		}

		// Should be unchanged when no padding
		if string(result) != string(testData) {
			t.Errorf("No padding should leave data unchanged")
		}

		// Also test ModifyInbound returns data unchanged (regression: asymmetry bug)
		inbound, err := modifier.ModifyInbound(PhaseExchange, testData)
		if err != nil {
			t.Errorf("ModifyInbound() error = %v", err)
		}

		if string(inbound) != string(testData) {
			t.Errorf("No padding inbound should leave data unchanged, got %v", string(inbound))
		}
	})

	t.Run("No padding configuration round-trip", func(t *testing.T) {
		modifier, err := NewPaddingModifier("no-padding-roundtrip", 0, 0)
		if err != nil {
			t.Errorf("NewPaddingModifier() error = %v", err)
		}

		testData := []byte("round trip with zero padding")

		outbound, err := modifier.ModifyOutbound(PhaseInitial, testData)
		if err != nil {
			t.Errorf("ModifyOutbound() error = %v", err)
		}

		recovered, err := modifier.ModifyInbound(PhaseInitial, outbound)
		if err != nil {
			t.Errorf("ModifyInbound() error = %v", err)
		}

		if string(recovered) != string(testData) {
			t.Errorf("Zero-padding round-trip failed: got %q, want %q", string(recovered), string(testData))
		}
	})

	t.Run("Random padding size varies within range", func(t *testing.T) {
		modifier, err := NewPaddingModifier("random-range", 5, 20)
		if err != nil {
			t.Fatalf("NewPaddingModifier() error = %v", err)
		}

		testData := []byte("fixed input data")
		sizes := make(map[int]bool)

		// Run multiple times to verify randomness (probabilistic test)
		for i := 0; i < 100; i++ {
			padded, err := modifier.ModifyOutbound(PhaseInitial, testData)
			if err != nil {
				t.Fatalf("ModifyOutbound() error = %v", err)
			}

			paddedLen := len(padded) - 4 - len(testData) // subtract length prefix and data
			sizes[paddedLen] = true

			// Verify padding is within bounds
			if paddedLen < 5 || paddedLen > 20 {
				t.Errorf("Padding size %d outside range [5, 20]", paddedLen)
			}

			// Verify round-trip still works
			recovered, err := modifier.ModifyInbound(PhaseInitial, padded)
			if err != nil {
				t.Fatalf("ModifyInbound() error = %v", err)
			}
			if string(recovered) != string(testData) {
				t.Errorf("Round-trip failed with random padding")
			}
		}

		// With 100 iterations over a range of 16 possible sizes,
		// we should see at least 2 distinct sizes
		if len(sizes) < 2 {
			t.Errorf("Expected multiple distinct padding sizes over 100 iterations, got %d", len(sizes))
		}
	})

	t.Run("Invalid padded data - too short", func(t *testing.T) {
		modifier, err := NewPaddingModifier("short-data", 1, 1)
		if err != nil {
			t.Errorf("NewPaddingModifier() error = %v", err)
		}

		// Data too short for length prefix
		shortData := []byte{0x01, 0x02}

		_, err = modifier.ModifyInbound(PhaseFinal, shortData)
		if err == nil {
			t.Error("ModifyInbound() expected error for short data")
		}

		if !strings.Contains(err.Error(), "padded data too short") {
			t.Errorf("Error message = %v, want short data error", err.Error())
		}
	})

	t.Run("Invalid padded data - bad length", func(t *testing.T) {
		modifier, err := NewPaddingModifier("bad-length", 1, 1)
		if err != nil {
			t.Errorf("NewPaddingModifier() error = %v", err)
		}

		// Create data with invalid length prefix
		badData := []byte{0x00, 0x00, 0x00, 0xFF, 0x01, 0x02} // length = 255, but only 2 data bytes

		_, err = modifier.ModifyInbound(PhaseFinal, badData)
		if err == nil {
			t.Error("ModifyInbound() expected error for invalid length")
		}

		if !strings.Contains(err.Error(), "invalid original length") {
			t.Errorf("Error message = %v, want invalid length error", err.Error())
		}
	})

	t.Run("Empty data padding", func(t *testing.T) {
		modifier, err := NewPaddingModifier("empty", 2, 2)
		if err != nil {
			t.Errorf("NewPaddingModifier() error = %v", err)
		}

		emptyData := []byte{}

		// Pad empty data
		padded, err := modifier.ModifyOutbound(PhaseInitial, emptyData)
		if err != nil {
			t.Errorf("ModifyOutbound() error = %v", err)
		}

		// Should have length prefix and padding
		expectedLen := 4 + 0 + 2 // prefix + empty data + padding
		if len(padded) != expectedLen {
			t.Errorf("Padded empty data length = %v, want %v", len(padded), expectedLen)
		}

		// Recover empty data
		recovered, err := modifier.ModifyInbound(PhaseInitial, padded)
		if err != nil {
			t.Errorf("ModifyInbound() error = %v", err)
		}

		if len(recovered) != 0 {
			t.Errorf("Recovered data should be empty, got %v", recovered)
		}
	})
}
