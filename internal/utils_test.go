package internal

import (
	"testing"
)

// --- SecureZero tests ---

func TestSecureZero_NormalSlice(t *testing.T) {
	b := []byte{0xFF, 0xAB, 0x42, 0x13, 0x99}
	SecureZero(b)
	for i, v := range b {
		if v != 0 {
			t.Errorf("SecureZero: b[%d] = 0x%02X, want 0x00", i, v)
		}
	}
}

func TestSecureZero_EmptySlice(t *testing.T) {
	b := []byte{}
	SecureZero(b) // should not panic
	if len(b) != 0 {
		t.Errorf("SecureZero: expected empty slice, got len %d", len(b))
	}
}

func TestSecureZero_NilSlice(t *testing.T) {
	var b []byte
	SecureZero(b) // should not panic
}

func TestSecureZero_LargeSlice(t *testing.T) {
	b := make([]byte, 4096)
	for i := range b {
		b[i] = 0xFF
	}
	SecureZero(b)
	for i, v := range b {
		if v != 0 {
			t.Errorf("SecureZero: b[%d] = 0x%02X, want 0x00", i, v)
		}
	}
}

// --- RandomBytes tests ---

func TestRandomBytes_Positive(t *testing.T) {
	b, err := RandomBytes(32)
	if err != nil {
		t.Fatalf("RandomBytes(32) error: %v", err)
	}
	if len(b) != 32 {
		t.Errorf("RandomBytes(32) returned %d bytes, want 32", len(b))
	}
	// Verify not all zeros (extremely unlikely for 32 random bytes)
	allZero := true
	for _, v := range b {
		if v != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("RandomBytes(32) returned all zeros — extremely unlikely for random data")
	}
}

func TestRandomBytes_Zero(t *testing.T) {
	b, err := RandomBytes(0)
	if err != nil {
		t.Fatalf("RandomBytes(0) error: %v", err)
	}
	if len(b) != 0 {
		t.Errorf("RandomBytes(0) returned %d bytes, want 0", len(b))
	}
}

func TestRandomBytes_Negative(t *testing.T) {
	b, err := RandomBytes(-1)
	if err == nil {
		t.Fatal("RandomBytes(-1) expected error, got nil")
	}
	if b != nil {
		t.Errorf("RandomBytes(-1) returned non-nil slice: %v", b)
	}
}

func TestRandomBytes_Uniqueness(t *testing.T) {
	// Two calls should produce different outputs (with overwhelming probability)
	b1, err := RandomBytes(32)
	if err != nil {
		t.Fatalf("RandomBytes(32) first call error: %v", err)
	}
	b2, err := RandomBytes(32)
	if err != nil {
		t.Fatalf("RandomBytes(32) second call error: %v", err)
	}
	if string(b1) == string(b2) {
		t.Error("RandomBytes produced identical outputs on two calls — extremely unlikely")
	}
}

// --- ValidateKeySize tests ---

func TestValidateKeySize_Correct(t *testing.T) {
	key := make([]byte, 32)
	if !ValidateKeySize(key, 32) {
		t.Error("ValidateKeySize(32-byte key, 32) = false, want true")
	}
}

func TestValidateKeySize_Wrong(t *testing.T) {
	key := make([]byte, 16)
	if ValidateKeySize(key, 32) {
		t.Error("ValidateKeySize(16-byte key, 32) = true, want false")
	}
}

func TestValidateKeySize_Empty(t *testing.T) {
	if ValidateKeySize([]byte{}, 32) {
		t.Error("ValidateKeySize(empty, 32) = true, want false")
	}
	if !ValidateKeySize([]byte{}, 0) {
		t.Error("ValidateKeySize(empty, 0) = false, want true")
	}
}

func TestValidateKeySize_Nil(t *testing.T) {
	if ValidateKeySize(nil, 32) {
		t.Error("ValidateKeySize(nil, 32) = true, want false")
	}
	if !ValidateKeySize(nil, 0) {
		t.Error("ValidateKeySize(nil, 0) = false, want true")
	}
}
