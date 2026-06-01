package securemem

import (
	"testing"
)

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
