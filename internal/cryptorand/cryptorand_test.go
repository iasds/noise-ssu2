package cryptorand

import (
	"testing"
)

func TestRandomBytes_Positive(t *testing.T) {
	b, err := RandomBytes(32)
	if err != nil {
		t.Fatalf("RandomBytes(32) error: %v", err)
	}
	if len(b) != 32 {
		t.Errorf("RandomBytes(32) returned %d bytes, want 32", len(b))
	}
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
