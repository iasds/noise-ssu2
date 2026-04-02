package internal

import (
	"testing"
	"time"
)

func TestValidatePattern_Empty(t *testing.T) {
	err := ValidatePattern("", "test")
	if err == nil {
		t.Fatal("expected error for empty pattern")
	}
}

func TestValidatePattern_Valid(t *testing.T) {
	for _, p := range []string{"XX", "IK", "XK", "NK"} {
		if err := ValidatePattern(p, "test"); err != nil {
			t.Errorf("ValidatePattern(%q) unexpected error: %v", p, err)
		}
	}
}

func TestValidateHandshakeTimeout_Zero(t *testing.T) {
	if err := ValidateHandshakeTimeout(0, "test"); err == nil {
		t.Fatal("expected error for zero timeout")
	}
}

func TestValidateHandshakeTimeout_Negative(t *testing.T) {
	if err := ValidateHandshakeTimeout(-time.Second, "test"); err == nil {
		t.Fatal("expected error for negative timeout")
	}
}

func TestValidateHandshakeTimeout_Positive(t *testing.T) {
	if err := ValidateHandshakeTimeout(5*time.Second, "test"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateKeyLength_Empty(t *testing.T) {
	if err := ValidateKeyLength(nil, "static", "test"); err != nil {
		t.Fatalf("nil key should be valid: %v", err)
	}
	if err := ValidateKeyLength([]byte{}, "static", "test"); err != nil {
		t.Fatalf("empty key should be valid: %v", err)
	}
}

func TestValidateKeyLength_Valid32(t *testing.T) {
	key := make([]byte, 32)
	if err := ValidateKeyLength(key, "static", "test"); err != nil {
		t.Fatalf("32-byte key should be valid: %v", err)
	}
}

func TestValidateKeyLength_Wrong(t *testing.T) {
	for _, n := range []int{1, 16, 31, 33, 64} {
		key := make([]byte, n)
		if err := ValidateKeyLength(key, "static", "test"); err == nil {
			t.Errorf("expected error for %d-byte key", n)
		}
	}
}

func TestValidateRetryConfig_Valid(t *testing.T) {
	cases := []struct {
		retries int
		backoff time.Duration
	}{
		{-1, 0},                     // infinite retries, no backoff
		{0, 0},                      // no retries
		{3, 100 * time.Millisecond}, // normal case
		{0, time.Second},            // no retries, with backoff
	}
	for _, tc := range cases {
		if err := ValidateRetryConfig(tc.retries, tc.backoff, "test"); err != nil {
			t.Errorf("ValidateRetryConfig(%d, %v) unexpected error: %v", tc.retries, tc.backoff, err)
		}
	}
}

func TestValidateRetryConfig_InvalidRetries(t *testing.T) {
	if err := ValidateRetryConfig(-2, 0, "test"); err == nil {
		t.Fatal("expected error for retries < -1")
	}
	if err := ValidateRetryConfig(-100, time.Second, "test"); err == nil {
		t.Fatal("expected error for retries -100")
	}
}

func TestValidateRetryConfig_NegativeBackoff(t *testing.T) {
	if err := ValidateRetryConfig(3, -time.Second, "test"); err == nil {
		t.Fatal("expected error for negative backoff")
	}
}

func TestRunValidators_Empty(t *testing.T) {
	if err := RunValidators(); err != nil {
		t.Fatalf("no validators should return nil: %v", err)
	}
}

func TestRunValidators_AllPass(t *testing.T) {
	pass := func() error { return nil }
	if err := RunValidators(pass, pass, pass); err != nil {
		t.Fatalf("all-pass should return nil: %v", err)
	}
}

func TestRunValidators_StopsAtFirstError(t *testing.T) {
	calls := 0
	pass := func() error { calls++; return nil }
	fail := func() error { calls++; return ValidatePattern("", "test") }
	after := func() error { calls++; return nil }

	err := RunValidators(pass, fail, after)
	if err == nil {
		t.Fatal("expected error from failing validator")
	}
	if calls != 2 {
		t.Fatalf("expected 2 calls (pass + fail), got %d", calls)
	}
}
