package handshake

import (
	"time"
)

const (
	// PublishedKeyMinAge is the minimum age before rotating keys that are published
	// in router addresses. Per ssu2.rst: "With published addresses: ~1 month minimum"
	PublishedKeyMinAge = 30 * 24 * time.Hour // ~1 month

	// UnpublishedKeyMinAge is the minimum age before rotating keys that are not published.
	// Per ssu2.rst: "Without published addresses: ~2 hours minimum"
	UnpublishedKeyMinAge = 2 * time.Hour

	// KeyRotationCheckInterval is how often to check if rotation is needed.
	KeyRotationCheckInterval = 15 * time.Minute

	// KeyGracePeriod is the duration after key rotation during which the old
	// key is still accepted for decrypting in-flight packets. This prevents
	// connection disruption during key transitions.
	KeyGracePeriod = 30 * time.Second

	// StaticKeySize is the size of X25519 static keys.
	StaticKeySize = 32

	// IntroKeySize is the size of introduction keys.
	IntroKeySize = 32
)

// KeyState represents the state of a key in the rotation lifecycle.
type KeyState int

const (
	// KeyStateActive means the key is currently in use.
	KeyStateActive KeyState = iota

	// KeyStatePendingRotation means the key has met age requirements and can be rotated.
	KeyStatePendingRotation

	// KeyStateRotating means rotation is in progress.
	KeyStateRotating

	// KeyStateRetired means the key has been replaced and is no longer valid.
	KeyStateRetired
)

// String returns a human-readable representation of the key state.
func (ks KeyState) String() string {
	switch ks {
	case KeyStateActive:
		return "active"
	case KeyStatePendingRotation:
		return "pending_rotation"
	case KeyStateRotating:
		return "rotating"
	case KeyStateRetired:
		return "retired"
	default:
		return "unknown"
	}
}

// ManagedKey represents a key with rotation metadata.
type ManagedKey struct {
	// Key is the raw key bytes (32 bytes for X25519/intro keys).
	Key []byte

	// CreatedAt is when this key was generated.
	CreatedAt time.Time

	// State is the current lifecycle state of this key.
	State KeyState

	// IsPublished indicates if this key is published in router addresses.
	// Published keys have longer minimum age before rotation.
	IsPublished bool

	// RotatedAt is when this key was retired (zero if still active).
	RotatedAt time.Time

	// Successor is the key that replaced this one (nil if still active).
	Successor *ManagedKey
}

// Age returns how long this key has existed.
func (mk *ManagedKey) Age() time.Duration {
	return time.Since(mk.CreatedAt)
}

// MinAge returns the minimum age required before this key can be rotated.
func (mk *ManagedKey) MinAge() time.Duration {
	if mk.IsPublished {
		return PublishedKeyMinAge
	}
	return UnpublishedKeyMinAge
}

// CanRotate returns true if this key has met the minimum age requirements.
func (mk *ManagedKey) CanRotate() bool {
	return mk.State == KeyStateActive && mk.Age() >= mk.MinAge()
}

// TimeUntilRotation returns the time remaining until this key can be rotated.
// Returns 0 if the key can already be rotated.
func (mk *ManagedKey) TimeUntilRotation() time.Duration {
	remaining := mk.MinAge() - mk.Age()
	if remaining < 0 {
		return 0
	}
	return remaining
}

// KeyRotationCallback is called when a key rotation occurs.
// oldKey is the key being retired, newKey is the replacement.
