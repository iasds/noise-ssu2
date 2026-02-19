package ssu2

import (
	"crypto/rand"
	"sync"
	"time"

	"github.com/samber/oops"
)

// Key rotation timing constants per SSU2 specification.
// Keys must persist across restarts with minimum downtime before rotation.
const (
	// PublishedKeyMinAge is the minimum age before rotating keys that are published
	// in router addresses. Per SSU2.md: "With published addresses: ~1 month minimum"
	PublishedKeyMinAge = 30 * 24 * time.Hour // ~1 month

	// UnpublishedKeyMinAge is the minimum age before rotating keys that are not published.
	// Per SSU2.md: "Without published addresses: ~2 hours minimum"
	UnpublishedKeyMinAge = 2 * time.Hour

	// KeyRotationCheckInterval is how often to check if rotation is needed.
	KeyRotationCheckInterval = 15 * time.Minute

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
type KeyRotationCallback func(keyType string, oldKey, newKey *ManagedKey)

// KeyRotationManager manages SSU2 key lifecycle and rotation.
// It tracks static keys and introduction keys, ensuring they meet
// the minimum age requirements before rotation per the SSU2 specification.
type KeyRotationManager struct {
	mu sync.RWMutex

	// staticKey is the current static key for Noise XK handshakes.
	staticKey *ManagedKey

	// introKey is the current introduction key for header encryption.
	introKey *ManagedKey

	// onRotation is called when a key rotation occurs.
	onRotation KeyRotationCallback

	// stopCh signals the background checker to stop.
	stopCh chan struct{}

	// running indicates if the background checker is active.
	running bool

	// clock allows time mocking for testing.
	clock func() time.Time
}

// NewKeyRotationManager creates a new key rotation manager.
// staticKey and introKey are the initial keys (32 bytes each).
// isPublished indicates if these keys are published in router addresses.
func NewKeyRotationManager(staticKey, introKey []byte, isPublished bool) (*KeyRotationManager, error) {
	if len(staticKey) != StaticKeySize {
		return nil, oops.
			In("ssu2").
			With("expected", StaticKeySize).
			With("actual", len(staticKey)).
			Errorf("static key must be exactly %d bytes", StaticKeySize)
	}

	if len(introKey) != IntroKeySize {
		return nil, oops.
			In("ssu2").
			With("expected", IntroKeySize).
			With("actual", len(introKey)).
			Errorf("intro key must be exactly %d bytes", IntroKeySize)
	}

	now := time.Now()

	// Create managed keys with defensive copies
	sk := make([]byte, StaticKeySize)
	copy(sk, staticKey)
	ik := make([]byte, IntroKeySize)
	copy(ik, introKey)

	return &KeyRotationManager{
		staticKey: &ManagedKey{
			Key:         sk,
			CreatedAt:   now,
			State:       KeyStateActive,
			IsPublished: isPublished,
		},
		introKey: &ManagedKey{
			Key:         ik,
			CreatedAt:   now,
			State:       KeyStateActive,
			IsPublished: isPublished,
		},
		stopCh: make(chan struct{}),
		clock:  time.Now,
	}, nil
}

// NewKeyRotationManagerWithAge creates a manager with keys that have a specified age.
// This is useful for restoring keys from persistent storage.
func NewKeyRotationManagerWithAge(
	staticKey, introKey []byte,
	keyAge time.Duration,
	isPublished bool,
) (*KeyRotationManager, error) {
	mgr, err := NewKeyRotationManager(staticKey, introKey, isPublished)
	if err != nil {
		return nil, err
	}

	// Backdate the creation time
	createdAt := time.Now().Add(-keyAge)
	mgr.staticKey.CreatedAt = createdAt
	mgr.introKey.CreatedAt = createdAt

	return mgr, nil
}

// SetRotationCallback sets the callback to be invoked on key rotations.
func (krm *KeyRotationManager) SetRotationCallback(cb KeyRotationCallback) {
	krm.mu.Lock()
	defer krm.mu.Unlock()
	krm.onRotation = cb
}

// GetStaticKey returns a copy of the current static key.
func (krm *KeyRotationManager) GetStaticKey() []byte {
	krm.mu.RLock()
	defer krm.mu.RUnlock()

	key := make([]byte, len(krm.staticKey.Key))
	copy(key, krm.staticKey.Key)
	return key
}

// GetIntroKey returns a copy of the current introduction key.
func (krm *KeyRotationManager) GetIntroKey() []byte {
	krm.mu.RLock()
	defer krm.mu.RUnlock()

	key := make([]byte, len(krm.introKey.Key))
	copy(key, krm.introKey.Key)
	return key
}

// GetStaticKeyInfo returns rotation metadata for the static key.
func (krm *KeyRotationManager) GetStaticKeyInfo() ManagedKey {
	krm.mu.RLock()
	defer krm.mu.RUnlock()

	// Return a copy without the actual key bytes for safety
	return ManagedKey{
		CreatedAt:   krm.staticKey.CreatedAt,
		State:       krm.staticKey.State,
		IsPublished: krm.staticKey.IsPublished,
		RotatedAt:   krm.staticKey.RotatedAt,
	}
}

// GetIntroKeyInfo returns rotation metadata for the introduction key.
func (krm *KeyRotationManager) GetIntroKeyInfo() ManagedKey {
	krm.mu.RLock()
	defer krm.mu.RUnlock()

	return ManagedKey{
		CreatedAt:   krm.introKey.CreatedAt,
		State:       krm.introKey.State,
		IsPublished: krm.introKey.IsPublished,
		RotatedAt:   krm.introKey.RotatedAt,
	}
}

// CanRotateStaticKey returns true if the static key can be rotated.
func (krm *KeyRotationManager) CanRotateStaticKey() bool {
	krm.mu.RLock()
	defer krm.mu.RUnlock()
	return krm.staticKey.CanRotate()
}

// CanRotateIntroKey returns true if the introduction key can be rotated.
func (krm *KeyRotationManager) CanRotateIntroKey() bool {
	krm.mu.RLock()
	defer krm.mu.RUnlock()
	return krm.introKey.CanRotate()
}

// StaticKeyAge returns the age of the current static key.
func (krm *KeyRotationManager) StaticKeyAge() time.Duration {
	krm.mu.RLock()
	defer krm.mu.RUnlock()
	return time.Since(krm.staticKey.CreatedAt)
}

// IntroKeyAge returns the age of the current introduction key.
func (krm *KeyRotationManager) IntroKeyAge() time.Duration {
	krm.mu.RLock()
	defer krm.mu.RUnlock()
	return time.Since(krm.introKey.CreatedAt)
}

// SetPublished updates the published status of both keys.
// This affects the minimum age before rotation.
func (krm *KeyRotationManager) SetPublished(isPublished bool) {
	krm.mu.Lock()
	defer krm.mu.Unlock()

	krm.staticKey.IsPublished = isPublished
	krm.introKey.IsPublished = isPublished
}

// RotateStaticKey generates a new static key if rotation is allowed.
// Returns the new key bytes or an error if rotation is not permitted.
func (krm *KeyRotationManager) RotateStaticKey() ([]byte, error) {
	krm.mu.Lock()
	defer krm.mu.Unlock()

	if !krm.staticKey.CanRotate() {
		remaining := krm.staticKey.TimeUntilRotation()
		return nil, oops.
			In("ssu2").
			With("key_age", krm.staticKey.Age()).
			With("min_age", krm.staticKey.MinAge()).
			With("remaining", remaining).
			Errorf("static key cannot be rotated yet, %v remaining", remaining)
	}

	return krm.rotateStaticKeyLocked()
}

// ForceRotateStaticKey rotates the static key regardless of age.
// Use with caution - this bypasses security requirements.
func (krm *KeyRotationManager) ForceRotateStaticKey() ([]byte, error) {
	krm.mu.Lock()
	defer krm.mu.Unlock()

	return krm.rotateStaticKeyLocked()
}

// rotateStaticKeyLocked performs the actual key rotation.
// Caller must hold the write lock.
func (krm *KeyRotationManager) rotateStaticKeyLocked() ([]byte, error) {
	// Generate new key
	newKey := make([]byte, StaticKeySize)
	if _, err := rand.Read(newKey); err != nil {
		return nil, oops.Wrapf(err, "failed to generate new static key")
	}

	now := krm.clock()

	// Retire old key
	oldKey := krm.staticKey
	oldKey.State = KeyStateRetired
	oldKey.RotatedAt = now

	// Create new managed key
	krm.staticKey = &ManagedKey{
		Key:         newKey,
		CreatedAt:   now,
		State:       KeyStateActive,
		IsPublished: oldKey.IsPublished,
	}
	oldKey.Successor = krm.staticKey

	// Notify callback
	if krm.onRotation != nil {
		go krm.onRotation("static", oldKey, krm.staticKey)
	}

	// Return copy
	result := make([]byte, StaticKeySize)
	copy(result, newKey)
	return result, nil
}

// RotateIntroKey generates a new introduction key if rotation is allowed.
// Returns the new key bytes or an error if rotation is not permitted.
func (krm *KeyRotationManager) RotateIntroKey() ([]byte, error) {
	krm.mu.Lock()
	defer krm.mu.Unlock()

	if !krm.introKey.CanRotate() {
		remaining := krm.introKey.TimeUntilRotation()
		return nil, oops.
			In("ssu2").
			With("key_age", krm.introKey.Age()).
			With("min_age", krm.introKey.MinAge()).
			With("remaining", remaining).
			Errorf("intro key cannot be rotated yet, %v remaining", remaining)
	}

	return krm.rotateIntroKeyLocked()
}

// ForceRotateIntroKey rotates the introduction key regardless of age.
// Use with caution - this bypasses security requirements.
func (krm *KeyRotationManager) ForceRotateIntroKey() ([]byte, error) {
	krm.mu.Lock()
	defer krm.mu.Unlock()

	return krm.rotateIntroKeyLocked()
}

// rotateIntroKeyLocked performs the actual key rotation.
// Caller must hold the write lock.
func (krm *KeyRotationManager) rotateIntroKeyLocked() ([]byte, error) {
	// Generate new key
	newKey := make([]byte, IntroKeySize)
	if _, err := rand.Read(newKey); err != nil {
		return nil, oops.Wrapf(err, "failed to generate new intro key")
	}

	now := krm.clock()

	// Retire old key
	oldKey := krm.introKey
	oldKey.State = KeyStateRetired
	oldKey.RotatedAt = now

	// Create new managed key
	krm.introKey = &ManagedKey{
		Key:         newKey,
		CreatedAt:   now,
		State:       KeyStateActive,
		IsPublished: oldKey.IsPublished,
	}
	oldKey.Successor = krm.introKey

	// Notify callback
	if krm.onRotation != nil {
		go krm.onRotation("intro", oldKey, krm.introKey)
	}

	// Return copy
	result := make([]byte, IntroKeySize)
	copy(result, newKey)
	return result, nil
}

// RotateAllKeys rotates both static and introduction keys if allowed.
// Returns the new keys or an error. Partial rotation is not performed -
// if either key cannot be rotated, neither is rotated.
func (krm *KeyRotationManager) RotateAllKeys() (staticKey, introKey []byte, err error) {
	krm.mu.Lock()
	defer krm.mu.Unlock()

	if !krm.staticKey.CanRotate() {
		return nil, nil, oops.
			In("ssu2").
			Errorf("static key cannot be rotated yet")
	}
	if !krm.introKey.CanRotate() {
		return nil, nil, oops.
			In("ssu2").
			Errorf("intro key cannot be rotated yet")
	}

	staticKey, err = krm.rotateStaticKeyLocked()
	if err != nil {
		return nil, nil, err
	}

	introKey, err = krm.rotateIntroKeyLocked()
	if err != nil {
		return nil, nil, err
	}

	return staticKey, introKey, nil
}

// Start begins background key rotation checking.
// Keys that meet rotation requirements will trigger the rotation callback
// but will NOT be automatically rotated - the callback should handle rotation.
func (krm *KeyRotationManager) Start() {
	krm.mu.Lock()
	if krm.running {
		krm.mu.Unlock()
		return
	}
	krm.running = true
	krm.stopCh = make(chan struct{})
	krm.mu.Unlock()

	go krm.runRotationChecker()
}

// Stop halts the background key rotation checker.
func (krm *KeyRotationManager) Stop() {
	krm.mu.Lock()
	defer krm.mu.Unlock()

	if !krm.running {
		return
	}
	krm.running = false
	close(krm.stopCh)
}

// IsRunning returns true if the background checker is active.
func (krm *KeyRotationManager) IsRunning() bool {
	krm.mu.RLock()
	defer krm.mu.RUnlock()
	return krm.running
}

// runRotationChecker periodically checks if keys can be rotated.
func (krm *KeyRotationManager) runRotationChecker() {
	ticker := time.NewTicker(KeyRotationCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-krm.stopCh:
			return
		case <-ticker.C:
			krm.checkRotation()
		}
	}
}

// checkRotation checks if any keys can be rotated and updates their state.
func (krm *KeyRotationManager) checkRotation() {
	krm.mu.Lock()
	defer krm.mu.Unlock()

	// Check static key
	if krm.staticKey.State == KeyStateActive && krm.staticKey.CanRotate() {
		krm.staticKey.State = KeyStatePendingRotation
	}

	// Check intro key
	if krm.introKey.State == KeyStateActive && krm.introKey.CanRotate() {
		krm.introKey.State = KeyStatePendingRotation
	}
}

// GetStatus returns a summary of the key rotation state.
func (krm *KeyRotationManager) GetStatus() KeyRotationStatus {
	krm.mu.RLock()
	defer krm.mu.RUnlock()

	return KeyRotationStatus{
		StaticKeyAge:          time.Since(krm.staticKey.CreatedAt),
		StaticKeyState:        krm.staticKey.State,
		StaticKeyCanRotate:    krm.staticKey.CanRotate(),
		StaticKeyTimeToRotate: krm.staticKey.TimeUntilRotation(),
		IntroKeyAge:           time.Since(krm.introKey.CreatedAt),
		IntroKeyState:         krm.introKey.State,
		IntroKeyCanRotate:     krm.introKey.CanRotate(),
		IntroKeyTimeToRotate:  krm.introKey.TimeUntilRotation(),
		IsPublished:           krm.staticKey.IsPublished,
		IsRunning:             krm.running,
	}
}

// KeyRotationStatus contains a snapshot of the rotation manager state.
type KeyRotationStatus struct {
	StaticKeyAge          time.Duration
	StaticKeyState        KeyState
	StaticKeyCanRotate    bool
	StaticKeyTimeToRotate time.Duration
	IntroKeyAge           time.Duration
	IntroKeyState         KeyState
	IntroKeyCanRotate     bool
	IntroKeyTimeToRotate  time.Duration
	IsPublished           bool
	IsRunning             bool
}

// GenerateNewStaticKey generates a new random 32-byte static key.
// This is a helper for creating keys outside the manager.
func GenerateNewStaticKey() ([]byte, error) {
	key := make([]byte, StaticKeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, oops.Wrapf(err, "failed to generate static key")
	}
	return key, nil
}

// GenerateNewIntroKey generates a new random 32-byte introduction key.
// This is a helper for creating keys outside the manager.
func GenerateNewIntroKey() ([]byte, error) {
	key := make([]byte, IntroKeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, oops.Wrapf(err, "failed to generate intro key")
	}
	return key, nil
}
