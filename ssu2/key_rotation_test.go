package ssu2

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createTestKeys() (staticKey, introKey []byte) {
	staticKey = make([]byte, StaticKeySize)
	introKey = make([]byte, IntroKeySize)
	for i := 0; i < 32; i++ {
		staticKey[i] = byte(i)
		introKey[i] = byte(255 - i)
	}
	return
}

func TestNewKeyRotationManager_ValidKeys(t *testing.T) {
	staticKey, introKey := createTestKeys()

	mgr, err := NewKeyRotationManager(staticKey, introKey, false)
	require.NoError(t, err)
	require.NotNil(t, mgr)

	// Verify keys are stored correctly
	assert.Equal(t, staticKey, mgr.GetStaticKey())
	assert.Equal(t, introKey, mgr.GetIntroKey())
}

func TestNewKeyRotationManager_InvalidStaticKeySize(t *testing.T) {
	_, introKey := createTestKeys()
	shortKey := make([]byte, 16)

	mgr, err := NewKeyRotationManager(shortKey, introKey, false)
	assert.Error(t, err)
	assert.Nil(t, mgr)
	assert.Contains(t, err.Error(), "static key must be exactly 32 bytes")
}

func TestNewKeyRotationManager_InvalidIntroKeySize(t *testing.T) {
	staticKey, _ := createTestKeys()
	shortKey := make([]byte, 16)

	mgr, err := NewKeyRotationManager(staticKey, shortKey, false)
	assert.Error(t, err)
	assert.Nil(t, mgr)
	assert.Contains(t, err.Error(), "intro key must be exactly 32 bytes")
}

func TestNewKeyRotationManagerWithAge(t *testing.T) {
	staticKey, introKey := createTestKeys()
	age := 3 * time.Hour

	mgr, err := NewKeyRotationManagerWithAge(staticKey, introKey, age, false)
	require.NoError(t, err)
	require.NotNil(t, mgr)

	// Key age should be approximately the specified age
	assert.InDelta(t, age.Seconds(), mgr.StaticKeyAge().Seconds(), 1.0)
	assert.InDelta(t, age.Seconds(), mgr.IntroKeyAge().Seconds(), 1.0)
}

func TestKeyRotationManager_DefensiveCopy(t *testing.T) {
	staticKey, introKey := createTestKeys()
	mgr, _ := NewKeyRotationManager(staticKey, introKey, false)

	// Modify original keys to a different value
	originalStatic0 := staticKey[0]
	originalIntro0 := introKey[0]
	staticKey[0] = originalStatic0 ^ 0xFF // Flip all bits
	introKey[0] = originalIntro0 ^ 0xFF

	// Manager should have copies with original values
	gotStatic := mgr.GetStaticKey()
	gotIntro := mgr.GetIntroKey()

	assert.Equal(t, originalStatic0, gotStatic[0])
	assert.Equal(t, originalIntro0, gotIntro[0])
}

func TestKeyRotationManager_PublishedVsUnpublished(t *testing.T) {
	staticKey, introKey := createTestKeys()

	// Published keys have 1 month min age
	publishedMgr, _ := NewKeyRotationManager(staticKey, introKey, true)
	publishedInfo := publishedMgr.GetStaticKeyInfo()
	assert.True(t, publishedInfo.IsPublished)
	assert.Equal(t, PublishedKeyMinAge, publishedInfo.MinAge())

	// Unpublished keys have 2 hour min age
	unpublishedMgr, _ := NewKeyRotationManager(staticKey, introKey, false)
	unpublishedInfo := unpublishedMgr.GetStaticKeyInfo()
	assert.False(t, unpublishedInfo.IsPublished)
	assert.Equal(t, UnpublishedKeyMinAge, unpublishedInfo.MinAge())
}

func TestKeyRotationManager_CanRotate_NewKey(t *testing.T) {
	staticKey, introKey := createTestKeys()
	mgr, _ := NewKeyRotationManager(staticKey, introKey, false)

	// New keys cannot be rotated
	assert.False(t, mgr.CanRotateStaticKey())
	assert.False(t, mgr.CanRotateIntroKey())
}

func TestKeyRotationManager_CanRotate_OldUnpublishedKey(t *testing.T) {
	staticKey, introKey := createTestKeys()

	// Create manager with keys older than 2 hours
	mgr, _ := NewKeyRotationManagerWithAge(staticKey, introKey, 3*time.Hour, false)

	// Old unpublished keys can be rotated
	assert.True(t, mgr.CanRotateStaticKey())
	assert.True(t, mgr.CanRotateIntroKey())
}

func TestKeyRotationManager_CanRotate_OldPublishedKey_TooYoung(t *testing.T) {
	staticKey, introKey := createTestKeys()

	// Create manager with keys older than 2 hours but younger than 1 month
	mgr, _ := NewKeyRotationManagerWithAge(staticKey, introKey, 3*time.Hour, true)

	// Published keys need 1 month, so these cannot be rotated
	assert.False(t, mgr.CanRotateStaticKey())
	assert.False(t, mgr.CanRotateIntroKey())
}

func TestKeyRotationManager_CanRotate_OldPublishedKey(t *testing.T) {
	staticKey, introKey := createTestKeys()

	// Create manager with keys older than 1 month
	mgr, _ := NewKeyRotationManagerWithAge(staticKey, introKey, 32*24*time.Hour, true)

	// Old published keys can be rotated
	assert.True(t, mgr.CanRotateStaticKey())
	assert.True(t, mgr.CanRotateIntroKey())
}

func TestKeyRotationManager_RotateStaticKey_NotAllowed(t *testing.T) {
	staticKey, introKey := createTestKeys()
	mgr, _ := NewKeyRotationManager(staticKey, introKey, false)

	// New keys cannot be rotated
	newKey, err := mgr.RotateStaticKey()
	assert.Error(t, err)
	assert.Nil(t, newKey)
	assert.Contains(t, err.Error(), "cannot be rotated yet")
}

func TestKeyRotationManager_RotateStaticKey_Allowed(t *testing.T) {
	staticKey, introKey := createTestKeys()
	mgr, _ := NewKeyRotationManagerWithAge(staticKey, introKey, 3*time.Hour, false)

	originalKey := mgr.GetStaticKey()

	newKey, err := mgr.RotateStaticKey()
	require.NoError(t, err)
	require.NotNil(t, newKey)

	// New key should be different
	assert.NotEqual(t, originalKey, newKey)
	assert.Equal(t, newKey, mgr.GetStaticKey())
}

func TestKeyRotationManager_RotateIntroKey_Allowed(t *testing.T) {
	staticKey, introKey := createTestKeys()
	mgr, _ := NewKeyRotationManagerWithAge(staticKey, introKey, 3*time.Hour, false)

	originalKey := mgr.GetIntroKey()

	newKey, err := mgr.RotateIntroKey()
	require.NoError(t, err)
	require.NotNil(t, newKey)

	// New key should be different
	assert.NotEqual(t, originalKey, newKey)
	assert.Equal(t, newKey, mgr.GetIntroKey())
}

func TestKeyRotationManager_ForceRotateStaticKey(t *testing.T) {
	staticKey, introKey := createTestKeys()
	mgr, _ := NewKeyRotationManager(staticKey, introKey, false)

	originalKey := mgr.GetStaticKey()

	// Force rotation should work even for new keys
	newKey, err := mgr.ForceRotateStaticKey()
	require.NoError(t, err)
	require.NotNil(t, newKey)

	assert.NotEqual(t, originalKey, newKey)
	assert.Equal(t, newKey, mgr.GetStaticKey())
}

func TestKeyRotationManager_ForceRotateIntroKey(t *testing.T) {
	staticKey, introKey := createTestKeys()
	mgr, _ := NewKeyRotationManager(staticKey, introKey, false)

	originalKey := mgr.GetIntroKey()

	// Force rotation should work even for new keys
	newKey, err := mgr.ForceRotateIntroKey()
	require.NoError(t, err)
	require.NotNil(t, newKey)

	assert.NotEqual(t, originalKey, newKey)
	assert.Equal(t, newKey, mgr.GetIntroKey())
}

func TestKeyRotationManager_RotateAllKeys(t *testing.T) {
	staticKey, introKey := createTestKeys()
	mgr, _ := NewKeyRotationManagerWithAge(staticKey, introKey, 3*time.Hour, false)

	origStatic := mgr.GetStaticKey()
	origIntro := mgr.GetIntroKey()

	newStatic, newIntro, err := mgr.RotateAllKeys()
	require.NoError(t, err)

	assert.NotEqual(t, origStatic, newStatic)
	assert.NotEqual(t, origIntro, newIntro)
	assert.Equal(t, newStatic, mgr.GetStaticKey())
	assert.Equal(t, newIntro, mgr.GetIntroKey())
}

func TestKeyRotationManager_RotateAllKeys_PartialNotAllowed(t *testing.T) {
	staticKey, introKey := createTestKeys()
	mgr, _ := NewKeyRotationManager(staticKey, introKey, false)

	// Neither key can be rotated, so RotateAllKeys should fail
	newStatic, newIntro, err := mgr.RotateAllKeys()
	assert.Error(t, err)
	assert.Nil(t, newStatic)
	assert.Nil(t, newIntro)
}

func TestKeyRotationManager_RotationCallback(t *testing.T) {
	staticKey, introKey := createTestKeys()
	mgr, _ := NewKeyRotationManagerWithAge(staticKey, introKey, 3*time.Hour, false)

	var callbackInvoked atomic.Bool
	var callbackKeyType string
	var wg sync.WaitGroup
	wg.Add(1)

	mgr.SetRotationCallback(func(keyType string, oldKey, newKey *ManagedKey) {
		callbackKeyType = keyType
		callbackInvoked.Store(true)
		wg.Done()
	})

	_, err := mgr.RotateStaticKey()
	require.NoError(t, err)

	// Wait for async callback
	wg.Wait()

	assert.True(t, callbackInvoked.Load())
	assert.Equal(t, "static", callbackKeyType)
}

func TestKeyRotationManager_SetPublished(t *testing.T) {
	staticKey, introKey := createTestKeys()
	mgr, _ := NewKeyRotationManager(staticKey, introKey, false)

	// Initially unpublished
	info := mgr.GetStaticKeyInfo()
	assert.False(t, info.IsPublished)
	assert.Equal(t, UnpublishedKeyMinAge, info.MinAge())

	// Change to published
	mgr.SetPublished(true)

	info = mgr.GetStaticKeyInfo()
	assert.True(t, info.IsPublished)
	assert.Equal(t, PublishedKeyMinAge, info.MinAge())
}

func TestKeyRotationManager_GetStatus(t *testing.T) {
	staticKey, introKey := createTestKeys()
	mgr, _ := NewKeyRotationManagerWithAge(staticKey, introKey, 1*time.Hour, false)

	status := mgr.GetStatus()

	assert.InDelta(t, 1*time.Hour.Seconds(), status.StaticKeyAge.Seconds(), 1.0)
	assert.Equal(t, KeyStateActive, status.StaticKeyState)
	assert.False(t, status.StaticKeyCanRotate) // Need 2 hours for unpublished
	assert.False(t, status.IsPublished)
	assert.False(t, status.IsRunning)
}

func TestKeyRotationManager_StartStop(t *testing.T) {
	staticKey, introKey := createTestKeys()
	mgr, _ := NewKeyRotationManager(staticKey, introKey, false)

	assert.False(t, mgr.IsRunning())

	mgr.Start()
	assert.True(t, mgr.IsRunning())

	// Double start should be safe
	mgr.Start()
	assert.True(t, mgr.IsRunning())

	mgr.Stop()
	assert.False(t, mgr.IsRunning())

	// Double stop should be safe
	mgr.Stop()
	assert.False(t, mgr.IsRunning())
}

func TestKeyRotationManager_ConcurrentAccess(t *testing.T) {
	staticKey, introKey := createTestKeys()
	mgr, _ := NewKeyRotationManagerWithAge(staticKey, introKey, 3*time.Hour, false)

	var wg sync.WaitGroup
	iterations := 100

	// Concurrent reads
	for i := 0; i < iterations; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = mgr.GetStaticKey()
			_ = mgr.GetIntroKey()
			_ = mgr.CanRotateStaticKey()
			_ = mgr.GetStatus()
		}()
	}

	wg.Wait()
}

func TestManagedKey_Age(t *testing.T) {
	mk := &ManagedKey{
		CreatedAt:   time.Now().Add(-2 * time.Hour),
		State:       KeyStateActive,
		IsPublished: false,
	}

	age := mk.Age()
	assert.InDelta(t, 2*time.Hour.Seconds(), age.Seconds(), 1.0)
}

func TestManagedKey_TimeUntilRotation(t *testing.T) {
	// Key that's 1 hour old, unpublished (needs 2 hours)
	mk := &ManagedKey{
		CreatedAt:   time.Now().Add(-1 * time.Hour),
		State:       KeyStateActive,
		IsPublished: false,
	}

	remaining := mk.TimeUntilRotation()
	assert.InDelta(t, 1*time.Hour.Seconds(), remaining.Seconds(), 1.0)

	// Key that's 3 hours old (already can rotate)
	mk2 := &ManagedKey{
		CreatedAt:   time.Now().Add(-3 * time.Hour),
		State:       KeyStateActive,
		IsPublished: false,
	}

	remaining2 := mk2.TimeUntilRotation()
	assert.Equal(t, time.Duration(0), remaining2)
}

func TestKeyState_String(t *testing.T) {
	tests := []struct {
		state    KeyState
		expected string
	}{
		{KeyStateActive, "active"},
		{KeyStatePendingRotation, "pending_rotation"},
		{KeyStateRotating, "rotating"},
		{KeyStateRetired, "retired"},
		{KeyState(99), "unknown"},
	}

	for _, tt := range tests {
		assert.Equal(t, tt.expected, tt.state.String())
	}
}

func TestGenerateNewStaticKey(t *testing.T) {
	key1, err := GenerateNewStaticKey()
	require.NoError(t, err)
	assert.Len(t, key1, StaticKeySize)

	key2, err := GenerateNewStaticKey()
	require.NoError(t, err)
	assert.Len(t, key2, StaticKeySize)

	// Keys should be different (random)
	assert.NotEqual(t, key1, key2)
}

func TestGenerateNewIntroKey(t *testing.T) {
	key1, err := GenerateNewIntroKey()
	require.NoError(t, err)
	assert.Len(t, key1, IntroKeySize)

	key2, err := GenerateNewIntroKey()
	require.NoError(t, err)
	assert.Len(t, key2, IntroKeySize)

	// Keys should be different (random)
	assert.NotEqual(t, key1, key2)
}

func TestKeyRotationManager_KeyInfoDoesNotExposeKey(t *testing.T) {
	staticKey, introKey := createTestKeys()
	mgr, _ := NewKeyRotationManager(staticKey, introKey, false)

	info := mgr.GetStaticKeyInfo()

	// Key field should be nil/empty in the info struct
	assert.Nil(t, info.Key)
}

func TestKeyRotationManager_RotationUpdatesState(t *testing.T) {
	staticKey, introKey := createTestKeys()
	mgr, _ := NewKeyRotationManagerWithAge(staticKey, introKey, 3*time.Hour, false)

	// Before rotation
	info := mgr.GetStaticKeyInfo()
	assert.Equal(t, KeyStateActive, info.State)

	// Rotate
	_, err := mgr.RotateStaticKey()
	require.NoError(t, err)

	// After rotation - new key should be active
	info = mgr.GetStaticKeyInfo()
	assert.Equal(t, KeyStateActive, info.State)

	// New key should be young
	assert.Less(t, info.CreatedAt.Add(-1*time.Second), time.Now())
}

func TestKeyRotationManager_GetKeyInfo_Independence(t *testing.T) {
	staticKey, introKey := createTestKeys()
	mgr, _ := NewKeyRotationManager(staticKey, introKey, true)

	staticInfo := mgr.GetStaticKeyInfo()
	introInfo := mgr.GetIntroKeyInfo()

	// Both should reflect the same published status
	assert.True(t, staticInfo.IsPublished)
	assert.True(t, introInfo.IsPublished)

	// But should be independent copies
	assert.Equal(t, staticInfo.State, introInfo.State)
}

func TestConstants(t *testing.T) {
	// Verify constants match spec
	assert.Equal(t, 30*24*time.Hour, PublishedKeyMinAge)
	assert.Equal(t, 2*time.Hour, UnpublishedKeyMinAge)
	assert.Equal(t, 32, StaticKeySize)
	assert.Equal(t, 32, IntroKeySize)
}

func TestManagedKey_CanRotate_WrongState(t *testing.T) {
	mk := &ManagedKey{
		CreatedAt:   time.Now().Add(-3 * time.Hour),
		State:       KeyStateRetired, // Wrong state
		IsPublished: false,
	}

	// Can't rotate retired key even if old enough
	assert.False(t, mk.CanRotate())
}

func TestKeyRotationManager_MultipleRotations(t *testing.T) {
	staticKey, introKey := createTestKeys()
	mgr, _ := NewKeyRotationManagerWithAge(staticKey, introKey, 3*time.Hour, false)

	// First rotation
	key1, err := mgr.RotateStaticKey()
	require.NoError(t, err)

	// Second rotation should fail (new key is too young)
	key2, err := mgr.RotateStaticKey()
	assert.Error(t, err)
	assert.Nil(t, key2)

	// Key should still be the one from first rotation
	assert.Equal(t, key1, mgr.GetStaticKey())
}
