package ssu2

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewRelayManager tests relay manager creation.
func TestNewRelayManager(t *testing.T) {
	listener := createMockListener(t)
	defer listener.Close()

	rm := NewRelayManager(listener)
	require.NotNil(t, rm)
	defer rm.Stop()

	assert.NotNil(t, rm.listener)
	assert.Empty(t, rm.introducers)
	assert.Empty(t, rm.relayTags)
	assert.Empty(t, rm.pendingSessions)
}

// TestRelayManager_Stop tests cleanup on stop.
func TestRelayManager_Stop(t *testing.T) {
	listener := createMockListener(t)
	defer listener.Close()

	rm := NewRelayManager(listener)
	require.NotNil(t, rm)

	// Add some state
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
	routerHash := make([]byte, 32)
	err := rm.RegisterIntroducer(addr, routerHash, 123)
	require.NoError(t, err)

	// Stop should clean up
	rm.Stop()

	// State should be nil after stop
	assert.Nil(t, rm.introducers)
	assert.Nil(t, rm.relayTags)
	assert.Nil(t, rm.pendingSessions)
}

// TestRelayManager_RegisterIntroducer tests introducer registration.
func TestRelayManager_RegisterIntroducer(t *testing.T) {
	listener := createMockListener(t)
	defer listener.Close()

	rm := NewRelayManager(listener)
	defer rm.Stop()

	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
	routerHash := make([]byte, 32)
	for i := range routerHash {
		routerHash[i] = byte(i)
	}

	// Register introducer
	err := rm.RegisterIntroducer(addr, routerHash, 123)
	require.NoError(t, err)

	// Verify registration
	introducers := rm.GetIntroducers()
	require.Len(t, introducers, 1)
	assert.Equal(t, addr.String(), introducers[0].Addr.String())
	assert.Equal(t, routerHash, introducers[0].RouterHash)
	assert.Equal(t, uint32(123), introducers[0].RelayTag)
}

// TestRelayManager_RegisterIntroducer_NilAddress tests error handling.
func TestRelayManager_RegisterIntroducer_NilAddress(t *testing.T) {
	listener := createMockListener(t)
	defer listener.Close()

	rm := NewRelayManager(listener)
	defer rm.Stop()

	routerHash := make([]byte, 32)
	err := rm.RegisterIntroducer(nil, routerHash, 123)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "address cannot be nil")
}

// TestRelayManager_RegisterIntroducer_InvalidRouterHash tests router hash validation.
func TestRelayManager_RegisterIntroducer_InvalidRouterHash(t *testing.T) {
	listener := createMockListener(t)
	defer listener.Close()

	rm := NewRelayManager(listener)
	defer rm.Stop()

	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}

	// Wrong length
	err := rm.RegisterIntroducer(addr, make([]byte, 16), 123)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "must be exactly 32 bytes")
}

// TestRelayManager_RegisterIntroducer_ZeroTag tests tag validation.
func TestRelayManager_RegisterIntroducer_ZeroTag(t *testing.T) {
	listener := createMockListener(t)
	defer listener.Close()

	rm := NewRelayManager(listener)
	defer rm.Stop()

	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
	routerHash := make([]byte, 32)

	err := rm.RegisterIntroducer(addr, routerHash, 0)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "relay tag cannot be zero")
}

// TestRelayManager_RegisterIntroducer_Update tests updating existing introducer.
func TestRelayManager_RegisterIntroducer_Update(t *testing.T) {
	listener := createMockListener(t)
	defer listener.Close()

	rm := NewRelayManager(listener)
	defer rm.Stop()

	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
	routerHash := make([]byte, 32)

	// Register with tag 123
	err := rm.RegisterIntroducer(addr, routerHash, 123)
	require.NoError(t, err)

	// Update with tag 456
	err = rm.RegisterIntroducer(addr, routerHash, 456)
	require.NoError(t, err)

	// Should still have only one introducer
	introducers := rm.GetIntroducers()
	require.Len(t, introducers, 1)
	assert.Equal(t, uint32(456), introducers[0].RelayTag)
}

// TestRelayManager_RegisterIntroducer_MaxLimit tests max introducer limit.
func TestRelayManager_RegisterIntroducer_MaxLimit(t *testing.T) {
	listener := createMockListener(t)
	defer listener.Close()

	rm := NewRelayManager(listener)
	defer rm.Stop()

	routerHash := make([]byte, 32)

	// Register 3 introducers (max)
	for i := 0; i < 3; i++ {
		addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345 + i}
		err := rm.RegisterIntroducer(addr, routerHash, uint32(100+i))
		require.NoError(t, err)
	}

	introducers := rm.GetIntroducers()
	assert.Len(t, introducers, 3)

	// Register 4th introducer (should replace oldest)
	addr4 := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12348}
	err := rm.RegisterIntroducer(addr4, routerHash, 103)
	require.NoError(t, err)

	// Should still have 3 introducers
	introducers = rm.GetIntroducers()
	assert.Len(t, introducers, 3)
}

// TestRelayManager_GetIntroducers tests retrieval of introducers.
func TestRelayManager_GetIntroducers(t *testing.T) {
	listener := createMockListener(t)
	defer listener.Close()

	rm := NewRelayManager(listener)
	defer rm.Stop()

	// Initially empty
	introducers := rm.GetIntroducers()
	assert.Empty(t, introducers)

	// Add introducers
	routerHash := make([]byte, 32)
	for i := 0; i < 2; i++ {
		addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345 + i}
		err := rm.RegisterIntroducer(addr, routerHash, uint32(100+i))
		require.NoError(t, err)
	}

	introducers = rm.GetIntroducers()
	assert.Len(t, introducers, 2)
}

// TestRelayManager_RemoveIntroducer tests introducer removal.
func TestRelayManager_RemoveIntroducer(t *testing.T) {
	listener := createMockListener(t)
	defer listener.Close()

	rm := NewRelayManager(listener)
	defer rm.Stop()

	addr1 := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
	addr2 := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12346}
	routerHash := make([]byte, 32)

	// Register two introducers
	err := rm.RegisterIntroducer(addr1, routerHash, 123)
	require.NoError(t, err)
	err = rm.RegisterIntroducer(addr2, routerHash, 124)
	require.NoError(t, err)

	assert.Len(t, rm.GetIntroducers(), 2)

	// Remove first
	rm.RemoveIntroducer(addr1)
	introducers := rm.GetIntroducers()
	assert.Len(t, introducers, 1)
	assert.Equal(t, addr2.String(), introducers[0].Addr.String())

	// Remove nil address (should not panic)
	rm.RemoveIntroducer(nil)
	assert.Len(t, rm.GetIntroducers(), 1)
}

// TestRelayManager_AllocateRelayTag tests relay tag allocation.
func TestRelayManager_AllocateRelayTag(t *testing.T) {
	listener := createMockListener(t)
	defer listener.Close()

	rm := NewRelayManager(listener)
	defer rm.Stop()

	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}

	// Allocate tag
	tag, err := rm.AllocateRelayTag(addr)
	require.NoError(t, err)
	assert.NotZero(t, tag)

	// Tag should be retrievable
	relayTag := rm.GetRelayTag(tag)
	require.NotNil(t, relayTag)
	assert.Equal(t, tag, relayTag.Tag)
	assert.Equal(t, addr.String(), relayTag.ForAddr.String())
}

// TestRelayManager_AllocateRelayTag_NilAddress tests error handling.
func TestRelayManager_AllocateRelayTag_NilAddress(t *testing.T) {
	listener := createMockListener(t)
	defer listener.Close()

	rm := NewRelayManager(listener)
	defer rm.Stop()

	tag, err := rm.AllocateRelayTag(nil)
	assert.Error(t, err)
	assert.Zero(t, tag)
	assert.Contains(t, err.Error(), "address cannot be nil")
}

// TestRelayManager_AllocateRelayTag_MultipleAllocations tests multiple tag allocations.
func TestRelayManager_AllocateRelayTag_MultipleAllocations(t *testing.T) {
	listener := createMockListener(t)
	defer listener.Close()

	rm := NewRelayManager(listener)
	defer rm.Stop()

	// Allocate multiple tags
	tags := make(map[uint32]bool)
	for i := 0; i < 10; i++ {
		addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345 + i}
		tag, err := rm.AllocateRelayTag(addr)
		require.NoError(t, err)
		assert.NotZero(t, tag)

		// Should be unique
		assert.False(t, tags[tag], "duplicate tag allocated")
		tags[tag] = true
	}
}

// TestRelayManager_ValidateRelayTag tests tag validation.
func TestRelayManager_ValidateRelayTag(t *testing.T) {
	listener := createMockListener(t)
	defer listener.Close()

	rm := NewRelayManager(listener)
	defer rm.Stop()

	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}

	// Allocate tag
	tag, err := rm.AllocateRelayTag(addr)
	require.NoError(t, err)

	// Valid tag and address
	assert.True(t, rm.ValidateRelayTag(tag, addr))

	// Wrong address
	wrongAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 99999}
	assert.False(t, rm.ValidateRelayTag(tag, wrongAddr))

	// Non-existent tag
	assert.False(t, rm.ValidateRelayTag(99999, addr))

	// Zero tag
	assert.False(t, rm.ValidateRelayTag(0, addr))

	// Nil address
	assert.False(t, rm.ValidateRelayTag(tag, nil))
}

// TestRelayManager_GetRelayTag tests tag retrieval.
func TestRelayManager_GetRelayTag(t *testing.T) {
	listener := createMockListener(t)
	defer listener.Close()

	rm := NewRelayManager(listener)
	defer rm.Stop()

	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}

	// Allocate tag
	tag, err := rm.AllocateRelayTag(addr)
	require.NoError(t, err)

	// Get tag
	relayTag := rm.GetRelayTag(tag)
	require.NotNil(t, relayTag)
	assert.Equal(t, tag, relayTag.Tag)
	assert.Equal(t, addr.String(), relayTag.ForAddr.String())
	assert.False(t, relayTag.CreatedAt.IsZero())
	assert.False(t, relayTag.ExpiresAt.IsZero())

	// Non-existent tag
	assert.Nil(t, rm.GetRelayTag(99999))

	// Zero tag
	assert.Nil(t, rm.GetRelayTag(0))
}

// TestRelayManager_AddPendingSession tests pending session management.
func TestRelayManager_AddPendingSession(t *testing.T) {
	listener := createMockListener(t)
	defer listener.Close()

	rm := NewRelayManager(listener)
	defer rm.Stop()

	sessionID := uint64(12345)
	remoteAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
	introducerAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12346}
	relayTag := uint32(100)

	// Add session
	err := rm.AddPendingSession(sessionID, remoteAddr, introducerAddr, relayTag)
	require.NoError(t, err)

	// Retrieve session
	session := rm.GetPendingSession(sessionID)
	require.NotNil(t, session)
	assert.Equal(t, sessionID, session.SessionID)
	assert.Equal(t, remoteAddr.String(), session.RemoteAddr.String())
	assert.Equal(t, introducerAddr.String(), session.IntroducerAddr.String())
	assert.Equal(t, relayTag, session.RelayTag)
	assert.Equal(t, 0, session.Retries)
}

// TestRelayManager_AddPendingSession_InvalidParams tests error handling.
func TestRelayManager_AddPendingSession_InvalidParams(t *testing.T) {
	listener := createMockListener(t)
	defer listener.Close()

	rm := NewRelayManager(listener)
	defer rm.Stop()

	remoteAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
	introducerAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12346}

	// Zero session ID
	err := rm.AddPendingSession(0, remoteAddr, introducerAddr, 100)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "session ID cannot be zero")

	// Nil remote address
	err = rm.AddPendingSession(123, nil, introducerAddr, 100)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "addresses cannot be nil")

	// Nil introducer address
	err = rm.AddPendingSession(123, remoteAddr, nil, 100)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "addresses cannot be nil")
}

// TestRelayManager_GetPendingSession_NotFound tests missing session.
func TestRelayManager_GetPendingSession_NotFound(t *testing.T) {
	listener := createMockListener(t)
	defer listener.Close()

	rm := NewRelayManager(listener)
	defer rm.Stop()

	session := rm.GetPendingSession(99999)
	assert.Nil(t, session)
}

// TestRelayManager_RemovePendingSession tests session removal.
func TestRelayManager_RemovePendingSession(t *testing.T) {
	listener := createMockListener(t)
	defer listener.Close()

	rm := NewRelayManager(listener)
	defer rm.Stop()

	sessionID := uint64(12345)
	remoteAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
	introducerAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12346}

	// Add session
	err := rm.AddPendingSession(sessionID, remoteAddr, introducerAddr, 100)
	require.NoError(t, err)

	// Remove session
	rm.RemovePendingSession(sessionID)

	// Should no longer exist
	session := rm.GetPendingSession(sessionID)
	assert.Nil(t, session)
}

// TestRelayManager_IncrementRetries tests retry counting.
func TestRelayManager_IncrementRetries(t *testing.T) {
	listener := createMockListener(t)
	defer listener.Close()

	rm := NewRelayManager(listener)
	defer rm.Stop()

	sessionID := uint64(12345)
	remoteAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
	introducerAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12346}

	// Add session
	err := rm.AddPendingSession(sessionID, remoteAddr, introducerAddr, 100)
	require.NoError(t, err)

	// Increment retries
	retries := rm.IncrementRetries(sessionID)
	assert.Equal(t, 1, retries)

	retries = rm.IncrementRetries(sessionID)
	assert.Equal(t, 2, retries)

	// Verify via GetPendingSession
	session := rm.GetPendingSession(sessionID)
	assert.Equal(t, 2, session.Retries)

	// Non-existent session
	retries = rm.IncrementRetries(99999)
	assert.Equal(t, -1, retries)
}

// TestRelayManager_GetStats tests statistics retrieval.
func TestRelayManager_GetStats(t *testing.T) {
	listener := createMockListener(t)
	defer listener.Close()

	rm := NewRelayManager(listener)
	defer rm.Stop()

	// Initially empty
	stats := rm.GetStats()
	assert.Equal(t, 0, stats["introducers"])
	assert.Equal(t, 0, stats["relay_tags"])
	assert.Equal(t, 0, stats["pending_sessions"])

	// Add some state
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
	routerHash := make([]byte, 32)
	err := rm.RegisterIntroducer(addr, routerHash, 123)
	require.NoError(t, err)

	_, err = rm.AllocateRelayTag(addr)
	require.NoError(t, err)

	remoteAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12346}
	err = rm.AddPendingSession(12345, remoteAddr, addr, 100)
	require.NoError(t, err)

	// Stats should reflect state
	stats = rm.GetStats()
	assert.Equal(t, 1, stats["introducers"])
	assert.Equal(t, 1, stats["relay_tags"])
	assert.Equal(t, 1, stats["pending_sessions"])
}

// TestRelayManager_CleanupExpired tests cleanup of expired entries.
func TestRelayManager_CleanupExpired(t *testing.T) {
	listener := createMockListener(t)
	defer listener.Close()

	rm := NewRelayManager(listener)
	defer rm.Stop()

	// Add introducer with short expiry
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
	routerHash := make([]byte, 32)
	err := rm.RegisterIntroducer(addr, routerHash, 123)
	require.NoError(t, err)

	// Manually expire it
	rm.mutex.Lock()
	rm.introducers[0].ExpiresAt = time.Now().Add(-1 * time.Hour)
	rm.mutex.Unlock()

	// Run cleanup
	rm.cleanupExpired()

	// Should be removed
	introducers := rm.GetIntroducers()
	assert.Empty(t, introducers)
}

// Helper function to create a mock listener for testing.
func createMockListener(t *testing.T) *SSU2Listener {
	config := createTestResponderConfig(t)
	packetConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)

	listener, err := NewSSU2Listener(packetConn, config)
	require.NoError(t, err)
	return listener
}

// Helper function to create a test responder configuration.
func createTestResponderConfig(t *testing.T) *SSU2Config {
	routerHash := make([]byte, 32)
	staticKey := make([]byte, 32)

	config, err := NewSSU2Config(routerHash, false)
	require.NoError(t, err)

	return config.WithStaticKey(staticKey)
}
