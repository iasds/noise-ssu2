package server

import (
	"crypto/rand"
	"encoding/binary"
	"net"
	"testing"

	"github.com/go-i2p/go-noise/ssu2/config"
	"github.com/go-i2p/go-noise/ssu2/wire"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHandleIncomingPacket_FastPathRouting verifies that the listener's
// handleIncomingPacket correctly routes packets to existing sessions
// using only the intro key for connID extraction (without full parse).
//
// This is the critical fix for SSU2: SessionCreated packets use
// SessCreateHeader key for full header protection, which the listener
// can't decrypt. But the connID (bytes 0-7) is ALWAYS masked with
// the receiver's intro key, so we can demux without full decryption.
func TestHandleIncomingPacket_FastPathRouting(t *testing.T) {
	introKey := make([]byte, 32)
	_, err := rand.Read(introKey)
	require.NoError(t, err)

	routerHash := generateTestHash()
	cfg, err := config.NewSSU2Config(routerHash, false) // responder
	require.NoError(t, err)
	cfg.IntroKey = introKey
	cfg.StaticKey = make([]byte, 32)
	rand.Read(cfg.StaticKey)
	cfg.RouterInfoValidator = DefaultRouterInfoValidator

	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	defer pc.Close()

	listener, err := NewSSU2Listener(pc, cfg)
	require.NoError(t, err)

	// Verify intro header protector was initialized
	require.NotNil(t, listener.introHeaderProtector, "intro header protector should be set")

	// Create a mock session and register it in the router
	targetConnID := uint64(0xCAFEBABE12345678)
	mockConn := NewMockSSU2Conn(targetConnID)
	err = listener.router.AddSession(mockConn)
	require.NoError(t, err)

	// Build a packet with the target connID, encrypted with intro key
	hp, err := wire.NewHeaderProtectorFromIntroKey(introKey, wire.HeaderTypeSessionRequest)
	require.NoError(t, err)

	// Long header packet: 64 bytes header + 24 bytes tail = 88 bytes
	packet := make([]byte, 88)
	binary.BigEndian.PutUint64(packet[0:8], targetConnID)
	_, err = rand.Read(packet[64:])
	require.NoError(t, err)

	err = hp.EncryptHeader(packet)
	require.NoError(t, err)

	// Verify ExtractConnIDWithIntroKey can recover the connID
	extractedID, err := wire.ExtractConnIDWithIntroKey(packet, introKey)
	require.NoError(t, err)
	assert.Equal(t, targetConnID, extractedID)

	// Verify the router can find the session
	found := listener.router.GetSession(targetConnID)
	require.NotNil(t, found, "session should be in router")
	assert.Equal(t, targetConnID, found.GetSSU2Addr().ConnectionID())
}

// TestHandleIncomingPacket_FastPathVsSlowPath verifies that the fast path
// correctly skips to the slow path for unknown connIDs.
func TestHandleIncomingPacket_FastPathVsSlowPath(t *testing.T) {
	introKey := make([]byte, 32)
	rand.Read(introKey)

	routerHash := generateTestHash()
	cfg, err := config.NewSSU2Config(routerHash, false)
	require.NoError(t, err)
	cfg.IntroKey = introKey
	cfg.StaticKey = make([]byte, 32)
	rand.Read(cfg.StaticKey)
	cfg.RouterInfoValidator = DefaultRouterInfoValidator

	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.NoError(t, err)
	defer pc.Close()

	listener, err := NewSSU2Listener(pc, cfg)
	require.NoError(t, err)

	// Build a packet with an unknown connID
	unknownConnID := uint64(0x1111111111111111)
	hp, err := wire.NewHeaderProtectorFromIntroKey(introKey, wire.HeaderTypeSessionRequest)
	require.NoError(t, err)

	packet := make([]byte, 88)
	binary.BigEndian.PutUint64(packet[0:8], unknownConnID)
	rand.Read(packet[64:])
	err = hp.EncryptHeader(packet)
	require.NoError(t, err)

	// The fast path should NOT find a session
	found := listener.router.GetSession(unknownConnID)
	assert.Nil(t, found, "unknown connID should not be in router")

	// handleIncomingPacket should fall through to slow path without panicking
	remoteAddr := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 1), Port: 12345}
	listener.handleIncomingPacket(packet, remoteAddr)
}

func generateTestHash() [32]byte {
	var h [32]byte
	rand.Read(h[:])
	return h
}
