package wire

import (
	"crypto/rand"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractConnIDWithIntroKey_Roundtrip(t *testing.T) {
	// Generate a random intro key
	introKey := make([]byte, HeaderKeySize)
	_, err := rand.Read(introKey)
	require.NoError(t, err)

	// Create a HeaderProtector using the intro key (as a receiver would)
	hp, err := NewHeaderProtectorFromIntroKey(introKey, HeaderTypeSessionRequest)
	require.NoError(t, err)

	// Build a minimal packet: 64-byte long header + 24-byte tail = 88 bytes
	// (SessionRequest is a long-header packet)
	originalConnID := uint64(0xDEADBEEFCAFEBABE)
	packet := make([]byte, 88)

	// Set the connID in bytes 0-7 (plaintext before encryption)
	binary.BigEndian.PutUint64(packet[0:8], originalConnID)

	// Fill the tail (last 24 bytes) with random data to serve as IV source
	_, err = rand.Read(packet[64:])
	require.NoError(t, err)

	// Encrypt the header (simulates what the sender does)
	err = hp.EncryptHeader(packet)
	require.NoError(t, err)

	// Now extract the connID using ONLY the intro key (simulates listener fast path)
	extractedConnID, err := ExtractConnIDWithIntroKey(packet, introKey)
	require.NoError(t, err)

	assert.Equal(t, originalConnID, extractedConnID,
		"connID extracted with intro key should match original")
}

func TestExtractConnIDWithIntroKey_DataPhase(t *testing.T) {
	// Even data-phase packets use intro key for connID masking
	introKey := make([]byte, HeaderKeySize)
	_, err := rand.Read(introKey)
	require.NoError(t, err)

	hp, err := NewHeaderProtectorFromIntroKey(introKey, HeaderTypeData)
	require.NoError(t, err)

	// Short header packet: 16-byte header + 24-byte tail = 40 bytes
	originalConnID := uint64(0x1234567890ABCDEF)
	packet := make([]byte, 40)
	binary.BigEndian.PutUint64(packet[0:8], originalConnID)
	_, err = rand.Read(packet[16:])
	require.NoError(t, err)

	err = hp.EncryptHeader(packet)
	require.NoError(t, err)

	extractedConnID, err := ExtractConnIDWithIntroKey(packet, introKey)
	require.NoError(t, err)

	assert.Equal(t, originalConnID, extractedConnID)
}

func TestExtractConnIDWithIntroKey_WrongKey(t *testing.T) {
	// Using a different key should produce a wrong connID
	introKey := make([]byte, HeaderKeySize)
	rand.Read(introKey)

	wrongKey := make([]byte, HeaderKeySize)
	rand.Read(wrongKey)

	hp, err := NewHeaderProtectorFromIntroKey(introKey, HeaderTypeSessionRequest)
	require.NoError(t, err)

	packet := make([]byte, 88)
	binary.BigEndian.PutUint64(packet[0:8], 42)
	rand.Read(packet[64:])

	err = hp.EncryptHeader(packet)
	require.NoError(t, err)

	extractedConnID, err := ExtractConnIDWithIntroKey(packet, wrongKey)
	require.NoError(t, err)

	assert.NotEqual(t, uint64(42), extractedConnID,
		"wrong key should produce different connID")
}

func TestExtractConnIDWithIntroKey_PacketTooSmall(t *testing.T) {
	introKey := make([]byte, HeaderKeySize)
	rand.Read(introKey)

	_, err := ExtractConnIDWithIntroKey(make([]byte, 16), introKey)
	assert.Error(t, err, "should fail for packet < 32 bytes")
}

func TestExtractConnIDWithIntroKey_InvalidKeySize(t *testing.T) {
	_, err := ExtractConnIDWithIntroKey(make([]byte, 40), make([]byte, 16))
	assert.Error(t, err, "should fail for key != 32 bytes")
}

func TestExtractConnIDWithIntroKey_MultipleConnIDs(t *testing.T) {
	// Simulate multiple sessions with different connIDs, all using the same intro key
	introKey := make([]byte, HeaderKeySize)
	rand.Read(introKey)

	connIDs := []uint64{1, 255, 65536, 0xFFFFFFFF, 0xDEADBEEFCAFEBABE}

	for _, expectedID := range connIDs {
		hp, err := NewHeaderProtectorFromIntroKey(introKey, HeaderTypeSessionRequest)
		require.NoError(t, err)

		packet := make([]byte, 88)
		binary.BigEndian.PutUint64(packet[0:8], expectedID)
		rand.Read(packet[64:])

		err = hp.EncryptHeader(packet)
		require.NoError(t, err)

		extracted, err := ExtractConnIDWithIntroKey(packet, introKey)
		require.NoError(t, err)
		assert.Equal(t, expectedID, extracted, "connID mismatch for %x", expectedID)
	}
}
