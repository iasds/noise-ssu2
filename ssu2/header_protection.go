package ssu2

import (
	"encoding/binary"
	"sync"

	"github.com/samber/oops"
	"golang.org/x/crypto/chacha20"
)

// HeaderType indicates the type of SSU2 packet for header protection purposes.
// Different packet types use different header protection key phases.
type HeaderType int

const (
	// HeaderTypeSessionRequest is for Session Request packets (Message 1)
	// Uses: k_header_1 = receiver's intro key, k_header_2 = receiver's intro key
	HeaderTypeSessionRequest HeaderType = iota

	// HeaderTypeSessionCreated is for Session Created packets (Message 2)
	// Uses: k_header_1 = sender's intro key, k_header_2 = derived from handshake KDF
	HeaderTypeSessionCreated

	// HeaderTypeRetry is for Retry packets
	// Uses: k_header_1 = sender's intro key, k_header_2 = sender's intro key
	HeaderTypeRetry

	// HeaderTypeTokenRequest is for Token Request packets
	// Uses: k_header_1 = receiver's intro key, k_header_2 = receiver's intro key
	HeaderTypeTokenRequest

	// HeaderTypeSessionConfirmed is for Session Confirmed packets (Message 3)
	// Uses: k_header_1 = k_header_1 from KDF, k_header_2 = k_header_2 from KDF
	HeaderTypeSessionConfirmed

	// HeaderTypeData is for Data phase packets
	// Uses: k_header_1 = k_header_1 from KDF, k_header_2 = k_header_2 from KDF
	HeaderTypeData

	// HeaderTypePeerTest is for Peer Test packets
	// Uses: k_header_1 = intro key of test target, k_header_2 = intro key of test target
	HeaderTypePeerTest

	// HeaderTypeHolePunch is for Hole Punch packets
	// Uses: k_header_1 = receiver's intro key, k_header_2 = receiver's intro key
	HeaderTypeHolePunch
)

// HeaderSize constants per SSU2 specification
const (
	// HeaderKeySize is the size of header protection keys (ChaCha20 key)
	HeaderKeySize = 32

	// MinPacketSizeForEncryption is the minimum packet size to have valid IV extraction
	// We need at least 24 bytes after the header for IV extraction
	MinPacketSizeForEncryption = 56
)

// HeaderProtector implements SSU2 header encryption and decryption per the I2P SSU2 spec.
// It uses ChaCha20 to generate XOR masks from keys and IVs extracted from packet data.
//
// Header Encryption Algorithm (from spec):
//  1. Extract IV from last 24 bytes of packet (iv1 = packet[len-24:len-13], iv2 = packet[len-12:len-1])
//  2. Generate mask using ChaCha20.encrypt(key, iv, zeros)
//  3. XOR header bytes 0-7 with first mask
//  4. XOR header bytes 8-15 with second mask
//  5. For long headers (Session Request/Created): encrypt bytes 16-63 with ChaCha20(key1, n=0)
type HeaderProtector struct {
	// mu protects concurrent access to the protector
	mu sync.RWMutex

	// kHeader1 is the first header protection key (for bytes 0-7)
	kHeader1 []byte

	// kHeader2 is the second header protection key (for bytes 8-15)
	kHeader2 []byte

	// headerType determines whether we use long or short header encryption
	headerType HeaderType
}

// NewHeaderProtector creates a new HeaderProtector with the given keys.
// Both keys must be exactly 32 bytes (ChaCha20 key size).
// headerType determines the packet type for appropriate header size handling.
func NewHeaderProtector(kHeader1, kHeader2 []byte, headerType HeaderType) (*HeaderProtector, error) {
	if len(kHeader1) != HeaderKeySize {
		return nil, oops.
			Code("INVALID_KEY_SIZE").
			In("ssu2").
			With("key", "kHeader1").
			With("expected", HeaderKeySize).
			With("actual", len(kHeader1)).
			Errorf("kHeader1 must be exactly %d bytes", HeaderKeySize)
	}

	if len(kHeader2) != HeaderKeySize {
		return nil, oops.
			Code("INVALID_KEY_SIZE").
			In("ssu2").
			With("key", "kHeader2").
			With("expected", HeaderKeySize).
			With("actual", len(kHeader2)).
			Errorf("kHeader2 must be exactly %d bytes", HeaderKeySize)
	}

	// Make defensive copies
	k1 := make([]byte, HeaderKeySize)
	k2 := make([]byte, HeaderKeySize)
	copy(k1, kHeader1)
	copy(k2, kHeader2)

	return &HeaderProtector{
		kHeader1:   k1,
		kHeader2:   k2,
		headerType: headerType,
	}, nil
}

// NewHeaderProtectorFromIntroKey creates a HeaderProtector using an intro key for both keys.
// This is used for Session Request, Retry, Token Request, Peer Test, and Hole Punch packets
// where both k_header_1 and k_header_2 are the same (receiver's intro key).
func NewHeaderProtectorFromIntroKey(introKey []byte, headerType HeaderType) (*HeaderProtector, error) {
	return NewHeaderProtector(introKey, introKey, headerType)
}

// EncryptHeader encrypts the header bytes of an SSU2 packet in place.
// The packet must be the complete SSU2 packet including header, payload, and MAC.
// Returns error if packet is too small for header encryption.
func (hp *HeaderProtector) EncryptHeader(packet []byte) error {
	hp.mu.Lock()
	defer hp.mu.Unlock()

	return hp.applyHeaderProtection(packet)
}

// DecryptHeader decrypts the header bytes of an SSU2 packet in place.
// Since header protection uses XOR, encryption and decryption are the same operation.
// The packet must be the complete SSU2 packet including header, payload, and MAC.
func (hp *HeaderProtector) DecryptHeader(packet []byte) error {
	hp.mu.Lock()
	defer hp.mu.Unlock()

	// XOR is symmetric, so encrypt and decrypt are the same
	return hp.applyHeaderProtection(packet)
}

// applyHeaderProtection applies or removes header protection (XOR is symmetric).
// This implements the SSU2 header encryption algorithm from the specification.
func (hp *HeaderProtector) applyHeaderProtection(packet []byte) error {
	headerSize := hp.getHeaderSize()

	// Minimum packet size check: need header + at least 24 bytes for IV extraction
	minSize := headerSize + 24
	if len(packet) < minSize {
		return oops.
			Code("PACKET_TOO_SMALL").
			In("ssu2").
			With("packet_size", len(packet)).
			With("min_size", minSize).
			With("header_type", hp.headerType).
			Errorf("packet too small for header protection: need at least %d bytes", minSize)
	}

	// Extract IV1 from packet[len-24:len-13] (11 bytes, we use first 12 for ChaCha20 nonce)
	// The spec says bytes [len-24:len-13] which is 11 bytes
	// ChaCha20 uses 12-byte nonce, so we pad the 11 bytes to 12
	iv1Start := len(packet) - 24
	iv1 := make([]byte, 12)
	copy(iv1, packet[iv1Start:iv1Start+11])

	// Generate first mask using ChaCha20(kHeader1, iv1, zeros)
	mask1, err := hp.generateMask(hp.kHeader1, iv1)
	if err != nil {
		return oops.Wrapf(err, "failed to generate first header mask")
	}

	// XOR bytes 0-7 with mask1[0:8]
	for i := 0; i < 8; i++ {
		packet[i] ^= mask1[i]
	}

	// Extract IV2 from packet[len-12:len-1] (11 bytes)
	iv2Start := len(packet) - 12
	iv2 := make([]byte, 12)
	copy(iv2, packet[iv2Start:iv2Start+11])

	// Generate second mask using ChaCha20(kHeader2, iv2, zeros)
	mask2, err := hp.generateMask(hp.kHeader2, iv2)
	if err != nil {
		return oops.Wrapf(err, "failed to generate second header mask")
	}

	// XOR bytes 8-15 with mask2[0:8]
	for i := 8; i < 16; i++ {
		packet[i] ^= mask2[i-8]
	}

	// For long headers (Session Request/Created/Retry/TokenRequest/PeerTest/HolePunch):
	// Encrypt bytes 16-31 with ChaCha20(kHeader1, n=0) for the remaining header bytes
	// (Static key or router hash encryption)
	if hp.isLongHeader() && len(packet) >= LongHeaderSize {
		err = hp.encryptLongHeaderExtension(packet)
		if err != nil {
			return oops.Wrapf(err, "failed to encrypt long header extension")
		}
	}

	return nil
}

// isLongHeader returns true if this is a long header type (32 bytes).
func (hp *HeaderProtector) isLongHeader() bool {
	switch hp.headerType {
	case HeaderTypeSessionRequest, HeaderTypeSessionCreated, HeaderTypeRetry,
		HeaderTypeTokenRequest, HeaderTypePeerTest, HeaderTypeHolePunch:
		return true
	default:
		return false
	}
}

// getHeaderSize returns the header size based on header type.
func (hp *HeaderProtector) getHeaderSize() int {
	if hp.isLongHeader() {
		return LongHeaderSize
	}
	return ShortHeaderSize
}

// generateMask generates an 8-byte XOR mask using ChaCha20.
// The mask is generated by encrypting 8 zero bytes with ChaCha20.
func (hp *HeaderProtector) generateMask(key, nonce []byte) ([]byte, error) {
	cipher, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to initialize ChaCha20 cipher")
	}

	// Generate mask by encrypting zeros
	zeros := make([]byte, 8)
	mask := make([]byte, 8)
	cipher.XORKeyStream(mask, zeros)

	return mask, nil
}

// encryptLongHeaderExtension encrypts bytes 16-31 of a long header.
// Uses ChaCha20 with kHeader1 and nonce=0.
func (hp *HeaderProtector) encryptLongHeaderExtension(packet []byte) error {
	if len(packet) < LongHeaderSize {
		return nil // Nothing to encrypt
	}

	// Create ChaCha20 cipher with nonce = 0
	nonce := make([]byte, 12)
	cipher, err := chacha20.NewUnauthenticatedCipher(hp.kHeader1, nonce)
	if err != nil {
		return oops.Wrapf(err, "failed to initialize ChaCha20 for header extension")
	}

	// Encrypt bytes 16-31 in place
	cipher.XORKeyStream(packet[16:32], packet[16:32])

	return nil
}

// UpdateKeys updates the header protection keys.
// This is used when transitioning between handshake phases.
// Both keys must be exactly 32 bytes.
func (hp *HeaderProtector) UpdateKeys(kHeader1, kHeader2 []byte) error {
	if len(kHeader1) != HeaderKeySize {
		return oops.
			Code("INVALID_KEY_SIZE").
			In("ssu2").
			With("key", "kHeader1").
			With("expected", HeaderKeySize).
			With("actual", len(kHeader1)).
			Errorf("kHeader1 must be exactly %d bytes", HeaderKeySize)
	}

	if len(kHeader2) != HeaderKeySize {
		return oops.
			Code("INVALID_KEY_SIZE").
			In("ssu2").
			With("key", "kHeader2").
			With("expected", HeaderKeySize).
			With("actual", len(kHeader2)).
			Errorf("kHeader2 must be exactly %d bytes", HeaderKeySize)
	}

	hp.mu.Lock()
	defer hp.mu.Unlock()

	copy(hp.kHeader1, kHeader1)
	copy(hp.kHeader2, kHeader2)

	return nil
}

// SetHeaderType updates the header type.
// This affects whether long or short header encryption is used.
func (hp *HeaderProtector) SetHeaderType(headerType HeaderType) {
	hp.mu.Lock()
	defer hp.mu.Unlock()
	hp.headerType = headerType
}

// GetHeaderType returns the current header type.
func (hp *HeaderProtector) GetHeaderType() HeaderType {
	hp.mu.RLock()
	defer hp.mu.RUnlock()
	return hp.headerType
}

// HeaderProtectorManager manages header protection for different phases of SSU2.
// It tracks the current phase and provides appropriate header protection based on state.
type HeaderProtectorManager struct {
	mu sync.RWMutex

	// introKey is the local router's intro key (used for incoming packets)
	introKey []byte

	// remoteIntroKey is the remote router's intro key (used for outgoing packets)
	remoteIntroKey []byte

	// kdfHeader1 is the k_header_1 derived from handshake KDF
	kdfHeader1 []byte

	// kdfHeader2 is the k_header_2 derived from handshake KDF
	kdfHeader2 []byte

	// current is the current header protector
	current *HeaderProtector

	// isInitiator indicates if we are the handshake initiator
	isInitiator bool
}

// NewHeaderProtectorManager creates a new header protector manager.
// introKey is the local router's intro key.
// remoteIntroKey is the remote peer's intro key (can be nil for listeners).
// isInitiator indicates whether we are initiating the handshake.
func NewHeaderProtectorManager(introKey, remoteIntroKey []byte, isInitiator bool) (*HeaderProtectorManager, error) {
	if len(introKey) != HeaderKeySize {
		return nil, oops.
			Code("INVALID_INTRO_KEY").
			In("ssu2").
			With("expected", HeaderKeySize).
			With("actual", len(introKey)).
			Errorf("intro key must be exactly %d bytes", HeaderKeySize)
	}

	// Make defensive copies
	intro := make([]byte, HeaderKeySize)
	copy(intro, introKey)

	var remote []byte
	if len(remoteIntroKey) == HeaderKeySize {
		remote = make([]byte, HeaderKeySize)
		copy(remote, remoteIntroKey)
	}

	return &HeaderProtectorManager{
		introKey:       intro,
		remoteIntroKey: remote,
		isInitiator:    isInitiator,
	}, nil
}

// GetProtectorForType returns a header protector configured for the given packet type.
// This creates a new protector with the appropriate keys based on the packet type
// and whether we are the initiator or responder.
func (hpm *HeaderProtectorManager) GetProtectorForType(headerType HeaderType) (*HeaderProtector, error) {
	hpm.mu.RLock()
	defer hpm.mu.RUnlock()

	var k1, k2 []byte

	switch headerType {
	case HeaderTypeSessionRequest, HeaderTypeTokenRequest, HeaderTypeHolePunch:
		// Uses receiver's intro key for both
		if hpm.isInitiator {
			// We're sending to receiver, use their intro key
			if len(hpm.remoteIntroKey) != HeaderKeySize {
				return nil, oops.
					Code("MISSING_REMOTE_INTRO_KEY").
					In("ssu2").
					Errorf("remote intro key required for Session Request")
			}
			k1 = hpm.remoteIntroKey
			k2 = hpm.remoteIntroKey
		} else {
			// We're receiving, use our intro key
			k1 = hpm.introKey
			k2 = hpm.introKey
		}

	case HeaderTypeSessionCreated, HeaderTypeRetry:
		// Sender's intro key for k1, derived key for k2 (Session Created)
		// Or sender's intro key for both (Retry)
		if hpm.isInitiator {
			// We're receiving from responder, use their intro key
			if len(hpm.remoteIntroKey) != HeaderKeySize {
				return nil, oops.
					Code("MISSING_REMOTE_INTRO_KEY").
					In("ssu2").
					Errorf("remote intro key required for Session Created/Retry")
			}
			k1 = hpm.remoteIntroKey
			if headerType == HeaderTypeRetry {
				k2 = hpm.remoteIntroKey
			} else {
				// Session Created uses KDF-derived k2
				if len(hpm.kdfHeader2) != HeaderKeySize {
					// Fall back to intro key if KDF not yet available
					k2 = hpm.remoteIntroKey
				} else {
					k2 = hpm.kdfHeader2
				}
			}
		} else {
			// We're sending as responder, use our intro key
			k1 = hpm.introKey
			if headerType == HeaderTypeRetry {
				k2 = hpm.introKey
			} else {
				// Session Created uses KDF-derived k2
				if len(hpm.kdfHeader2) != HeaderKeySize {
					// Fall back to intro key if KDF not yet available
					k2 = hpm.introKey
				} else {
					k2 = hpm.kdfHeader2
				}
			}
		}

	case HeaderTypeSessionConfirmed, HeaderTypeData:
		// Uses KDF-derived keys for both
		if len(hpm.kdfHeader1) != HeaderKeySize || len(hpm.kdfHeader2) != HeaderKeySize {
			return nil, oops.
				Code("MISSING_KDF_KEYS").
				In("ssu2").
				With("header_type", headerType).
				Errorf("KDF-derived keys required for Session Confirmed/Data packets")
		}
		k1 = hpm.kdfHeader1
		k2 = hpm.kdfHeader2

	case HeaderTypePeerTest:
		// Uses test target's intro key for both
		// For Peer Test, the caller should provide the target's intro key separately
		return nil, oops.
			Code("PEER_TEST_NOT_SUPPORTED").
			In("ssu2").
			Errorf("Peer Test requires target's intro key - use GetProtectorForType with explicit keys")

	default:
		return nil, oops.
			Code("UNKNOWN_HEADER_TYPE").
			In("ssu2").
			With("header_type", headerType).
			Errorf("unknown header type")
	}

	return NewHeaderProtector(k1, k2, headerType)
}

// SetKDFKeys sets the KDF-derived header protection keys.
// These are derived from the Noise handshake and used for Session Confirmed and Data packets.
func (hpm *HeaderProtectorManager) SetKDFKeys(kHeader1, kHeader2 []byte) error {
	if len(kHeader1) != HeaderKeySize {
		return oops.
			Code("INVALID_KEY_SIZE").
			In("ssu2").
			With("key", "kHeader1").
			Errorf("kHeader1 must be exactly %d bytes", HeaderKeySize)
	}
	if len(kHeader2) != HeaderKeySize {
		return oops.
			Code("INVALID_KEY_SIZE").
			In("ssu2").
			With("key", "kHeader2").
			Errorf("kHeader2 must be exactly %d bytes", HeaderKeySize)
	}

	hpm.mu.Lock()
	defer hpm.mu.Unlock()

	hpm.kdfHeader1 = make([]byte, HeaderKeySize)
	hpm.kdfHeader2 = make([]byte, HeaderKeySize)
	copy(hpm.kdfHeader1, kHeader1)
	copy(hpm.kdfHeader2, kHeader2)

	return nil
}

// SetRemoteIntroKey sets the remote peer's intro key.
// This is typically learned during connection establishment.
func (hpm *HeaderProtectorManager) SetRemoteIntroKey(remoteIntroKey []byte) error {
	if len(remoteIntroKey) != HeaderKeySize {
		return oops.
			Code("INVALID_INTRO_KEY").
			In("ssu2").
			With("expected", HeaderKeySize).
			With("actual", len(remoteIntroKey)).
			Errorf("remote intro key must be exactly %d bytes", HeaderKeySize)
	}

	hpm.mu.Lock()
	defer hpm.mu.Unlock()

	hpm.remoteIntroKey = make([]byte, HeaderKeySize)
	copy(hpm.remoteIntroKey, remoteIntroKey)

	return nil
}

// EncryptOutboundHeader encrypts the header of an outbound packet.
// Automatically selects the correct keys based on header type.
func (hpm *HeaderProtectorManager) EncryptOutboundHeader(packet []byte, headerType HeaderType) error {
	protector, err := hpm.GetProtectorForType(headerType)
	if err != nil {
		return err
	}
	return protector.EncryptHeader(packet)
}

// DecryptInboundHeader decrypts the header of an inbound packet.
// Automatically selects the correct keys based on header type.
func (hpm *HeaderProtectorManager) DecryptInboundHeader(packet []byte, headerType HeaderType) error {
	protector, err := hpm.GetProtectorForType(headerType)
	if err != nil {
		return err
	}
	return protector.DecryptHeader(packet)
}

// ExtractConnectionID extracts the destination connection ID from a decrypted header.
// This reads bytes 0-7 as a big-endian uint64.
func ExtractConnectionID(header []byte) (uint64, error) {
	if len(header) < 8 {
		return 0, oops.
			Code("HEADER_TOO_SHORT").
			In("ssu2").
			With("header_size", len(header)).
			Errorf("header must be at least 8 bytes to extract connection ID")
	}
	return binary.BigEndian.Uint64(header[0:8]), nil
}

// EncodeConnectionID encodes a connection ID into header bytes 0-7.
func EncodeConnectionID(header []byte, connID uint64) error {
	if len(header) < 8 {
		return oops.
			Code("HEADER_TOO_SHORT").
			In("ssu2").
			With("header_size", len(header)).
			Errorf("header must be at least 8 bytes to encode connection ID")
	}
	binary.BigEndian.PutUint64(header[0:8], connID)
	return nil
}

// ExtractPacketNumber extracts the packet number from a decrypted header.
// This reads bytes 8-11 as a big-endian uint32.
func ExtractPacketNumber(header []byte) (uint32, error) {
	if len(header) < 12 {
		return 0, oops.
			Code("HEADER_TOO_SHORT").
			In("ssu2").
			With("header_size", len(header)).
			Errorf("header must be at least 12 bytes to extract packet number")
	}
	return binary.BigEndian.Uint32(header[8:12]), nil
}

// EncodePacketNumber encodes a packet number into header bytes 8-11.
func EncodePacketNumber(header []byte, pktNum uint32) error {
	if len(header) < 12 {
		return oops.
			Code("HEADER_TOO_SHORT").
			In("ssu2").
			With("header_size", len(header)).
			Errorf("header must be at least 12 bytes to encode packet number")
	}
	binary.BigEndian.PutUint32(header[8:12], pktNum)
	return nil
}
