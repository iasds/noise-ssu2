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
//  1. Extract IV from last 24 bytes of packet (iv1 = packet[len-24:len-12], iv2 = packet[len-12:len])
//  2. Generate mask using ChaCha20.encrypt(key, iv, zeros)
//  3. XOR header bytes 0-7 with first mask
//  4. XOR header bytes 8-15 with second mask
//
// 5. For long headers: encrypt bytes 16-63 with ChaCha20(k_header_2, iv=zeros) per spec
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
// Per SSU2 spec, encryption order: ChaCha20 extension first, then XOR masks.
func (hp *HeaderProtector) EncryptHeader(packet []byte) error {
	hp.mu.Lock()
	defer hp.mu.Unlock()

	if err := hp.validatePacketSize(packet); err != nil {
		return err
	}

	// Step 1: Encrypt long header extension (+ ephemeral key) with ChaCha20
	// This must happen before XOR masks so that the IVs (from packet tail)
	// are in a consistent state for both encrypt and decrypt.
	if hp.isLongHeader() && len(packet) >= LongHeaderSize {
		if err := hp.encryptLongHeaderExtension(packet); err != nil {
			return oops.Wrapf(err, "failed to encrypt long header extension")
		}
	}

	// Step 2: Apply XOR masks to bytes 0-15
	return hp.applyXORMasks(packet)
}

// DecryptHeader decrypts the header bytes of an SSU2 packet in place.
// Per SSU2 spec, decryption order: XOR masks first, then ChaCha20 extension.
func (hp *HeaderProtector) DecryptHeader(packet []byte) error {
	hp.mu.Lock()
	defer hp.mu.Unlock()

	if err := hp.validatePacketSize(packet); err != nil {
		return err
	}

	// Step 1: Remove XOR masks from bytes 0-15
	if err := hp.applyXORMasks(packet); err != nil {
		return err
	}

	// Step 2: Decrypt long header extension (+ ephemeral key) with ChaCha20
	if hp.isLongHeader() && len(packet) >= LongHeaderSize {
		if err := hp.encryptLongHeaderExtension(packet); err != nil {
			return oops.Wrapf(err, "failed to decrypt long header extension")
		}
	}

	return nil
}

// validatePacketSize checks that the packet is large enough for header protection.
func (hp *HeaderProtector) validatePacketSize(packet []byte) error {
	headerSize := hp.getHeaderSize()
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
	return nil
}

// applyXORMasks applies or removes XOR masks on header bytes 0-15.
// XOR is symmetric so this works for both encrypt and decrypt.
func (hp *HeaderProtector) applyXORMasks(packet []byte) error {
	// SSU2 spec §"Header Protection": IV1 = packet[len-24 : len-12] (12 bytes).
	iv1Start := len(packet) - 24
	iv1 := make([]byte, 12)
	copy(iv1, packet[iv1Start:iv1Start+12])

	// Generate first mask using ChaCha20(kHeader1, iv1, zeros)
	mask1, err := hp.generateMask(hp.kHeader1, iv1)
	if err != nil {
		return oops.Wrapf(err, "failed to generate first header mask")
	}

	// XOR bytes 0-7 with mask1[0:8]
	for i := 0; i < 8; i++ {
		packet[i] ^= mask1[i]
	}

	// SSU2 spec §"Header Protection": IV2 = packet[len-12 : len] (12 bytes).
	iv2Start := len(packet) - 12
	iv2 := make([]byte, 12)
	copy(iv2, packet[iv2Start:iv2Start+12])

	// Generate second mask using ChaCha20(kHeader2, iv2, zeros)
	mask2, err := hp.generateMask(hp.kHeader2, iv2)
	if err != nil {
		return oops.Wrapf(err, "failed to generate second header mask")
	}

	// XOR bytes 8-15 with mask2[0:8]
	for i := 8; i < 16; i++ {
		packet[i] ^= mask2[i-8]
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

// encryptLongHeaderExtension encrypts the long header extension and optional
// ephemeral key per the SSU2 spec. Uses ChaCha20 with kHeader2 at counter
// position n=1 per spec ("key: Bob's intro key, n: 1, data: 48 bytes").
// For SessionRequest/SessionCreated (which include a 32-byte ephemeral key),
// encrypts bytes 16-63 (48 bytes) as one ChaCha20 operation.
// For other long header types, encrypts bytes 16-31 (16 bytes).
func (hp *HeaderProtector) encryptLongHeaderExtension(packet []byte) error {
	if len(packet) < LongHeaderSize {
		return nil // Nothing to encrypt
	}

	// SSU2 spec: ChaCha20.encrypt(k_header_2, n=1, packet[16:63])
	nonce := make([]byte, 12) // all-zero nonce; counter set to 1 below
	cipher, err := chacha20.NewUnauthenticatedCipher(hp.kHeader2, nonce)
	if err != nil {
		return oops.Wrapf(err, "failed to initialize ChaCha20 for header extension")
	}
	// SSU2 spec requires n=1 (counter position 1, skipping the first 64 bytes)
	cipher.SetCounter(1)

	// For packets with ephemeral keys, encrypt 48 bytes (header[16:64])
	hasEphemeral := hp.headerType == HeaderTypeSessionRequest ||
		hp.headerType == HeaderTypeSessionCreated
	if hasEphemeral && len(packet) >= LongHeaderSize+EphemeralKeySize {
		cipher.XORKeyStream(packet[16:64], packet[16:64])
	} else {
		cipher.XORKeyStream(packet[16:32], packet[16:32])
	}

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

	// sendDataHeader2 is k_header_2 for outbound Data packets, derived per
	// "HKDFSSU2DataKeys" from the send cipher key (k_ab for initiator).
	sendDataHeader2 []byte

	// recvDataHeader2 is k_header_2 for inbound Data packets, derived per
	// "HKDFSSU2DataKeys" from the recv cipher key (k_ba for initiator).
	recvDataHeader2 []byte

	// sessCreateHeader2 is k_header_2 for SessionCreated, derived from
	// chainKey after message 1 with info \"SessCreateHeader\"
	sessCreateHeader2 []byte

	// sessionConfirmedHeader2 is k_header_2 for SessionConfirmed, derived
	// from chainKey after message 2 with info \"SessionConfirmed\"
	sessionConfirmedHeader2 []byte

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
	var err error

	switch headerType {
	case HeaderTypeSessionRequest, HeaderTypeTokenRequest:
		k1, k2, err = hpm.keysForIntroProtected()
	case HeaderTypeHolePunch:
		// Per spec: "Both header encryption keys are the receiver's intro key"
		// The receiver is always the remote peer, so use remoteIntroKey (G-8).
		k1, k2, err = hpm.keysForHolePunch()
	case HeaderTypeSessionCreated, HeaderTypeRetry:
		k1, k2, err = hpm.keysForSessionCreatedRetry(headerType)
	case HeaderTypeSessionConfirmed, HeaderTypeData:
		k1, k2, err = hpm.keysForKDFProtected(headerType)
	case HeaderTypePeerTest:
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

	if err != nil {
		return nil, err
	}
	return NewHeaderProtector(k1, k2, headerType)
}

// keysForIntroProtected returns keys for packets protected solely by intro keys
// (SessionRequest, TokenRequest).
func (hpm *HeaderProtectorManager) keysForIntroProtected() (k1, k2 []byte, err error) {
	if hpm.isInitiator {
		if len(hpm.remoteIntroKey) != HeaderKeySize {
			return nil, nil, oops.
				Code("MISSING_REMOTE_INTRO_KEY").
				In("ssu2").
				Errorf("remote intro key required for Session Request")
		}
		return hpm.remoteIntroKey, hpm.remoteIntroKey, nil
	}
	return hpm.introKey, hpm.introKey, nil
}

// keysForHolePunch returns keys for HolePunch packets.
// Per spec §HolePunch: "Both header encryption keys are the receiver's intro key."
// The receiver is always the remote peer, so we always use remoteIntroKey (G-8).
func (hpm *HeaderProtectorManager) keysForHolePunch() (k1, k2 []byte, err error) {
	if len(hpm.remoteIntroKey) != HeaderKeySize {
		return nil, nil, oops.
			Code("MISSING_REMOTE_INTRO_KEY").
			In("ssu2").
			Errorf("remote intro key required for HolePunch header protection")
	}
	return hpm.remoteIntroKey, hpm.remoteIntroKey, nil
}

// keysForSessionCreatedRetry returns keys for SessionCreated or Retry packets.
// Retry uses the sender's intro key for both k1 and k2.
// SessionCreated uses the intro key for k1 and requires KDF-derived k2 per spec.
func (hpm *HeaderProtectorManager) keysForSessionCreatedRetry(headerType HeaderType) (k1, k2 []byte, err error) {
	base := hpm.introKey
	if hpm.isInitiator {
		if len(hpm.remoteIntroKey) != HeaderKeySize {
			return nil, nil, oops.
				Code("MISSING_REMOTE_INTRO_KEY").
				In("ssu2").
				Errorf("remote intro key required for Session Created/Retry")
		}
		base = hpm.remoteIntroKey
	}

	k1 = base
	if headerType == HeaderTypeRetry {
		k2 = base
	} else if len(hpm.sessCreateHeader2) == HeaderKeySize {
		k2 = hpm.sessCreateHeader2
	} else {
		return nil, nil, oops.
			Code("MISSING_KDF_KEY").
			In("ssu2").
			Errorf("SessCreateHeader k_header_2 required for SessionCreated per spec")
	}
	return k1, k2, nil
}

// keysForKDFProtected returns keys for packets protected by KDF-derived keys
// (SessionConfirmed, Data).
func (hpm *HeaderProtectorManager) keysForKDFProtected(headerType HeaderType) (k1, k2 []byte, err error) {
	if headerType == HeaderTypeSessionConfirmed {
		// Spec: SessionConfirmed uses k_header_1 = Bob's intro key (bik),
		// k_header_2 = KDF-derived from SessionCreated.
		if hpm.isInitiator {
			if len(hpm.remoteIntroKey) != HeaderKeySize {
				return nil, nil, oops.
					Code("MISSING_REMOTE_INTRO_KEY").
					In("ssu2").
					Errorf("remote intro key (bik) required for SessionConfirmed k_header_1")
			}
			k1 = hpm.remoteIntroKey
		} else {
			k1 = hpm.introKey
		}
		if len(hpm.sessionConfirmedHeader2) != HeaderKeySize {
			return nil, nil, oops.
				Code("MISSING_KDF_KEY").
				In("ssu2").
				Errorf("SessionConfirmed k_header_2 required (from \"SessionConfirmed\" KDF)")
		}
		return k1, hpm.sessionConfirmedHeader2, nil
	}

	// Data phase: k_header_1 = receiver's intro key per spec.
	// Direction-dependent keys are returned for the outbound (encrypt) path.
	// For inbound, getDataInboundKeys() is used directly.
	if len(hpm.remoteIntroKey) != HeaderKeySize {
		return nil, nil, oops.
			Code("MISSING_REMOTE_INTRO_KEY").
			In("ssu2").
			Errorf("remote intro key required for Data phase k_header_1")
	}
	if len(hpm.sendDataHeader2) != HeaderKeySize {
		return nil, nil, oops.
			Code("MISSING_KDF_KEYS").
			In("ssu2").
			Errorf("send data k_header_2 required for Data packets")
	}
	return hpm.remoteIntroKey, hpm.sendDataHeader2, nil
}

// SetKDFKeys sets the KDF-derived header protection keys for the data phase.
// sendKH2 is the k_header_2 for outbound Data packets.
// recvKH2 is the k_header_2 for inbound Data packets.
func (hpm *HeaderProtectorManager) SetKDFKeys(sendKH2, recvKH2 []byte) error {
	if len(sendKH2) != HeaderKeySize {
		return oops.
			Code("INVALID_KEY_SIZE").
			In("ssu2").
			With("key", "sendKH2").
			Errorf("sendKH2 must be exactly %d bytes", HeaderKeySize)
	}
	if len(recvKH2) != HeaderKeySize {
		return oops.
			Code("INVALID_KEY_SIZE").
			In("ssu2").
			With("key", "recvKH2").
			Errorf("recvKH2 must be exactly %d bytes", HeaderKeySize)
	}

	hpm.mu.Lock()
	defer hpm.mu.Unlock()

	hpm.sendDataHeader2 = make([]byte, HeaderKeySize)
	hpm.recvDataHeader2 = make([]byte, HeaderKeySize)
	copy(hpm.sendDataHeader2, sendKH2)
	copy(hpm.recvDataHeader2, recvKH2)

	return nil
}

// SetSessCreateHeaderKey sets the k_header_2 for SessionCreated header
// protection, derived from the chainKey after handshake message 1 using
// info string "SessCreateHeader".
func (hpm *HeaderProtectorManager) SetSessCreateHeaderKey(key []byte) error {
	if len(key) != HeaderKeySize {
		return oops.
			Code("INVALID_KEY_SIZE").
			In("ssu2").
			Errorf("SessCreateHeader key must be exactly %d bytes", HeaderKeySize)
	}
	hpm.mu.Lock()
	defer hpm.mu.Unlock()
	hpm.sessCreateHeader2 = make([]byte, HeaderKeySize)
	copy(hpm.sessCreateHeader2, key)
	return nil
}

// SetSessionConfirmedHeaderKey sets the k_header_2 for SessionConfirmed
// header protection, derived from the chainKey after handshake message 2
// using info string "SessionConfirmed".
func (hpm *HeaderProtectorManager) SetSessionConfirmedHeaderKey(key []byte) error {
	if len(key) != HeaderKeySize {
		return oops.
			Code("INVALID_KEY_SIZE").
			In("ssu2").
			Errorf("SessionConfirmed header key must be exactly %d bytes", HeaderKeySize)
	}
	hpm.mu.Lock()
	defer hpm.mu.Unlock()
	hpm.sessionConfirmedHeader2 = make([]byte, HeaderKeySize)
	copy(hpm.sessionConfirmedHeader2, key)
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
// For Data packets, uses direction-aware inbound keys (introKey + recvDataHeader2).
// For other types, uses the standard key selection via GetProtectorForType.
func (hpm *HeaderProtectorManager) DecryptInboundHeader(packet []byte, headerType HeaderType) error {
	if headerType == HeaderTypeData {
		hpm.mu.RLock()
		k1, k2, err := hpm.getDataInboundKeys()
		hpm.mu.RUnlock()
		if err != nil {
			return err
		}
		protector, err := NewHeaderProtector(k1, k2, headerType)
		if err != nil {
			return err
		}
		return protector.DecryptHeader(packet)
	}
	protector, err := hpm.GetProtectorForType(headerType)
	if err != nil {
		return err
	}
	return protector.DecryptHeader(packet)
}

// getDataInboundKeys returns the keys for decrypting inbound Data packets.
// k_header_1 = our intro key (we are the receiver), k_header_2 = recv-direction KDF key.
// Must be called with hpm.mu held (at least RLock).
func (hpm *HeaderProtectorManager) getDataInboundKeys() (k1, k2 []byte, err error) {
	if len(hpm.introKey) != HeaderKeySize {
		return nil, nil, oops.
			Code("MISSING_INTRO_KEY").
			In("ssu2").
			Errorf("own intro key required for inbound Data k_header_1")
	}
	if len(hpm.recvDataHeader2) != HeaderKeySize {
		return nil, nil, oops.
			Code("MISSING_KDF_KEYS").
			In("ssu2").
			Errorf("recv data k_header_2 required for inbound Data packets")
	}
	return hpm.introKey, hpm.recvDataHeader2, nil
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
