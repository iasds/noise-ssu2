package ssu2

import (
	"crypto/ed25519"
	"encoding/binary"
	"net"

	"github.com/go-i2p/common/data"
	"github.com/samber/oops"
)

// Relay signature prologues per SSU2 spec §Relay Request and §Relay Response.
const (
	// RelayRequestPrologue is prepended to signed data for relay requests.
	// 16 bytes, not null-terminated.
	RelayRequestPrologue = "RelayRequestData"

	// RelayAgreementPrologue is prepended to signed data for relay responses.
	// 16 bytes, not null-terminated.
	RelayAgreementPrologue = "RelayAgreementOK"
)

// BuildRelayRequestSignedData constructs the data to be signed for a relay request.
//
// Per SSU2 spec §Relay Request, the signed data is:
//   - prologue: 16 bytes "RelayRequestData"
//   - bhash: Bob's 32-byte router hash
//   - chash: Charlie's 32-byte router hash
//   - nonce: 4 bytes
//   - relay tag: 4 bytes
//   - timestamp: 4 bytes
//   - ver: 1 byte
//   - asz: 1 byte (6 for IPv4, 18 for IPv6)
//   - AlicePort: 2 bytes
//   - AliceIP: (asz-2) bytes
func BuildRelayRequestSignedData(
	bobHash, charlieHash data.Hash,
	nonce, relayTag, timestamp uint32,
	version uint8,
	alicePort uint16,
	aliceIP net.IP,
) ([]byte, error) {
	ipBytes, asz, err := normalizeIP(aliceIP)
	if err != nil {
		return nil, oops.Wrapf(err, "invalid aliceIP")
	}

	// prologue(16) + bhash(32) + chash(32) + nonce(4) + relayTag(4) + timestamp(4) + ver(1) + asz(1) + port(2) + ip
	size := 16 + 32 + 32 + 4 + 4 + 4 + 1 + 1 + 2 + len(ipBytes)
	buf := make([]byte, size)
	off := 0

	copy(buf[off:], RelayRequestPrologue)
	off += 16
	copy(buf[off:], bobHash[:])
	off += 32
	copy(buf[off:], charlieHash[:])
	off += 32
	binary.BigEndian.PutUint32(buf[off:], nonce)
	off += 4
	binary.BigEndian.PutUint32(buf[off:], relayTag)
	off += 4
	binary.BigEndian.PutUint32(buf[off:], timestamp)
	off += 4
	buf[off] = version
	off++
	buf[off] = asz
	off++
	binary.BigEndian.PutUint16(buf[off:], alicePort)
	off += 2
	copy(buf[off:], ipBytes)

	return buf, nil
}

// SignRelayRequest signs a relay request using Alice's Ed25519 private key.
func SignRelayRequest(
	privateKey ed25519.PrivateKey,
	bobHash, charlieHash data.Hash,
	nonce, relayTag, timestamp uint32,
	version uint8,
	alicePort uint16,
	aliceIP net.IP,
) ([]byte, error) {
	data, err := BuildRelayRequestSignedData(bobHash, charlieHash, nonce, relayTag, timestamp, version, alicePort, aliceIP)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to build relay request signed data")
	}
	return signData(privateKey, data), nil
}

// VerifyRelayRequestSignature verifies a relay request signature using Alice's Ed25519 public key.
func VerifyRelayRequestSignature(
	publicKey ed25519.PublicKey,
	signature []byte,
	bobHash, charlieHash data.Hash,
	nonce, relayTag, timestamp uint32,
	version uint8,
	alicePort uint16,
	aliceIP net.IP,
) (bool, error) {
	data, err := BuildRelayRequestSignedData(bobHash, charlieHash, nonce, relayTag, timestamp, version, alicePort, aliceIP)
	if err != nil {
		return false, oops.Wrapf(err, "failed to build relay request signed data for verification")
	}
	return verifyData(publicKey, data, signature), nil
}

// BuildRelayResponseSignedData constructs the data to be signed for a relay response.
//
// Per SSU2 spec §Relay Response, the signed data is:
//   - prologue: 16 bytes "RelayAgreementOK"
//   - bhash: Bob's 32-byte router hash
//   - nonce: 4 bytes
//   - timestamp: 4 bytes
//   - ver: 1 byte
//   - csz: 1 byte (0, 6, or 18)
//   - CharliePort: 2 bytes (not present if csz is 0)
//   - CharlieIP: (csz-2) bytes (not present if csz is 0)
func BuildRelayResponseSignedData(
	bobHash data.Hash,
	nonce, timestamp uint32,
	version uint8,
	charliePort uint16,
	charlieIP net.IP,
) ([]byte, error) {
	ipBytes, csz, err := normalizeIP(charlieIP)
	if err != nil {
		return nil, oops.Wrapf(err, "invalid charlieIP")
	}

	// prologue(16) + bhash(32) + nonce(4) + timestamp(4) + ver(1) + csz(1) + [port(2) + ip]
	size := 16 + 32 + 4 + 4 + 1 + 1
	if csz > 0 {
		size += 2 + len(ipBytes)
	}
	buf := make([]byte, size)
	off := 0

	copy(buf[off:], RelayAgreementPrologue)
	off += 16
	copy(buf[off:], bobHash[:])
	off += 32
	binary.BigEndian.PutUint32(buf[off:], nonce)
	off += 4
	binary.BigEndian.PutUint32(buf[off:], timestamp)
	off += 4
	buf[off] = version
	off++
	buf[off] = csz
	off++
	if csz > 0 {
		binary.BigEndian.PutUint16(buf[off:], charliePort)
		off += 2
		copy(buf[off:], ipBytes)
	}

	return buf, nil
}

// SignRelayResponse signs a relay response using the signer's Ed25519 private key.
// For accepted responses (code 0), Charlie signs. For Bob rejections (code 1-63), Bob signs.
func SignRelayResponse(
	privateKey ed25519.PrivateKey,
	bobHash data.Hash,
	nonce, timestamp uint32,
	version uint8,
	charliePort uint16,
	charlieIP net.IP,
) ([]byte, error) {
	data, err := BuildRelayResponseSignedData(bobHash, nonce, timestamp, version, charliePort, charlieIP)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to build relay response signed data")
	}
	return signData(privateKey, data), nil
}

// VerifyRelayResponseSignature verifies a relay response signature.
// For accepted responses (code 0), use Charlie's public key.
// For Bob rejections (code 1-63), use Bob's public key.
func VerifyRelayResponseSignature(
	publicKey ed25519.PublicKey,
	signature []byte,
	bobHash data.Hash,
	nonce, timestamp uint32,
	version uint8,
	charliePort uint16,
	charlieIP net.IP,
) (bool, error) {
	data, err := BuildRelayResponseSignedData(bobHash, nonce, timestamp, version, charliePort, charlieIP)
	if err != nil {
		return false, oops.Wrapf(err, "failed to build relay response signed data for verification")
	}
	return verifyData(publicKey, data, signature), nil
}
