package ssu2

import (
	"crypto/ed25519"
	"encoding/binary"
	"net"

	"github.com/go-i2p/common/data"
	"github.com/samber/oops"
)

// PeerTestPrologue is prepended to signed data for peer test messages.
// 16 bytes, not null-terminated, per SSU2 spec §Peer Test.
const PeerTestPrologue = "PeerTestValidate"

// BuildPeerTestSignedData constructs the data to be signed for a peer test message.
//
// Per SSU2 spec §Peer Test, the signed data is:
//   - prologue: 16 bytes "PeerTestValidate"
//   - bhash: Bob's 32-byte router hash
//   - ahash: Alice's 32-byte router hash (only for messages 3 and 4)
//   - ver: 1 byte
//   - nonce: 4 bytes
//   - timestamp: 4 bytes
//   - asz: 1 byte (6 or 18)
//   - AlicePort: 2 bytes
//   - AliceIP: (asz-2) bytes
//
// Set aliceHash to nil for messages 1 and 2.
func BuildPeerTestSignedData(
	bobHash data.Hash,
	aliceHash *data.Hash,
	version uint8,
	nonce, timestamp uint32,
	alicePort uint16,
	aliceIP net.IP,
) ([]byte, error) {
	ip4 := aliceIP.To4()
	var ipBytes []byte
	var asz uint8
	if ip4 != nil {
		ipBytes = ip4
		asz = 6
	} else {
		ipBytes = aliceIP.To16()
		if ipBytes == nil {
			return nil, oops.Errorf("invalid aliceIP")
		}
		asz = 18
	}

	// prologue(16) + bhash(32) + [ahash(32)] + ver(1) + nonce(4) + timestamp(4) + asz(1) + port(2) + ip
	size := 16 + 32 + 1 + 4 + 4 + 1 + 2 + len(ipBytes)
	if aliceHash != nil {
		size += 32
	}

	buf := make([]byte, size)
	off := 0

	copy(buf[off:], PeerTestPrologue)
	off += 16
	copy(buf[off:], bobHash[:])
	off += 32
	if aliceHash != nil {
		copy(buf[off:], aliceHash[:])
		off += 32
	}
	buf[off] = version
	off++
	binary.BigEndian.PutUint32(buf[off:], nonce)
	off += 4
	binary.BigEndian.PutUint32(buf[off:], timestamp)
	off += 4
	buf[off] = asz
	off++
	binary.BigEndian.PutUint16(buf[off:], alicePort)
	off += 2
	copy(buf[off:], ipBytes)

	return buf, nil
}

// SignPeerTest signs peer test data using the signer's Ed25519 private key.
// For messages 1/2, aliceHash should be nil. For messages 3/4, aliceHash must be provided.
func SignPeerTest(
	privateKey ed25519.PrivateKey,
	bobHash data.Hash, aliceHash *data.Hash,
	version uint8,
	nonce, timestamp uint32,
	alicePort uint16,
	aliceIP net.IP,
) ([]byte, error) {
	data, err := BuildPeerTestSignedData(bobHash, aliceHash, version, nonce, timestamp, alicePort, aliceIP)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to build peer test signed data")
	}
	return ed25519.Sign(privateKey, data), nil
}

// VerifyPeerTestSignature verifies a peer test signature.
// For messages 1/2, aliceHash should be nil. For messages 3/4, aliceHash must be provided.
func VerifyPeerTestSignature(
	publicKey ed25519.PublicKey,
	signature []byte,
	bobHash data.Hash, aliceHash *data.Hash,
	version uint8,
	nonce, timestamp uint32,
	alicePort uint16,
	aliceIP net.IP,
) (bool, error) {
	data, err := BuildPeerTestSignedData(bobHash, aliceHash, version, nonce, timestamp, alicePort, aliceIP)
	if err != nil {
		return false, oops.Wrapf(err, "failed to build peer test signed data for verification")
	}
	return ed25519.Verify(publicKey, data, signature), nil
}
