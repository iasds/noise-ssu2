package ssu2

import (
	"crypto/ed25519"
	"net"

	"github.com/samber/oops"
)

// normalizeIP converts the given IP into its compact byte form and returns
// the corresponding address-size field value per SSU2 spec (6 for IPv4, 18
// for IPv6). A nil IP is valid and returns (nil, 0, nil).
func normalizeIP(ip net.IP) (ipBytes []byte, asz uint8, err error) {
	if ip == nil {
		return nil, 0, nil
	}
	if v4 := ip.To4(); v4 != nil {
		return v4, 6, nil
	}
	if v6 := ip.To16(); v6 != nil {
		return v6, 18, nil
	}
	return nil, 0, oops.Errorf("invalid IP address")
}

// signData signs the provided data with the given Ed25519 private key.
func signData(privateKey ed25519.PrivateKey, data []byte) []byte {
	return ed25519.Sign(privateKey, data)
}

// verifyData verifies an Ed25519 signature over the provided data.
func verifyData(publicKey ed25519.PublicKey, data, signature []byte) bool {
	return ed25519.Verify(publicKey, data, signature)
}
