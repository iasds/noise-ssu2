package ssu2

import (
	i2pbase64 "github.com/go-i2p/common/base64"
	"github.com/samber/oops"
)

// IntroKeyFromRouterAddress extracts the 32-byte introduction key from
// a RouterAddress options map. The "i" parameter is a 44-byte I2P
// Base64-encoded string representing the 32-byte ChaCha20 key used
// for header encryption.
//
// Per SSU2 spec §Published Router Address: "i=(Base64 key) — The current
// introduction key for encrypting the headers for this RouterAddress.
// Base 64 encoded using the standard I2P Base 64 alphabet. 32 bytes in
// binary, 44 bytes as Base 64 encoded, big-endian ChaCha20 key."
func IntroKeyFromRouterAddress(options map[string]string) ([]byte, error) {
	iParam, ok := options["i"]
	if !ok || iParam == "" {
		return nil, oops.Errorf("RouterAddress missing required 'i' (introduction key) parameter")
	}

	key, err := i2pbase64.I2PEncoding.DecodeString(iParam)
	if err != nil {
		return nil, oops.Wrapf(err, "invalid Base64 in 'i' parameter")
	}

	if len(key) != 32 {
		return nil, oops.Errorf("introduction key must be 32 bytes, got %d", len(key))
	}

	return key, nil
}

// StaticKeyFromRouterAddress extracts the 32-byte static public key from
// a RouterAddress options map. The "s" parameter is a 44-byte I2P
// Base64-encoded string representing the X25519 public key.
func StaticKeyFromRouterAddress(options map[string]string) ([]byte, error) {
	sParam, ok := options["s"]
	if !ok || sParam == "" {
		return nil, oops.Errorf("RouterAddress missing required 's' (static key) parameter")
	}

	key, err := i2pbase64.I2PEncoding.DecodeString(sParam)
	if err != nil {
		return nil, oops.Wrapf(err, "invalid Base64 in 's' parameter")
	}

	if len(key) != 32 {
		return nil, oops.Errorf("static key must be 32 bytes, got %d", len(key))
	}

	return key, nil
}
