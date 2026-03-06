package ntcp2

import (
	"testing"

	"github.com/go-i2p/crypto/rand"

	upstreamnoise "github.com/go-i2p/noise"
	"github.com/stretchr/testify/require"
)

// testCryptoMaterial holds random byte slices commonly needed by NTCP2 tests.
type testCryptoMaterial struct {
	routerHash    []byte
	staticKey     []byte
	remoteHash    []byte
	obfuscationIV []byte
}

// newTestCryptoMaterial generates random test key material for NTCP2 tests.
func newTestCryptoMaterial(t *testing.T) testCryptoMaterial {
	t.Helper()
	return testCryptoMaterial{
		routerHash:    generateRandomBytes(32),
		staticKey:     generateRandomBytes(32),
		remoteHash:    generateRandomBytes(32),
		obfuscationIV: generateRandomBytes(16),
	}
}

// newTestInitiatorConfig creates a fully-configured NTCP2Config for an
// initiator with random key material, a remote static key, and AES obfuscation.
// Returns the config and the underlying crypto material for assertions.
func newTestInitiatorConfig(t *testing.T) (*NTCP2Config, testCryptoMaterial) {
	t.Helper()
	m := newTestCryptoMaterial(t)
	config := newTestInitiatorConfigFrom(t, m)
	return config, m
}

// newTestInitiatorConfigFrom builds a fully-configured initiator NTCP2Config
// from the given crypto material.
func newTestInitiatorConfigFrom(t *testing.T, m testCryptoMaterial) *NTCP2Config {
	t.Helper()
	config, err := NewNTCP2Config(m.routerHash, true)
	require.NoError(t, err)
	config, err = config.WithStaticKey(m.staticKey)
	require.NoError(t, err)
	config, err = config.WithRemoteRouterHash(m.remoteHash)
	require.NoError(t, err)
	config, err = config.WithRemoteStaticKey(generateRandomBytes(32))
	require.NoError(t, err)
	config, err = config.WithAESObfuscation(true, m.obfuscationIV)
	require.NoError(t, err)
	return config
}

// testXKConfigPair holds a matched initiator/responder config pair for XK tests.
type testXKConfigPair struct {
	initiatorConfig *NTCP2Config
	responderConfig *NTCP2Config
	initiatorHash   []byte
	responderHash   []byte
}

// newTestXKConfigPair creates a matched initiator+responder NTCP2Config pair
// with ChaChaPoly cipher suite, freshly generated Curve25519 keypairs,
// and deterministic router hashes. AES obfuscation is disabled.
func newTestXKConfigPair(t *testing.T) testXKConfigPair {
	t.Helper()

	cs := upstreamnoise.NewCipherSuite(
		upstreamnoise.DH25519,
		upstreamnoise.CipherChaChaPoly,
		upstreamnoise.HashSHA256,
	)

	initiatorKP, err := cs.GenerateKeypair(rand.Reader)
	require.NoError(t, err)
	responderKP, err := cs.GenerateKeypair(rand.Reader)
	require.NoError(t, err)

	initiatorHash := make([]byte, RouterHashSize)
	copy(initiatorHash, "initiator-hash-32-bytes-long!!!!")
	responderHash := make([]byte, RouterHashSize)
	copy(responderHash, "responder-hash-32-bytes-long!!!!")

	responderConfig, err := NewNTCP2Config(responderHash, false)
	require.NoError(t, err)
	responderConfig, err = responderConfig.WithStaticKey(responderKP.Private)
	require.NoError(t, err)
	responderConfig, err = responderConfig.WithAESObfuscation(false, nil)
	require.NoError(t, err)

	initiatorConfig, err := NewNTCP2Config(initiatorHash, true)
	require.NoError(t, err)
	initiatorConfig, err = initiatorConfig.WithStaticKey(initiatorKP.Private)
	require.NoError(t, err)
	initiatorConfig, err = initiatorConfig.WithRemoteRouterHash(responderHash)
	require.NoError(t, err)
	initiatorConfig, err = initiatorConfig.WithRemoteStaticKey(responderKP.Public)
	require.NoError(t, err)
	initiatorConfig, err = initiatorConfig.WithAESObfuscation(false, nil)
	require.NoError(t, err)

	return testXKConfigPair{
		initiatorConfig: initiatorConfig,
		responderConfig: responderConfig,
		initiatorHash:   initiatorHash,
		responderHash:   responderHash,
	}
}
