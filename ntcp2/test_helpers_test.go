package ntcp2

import (
	"net"
	"testing"

	"github.com/go-i2p/crypto/rand"

	noise "github.com/go-i2p/go-noise"
	upstreamnoise "github.com/go-i2p/noise"
	"github.com/stretchr/testify/require"
)

// testNTCP2Listener holds a fully-wired NTCP2 listener backed by a real
// TCP listener, with random router‐hash and config.
type testNTCP2Listener struct {
	listener   *NTCP2Listener
	tcpAddr    net.Addr
	routerHash []byte
}

// newTestNTCP2Listener creates a real TCP listener on localhost, generates a
// random router‐hash, and wraps both in an NTCP2Listener. The TCP and NTCP2
// listeners are registered with t.Cleanup.
func newTestNTCP2Listener(t *testing.T) testNTCP2Listener {
	t.Helper()
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { tcpLn.Close() })

	routerHash := make([]byte, 32)
	_, err = rand.Read(routerHash)
	require.NoError(t, err)

	config, err := NewNTCP2Config(routerHash, false)
	require.NoError(t, err)

	ln, err := NewNTCP2Listener(tcpLn, config)
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })

	return testNTCP2Listener{
		listener:   ln,
		tcpAddr:    tcpLn.Addr(),
		routerHash: routerHash,
	}
}

// pipedNTCP2Conn holds all the pieces created by newPipedNTCP2Conn, so
// callers can access the raw pipe ends and the SipHash modifier, if set.
type pipedNTCP2Conn struct {
	conn    *NTCP2Conn
	client  net.Conn // client end of net.Pipe (used by NoiseConn)
	server  net.Conn // server end of net.Pipe (for test writes/reads)
	noise   *noise.NoiseConn
	localA  *NTCP2Addr
	remoteA *NTCP2Addr
}

// newPipedNTCP2Conn creates an *NTCP2Conn backed by a net.Pipe(), wired
// through a NoiseConn with the XK pattern. Both pipe ends are registered
// with t.Cleanup so callers don't need explicit defers.
func newPipedNTCP2Conn(t *testing.T) pipedNTCP2Conn {
	t.Helper()
	client, server := net.Pipe()
	t.Cleanup(func() { client.Close(); server.Close() })

	config := noise.NewConnConfig("XK", true)
	noiseConn, err := noise.NewNoiseConn(client, config)
	require.NoError(t, err)
	t.Cleanup(func() { noiseConn.Close() })

	localAddr := createTestNTCP2Addr("local", "initiator")
	remoteAddr := createTestNTCP2Addr("remote", "responder")
	conn, err := NewNTCP2Conn(noiseConn, localAddr, remoteAddr)
	require.NoError(t, err)

	return pipedNTCP2Conn{
		conn:    conn,
		client:  client,
		server:  server,
		noise:   noiseConn,
		localA:  localAddr,
		remoteA: remoteAddr,
	}
}

// withSipHash attaches a SipHashLengthModifier with the given keys to the
// connection and returns the modifier (useful for mask probing).
func (p pipedNTCP2Conn) withSipHash(keys [2]uint64) *SipHashLengthModifier {
	slm := NewSipHashLengthModifier("test", keys, 0)
	p.conn.SetLengthObfuscator(slm)
	return slm
}

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
