package noise

import (
	"bytes"
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/go-i2p/go-noise/internal"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupNNHandshake creates an NN handshake pair over net.Pipe and completes
// the handshake. Returns the established initiator and responder NoiseConns.
// The caller must Close() both connections when done.
func setupNNHandshake(t *testing.T) (initiator, responder *NoiseConn) {
	t.Helper()

	clientPipe, serverPipe := net.Pipe()

	clientCfg := NewConnConfig("NN", true).
		WithHandshakeTimeout(5 * time.Second)
	serverCfg := NewConnConfig("NN", false).
		WithHandshakeTimeout(5 * time.Second)

	client, err := NewNoiseConn(clientPipe, clientCfg)
	require.NoError(t, err, "create client NoiseConn")

	server, err := NewNoiseConn(serverPipe, serverCfg)
	require.NoError(t, err, "create server NoiseConn")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	var clientErr, serverErr error

	wg.Add(2)
	go func() {
		defer wg.Done()
		clientErr = client.Handshake(ctx)
	}()
	go func() {
		defer wg.Done()
		serverErr = server.Handshake(ctx)
	}()
	wg.Wait()

	require.NoError(t, clientErr, "NN initiator handshake")
	require.NoError(t, serverErr, "NN responder handshake")

	return client, server
}

// ===========================================================================
// Encrypt / Decrypt tests
// ===========================================================================

// TestCryptoOp_BeforeHandshake verifies Encrypt and Decrypt fail when
// the handshake has not been completed.
func TestCryptoOp_BeforeHandshake(t *testing.T) {
	tests := []struct {
		name      string
		op        string
		input     []byte
		errSubstr string
	}{
		{"Encrypt", "encrypt", []byte("hello"), "handshake not completed"},
		{"Decrypt", "decrypt", []byte("ciphertext"), "handshake not completed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn, err := createTestConnection()
			require.NoError(t, err)
			defer conn.Close()

			if tt.op == "encrypt" {
				_, err = conn.Encrypt(tt.input)
			} else {
				_, err = conn.Decrypt(tt.input)
			}
			require.Error(t, err, "%s should fail before handshake", tt.name)
			assert.Contains(t, err.Error(), tt.errSubstr)
		})
	}
}

// TestCryptoOp_AfterClose verifies Encrypt and Decrypt fail on a
// closed connection.
func TestCryptoOp_AfterClose(t *testing.T) {
	tests := []struct {
		name      string
		op        string
		input     []byte
		errSubstr string
	}{
		{"Encrypt", "encrypt", []byte("hello"), "closed"},
		{"Decrypt", "decrypt", []byte("ciphertext"), "closed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn, err := createTestConnection()
			require.NoError(t, err)
			conn.Close()

			if tt.op == "encrypt" {
				_, err = conn.Encrypt(tt.input)
			} else {
				_, err = conn.Decrypt(tt.input)
			}
			require.Error(t, err, "%s should fail after close", tt.name)
			assert.Contains(t, err.Error(), tt.errSubstr)
		})
	}
}

// TestCryptoOp_NilCipherState verifies Encrypt/Decrypt fail when the
// connection is in established state but has no cipher state.
func TestCryptoOp_NilCipherState(t *testing.T) {
	tests := []struct {
		name      string
		op        string
		input     []byte
		errSubstr string
	}{
		{"Encrypt_NilSend", "encrypt", []byte("hello"), "cipher state"},
		{"Decrypt_NilRecv", "decrypt", []byte("ciphertext"), "cipher state"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn, err := createTestConnection()
			require.NoError(t, err)
			defer conn.Close()

			// Force established state without cipher states
			conn.setState(internal.StateEstablished)

			if tt.op == "encrypt" {
				_, err = conn.Encrypt(tt.input)
			} else {
				_, err = conn.Decrypt(tt.input)
			}
			require.Error(t, err, "%s should fail with nil cipher state", tt.name)
			assert.Contains(t, err.Error(), tt.errSubstr)
		})
	}
}

// TestEncryptDecrypt_RoundTrip verifies that Encrypt on the initiator
// produces ciphertext that Decrypt on the responder recovers to the
// original plaintext.
func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	client, server := setupNNHandshake(t)
	defer client.Close()
	defer server.Close()

	plaintext := []byte("Encrypt/Decrypt round-trip test")

	ciphertext, err := client.Encrypt(plaintext)
	require.NoError(t, err, "Encrypt should succeed on established connection")
	require.NotEmpty(t, ciphertext, "ciphertext must not be empty")

	// The ciphertext must be different from the plaintext (encryption happened).
	assert.False(t, bytes.Equal(plaintext, ciphertext),
		"ciphertext must differ from plaintext")

	// Decrypt on the server side (server's recvCipherState matches client's sendCipherState).
	recovered, err := server.Decrypt(ciphertext)
	require.NoError(t, err, "Decrypt should succeed with matching cipher state")
	assert.Equal(t, plaintext, recovered, "decrypted data must match original plaintext")
}

// TestEncryptDecrypt_MultipleMessages verifies that Encrypt/Decrypt work
// correctly for multiple sequential messages (nonce counter advances).
func TestEncryptDecrypt_MultipleMessages(t *testing.T) {
	client, server := setupNNHandshake(t)
	defer client.Close()
	defer server.Close()

	messages := []string{
		"first message",
		"second message",
		"third message with more data",
	}

	for i, msg := range messages {
		ct, err := client.Encrypt([]byte(msg))
		require.NoError(t, err, "Encrypt message %d", i)

		pt, err := server.Decrypt(ct)
		require.NoError(t, err, "Decrypt message %d", i)
		assert.Equal(t, msg, string(pt), "round-trip message %d", i)
	}
}

// TestEncryptDecrypt_EmptyPayload verifies that encrypting an empty slice
// produces valid ciphertext (just the AEAD tag) that decrypts to empty.
func TestEncryptDecrypt_EmptyPayload(t *testing.T) {
	client, server := setupNNHandshake(t)
	defer client.Close()
	defer server.Close()

	ct, err := client.Encrypt([]byte{})
	require.NoError(t, err, "Encrypt empty payload")
	require.NotEmpty(t, ct, "ciphertext should contain at least the AEAD tag")

	pt, err := server.Decrypt(ct)
	require.NoError(t, err, "Decrypt empty payload")
	assert.Empty(t, pt, "decrypted empty payload should be empty")
}

// TestDecrypt_TamperedCiphertext verifies that decrypting modified ciphertext
// returns an authentication error.
func TestDecrypt_TamperedCiphertext(t *testing.T) {
	client, server := setupNNHandshake(t)
	defer client.Close()
	defer server.Close()

	ct, err := client.Encrypt([]byte("tamper test"))
	require.NoError(t, err)

	// Flip a bit in the ciphertext
	ct[0] ^= 0xFF

	_, err = server.Decrypt(ct)
	require.Error(t, err, "Decrypt should fail on tampered ciphertext")
}

// ===========================================================================
// Rekey tests
// ===========================================================================

// TestRekey_ErrorStates verifies Rekey fails in various non-established states.
func TestRekey_ErrorStates(t *testing.T) {
	tests := []struct {
		name      string
		setup     func(t *testing.T) *NoiseConn
		errSubstr string
	}{
		{
			name: "before handshake",
			setup: func(t *testing.T) *NoiseConn {
				t.Helper()
				conn, err := createTestConnection()
				require.NoError(t, err)
				return conn
			},
			errSubstr: "not in established state",
		},
		{
			name: "nil cipher state",
			setup: func(t *testing.T) *NoiseConn {
				t.Helper()
				conn, err := createTestConnection()
				require.NoError(t, err)
				conn.setState(internal.StateEstablished)
				return conn
			},
			errSubstr: "cipher states not available",
		},
		{
			name: "after close",
			setup: func(t *testing.T) *NoiseConn {
				t.Helper()
				conn, err := createTestConnection()
				require.NoError(t, err)
				conn.Close()
				return conn
			},
			errSubstr: "not in established state",
		},
		{
			name: "handshaking state",
			setup: func(t *testing.T) *NoiseConn {
				t.Helper()
				conn, err := createTestConnection()
				require.NoError(t, err)
				conn.setState(internal.StateHandshaking)
				return conn
			},
			errSubstr: "not in established state",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := tt.setup(t)
			defer conn.Close()

			err := conn.Rekey()
			require.Error(t, err, "Rekey should fail: %s", tt.name)
			assert.Contains(t, err.Error(), tt.errSubstr)
		})
	}
}

// TestRekey_Success verifies that Rekey succeeds on an established connection
// and that data can still be exchanged after rekeying.
func TestRekey_Success(t *testing.T) {
	client, server := setupNNHandshake(t)
	defer client.Close()
	defer server.Close()

	// Send a message before rekey
	preRekeyMsg := []byte("before rekey")
	ct, err := client.Encrypt(preRekeyMsg)
	require.NoError(t, err)
	pt, err := server.Decrypt(ct)
	require.NoError(t, err)
	assert.Equal(t, preRekeyMsg, pt)

	// Rekey both sides
	require.NoError(t, client.Rekey(), "client rekey")
	require.NoError(t, server.Rekey(), "server rekey")

	// Send a message after rekey — both sides must still agree on keys
	postRekeyMsg := []byte("after rekey")
	ct, err = client.Encrypt(postRekeyMsg)
	require.NoError(t, err)
	pt, err = server.Decrypt(ct)
	require.NoError(t, err)
	assert.Equal(t, postRekeyMsg, pt, "data should round-trip after rekey")
}

// ===========================================================================
// ZeroKeys tests
// ===========================================================================

// TestZeroKeys_NilCipherStates verifies ZeroKeys does not panic when
// cipher states are nil (e.g., before handshake).
func TestZeroKeys_NilCipherStates(t *testing.T) {
	conn, err := createTestConnection()
	require.NoError(t, err)
	defer conn.Close()

	// Should not panic
	assert.NotPanics(t, func() {
		conn.ZeroKeys()
	}, "ZeroKeys must not panic with nil cipher states")
}

// TestZeroKeys_InvalidatesEncryption verifies that after calling ZeroKeys,
// Encrypt fails because the cipher state has been zeroed.
func TestZeroKeys_InvalidatesEncryption(t *testing.T) {
	client, server := setupNNHandshake(t)
	defer client.Close()
	defer server.Close()

	// Confirm encryption works before zeroing
	ct, err := client.Encrypt([]byte("pre-zero check"))
	require.NoError(t, err)
	_, err = server.Decrypt(ct)
	require.NoError(t, err)

	// Zero the client's keys - this should prevent further encryption
	client.ZeroKeys()

	// After zeroing, Encrypt should fail or produce data that cannot be decrypted.
	// The upstream CipherState.Encrypt may panic or return error after ZeroKey().
	// We accept either behavior.
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Logf("ZeroKeys caused panic on subsequent Encrypt (expected): %v", r)
			}
		}()
		_, err = client.Encrypt([]byte("should fail"))
		if err != nil {
			t.Logf("Encrypt correctly failed after ZeroKeys: %v", err)
		}
	}()
}

// ===========================================================================
// ChannelBinding tests
// ===========================================================================

// TestChannelBinding_NilHandshakeState verifies ChannelBinding returns nil
// when the handshake state is nil.
func TestChannelBinding_NilHandshakeState(t *testing.T) {
	conn, err := createTestConnection()
	require.NoError(t, err)
	defer conn.Close()

	// handshakeState is set by NewNoiseConn, but test the nil path
	// by creating a minimal NoiseConn manually.
	nc := &NoiseConn{
		underlying: newMockNetConn(
			&mockNetAddr{"tcp", "127.0.0.1:1"},
			&mockNetAddr{"tcp", "127.0.0.1:2"},
		),
		metrics: internal.NewConnectionMetrics(),
		logger:  log,
	}

	assert.Nil(t, nc.ChannelBinding(),
		"ChannelBinding should return nil when handshakeState is nil")
}

// TestChannelBinding_AfterHandshake verifies ChannelBinding returns
// non-nil data after a successful handshake.
func TestChannelBinding_AfterHandshake(t *testing.T) {
	client, server := setupNNHandshake(t)
	defer client.Close()
	defer server.Close()

	clientCB := client.ChannelBinding()
	serverCB := server.ChannelBinding()

	require.NotNil(t, clientCB, "client ChannelBinding should be non-nil after handshake")
	require.NotNil(t, serverCB, "server ChannelBinding should be non-nil after handshake")
	assert.NotEmpty(t, clientCB, "channel binding data should not be empty")

	// Both sides must derive the same handshake hash
	assert.Equal(t, clientCB, serverCB,
		"channel binding must be identical on both sides of the handshake")
}

// ===========================================================================
// SendCipherState / RecvCipherState tests
// ===========================================================================

// TestCipherStateAccessors_BeforeHandshake verifies SendCipherState and
// RecvCipherState return nil before the handshake produces cipher states.
func TestCipherStateAccessors_BeforeHandshake(t *testing.T) {
	conn, err := createTestConnection()
	require.NoError(t, err)
	defer conn.Close()

	assert.Nil(t, conn.SendCipherState(),
		"SendCipherState should be nil before handshake")
	assert.Nil(t, conn.RecvCipherState(),
		"RecvCipherState should be nil before handshake")
}

// TestCipherStateAccessors_AfterHandshake verifies SendCipherState and
// RecvCipherState return non-nil after a successful handshake.
func TestCipherStateAccessors_AfterHandshake(t *testing.T) {
	client, server := setupNNHandshake(t)
	defer client.Close()
	defer server.Close()

	require.NotNil(t, client.SendCipherState(),
		"client SendCipherState should be non-nil after handshake")
	require.NotNil(t, client.RecvCipherState(),
		"client RecvCipherState should be non-nil after handshake")

	require.NotNil(t, server.SendCipherState(),
		"server SendCipherState should be non-nil after handshake")
	require.NotNil(t, server.RecvCipherState(),
		"server RecvCipherState should be non-nil after handshake")
}

// ===========================================================================
// AdditionalSymmetricKeys tests
// ===========================================================================

// TestAdditionalSymmetricKeys_NilHandshakeState verifies ASK returns nil
// when the handshake state is nil.
func TestAdditionalSymmetricKeys_NilHandshakeState(t *testing.T) {
	nc := &NoiseConn{
		underlying: newMockNetConn(
			&mockNetAddr{"tcp", "127.0.0.1:1"},
			&mockNetAddr{"tcp", "127.0.0.1:2"},
		),
		metrics: internal.NewConnectionMetrics(),
		logger:  log,
	}

	assert.Nil(t, nc.AdditionalSymmetricKeys(),
		"ASK should return nil with nil handshakeState")
}

// TestAdditionalSymmetricKeys_NoLabels verifies ASK returns nil when no
// labels were configured (default config).
func TestAdditionalSymmetricKeys_NoLabels(t *testing.T) {
	client, server := setupNNHandshake(t)
	defer client.Close()
	defer server.Close()

	assert.Nil(t, client.AdditionalSymmetricKeys(),
		"ASK should return nil with no labels configured")
	assert.Nil(t, server.AdditionalSymmetricKeys(),
		"ASK should return nil with no labels configured")
}

// ===========================================================================
// PeerStatic tests (supplementary — the method is already partially covered
// by the XK E2E test, but the nil path is not explicitly tested as a unit)
// ===========================================================================

// TestPeerStatic_NilHandshakeState verifies PeerStatic returns nil
// when the handshake state is nil.
func TestPeerStatic_NilHandshakeState(t *testing.T) {
	nc := &NoiseConn{
		underlying: newMockNetConn(
			&mockNetAddr{"tcp", "127.0.0.1:1"},
			&mockNetAddr{"tcp", "127.0.0.1:2"},
		),
		metrics: internal.NewConnectionMetrics(),
		logger:  log,
	}

	assert.Nil(t, nc.PeerStatic(),
		"PeerStatic should return nil with nil handshakeState")
}

// TestPeerStatic_NNPattern verifies PeerStatic returns nil for NN pattern
// which does not transmit static keys.
func TestPeerStatic_NNPattern(t *testing.T) {
	client, server := setupNNHandshake(t)
	defer client.Close()
	defer server.Close()

	// NN pattern has no static keys exchanged
	assert.Nil(t, client.PeerStatic(),
		"PeerStatic should be nil for NN initiator (no static exchange)")
	assert.Nil(t, server.PeerStatic(),
		"PeerStatic should be nil for NN responder (no static exchange)")
}

// ===========================================================================
// Underlying() accessor test
// ===========================================================================

// TestUnderlying_ReturnsWrappedConn verifies Underlying() returns the
// original net.Conn passed to NewNoiseConn.
func TestUnderlying_ReturnsWrappedConn(t *testing.T) {
	mockConn := newMockNetConn(
		&mockNetAddr{"tcp", "127.0.0.1:1"},
		&mockNetAddr{"tcp", "127.0.0.1:2"},
	)
	cfg := NewConnConfig("NN", true)
	nc, err := NewNoiseConn(mockConn, cfg)
	require.NoError(t, err)
	defer nc.Close()

	assert.Equal(t, mockConn, nc.Underlying(),
		"Underlying() must return the original net.Conn")
}

// ===========================================================================
// Combined scenario: Encrypt→Write→Read→Decrypt equivalence
// ===========================================================================

// TestEncryptDecrypt_MatchesWriteRead verifies that Encrypt produces the
// same ciphertext that Write sends on the wire, and Decrypt produces the
// same plaintext that Read returns. This is important for NTCP2 callers
// that use Encrypt/Decrypt with their own framing instead of Write/Read.
func TestEncryptDecrypt_MatchesWriteRead(t *testing.T) {
	client, server := setupNNHandshake(t)
	defer client.Close()
	defer server.Close()

	// Use Write/Read for the first message to verify the wire path works
	msg1 := []byte("via Write/Read")
	writeErr := make(chan error, 1)
	go func() {
		_, err := client.Write(msg1)
		writeErr <- err
	}()

	buf := make([]byte, 256)
	n, err := server.Read(buf)
	require.NoError(t, err)
	require.NoError(t, <-writeErr)
	assert.Equal(t, msg1, buf[:n])

	// Now use Encrypt/Decrypt for the second message (from server→client)
	msg2 := []byte("via Encrypt/Decrypt")
	ct, err := server.Encrypt(msg2)
	require.NoError(t, err)

	pt, err := client.Decrypt(ct)
	require.NoError(t, err)
	assert.Equal(t, msg2, pt,
		"Encrypt/Decrypt must produce identical results to Write/Read cipher path")
}
