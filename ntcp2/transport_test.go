package ntcp2

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/go-i2p/crypto/rand"

	upstreamnoise "github.com/go-i2p/noise"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// generateRandomBytes generates random bytes for testing
func generateRandomBytes(size int) []byte {
	bytes := make([]byte, size)
	rand.Read(bytes)
	return bytes
}

func TestDialNTCP2(t *testing.T) {
	tests := []struct {
		name        string
		setupConfig func() *NTCP2Config
		network     string
		addr        string
		expectError bool
		errorCode   string
	}{
		{
			name: "successful dial with valid config",
			setupConfig: func() *NTCP2Config {
				routerHash := generateRandomBytes(32)
				remoteHash := generateRandomBytes(32)
				staticKey := generateRandomBytes(32)

				config, err := NewNTCP2Config(routerHash, true)
				require.NoError(t, err)

				config, err = config.WithStaticKey(staticKey)
				require.NoError(t, err)
				config, err = config.WithRemoteRouterHash(remoteHash)
				require.NoError(t, err)
				config, err = config.WithRemoteStaticKey(generateRandomBytes(32))
				require.NoError(t, err)
				return config.
					WithHandshakeTimeout(5 * time.Second)
			},
			network:     "tcp",
			addr:        "127.0.0.1:0", // Use available port
			expectError: true,          // Will fail to connect since no server
			errorCode:   "failed to dial tcp://127.0.0.1:0",
		},
		{
			name: "invalid network parameter",
			setupConfig: func() *NTCP2Config {
				routerHash := generateRandomBytes(32)
				config, _ := NewNTCP2Config(routerHash, true)
				return config
			},
			network:     "",
			addr:        "127.0.0.1:8080",
			expectError: true,
			errorCode:   "network cannot be empty",
		},
		{
			name: "invalid address parameter",
			setupConfig: func() *NTCP2Config {
				routerHash := generateRandomBytes(32)
				config, _ := NewNTCP2Config(routerHash, true)
				return config
			},
			network:     "tcp",
			addr:        "",
			expectError: true,
			errorCode:   "address cannot be empty",
		},
		{
			name:        "nil config",
			setupConfig: func() *NTCP2Config { return nil },
			network:     "tcp",
			addr:        "127.0.0.1:8080",
			expectError: true,
			errorCode:   "config cannot be nil",
		},
		{
			name: "responder config for dial operation",
			setupConfig: func() *NTCP2Config {
				routerHash := generateRandomBytes(32)
				config, _ := NewNTCP2Config(routerHash, false) // responder
				return config
			},
			network:     "tcp",
			addr:        "127.0.0.1:8080",
			expectError: true,
			errorCode:   "dial operations require initiator=true in config",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := tt.setupConfig()

			conn, err := DialNTCP2(tt.network, tt.addr, config)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorCode != "" {
					assert.Contains(t, err.Error(), tt.errorCode)
				}
				assert.Nil(t, conn)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, conn)
				if conn != nil {
					conn.Close()
				}
			}
		})
	}
}

func TestListenNTCP2(t *testing.T) {
	tests := []struct {
		name        string
		setupConfig func() *NTCP2Config
		network     string
		addr        string
		expectError bool
		errorCode   string
	}{
		{
			name: "successful listen with valid config",
			setupConfig: func() *NTCP2Config {
				routerHash := generateRandomBytes(32)
				staticKey := generateRandomBytes(32)

				config, err := NewNTCP2Config(routerHash, false) // responder
				require.NoError(t, err)

				config, err = config.WithStaticKey(staticKey)
				require.NoError(t, err)
				return config.
					WithHandshakeTimeout(5 * time.Second)
			},
			network:     "tcp",
			addr:        "127.0.0.1:0", // Use available port
			expectError: false,
		},
		{
			name: "invalid network parameter",
			setupConfig: func() *NTCP2Config {
				routerHash := generateRandomBytes(32)
				config, _ := NewNTCP2Config(routerHash, false)
				return config
			},
			network:     "",
			addr:        "127.0.0.1:0",
			expectError: true,
			errorCode:   "network cannot be empty",
		},
		{
			name: "invalid address parameter",
			setupConfig: func() *NTCP2Config {
				routerHash := generateRandomBytes(32)
				config, _ := NewNTCP2Config(routerHash, false)
				return config
			},
			network:     "tcp",
			addr:        "",
			expectError: true,
			errorCode:   "address cannot be empty",
		},
		{
			name:        "nil config",
			setupConfig: func() *NTCP2Config { return nil },
			network:     "tcp",
			addr:        "127.0.0.1:0",
			expectError: true,
			errorCode:   "config cannot be nil",
		},
		{
			name: "initiator config for listen operation",
			setupConfig: func() *NTCP2Config {
				routerHash := generateRandomBytes(32)
				config, _ := NewNTCP2Config(routerHash, true) // initiator
				return config
			},
			network:     "tcp",
			addr:        "127.0.0.1:0",
			expectError: true,
			errorCode:   "listen operations require initiator=false in config",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := tt.setupConfig()

			listener, err := ListenNTCP2(tt.network, tt.addr, config)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorCode != "" {
					assert.Contains(t, err.Error(), tt.errorCode)
				}
				assert.Nil(t, listener)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, listener)
				if listener != nil {
					listener.Close()
				}
			}
		})
	}
}

func TestWrapNTCP2Conn(t *testing.T) {
	tests := []struct {
		name        string
		setupConn   func() net.Conn
		setupConfig func() *NTCP2Config
		expectError bool
		errorCode   string
	}{
		{
			name: "successful wrap with valid connection and config",
			setupConn: func() net.Conn {
				// Create a pipe connection for testing
				client, server := net.Pipe()
				go func() {
					defer server.Close()
					// Simple echo server
					buf := make([]byte, 1024)
					for {
						n, err := server.Read(buf)
						if err != nil {
							return
						}
						server.Write(buf[:n])
					}
				}()
				return client
			},
			setupConfig: func() *NTCP2Config {
				routerHash := generateRandomBytes(32)
				remoteHash := generateRandomBytes(32)
				staticKey := generateRandomBytes(32)
				obfuscationIV := generateRandomBytes(16)

				config, err := NewNTCP2Config(routerHash, true)
				require.NoError(t, err)

				config, err = config.WithStaticKey(staticKey)
				require.NoError(t, err)
				config, err = config.WithRemoteRouterHash(remoteHash)
				require.NoError(t, err)
				config, err = config.WithRemoteStaticKey(generateRandomBytes(32))
				require.NoError(t, err)
				config, err = config.WithAESObfuscation(true, obfuscationIV)
				require.NoError(t, err)
				return config
			},
			expectError: false,
		},
		{
			name:      "nil connection",
			setupConn: func() net.Conn { return nil },
			setupConfig: func() *NTCP2Config {
				routerHash := generateRandomBytes(32)
				config, _ := NewNTCP2Config(routerHash, true)
				return config
			},
			expectError: true,
			errorCode:   "connection cannot be nil",
		},
		{
			name: "nil config",
			setupConn: func() net.Conn {
				client, server := net.Pipe()
				go func() { defer server.Close() }()
				return client
			},
			setupConfig: func() *NTCP2Config { return nil },
			expectError: true,
			errorCode:   "config cannot be nil",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := tt.setupConn()
			config := tt.setupConfig()

			ntcp2Conn, err := WrapNTCP2Conn(conn, config)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorCode != "" {
					assert.Contains(t, err.Error(), tt.errorCode)
				}
				assert.Nil(t, ntcp2Conn)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, ntcp2Conn)
				if ntcp2Conn != nil {
					ntcp2Conn.Close()
				}
			}

			if conn != nil {
				conn.Close()
			}
		})
	}
}

func TestWrapNTCP2Listener(t *testing.T) {
	t.Run("successful wrap", func(t *testing.T) {
		// Create a TCP listener
		tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		defer tcpListener.Close()

		// Create NTCP2 config
		routerHash := generateRandomBytes(32)
		staticKey := generateRandomBytes(32)

		config, err := NewNTCP2Config(routerHash, false) // responder
		require.NoError(t, err)

		config, err = config.WithStaticKey(staticKey)
		require.NoError(t, err)

		// Wrap the listener
		ntcp2Listener, err := WrapNTCP2Listener(tcpListener, config)
		assert.NoError(t, err)
		assert.NotNil(t, ntcp2Listener)

		if ntcp2Listener != nil {
			ntcp2Listener.Close()
		}
	})
}

func TestDialNTCP2WithHandshake(t *testing.T) {
	t.Run("handshake with context timeout", func(t *testing.T) {
		cs := upstreamnoise.NewCipherSuite(
			upstreamnoise.DH25519,
			upstreamnoise.CipherChaChaPoly,
			upstreamnoise.HashSHA256,
		)

		// Generate real Curve25519 keypairs so the XK handshake works
		responderKP, err := cs.GenerateKeypair(rand.Reader)
		require.NoError(t, err)
		initiatorKP, err := cs.GenerateKeypair(rand.Reader)
		require.NoError(t, err)

		// Create responder (listener) config
		routerHash := generateRandomBytes(32)
		listenerConfig, err := NewNTCP2Config(routerHash, false)
		require.NoError(t, err)
		listenerConfig, err = listenerConfig.WithStaticKey(responderKP.Private)
		require.NoError(t, err)
		listenerConfig, err = listenerConfig.WithAESObfuscation(false, nil)
		require.NoError(t, err)

		listener, err := ListenNTCP2("tcp", "127.0.0.1:0", listenerConfig)
		require.NoError(t, err)
		defer listener.Close()

		// Accept and handshake on the server side in a goroutine
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			// Perform the responder handshake
			ntcp2Conn := conn.(*NTCP2Conn)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := ntcp2Conn.UnderlyingConn().Handshake(ctx); err != nil {
				ntcp2Conn.Close()
				return
			}
			ntcp2Conn.PropagateSipHash()
			ntcp2Conn.Close()
		}()

		// Create initiator (dial) config
		clientRouterHash := generateRandomBytes(32)
		dialConfig, err := NewNTCP2Config(clientRouterHash, true)
		require.NoError(t, err)
		dialConfig, err = dialConfig.WithStaticKey(initiatorKP.Private)
		require.NoError(t, err)
		dialConfig, err = dialConfig.WithRemoteRouterHash(routerHash)
		require.NoError(t, err)
		dialConfig, err = dialConfig.WithRemoteStaticKey(responderKP.Public)
		require.NoError(t, err)
		dialConfig, err = dialConfig.WithAESObfuscation(false, nil)
		require.NoError(t, err)
		dialConfig = dialConfig.
			WithHandshakeTimeout(5 * time.Second)

		// Dial with handshake — should succeed now that a responder is running
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		ntcp2Addr := listener.Addr().(*NTCP2Addr)
		underlyingAddr := ntcp2Addr.UnderlyingAddr().String()

		conn, err := DialNTCP2WithHandshakeContext(ctx, "tcp", underlyingAddr, dialConfig)

		// Handshake should succeed with matching keys and a live responder
		assert.NoError(t, err)
		if conn != nil {
			conn.Close()
		}

		wg.Wait()
	})
}

func TestValidateDialParams(t *testing.T) {
	tests := []struct {
		name        string
		network     string
		addr        string
		setupConfig func() *NTCP2Config
		expectError bool
		errorCode   string
	}{
		{
			name:    "valid parameters",
			network: "tcp",
			addr:    "127.0.0.1:8080",
			setupConfig: func() *NTCP2Config {
				routerHash := generateRandomBytes(32)
				remoteHash := generateRandomBytes(32)
				staticKey := generateRandomBytes(32)
				config, _ := NewNTCP2Config(routerHash, true)
				config, _ = config.WithStaticKey(staticKey)
				config, _ = config.WithRemoteRouterHash(remoteHash)
				config, _ = config.WithRemoteStaticKey(generateRandomBytes(32))
				return config
			},
			expectError: false,
		},
		{
			name:    "empty network",
			network: "",
			addr:    "127.0.0.1:8080",
			setupConfig: func() *NTCP2Config {
				routerHash := generateRandomBytes(32)
				config, _ := NewNTCP2Config(routerHash, true)
				return config
			},
			expectError: true,
			errorCode:   "network cannot be empty",
		},
		{
			name:    "empty address",
			network: "tcp",
			addr:    "",
			setupConfig: func() *NTCP2Config {
				routerHash := generateRandomBytes(32)
				config, _ := NewNTCP2Config(routerHash, true)
				return config
			},
			expectError: true,
			errorCode:   "address cannot be empty",
		},
		{
			name:        "nil config",
			network:     "tcp",
			addr:        "127.0.0.1:8080",
			setupConfig: func() *NTCP2Config { return nil },
			expectError: true,
			errorCode:   "config cannot be nil",
		},
		{
			name:    "responder config",
			network: "tcp",
			addr:    "127.0.0.1:8080",
			setupConfig: func() *NTCP2Config {
				routerHash := generateRandomBytes(32)
				config, _ := NewNTCP2Config(routerHash, false) // responder
				return config
			},
			expectError: true,
			errorCode:   "dial operations require initiator=true in config",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := tt.setupConfig()
			err := validateDialParams(tt.network, tt.addr, config)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorCode != "" {
					assert.Contains(t, err.Error(), tt.errorCode)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateListenParams(t *testing.T) {
	tests := []struct {
		name        string
		network     string
		addr        string
		setupConfig func() *NTCP2Config
		expectError bool
		errorCode   string
	}{
		{
			name:    "valid parameters",
			network: "tcp",
			addr:    "127.0.0.1:0",
			setupConfig: func() *NTCP2Config {
				routerHash := generateRandomBytes(32)
				staticKey := generateRandomBytes(32)
				config, _ := NewNTCP2Config(routerHash, false) // responder
				config, _ = config.WithStaticKey(staticKey)
				return config
			},
			expectError: false,
		},
		{
			name:    "empty network",
			network: "",
			addr:    "127.0.0.1:0",
			setupConfig: func() *NTCP2Config {
				routerHash := generateRandomBytes(32)
				config, _ := NewNTCP2Config(routerHash, false)
				return config
			},
			expectError: true,
			errorCode:   "network cannot be empty",
		},
		{
			name:    "empty address",
			network: "tcp",
			addr:    "",
			setupConfig: func() *NTCP2Config {
				routerHash := generateRandomBytes(32)
				config, _ := NewNTCP2Config(routerHash, false)
				return config
			},
			expectError: true,
			errorCode:   "address cannot be empty",
		},
		{
			name:        "nil config",
			network:     "tcp",
			addr:        "127.0.0.1:0",
			setupConfig: func() *NTCP2Config { return nil },
			expectError: true,
			errorCode:   "config cannot be nil",
		},
		{
			name:    "initiator config",
			network: "tcp",
			addr:    "127.0.0.1:0",
			setupConfig: func() *NTCP2Config {
				routerHash := generateRandomBytes(32)
				config, _ := NewNTCP2Config(routerHash, true) // initiator
				return config
			},
			expectError: true,
			errorCode:   "listen operations require initiator=false in config",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := tt.setupConfig()
			err := validateListenParams(tt.network, tt.addr, config)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorCode != "" {
					assert.Contains(t, err.Error(), tt.errorCode)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestCreateDialAddresses(t *testing.T) {
	t.Run("successful address creation", func(t *testing.T) {
		// Create a pipe connection for testing
		client, server := net.Pipe()
		defer client.Close()
		defer server.Close()

		// Create config
		routerHash := generateRandomBytes(32)
		remoteHash := generateRandomBytes(32)

		config, err := NewNTCP2Config(routerHash, true)
		require.NoError(t, err)
		config, err = config.WithRemoteRouterHash(remoteHash)
		require.NoError(t, err)

		// Create addresses
		localAddr, remoteAddr, err := createDialAddresses(client, config)

		assert.NoError(t, err)
		assert.NotNil(t, localAddr)
		assert.NotNil(t, remoteAddr)

		// Verify addresses
		assert.Equal(t, "initiator", localAddr.Role())
		assert.Equal(t, "responder", remoteAddr.Role())
		assert.Equal(t, routerHash, localAddr.RouterHash())
		assert.Equal(t, remoteHash, remoteAddr.RouterHash())
	})
}

// TestDialNTCP2WithHandshake_Wrapper tests the DialNTCP2WithHandshake convenience
// function, which delegates to DialNTCP2WithHandshakeContext with context.Background().
// This covers the thin wrapper at 0% coverage identified in the audit.
func TestDialNTCP2WithHandshake_Wrapper(t *testing.T) {
	t.Run("delegates to DialNTCP2WithHandshakeContext", func(t *testing.T) {
		cs := upstreamnoise.NewCipherSuite(
			upstreamnoise.DH25519,
			upstreamnoise.CipherChaChaPoly,
			upstreamnoise.HashSHA256,
		)

		// Generate real Curve25519 keypairs so the XK handshake works
		responderKP, err := cs.GenerateKeypair(rand.Reader)
		require.NoError(t, err)
		initiatorKP, err := cs.GenerateKeypair(rand.Reader)
		require.NoError(t, err)

		// Create responder (listener) config
		routerHash := generateRandomBytes(32)
		listenerConfig, err := NewNTCP2Config(routerHash, false)
		require.NoError(t, err)
		listenerConfig, err = listenerConfig.WithStaticKey(responderKP.Private)
		require.NoError(t, err)
		listenerConfig, err = listenerConfig.WithAESObfuscation(false, nil)
		require.NoError(t, err)

		listener, err := ListenNTCP2("tcp", "127.0.0.1:0", listenerConfig)
		require.NoError(t, err)
		defer listener.Close()

		// Accept and handshake on the server side
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			ntcp2Conn := conn.(*NTCP2Conn)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if hsErr := ntcp2Conn.UnderlyingConn().Handshake(ctx); hsErr != nil {
				ntcp2Conn.Close()
				return
			}
			ntcp2Conn.PropagateSipHash()
			ntcp2Conn.Close()
		}()

		// Create initiator config
		clientRouterHash := generateRandomBytes(32)
		dialConfig, err := NewNTCP2Config(clientRouterHash, true)
		require.NoError(t, err)
		dialConfig, err = dialConfig.WithStaticKey(initiatorKP.Private)
		require.NoError(t, err)
		dialConfig, err = dialConfig.WithRemoteRouterHash(routerHash)
		require.NoError(t, err)
		dialConfig, err = dialConfig.WithRemoteStaticKey(responderKP.Public)
		require.NoError(t, err)
		dialConfig, err = dialConfig.WithAESObfuscation(false, nil)
		require.NoError(t, err)
		dialConfig = dialConfig.WithHandshakeTimeout(5 * time.Second)

		ntcp2Addr := listener.Addr().(*NTCP2Addr)
		underlyingAddr := ntcp2Addr.UnderlyingAddr().String()

		// Call the wrapper (not the Context variant) — this is the path under test
		conn, err := DialNTCP2WithHandshake("tcp", underlyingAddr, dialConfig)
		assert.NoError(t, err)
		if conn != nil {
			conn.Close()
		}

		wg.Wait()
	})

	t.Run("error propagated from invalid config", func(t *testing.T) {
		routerHash := generateRandomBytes(32)
		config, err := NewNTCP2Config(routerHash, true)
		require.NoError(t, err)

		// Dial with empty network — validation error
		conn, err := DialNTCP2WithHandshake("", "127.0.0.1:8080", config)
		assert.Error(t, err)
		assert.Nil(t, conn)
		assert.Contains(t, err.Error(), "network cannot be empty")
	})

	t.Run("error propagated from unreachable address", func(t *testing.T) {
		routerHash := generateRandomBytes(32)
		config, err := NewNTCP2Config(routerHash, true)
		require.NoError(t, err)

		// Dial an address that can't be reached — TCP connect error
		conn, err := DialNTCP2WithHandshake("tcp", "127.0.0.1:0", config)
		assert.Error(t, err)
		assert.Nil(t, conn)
	})
}

// TestAuditFix_SetNTCP2Config_NotRedundantInDialNTCP2WithHandshakeContext documents
// the removal of the redundant ntcp2Conn.SetNTCP2Config(config) call that previously
// existed in DialNTCP2WithHandshakeContext immediately after DialNTCP2 returned.
// DialNTCP2 already called SetNTCP2Config via buildNTCP2Connection; the second call
// was a no-op atomic store of the same pointer.
//
// This test verifies the underlying mechanism: SetNTCP2Config stores a pointer
// atomically, and a subsequent call with the same pointer is idempotent.  It also
// confirms that the config is accessible after a single SetNTCP2Config call, proving
// that removing the second call does not break callers that read the config later
// (e.g., PropagateSipHash).
func TestAuditFix_SetNTCP2Config_NotRedundantInDialNTCP2WithHandshakeContext(t *testing.T) {
	conn := createTestNTCP2Conn(&mockNoiseConn{})

	routerHash := generateRandomBytes(32)
	config, err := NewNTCP2Config(routerHash, true)
	require.NoError(t, err)

	// Simulate the single remaining SetNTCP2Config call (inside buildNTCP2Connection).
	conn.SetNTCP2Config(config)
	loadedConfig := conn.ntcp2Config.Load()
	assert.NotNil(t, loadedConfig, "config must be set after a single SetNTCP2Config call")
	assert.Same(t, config, loadedConfig, "stored config must be the identical pointer passed to SetNTCP2Config")

	// Simulate the previously-existing redundant second call — same pointer, no effect.
	// Verifying idempotency confirms that removing the call is safe.
	conn.SetNTCP2Config(config)
	assert.Same(t, config, conn.ntcp2Config.Load(),
		"repeated SetNTCP2Config with same pointer must be idempotent (atomic store)")
}
