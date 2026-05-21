package ntcp2

import (
	"net"
	"sync"
	"testing"

	"github.com/go-i2p/common/data"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewNTCP2Addr(t *testing.T) {
	tests := []struct {
		name         string
		underlying   net.Addr
		routerHash   data.Hash
		role         string
		expectError  bool
		errorMessage string
	}{
		{
			name:        "valid_initiator_addr",
			underlying:  &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 8080},
			routerHash:  data.Hash{}, // Valid zero hash
			role:        "initiator",
			expectError: false,
		},
		{
			name:        "valid_responder_addr",
			underlying:  &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 9091},
			routerHash:  data.Hash{},
			role:        "responder",
			expectError: false,
		},
		{
			name:         "nil_underlying_addr",
			underlying:   nil,
			routerHash:   data.Hash{},
			role:         "initiator",
			expectError:  true,
			errorMessage: "underlying address cannot be nil",
		},
		{
			name:         "invalid_role",
			underlying:   &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 8080},
			routerHash:   data.Hash{},
			role:         "invalid",
			expectError:  true,
			errorMessage: "role must be 'initiator' or 'responder'",
		},
		{
			name:         "empty_role",
			underlying:   &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 8080},
			routerHash:   data.Hash{},
			role:         "",
			expectError:  true,
			errorMessage: "role must be 'initiator' or 'responder'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, err := NewNTCP2Addr(tt.underlying, tt.routerHash, tt.role)

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMessage)
				assert.Nil(t, addr)
			} else {
				require.NoError(t, err)
				require.NotNil(t, addr)
				assert.Equal(t, tt.underlying, addr.underlying)
				assert.Equal(t, tt.role, addr.role)
			}
		})
	}
}

func TestNTCP2Addr_NetAddrInterface(t *testing.T) {
	underlying := &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 8080}
	var routerHash data.Hash
	addr, err := NewNTCP2Addr(underlying, routerHash, "initiator")
	require.NoError(t, err)

	// Test net.Addr interface compliance
	var netAddr net.Addr = addr
	assert.Equal(t, "ntcp2", netAddr.Network())
	assert.Contains(t, netAddr.String(), "ntcp2://")
}

func TestNTCP2Addr_Network(t *testing.T) {
	underlying := &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 8080}
	var routerHash data.Hash
	addr, err := NewNTCP2Addr(underlying, routerHash, "initiator")
	require.NoError(t, err)

	assert.Equal(t, "ntcp2", addr.Network())
}

func TestNTCP2Addr_String(t *testing.T) {
	underlying := &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 8080}
	var routerHash data.Hash
	// Set some recognizable bytes in router hash
	routerHash[0] = 0xAA
	routerHash[31] = 0xBB

	tests := []struct {
		name        string
		setupAddr   func(*Addr) *Addr
		contains    []string
		notContains []string
	}{
		{
			name: "basic_address",
			setupAddr: func(addr *Addr) *Addr {
				return addr
			},
			contains: []string{
				"ntcp2://",
				"/initiator/",
				"192.168.1.1:8080",
			},
			notContains: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			baseAddr, err := NewNTCP2Addr(underlying, routerHash, "initiator")
			require.NoError(t, err)

			addr := tt.setupAddr(baseAddr)
			str := addr.String()

			for _, substr := range tt.contains {
				assert.Contains(t, str, substr, "String should contain %s", substr)
			}

			for _, substr := range tt.notContains {
				assert.NotContains(t, str, substr, "String should not contain %s", substr)
			}
		})
	}
}

func TestNTCP2Addr_AccessorMethods(t *testing.T) {
	underlying := &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 8080}
	var routerHash data.Hash
	routerHash[0] = 0xAA // Set recognizable byte

	addr, err := NewNTCP2Addr(underlying, routerHash, "initiator")
	require.NoError(t, err)

	// Test RouterHash - returns value copy
	returnedHash := addr.RouterHash()
	assert.Equal(t, byte(0xAA), returnedHash[0])
	// Test value copy by modifying returned value
	returnedHash[0] = 0xFF
	assert.Equal(t, byte(0xAA), addr.RouterHash()[0]) // Original should be unchanged

	// Test Role
	assert.Equal(t, "initiator", addr.Role())

	// Test UnderlyingAddr
	assert.Equal(t, underlying, addr.UnderlyingAddr())

	// Test IdentHash - returns a [32]byte from the router hash
	identHash := addr.IdentHash()
	assert.Equal(t, byte(0xAA), identHash[0])
}

func TestNTCP2Addr_DefensiveCopying(t *testing.T) {
	underlying := &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 8080}
	var routerHash data.Hash
	routerHash[0] = 0xAA

	addr, err := NewNTCP2Addr(underlying, routerHash, "initiator")
	require.NoError(t, err)

	// Modify original router hash - should not affect created address (value type)
	routerHash[0] = 0xFF
	assert.Equal(t, byte(0xAA), addr.routerHash[0])

	// Modify returned router hash - should not affect internal state (value copy)
	returned := addr.RouterHash()
	returned[0] = 0xFF
	assert.Equal(t, byte(0xAA), addr.routerHash[0])
}

func TestNTCP2Addr_StringHandlesNilUnderlying(t *testing.T) {
	// Test edge case - this shouldn't happen in normal usage but we handle it gracefully
	addr := &Addr{
		underlying: nil,
		routerHash: data.Hash{},
		role:       "initiator",
	}

	str := addr.String()
	assert.Equal(t, "ntcp2://invalid", str)
}

func TestNTCP2Addr_IdentHash(t *testing.T) {
	// Test that IdentHash returns the correct [32]byte
	underlying := &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 8080}
	var routerHash data.Hash
	for i := range routerHash {
		routerHash[i] = byte(i)
	}

	addr, err := NewNTCP2Addr(underlying, routerHash, "initiator")
	require.NoError(t, err)

	identHash := addr.IdentHash()
	// Verify each byte matches
	for i := 0; i < 32; i++ {
		assert.Equal(t, byte(i), identHash[i], "byte %d mismatch", i)
	}
}

// Benchmark tests to ensure performance is adequate
func BenchmarkNTCP2Addr_Creation(b *testing.B) {
	underlying := &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 8080}
	var routerHash data.Hash

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = NewNTCP2Addr(underlying, routerHash, "initiator")
	}
}

func BenchmarkNTCP2Addr_String(b *testing.B) {
	underlying := &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 8080}
	var routerHash data.Hash
	addr, _ := NewNTCP2Addr(underlying, routerHash, "initiator")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = addr.String()
	}
}

func TestNTCP2AddrConcurrency(t *testing.T) {
	underlying := &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 8080}
	var routerHash data.Hash
	routerHash[0] = 0xAA

	addr, err := NewNTCP2Addr(underlying, routerHash, "initiator")
	require.NoError(t, err)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(4)
		go func() {
			defer wg.Done()
			_ = addr.RouterHash()
		}()
		go func() {
			defer wg.Done()
			_ = addr.IdentHash()
		}()
		go func() {
			defer wg.Done()
			_ = addr.String()
		}()
		go func(i int) {
			defer wg.Done()
			var newHash data.Hash
			newHash[0] = byte(i)
			addr.SetRouterHash(newHash)
		}(i)
	}
	wg.Wait()

	// Verify the address is still valid
	_ = addr.RouterHash()
}
