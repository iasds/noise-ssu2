package ssu2

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIsPortConsistent tests port consistency checking.
func TestIsPortConsistent(t *testing.T) {
	tests := []struct {
		name     string
		addr1    *net.UDPAddr
		addr2    *net.UDPAddr
		expected bool
	}{
		{
			name:     "same port",
			addr1:    &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 8080},
			addr2:    &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 8080},
			expected: true,
		},
		{
			name:     "different port",
			addr1:    &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 8080},
			addr2:    &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 9090},
			expected: false,
		},
		{
			name:     "nil first address",
			addr1:    nil,
			addr2:    &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 8080},
			expected: false,
		},
		{
			name:     "nil second address",
			addr1:    &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 8080},
			addr2:    nil,
			expected: false,
		},
		{
			name:     "both nil",
			addr1:    nil,
			addr2:    nil,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsPortConsistent(tt.addr1, tt.addr2)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestIsIPConsistent tests IP consistency checking.
func TestIsIPConsistent(t *testing.T) {
	tests := []struct {
		name     string
		addr1    *net.UDPAddr
		addr2    *net.UDPAddr
		expected bool
	}{
		{
			name:     "same IPv4",
			addr1:    &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 8080},
			addr2:    &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 9090},
			expected: true,
		},
		{
			name:     "different IPv4",
			addr1:    &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 8080},
			addr2:    &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 8080},
			expected: false,
		},
		{
			name:     "same IPv6",
			addr1:    &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 8080},
			addr2:    &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 9090},
			expected: true,
		},
		{
			name:     "different IPv6",
			addr1:    &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 8080},
			addr2:    &net.UDPAddr{IP: net.ParseIP("2001:db8::2"), Port: 8080},
			expected: false,
		},
		{
			name:     "nil first address",
			addr1:    nil,
			addr2:    &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 8080},
			expected: false,
		},
		{
			name:     "nil second address",
			addr1:    &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 8080},
			addr2:    nil,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsIPConsistent(tt.addr1, tt.addr2)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestIsAddressConsistent tests full address consistency checking.
func TestIsAddressConsistent(t *testing.T) {
	tests := []struct {
		name     string
		addr1    *net.UDPAddr
		addr2    *net.UDPAddr
		expected bool
	}{
		{
			name:     "identical addresses",
			addr1:    &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 8080},
			addr2:    &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 8080},
			expected: true,
		},
		{
			name:     "same IP different port",
			addr1:    &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 8080},
			addr2:    &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 9090},
			expected: false,
		},
		{
			name:     "different IP same port",
			addr1:    &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 8080},
			addr2:    &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 8080},
			expected: false,
		},
		{
			name:     "completely different",
			addr1:    &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 8080},
			addr2:    &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 9090},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsAddressConsistent(tt.addr1, tt.addr2)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestExtractExternalAddress tests external address extraction.
func TestExtractExternalAddress(t *testing.T) {
	t.Run("valid result", func(t *testing.T) {
		addr := &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 8080}
		result := &TestResult{ExternalAddr: addr}

		extracted := ExtractExternalAddress(result)
		assert.Equal(t, addr, extracted)
	})

	t.Run("nil result", func(t *testing.T) {
		extracted := ExtractExternalAddress(nil)
		assert.Nil(t, extracted)
	})

	t.Run("nil external address", func(t *testing.T) {
		result := &TestResult{ExternalAddr: nil}
		extracted := ExtractExternalAddress(result)
		assert.Nil(t, extracted)
	})
}

// TestExtractExternalPort tests external port extraction.
func TestExtractExternalPort(t *testing.T) {
	t.Run("valid result", func(t *testing.T) {
		result := &TestResult{ExternalPort: 8080}

		port := ExtractExternalPort(result)
		assert.Equal(t, uint16(8080), port)
	})

	t.Run("nil result", func(t *testing.T) {
		port := ExtractExternalPort(nil)
		assert.Equal(t, uint16(0), port)
	})

	t.Run("zero port", func(t *testing.T) {
		result := &TestResult{ExternalPort: 0}
		port := ExtractExternalPort(result)
		assert.Equal(t, uint16(0), port)
	})
}

// TestIsDirectlyReachable tests direct reachability checking.
func TestIsDirectlyReachable(t *testing.T) {
	t.Run("direct probe succeeded", func(t *testing.T) {
		result := &TestResult{DirectProbeSuccess: true}
		assert.True(t, IsDirectlyReachable(result))
	})

	t.Run("direct probe failed", func(t *testing.T) {
		result := &TestResult{DirectProbeSuccess: false}
		assert.False(t, IsDirectlyReachable(result))
	})

	t.Run("nil result", func(t *testing.T) {
		assert.False(t, IsDirectlyReachable(nil))
	})
}

// TestIsReachableViaRelay tests relay reachability checking.
func TestIsReachableViaRelay(t *testing.T) {
	t.Run("relayed probe succeeded", func(t *testing.T) {
		result := &TestResult{RelayedProbeSuccess: true}
		assert.True(t, IsReachableViaRelay(result))
	})

	t.Run("relayed probe failed", func(t *testing.T) {
		result := &TestResult{RelayedProbeSuccess: false}
		assert.False(t, IsReachableViaRelay(result))
	})

	t.Run("nil result", func(t *testing.T) {
		assert.False(t, IsReachableViaRelay(nil))
	})
}

// TestHasPublicIP tests public IP detection.
func TestHasPublicIP(t *testing.T) {
	tests := []struct {
		name     string
		natType  NATType
		expected bool
	}{
		{"no NAT", NATNone, true},
		{"full cone", NATCone, true},
		{"restricted", NATRestricted, false},
		{"port restricted", NATPortRestricted, false},
		{"symmetric", NATSymmetric, false},
		{"unknown", NATUnknown, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := HasPublicIP(tt.natType)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestRequiresRelay tests relay requirement detection.
func TestRequiresRelay(t *testing.T) {
	tests := []struct {
		name     string
		natType  NATType
		expected bool
	}{
		{"no NAT", NATNone, false},
		{"full cone", NATCone, false},
		{"restricted", NATRestricted, false},
		{"port restricted", NATPortRestricted, true},
		{"symmetric", NATSymmetric, true},
		{"unknown", NATUnknown, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := RequiresRelay(tt.natType)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestIsSymmetricNAT tests symmetric NAT detection.
func TestIsSymmetricNAT(t *testing.T) {
	tests := []struct {
		name     string
		natType  NATType
		expected bool
	}{
		{"no NAT", NATNone, false},
		{"full cone", NATCone, false},
		{"restricted", NATRestricted, false},
		{"port restricted", NATPortRestricted, false},
		{"symmetric", NATSymmetric, true},
		{"unknown", NATUnknown, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsSymmetricNAT(tt.natType)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestAnalyzeProbeResults tests probe result analysis.
func TestAnalyzeProbeResults(t *testing.T) {
	t.Run("both probes succeeded consistent", func(t *testing.T) {
		addr1 := &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 8080}
		addr2 := &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 8080}

		result := AnalyzeProbeResults(true, true, addr1, addr2)

		assert.True(t, result.DirectProbeSuccess)
		assert.True(t, result.RelayedProbeSuccess)
		assert.True(t, result.PortConsistent)
		assert.True(t, result.IPConsistent)
		assert.True(t, result.Reachable)
		assert.Equal(t, addr1, result.ExternalAddr)
		assert.Equal(t, uint16(8080), result.ExternalPort)
	})

	t.Run("port inconsistent", func(t *testing.T) {
		addr1 := &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 8080}
		addr2 := &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 9090}

		result := AnalyzeProbeResults(true, true, addr1, addr2)

		assert.True(t, result.DirectProbeSuccess)
		assert.True(t, result.RelayedProbeSuccess)
		assert.False(t, result.PortConsistent)
		assert.True(t, result.IPConsistent)
	})

	t.Run("IP inconsistent", func(t *testing.T) {
		addr1 := &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 8080}
		addr2 := &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 8080}

		result := AnalyzeProbeResults(true, true, addr1, addr2)

		assert.True(t, result.PortConsistent)
		assert.False(t, result.IPConsistent)
	})

	t.Run("only direct succeeded", func(t *testing.T) {
		addr1 := &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 8080}

		result := AnalyzeProbeResults(true, false, addr1, nil)

		assert.True(t, result.DirectProbeSuccess)
		assert.False(t, result.RelayedProbeSuccess)
		assert.True(t, result.Reachable)
		assert.Equal(t, addr1, result.ExternalAddr)
	})

	t.Run("only relayed succeeded", func(t *testing.T) {
		addr1 := &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 8080}

		result := AnalyzeProbeResults(false, true, addr1, nil)

		assert.False(t, result.DirectProbeSuccess)
		assert.True(t, result.RelayedProbeSuccess)
		assert.False(t, result.Reachable)
	})

	t.Run("both failed", func(t *testing.T) {
		result := AnalyzeProbeResults(false, false, nil, nil)

		assert.False(t, result.DirectProbeSuccess)
		assert.False(t, result.RelayedProbeSuccess)
		assert.False(t, result.Reachable)
		assert.Nil(t, result.ExternalAddr)
	})

	t.Run("use second address if first nil", func(t *testing.T) {
		addr2 := &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 8080}

		result := AnalyzeProbeResults(true, true, nil, addr2)

		assert.Equal(t, addr2, result.ExternalAddr)
		assert.Equal(t, uint16(8080), result.ExternalPort)
	})
}

// TestValidateTestResult tests test result validation.
func TestValidateTestResult(t *testing.T) {
	t.Run("nil result", func(t *testing.T) {
		err := ValidateTestResult(nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cannot be nil")
	})

	t.Run("valid result with direct probe", func(t *testing.T) {
		result := &TestResult{
			DirectProbeSuccess: true,
			ExternalAddr:       &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 8080},
		}

		err := ValidateTestResult(result)
		assert.NoError(t, err)
	})

	t.Run("valid result with relayed probe", func(t *testing.T) {
		result := &TestResult{
			RelayedProbeSuccess: true,
			ExternalAddr:        &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 8080},
		}

		err := ValidateTestResult(result)
		assert.NoError(t, err)
	})

	t.Run("missing external address with successful probe", func(t *testing.T) {
		result := &TestResult{
			DirectProbeSuccess: true,
			ExternalAddr:       nil,
		}

		err := ValidateTestResult(result)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "external address")
	})

	t.Run("both probes failed is valid", func(t *testing.T) {
		result := &TestResult{
			DirectProbeSuccess:  false,
			RelayedProbeSuccess: false,
		}

		err := ValidateTestResult(result)
		assert.NoError(t, err)
	})
}

// TestCompareNATTypes tests NAT type comparison.
func TestCompareNATTypes(t *testing.T) {
	tests := []struct {
		name     string
		nat1     NATType
		nat2     NATType
		expected int
	}{
		// Equal cases
		{"both none", NATNone, NATNone, 0},
		{"both cone", NATCone, NATCone, 0},
		{"both symmetric", NATSymmetric, NATSymmetric, 0},

		// Less restrictive (negative)
		{"none vs cone", NATNone, NATCone, -1},
		{"none vs symmetric", NATNone, NATSymmetric, -1},
		{"cone vs restricted", NATCone, NATRestricted, -1},
		{"restricted vs symmetric", NATRestricted, NATSymmetric, -1},

		// More restrictive (positive)
		{"symmetric vs none", NATSymmetric, NATNone, 1},
		{"symmetric vs cone", NATSymmetric, NATCone, 1},
		{"port restricted vs cone", NATPortRestricted, NATCone, 1},

		// Unknown is incomparable
		{"unknown vs none", NATUnknown, NATNone, 0},
		{"cone vs unknown", NATCone, NATUnknown, 0},
		{"unknown vs unknown", NATUnknown, NATUnknown, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CompareNATTypes(tt.nat1, tt.nat2)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestSelectBestNATType tests best NAT type selection.
func TestSelectBestNATType(t *testing.T) {
	tests := []struct {
		name     string
		nat1     NATType
		nat2     NATType
		expected NATType
	}{
		{"none vs cone", NATNone, NATCone, NATNone},
		{"cone vs symmetric", NATCone, NATSymmetric, NATCone},
		{"symmetric vs restricted", NATSymmetric, NATRestricted, NATRestricted},
		{"equal types", NATCone, NATCone, NATCone},
		{"unknown vs known", NATUnknown, NATCone, NATUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SelectBestNATType(tt.nat1, tt.nat2)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestSelectWorstNATType tests worst NAT type selection.
func TestSelectWorstNATType(t *testing.T) {
	tests := []struct {
		name     string
		nat1     NATType
		nat2     NATType
		expected NATType
	}{
		{"none vs cone", NATNone, NATCone, NATCone},
		{"cone vs symmetric", NATCone, NATSymmetric, NATSymmetric},
		{"symmetric vs restricted", NATSymmetric, NATRestricted, NATSymmetric},
		{"equal types", NATCone, NATCone, NATCone},
		{"unknown vs known", NATUnknown, NATCone, NATUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SelectWorstNATType(tt.nat1, tt.nat2)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestDescribeNATCapabilities tests NAT capability descriptions.
func TestDescribeNATCapabilities(t *testing.T) {
	tests := []struct {
		name     string
		natType  NATType
		contains string
	}{
		{"no NAT", NATNone, "Public IP"},
		{"full cone", NATCone, "Full cone NAT"},
		{"restricted", NATRestricted, "Restricted cone NAT"},
		{"port restricted", NATPortRestricted, "Port-restricted NAT"},
		{"symmetric", NATSymmetric, "Symmetric NAT"},
		{"unknown", NATUnknown, "Unknown NAT"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			description := DescribeNATCapabilities(tt.natType)
			assert.Contains(t, description, tt.contains)
			assert.NotEmpty(t, description)
		})
	}
}

// TestNATDetectionIntegration tests integration of helper functions.
func TestNATDetectionIntegration(t *testing.T) {
	t.Run("full cone NAT scenario", func(t *testing.T) {
		// Both probes succeed with consistent address
		addr := &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 8080}
		result := AnalyzeProbeResults(true, true, addr, addr)

		err := ValidateTestResult(result)
		assert.NoError(t, err)

		assert.True(t, IsDirectlyReachable(result))
		assert.True(t, IsReachableViaRelay(result))
		assert.True(t, HasPublicIP(NATCone))
		assert.False(t, RequiresRelay(NATCone))
	})

	t.Run("symmetric NAT scenario", func(t *testing.T) {
		// Only relayed succeeds, port inconsistent
		addr1 := &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 8080}
		addr2 := &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 9090}
		result := AnalyzeProbeResults(false, true, addr1, addr2)

		err := ValidateTestResult(result)
		assert.NoError(t, err)

		assert.False(t, IsDirectlyReachable(result))
		assert.True(t, IsReachableViaRelay(result))
		assert.False(t, result.PortConsistent)
		assert.True(t, RequiresRelay(NATSymmetric))
		assert.True(t, IsSymmetricNAT(NATSymmetric))
	})

	t.Run("NAT type comparison workflow", func(t *testing.T) {
		// Multiple tests suggest different NAT types
		best := SelectBestNATType(NATCone, NATSymmetric)
		assert.Equal(t, NATCone, best)

		worst := SelectWorstNATType(NATCone, NATSymmetric)
		assert.Equal(t, NATSymmetric, worst)

		// Verify ordering
		assert.Equal(t, -1, CompareNATTypes(NATCone, NATSymmetric))
		assert.Equal(t, 1, CompareNATTypes(NATSymmetric, NATCone))
	})
}
