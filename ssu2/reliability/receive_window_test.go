package reliability

import (
	"testing"
)

// TestSeqBefore_Wraparound verifies that seqBefore correctly handles uint32 wraparound.
// This test locks the contract that seqBefore works for |a - b| < 2^31.
func TestSeqBefore_Wraparound(t *testing.T) {
	tests := []struct {
		name     string
		a        uint32
		b        uint32
		expected bool
	}{
		{
			name:     "basic comparison: 100 < 200",
			a:        100,
			b:        200,
			expected: true,
		},
		{
			name:     "basic comparison: 200 > 100",
			a:        200,
			b:        100,
			expected: false,
		},
		{
			name:     "equal values: 100 == 100",
			a:        100,
			b:        100,
			expected: false, // a is not before b
		},
		{
			name:     "wraparound: 0xFFFFFFFE is before 0x00000001",
			a:        0xFFFFFFFE,
			b:        0x00000001,
			expected: true,
		},
		{
			name:     "wraparound: 0x00000001 is after 0xFFFFFFFE",
			a:        0x00000001,
			b:        0xFFFFFFFE,
			expected: false,
		},
		{
			name:     "wraparound: 0xFFFFFFFF is before 0x00000000",
			a:        0xFFFFFFFF,
			b:        0x00000000,
			expected: true,
		},
		{
			name:     "wraparound: 0x00000000 is after 0xFFFFFFFF",
			a:        0x00000000,
			b:        0xFFFFFFFF,
			expected: false,
		},
		{
			name:     "near wraparound: 0xFFFFFFF0 is before 0x00000010",
			a:        0xFFFFFFF0,
			b:        0x00000010,
			expected: true,
		},
		{
			name:     "near wraparound: 0x00000010 is after 0xFFFFFFF0",
			a:        0x00000010,
			b:        0xFFFFFFF0,
			expected: false,
		},
		{
			name:     "small difference: 0xFFFFFFFF is before 0x00000005",
			a:        0xFFFFFFFF,
			b:        0x00000005,
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := seqBefore(tt.a, tt.b)
			if result != tt.expected {
				t.Errorf("seqBefore(0x%08X, 0x%08X) = %v, want %v",
					tt.a, tt.b, result, tt.expected)
			}
		})
	}
}

// TestSeqBefore_HalfSpaceBoundary tests the boundary of the half-space precondition.
// For differences near 2^31, the comparison may produce incorrect results, but this
// should never occur in practice due to receive window size limits.
func TestSeqBefore_HalfSpaceBoundary(t *testing.T) {
	// At exactly 2^31 difference, the comparison breaks down
	// This documents the precondition rather than testing correct behavior
	a := uint32(0)
	b := uint32(1 << 31) // 2^31

	// At the boundary, int32(a - b) = int32(-2^31) = -2^31
	// This is the most negative int32 value and the comparison is ambiguous
	result := seqBefore(a, b)

	// We document this edge case but don't assert correctness since it violates
	// the precondition |a - b| < 2^31
	t.Logf("seqBefore(0, 2^31) = %v (at half-space boundary, result is implementation-defined)", result)
}
