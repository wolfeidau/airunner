package util

import (
	"math"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAsInt32(t *testing.T) {
	tests := []struct {
		name     string
		input    int
		expected int32
	}{
		{
			name:     "zero value",
			input:    0,
			expected: 0,
		},
		{
			name:     "positive value within range",
			input:    1000,
			expected: 1000,
		},
		{
			name:     "negative value within range",
			input:    -1000,
			expected: -1000,
		},
		{
			name:     "max int32 value",
			input:    2147483647,
			expected: 2147483647,
		},
		{
			name:     "min int32 value",
			input:    -2147483648,
			expected: -2147483648,
		},
		{
			name:     "value above max int32",
			input:    2147483648,
			expected: 2147483647,
		},
		{
			name:     "large positive value",
			input:    9223372036854775807, // max int64
			expected: 2147483647,
		},
		{
			name:     "value below min int32",
			input:    -2147483649,
			expected: -2147483648,
		},
		{
			name:     "large negative value",
			input:    -9223372036854775808, // min int64
			expected: -2147483648,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := AsInt32(tt.input)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestAsInt32_Constants(t *testing.T) {
	// Test using math constants to ensure we handle the exact boundaries
	require.Equal(t, int32(math.MaxInt32), AsInt32(math.MaxInt32))
	require.Equal(t, int32(math.MinInt32), AsInt32(math.MinInt32))
	require.Equal(t, int32(math.MaxInt32), AsInt32(math.MaxInt32+1))
	require.Equal(t, int32(math.MinInt32), AsInt32(math.MinInt32-1))
}
