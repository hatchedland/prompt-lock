package randutil

import (
	"encoding/hex"
	"testing"
)

func TestHexString_Length(t *testing.T) {
	t.Parallel()
	tests := []struct {
		n       int
		wantLen int
	}{
		{1, 2},
		{4, 8},
		{8, 16},
		{16, 32},
	}
	for _, tt := range tests {
		got, err := HexString(tt.n)
		if err != nil {
			t.Fatalf("HexString(%d) error: %v", tt.n, err)
		}
		if len(got) != tt.wantLen {
			t.Errorf("HexString(%d) length = %d, want %d", tt.n, len(got), tt.wantLen)
		}
	}
}

func TestHexString_ValidHex(t *testing.T) {
	t.Parallel()
	got, err := HexString(16)
	if err != nil {
		t.Fatalf("HexString(16) error: %v", err)
	}
	if _, err := hex.DecodeString(got); err != nil {
		t.Errorf("HexString(16) produced invalid hex %q: %v", got, err)
	}
}

func TestHexString_Uniqueness(t *testing.T) {
	t.Parallel()
	seen := make(map[string]struct{}, 10000)
	for i := 0; i < 10000; i++ {
		s, err := HexString(8)
		if err != nil {
			t.Fatalf("HexString(8) error on iteration %d: %v", i, err)
		}
		if _, exists := seen[s]; exists {
			t.Fatalf("HexString(8) produced duplicate on iteration %d: %q", i, s)
		}
		seen[s] = struct{}{}
	}
}

func TestHexString_InvalidLength(t *testing.T) {
	t.Parallel()
	if _, err := HexString(0); err == nil {
		t.Error("HexString(0) should return error")
	}
	if _, err := HexString(-1); err == nil {
		t.Error("HexString(-1) should return error")
	}
}
