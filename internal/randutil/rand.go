// Package randutil provides cryptographically secure random string generation.
package randutil

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// HexString returns a cryptographically random hex string.
// The returned string is 2*n characters long, where n is the number of random bytes.
func HexString(n int) (string, error) {
	if n <= 0 {
		return "", fmt.Errorf("randutil: byte length must be positive, got %d", n)
	}
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("randutil: read crypto/rand: %w", err)
	}
	return hex.EncodeToString(b), nil
}
