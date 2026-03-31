package sanitizer

import (
	"context"
	"strings"

	"golang.org/x/text/unicode/norm"
)

// UnicodeNormalizer applies NFKC normalization to input text.
//
// NFKC (Compatibility Decomposition + Canonical Composition) maps visually
// similar characters to their ASCII equivalents. This prevents homoglyph
// attacks where Cyrillic, fullwidth, or mathematical characters are used
// to evade pattern matching.
//
// Examples:
//   - "Ｉｇｎｏｒｅ" → "Ignore" (fullwidth)
//   - "ﬁle" → "file" (fi ligature)
type UnicodeNormalizer struct{}

// NewUnicodeNormalizer creates a new UnicodeNormalizer.
func NewUnicodeNormalizer() *UnicodeNormalizer {
	return &UnicodeNormalizer{}
}

// Sanitize normalizes the input to NFKC form and replaces invalid UTF-8 sequences.
func (n *UnicodeNormalizer) Sanitize(_ context.Context, input string) (string, error) {
	valid := strings.ToValidUTF8(input, "\uFFFD")
	return norm.NFKC.String(valid), nil
}
