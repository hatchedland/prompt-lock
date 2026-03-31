package sanitizer

import (
	"context"
	"strings"
)

// InvisibleCharStripper removes characters that are invisible but affect string matching.
//
// Stripped categories:
//   - Zero-width spaces: U+200B, U+200C, U+200D, U+FEFF
//   - Control characters: U+0000–U+001F (except \n, \r, \t), U+007F–U+009F
//   - Bidirectional overrides: U+202A–U+202E, U+2066–U+2069
//   - Tag characters: U+E0001–U+E007F
//   - Variation selectors: U+FE00–U+FE0F
//
// \n (0x0A), \r (0x0D), and \t (0x09) are preserved as they carry
// meaningful formatting in prompts.
type InvisibleCharStripper struct{}

// NewInvisibleCharStripper creates a new InvisibleCharStripper.
func NewInvisibleCharStripper() *InvisibleCharStripper {
	return &InvisibleCharStripper{}
}

// Sanitize removes invisible and control characters from the input.
func (s *InvisibleCharStripper) Sanitize(_ context.Context, input string) (string, error) {
	var b strings.Builder
	b.Grow(len(input))
	for _, r := range input {
		if !shouldStrip(r) {
			b.WriteRune(r)
		}
	}
	return b.String(), nil
}

// shouldStrip returns true if the rune should be removed from input.
func shouldStrip(r rune) bool {
	// Preserve tab, newline, carriage return
	if r == '\t' || r == '\n' || r == '\r' {
		return false
	}

	// C0 control characters (U+0000–U+001F) excluding \t \n \r
	if r >= 0x0000 && r <= 0x001F {
		return true
	}

	// Delete + C1 control characters (U+007F–U+009F)
	if r >= 0x007F && r <= 0x009F {
		return true
	}

	// Zero-width characters
	if r == 0x200B || r == 0x200C || r == 0x200D || r == 0xFEFF {
		return true
	}

	// Bidirectional override characters (U+202A–U+202E)
	if r >= 0x202A && r <= 0x202E {
		return true
	}

	// Bidirectional isolate characters (U+2066–U+2069)
	if r >= 0x2066 && r <= 0x2069 {
		return true
	}

	// Tag characters (U+E0001–U+E007F)
	if r >= 0xE0001 && r <= 0xE007F {
		return true
	}

	// Variation selectors (U+FE00–U+FE0F)
	if r >= 0xFE00 && r <= 0xFE0F {
		return true
	}

	return false
}
