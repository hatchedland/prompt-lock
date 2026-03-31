package sanitizer

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"regexp"
	"strings"
	"unicode"
)

var (
	base64Pattern = regexp.MustCompile(`[A-Za-z0-9+/]{20,}={0,2}`)
	hexPattern    = regexp.MustCompile(`(?:0x)?([0-9a-fA-F]{20,})`)
)

// defaultLeetspeakMap maps common leetspeak substitutions to their ASCII equivalents.
var defaultLeetspeakMap = map[rune]rune{
	'0': 'o',
	'1': 'i',
	'3': 'e',
	'4': 'a',
	'5': 's',
	'7': 't',
	'@': 'a',
}

// FormatDecoder detects and decodes encoded payloads hidden in input text.
//
// Supported formats: Base64, Hex, Leetspeak.
//
// Decoding is additive — the decoded version is appended to the output alongside
// the original text. This prevents false negatives from partial decoding and
// preserves the original for downstream processing.
type FormatDecoder struct {
	leetspeakMap map[rune]rune
	minB64Len    int
}

// DecoderOption configures a FormatDecoder.
type DecoderOption func(*FormatDecoder)

// WithLeetspeakMap sets a custom leetspeak substitution map.
func WithLeetspeakMap(m map[rune]rune) DecoderOption {
	return func(d *FormatDecoder) {
		d.leetspeakMap = m
	}
}

// WithMinBase64Length sets the minimum Base64 string length to attempt decoding.
func WithMinBase64Length(n int) DecoderOption {
	return func(d *FormatDecoder) {
		d.minB64Len = n
	}
}

// NewFormatDecoder creates a FormatDecoder with the given options.
func NewFormatDecoder(opts ...DecoderOption) *FormatDecoder {
	d := &FormatDecoder{
		leetspeakMap: defaultLeetspeakMap,
		minB64Len:    20,
	}
	for _, opt := range opts {
		opt(d)
	}
	return d
}

// Sanitize detects encoded segments in the input and appends their decoded forms.
func (d *FormatDecoder) Sanitize(_ context.Context, input string) (string, error) {
	var extras []string

	// Decode Base64 segments
	if decoded := d.decodeBase64Segments(input); len(decoded) > 0 {
		extras = append(extras, decoded...)
	}

	// Decode Hex segments
	if decoded := d.decodeHexSegments(input); len(decoded) > 0 {
		extras = append(extras, decoded...)
	}

	// Decode Leetspeak
	if decoded := d.decodeLeetspeak(input); decoded != input {
		extras = append(extras, decoded)
	}

	if len(extras) == 0 {
		return input, nil
	}

	var b strings.Builder
	b.Grow(len(input) + 64)
	b.WriteString(input)
	for _, extra := range extras {
		b.WriteString("\n[DECODED: ")
		b.WriteString(extra)
		b.WriteString("]")
	}
	return b.String(), nil
}

// decodeBase64Segments finds Base64-encoded segments and returns their decoded ASCII text.
func (d *FormatDecoder) decodeBase64Segments(input string) []string {
	matches := base64Pattern.FindAllString(input, -1)
	var decoded []string
	for _, match := range matches {
		if len(match) < d.minB64Len {
			continue
		}
		b, err := base64.StdEncoding.DecodeString(match)
		if err != nil {
			// Try URL-safe encoding
			b, err = base64.URLEncoding.DecodeString(match)
			if err != nil {
				continue
			}
		}
		if isPrintableASCII(b, 0.8) {
			decoded = append(decoded, string(b))
		}
	}
	return decoded
}

// decodeHexSegments finds hex-encoded segments and returns their decoded ASCII text.
func (d *FormatDecoder) decodeHexSegments(input string) []string {
	matches := hexPattern.FindAllStringSubmatch(input, -1)
	var decoded []string
	for _, match := range matches {
		hexStr := match[1] // captured group without "0x" prefix
		if len(hexStr)%2 != 0 {
			continue
		}
		b, err := hex.DecodeString(hexStr)
		if err != nil {
			continue
		}
		if isPrintableASCII(b, 0.8) {
			decoded = append(decoded, string(b))
		}
	}
	return decoded
}

// decodeLeetspeak applies the substitution map to the entire input.
func (d *FormatDecoder) decodeLeetspeak(input string) string {
	var b strings.Builder
	b.Grow(len(input))
	changed := false
	for _, r := range input {
		if replacement, ok := d.leetspeakMap[r]; ok {
			b.WriteRune(replacement)
			changed = true
		} else {
			b.WriteRune(r)
		}
	}
	if !changed {
		return input
	}
	return b.String()
}

// isPrintableASCII returns true if at least the given ratio of bytes are printable ASCII.
func isPrintableASCII(b []byte, threshold float64) bool {
	if len(b) == 0 {
		return false
	}
	printable := 0
	for _, c := range b {
		if (c >= 0x20 && c <= 0x7E) || c == '\n' || c == '\r' || c == '\t' {
			printable++
		} else if !unicode.IsPrint(rune(c)) {
			// Non-printable non-ASCII byte — likely binary
		}
	}
	return float64(printable)/float64(len(b)) >= threshold
}
