package delimiter

import (
	"strings"
	"testing"
)

func TestRandomDelimiter_Wrap(t *testing.T) {
	t.Parallel()
	d := New()
	wrapped, instruction, err := d.Wrap("hello world")
	if err != nil {
		t.Fatalf("Wrap() error: %v", err)
	}

	if !strings.HasPrefix(wrapped, "<user_input_") {
		t.Errorf("wrapped should start with <user_input_, got %q", wrapped[:30])
	}
	if !strings.Contains(wrapped, "hello world") {
		t.Error("wrapped should contain the original input")
	}
	if !strings.Contains(instruction, "user_input_") {
		t.Error("instruction should reference the tag name")
	}
	if !strings.Contains(instruction, "untrusted") {
		t.Error("instruction should mention untrusted data")
	}
}

func TestRandomDelimiter_Uniqueness(t *testing.T) {
	t.Parallel()
	d := New()
	seen := make(map[string]struct{}, 10000)

	for i := 0; i < 10000; i++ {
		wrapped, _, err := d.Wrap("test")
		if err != nil {
			t.Fatalf("Wrap() error on iteration %d: %v", i, err)
		}
		// Extract tag from wrapped output
		end := strings.Index(wrapped, ">")
		tag := wrapped[1:end]

		if _, exists := seen[tag]; exists {
			t.Fatalf("duplicate tag on iteration %d: %s", i, tag)
		}
		seen[tag] = struct{}{}
	}
}

func TestRandomDelimiter_Format(t *testing.T) {
	t.Parallel()
	d := New(WithTokenLength(4))
	wrapped, _, err := d.Wrap("content")
	if err != nil {
		t.Fatalf("Wrap() error: %v", err)
	}

	// Should be: <user_input_XXXXXXXX>content</user_input_XXXXXXXX>
	// With 4 bytes = 8 hex chars
	if !strings.Contains(wrapped, "content") {
		t.Error("wrapped should contain content")
	}

	// Check closing tag matches opening tag
	openEnd := strings.Index(wrapped, ">")
	openTag := wrapped[1:openEnd]
	expectedClose := "</" + openTag + ">"
	if !strings.HasSuffix(wrapped, expectedClose) {
		t.Errorf("closing tag mismatch: got %q, want suffix %q", wrapped, expectedClose)
	}
}

func TestRandomDelimiter_CustomPrefix(t *testing.T) {
	t.Parallel()
	d := New(WithPrefix("untrusted_data"))
	wrapped, _, err := d.Wrap("test")
	if err != nil {
		t.Fatalf("Wrap() error: %v", err)
	}
	if !strings.HasPrefix(wrapped, "<untrusted_data_") {
		t.Errorf("wrapped should use custom prefix, got %q", wrapped[:20])
	}
}

func BenchmarkWrap(b *testing.B) {
	d := New()
	input := strings.Repeat("test input ", 100)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = d.Wrap(input)
	}
}
