package vault

import (
	"context"
	"strings"
	"testing"
)

func TestPIIRedactor_Email(t *testing.T) {
	t.Parallel()
	r := NewPIIRedactor()
	ctx := context.Background()

	result, entities, err := r.Redact(ctx, "Contact me at user@example.com for details")
	if err != nil {
		t.Fatalf("Redact() error: %v", err)
	}
	if strings.Contains(result, "user@example.com") {
		t.Error("Redact() should mask email address")
	}
	if len(entities) != 1 {
		t.Fatalf("Redact() returned %d entities, want 1", len(entities))
	}
	if entities[0].Type != EntityEmail {
		t.Errorf("Entity type = %v, want EMAIL", entities[0].Type)
	}
	if entities[0].Original != "user@example.com" {
		t.Errorf("Original = %q, want %q", entities[0].Original, "user@example.com")
	}
}

func TestPIIRedactor_Phone(t *testing.T) {
	t.Parallel()
	r := NewPIIRedactor()
	ctx := context.Background()

	result, entities, err := r.Redact(ctx, "Call me at (555) 123-4567")
	if err != nil {
		t.Fatalf("Redact() error: %v", err)
	}
	if strings.Contains(result, "555") {
		t.Error("Redact() should mask phone number")
	}
	if len(entities) != 1 {
		t.Fatalf("Redact() returned %d entities, want 1", len(entities))
	}
	if entities[0].Type != EntityPhone {
		t.Errorf("Entity type = %v, want PHONE", entities[0].Type)
	}
}

func TestPIIRedactor_SSN(t *testing.T) {
	t.Parallel()
	r := NewPIIRedactor()
	ctx := context.Background()

	result, entities, err := r.Redact(ctx, "My SSN is 123-45-6789")
	if err != nil {
		t.Fatalf("Redact() error: %v", err)
	}
	if strings.Contains(result, "123-45-6789") {
		t.Error("Redact() should mask SSN")
	}
	if len(entities) < 1 {
		t.Fatal("Redact() should detect SSN")
	}
}

func TestPIIRedactor_APIKey(t *testing.T) {
	t.Parallel()
	r := NewPIIRedactor()
	ctx := context.Background()

	result, _, err := r.Redact(ctx, "My key is sk-abcdefghijklmnopqrstuvwxyz")
	if err != nil {
		t.Fatalf("Redact() error: %v", err)
	}
	if strings.Contains(result, "sk-abcdefghijklmnopqrstuvwxyz") {
		t.Error("Redact() should mask API key")
	}
}

func TestPIIRedactor_DuplicateSameEmail(t *testing.T) {
	t.Parallel()
	r := NewPIIRedactor()
	ctx := context.Background()

	input := "Email user@test.com and also user@test.com"
	result, entities, err := r.Redact(ctx, input)
	if err != nil {
		t.Fatalf("Redact() error: %v", err)
	}
	// Both occurrences should get the same placeholder
	if len(entities) != 2 {
		t.Fatalf("Redact() returned %d entities, want 2", len(entities))
	}
	if entities[0].Placeholder != entities[1].Placeholder {
		t.Error("Same value should get same placeholder")
	}
	_ = result
}

func TestPIIRedactor_CleanInput(t *testing.T) {
	t.Parallel()
	r := NewPIIRedactor()
	ctx := context.Background()

	input := "What is the weather in Tokyo?"
	result, entities, err := r.Redact(ctx, input)
	if err != nil {
		t.Fatalf("Redact() error: %v", err)
	}
	if result != input {
		t.Errorf("Clean input should be unchanged, got %q", result)
	}
	if len(entities) != 0 {
		t.Errorf("Clean input should have 0 entities, got %d", len(entities))
	}
}

func TestPIIRedactor_Restore(t *testing.T) {
	t.Parallel()
	r := NewPIIRedactor()
	ctx := context.Background()

	input := "Contact user@example.com please"
	redacted, entities, _ := r.Redact(ctx, input)

	restored := r.Restore(redacted, entities)
	if restored != input {
		t.Errorf("Restore() = %q, want %q", restored, input)
	}
}

func TestPIIRedactor_WithEntityTypes(t *testing.T) {
	t.Parallel()
	r := NewPIIRedactor(WithEntityTypes(EntityEmail))
	ctx := context.Background()

	input := "Email user@test.com phone (555) 123-4567"
	_, entities, _ := r.Redact(ctx, input)

	for _, e := range entities {
		if e.Type == EntityPhone {
			t.Error("Should not detect phone when only email is enabled")
		}
	}
}

func TestLuhnCheck(t *testing.T) {
	t.Parallel()
	tests := []struct {
		number string
		valid  bool
	}{
		{"4111111111111111", true},  // Visa test number
		{"5500000000000004", true},  // Mastercard test number
		{"4111111111111112", false}, // Invalid check digit
		{"1234567890", false},       // Too short
	}
	for _, tt := range tests {
		if got := luhnCheck(tt.number); got != tt.valid {
			t.Errorf("luhnCheck(%q) = %v, want %v", tt.number, got, tt.valid)
		}
	}
}

func BenchmarkRedact_4KB(b *testing.B) {
	r := NewPIIRedactor()
	ctx := context.Background()
	input := strings.Repeat("Contact user@example.com at (555) 123-4567. ", 80)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = r.Redact(ctx, input)
	}
}
