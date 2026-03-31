package registry

import (
	"context"
	"strings"
	"testing"
)

func TestNewMemoryStore_Valid(t *testing.T) {
	t.Parallel()
	patterns := []Pattern{
		{ID: "TEST_1", Regex: "(?i)test", Category: "jailbreak", Severity: "high", Weight: 50, Enabled: true},
		{ID: "TEST_2", Regex: "(?i)foo", Category: "injection", Severity: "low", Weight: 10, Enabled: true},
	}
	store, err := NewMemoryStore(patterns)
	if err != nil {
		t.Fatalf("NewMemoryStore() error: %v", err)
	}
	got := store.Patterns()
	if len(got) != 2 {
		t.Errorf("Patterns() returned %d, want 2", len(got))
	}
}

func TestNewMemoryStore_InvalidRegex(t *testing.T) {
	t.Parallel()
	patterns := []Pattern{
		{ID: "BAD", Regex: "[invalid", Category: "jailbreak", Severity: "high", Weight: 50, Enabled: true},
	}
	_, err := NewMemoryStore(patterns)
	if err == nil {
		t.Fatal("NewMemoryStore() should error on invalid regex")
	}
}

func TestNewMemoryStore_InvalidCategory(t *testing.T) {
	t.Parallel()
	patterns := []Pattern{
		{ID: "BAD", Regex: "test", Category: "invalid_cat", Severity: "high", Weight: 50, Enabled: true},
	}
	_, err := NewMemoryStore(patterns)
	if err == nil {
		t.Fatal("NewMemoryStore() should error on invalid category")
	}
}

func TestMemoryStore_ByCategory(t *testing.T) {
	t.Parallel()
	patterns := []Pattern{
		{ID: "A", Regex: "a", Category: "jailbreak", Severity: "high", Weight: 50, Enabled: true},
		{ID: "B", Regex: "b", Category: "injection", Severity: "high", Weight: 50, Enabled: true},
		{ID: "C", Regex: "c", Category: "jailbreak", Severity: "low", Weight: 10, Enabled: true},
	}
	store, _ := NewMemoryStore(patterns)
	got := store.ByCategory("jailbreak")
	if len(got) != 2 {
		t.Errorf("ByCategory(jailbreak) returned %d, want 2", len(got))
	}
}

func TestMemoryStore_BySeverity(t *testing.T) {
	t.Parallel()
	patterns := []Pattern{
		{ID: "A", Regex: "a", Category: "jailbreak", Severity: "low", Weight: 10, Enabled: true},
		{ID: "B", Regex: "b", Category: "jailbreak", Severity: "high", Weight: 50, Enabled: true},
		{ID: "C", Regex: "c", Category: "jailbreak", Severity: "critical", Weight: 90, Enabled: true},
	}
	store, _ := NewMemoryStore(patterns)
	got := store.BySeverity("high")
	if len(got) != 2 {
		t.Errorf("BySeverity(high) returned %d, want 2 (high + critical)", len(got))
	}
}

func TestMemoryStore_DisabledPatterns(t *testing.T) {
	t.Parallel()
	patterns := []Pattern{
		{ID: "A", Regex: "a", Category: "jailbreak", Severity: "high", Weight: 50, Enabled: true},
		{ID: "B", Regex: "b", Category: "jailbreak", Severity: "high", Weight: 50, Enabled: false},
	}
	store, _ := NewMemoryStore(patterns)
	got := store.Patterns()
	if len(got) != 1 {
		t.Errorf("Patterns() returned %d, want 1 (disabled should be filtered)", len(got))
	}
}

func TestMemoryStore_Add_Duplicate(t *testing.T) {
	t.Parallel()
	patterns := []Pattern{
		{ID: "A", Regex: "a", Category: "jailbreak", Severity: "high", Weight: 50, Enabled: true},
	}
	store, _ := NewMemoryStore(patterns)
	err := store.Add(Pattern{ID: "A", Regex: "b", Category: "jailbreak", Severity: "high", Weight: 50, Enabled: true})
	if err == nil {
		t.Fatal("Add() should error on duplicate ID")
	}
}

func TestMemoryStore_Remove(t *testing.T) {
	t.Parallel()
	patterns := []Pattern{
		{ID: "A", Regex: "a", Category: "jailbreak", Severity: "high", Weight: 50, Enabled: true},
		{ID: "B", Regex: "b", Category: "jailbreak", Severity: "high", Weight: 50, Enabled: true},
	}
	store, _ := NewMemoryStore(patterns)
	if !store.Remove("A") {
		t.Error("Remove(A) returned false, want true")
	}
	got := store.Patterns()
	if len(got) != 1 {
		t.Errorf("After Remove, Patterns() returned %d, want 1", len(got))
	}
}

func TestMemoryStore_Reload(t *testing.T) {
	t.Parallel()
	patterns := []Pattern{
		{ID: "A", Regex: "a", Category: "jailbreak", Severity: "high", Weight: 50, Enabled: true},
	}
	store, _ := NewMemoryStore(patterns)
	if err := store.Reload(context.Background()); err != nil {
		t.Errorf("Reload() error: %v", err)
	}
}

func TestLoadFromReader_Valid(t *testing.T) {
	t.Parallel()
	jsonData := `{"patterns":[{"id":"T","description":"test","regex":"test","category":"jailbreak","severity":"high","weight":50,"tags":[],"enabled":true,"version":1}]}`
	patterns, err := LoadFromReader(strings.NewReader(jsonData))
	if err != nil {
		t.Fatalf("LoadFromReader() error: %v", err)
	}
	if len(patterns) != 1 {
		t.Errorf("LoadFromReader() returned %d patterns, want 1", len(patterns))
	}
}

func TestDefaultPatterns_Loads(t *testing.T) {
	t.Parallel()
	patterns, err := DefaultPatterns()
	if err != nil {
		t.Fatalf("DefaultPatterns() error: %v", err)
	}
	if len(patterns) < 40 {
		t.Errorf("DefaultPatterns() returned %d patterns, expected at least 40", len(patterns))
	}
}

func TestValidate_WeightOutOfRange(t *testing.T) {
	t.Parallel()
	p := Pattern{ID: "T", Regex: "t", Category: "jailbreak", Severity: "high", Weight: 101}
	if err := Validate(p); err == nil {
		t.Error("Validate() should error on weight > 100")
	}
}
