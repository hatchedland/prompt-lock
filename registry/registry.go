// Package registry provides storage and management of malicious pattern definitions.
//
// The registry decouples pattern definitions from detection logic, allowing
// patterns to be updated without recompiling, loaded from embedded defaults
// or external files, and extended with custom patterns.
package registry

import (
	"context"
	"fmt"
	"regexp"
	"sync"
)

// Known category strings used in Pattern definitions.
const (
	CategoryJailbreak      = "jailbreak"
	CategoryInjection      = "injection"
	CategoryTokenSmuggling = "token_smuggling"
	CategoryPromptLeak     = "prompt_leak"
	CategoryContextOverflow = "context_overflow"
)

// Known severity strings used in Pattern definitions.
const (
	SeverityLow      = "low"
	SeverityMedium   = "medium"
	SeverityHigh     = "high"
	SeverityCritical = "critical"
)

var validCategories = map[string]bool{
	CategoryJailbreak:       true,
	CategoryInjection:       true,
	CategoryTokenSmuggling:  true,
	CategoryPromptLeak:      true,
	CategoryContextOverflow: true,
}

var validSeverities = map[string]bool{
	SeverityLow:      true,
	SeverityMedium:   true,
	SeverityHigh:     true,
	SeverityCritical: true,
}

// Pattern defines a single detection rule loaded from JSON.
type Pattern struct {
	ID          string   `json:"id"`
	Description string   `json:"description"`
	Regex       string   `json:"regex"`
	Category    string   `json:"category"`
	Severity    string   `json:"severity"`
	Weight      int      `json:"weight"`
	Tags        []string `json:"tags"`
	Enabled     bool     `json:"enabled"`
	Version     int      `json:"version"`
}

// PatternStore provides read access to the pattern collection.
type PatternStore interface {
	Patterns() []Pattern
	ByCategory(category string) []Pattern
	BySeverity(minSeverity string) []Pattern
}

// ReloadableStore extends PatternStore with hot-reload capability.
type ReloadableStore interface {
	PatternStore
	Reload(ctx context.Context) error
}

// MemoryStore is an in-memory, thread-safe PatternStore.
type MemoryStore struct {
	mu         sync.RWMutex
	patterns   []Pattern
	byCategory map[string][]Pattern
}

// NewMemoryStore creates a MemoryStore after validating all patterns.
func NewMemoryStore(patterns []Pattern) (*MemoryStore, error) {
	for _, p := range patterns {
		if err := Validate(p); err != nil {
			return nil, fmt.Errorf("registry: pattern %q: %w", p.ID, err)
		}
	}
	s := &MemoryStore{}
	s.patterns = make([]Pattern, len(patterns))
	copy(s.patterns, patterns)
	s.buildIndices()
	return s, nil
}

// Patterns returns a copy of all enabled patterns.
func (s *MemoryStore) Patterns() []Pattern {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]Pattern, 0, len(s.patterns))
	for _, p := range s.patterns {
		if p.Enabled {
			result = append(result, p)
		}
	}
	return result
}

// ByCategory returns enabled patterns matching the given category.
func (s *MemoryStore) ByCategory(category string) []Pattern {
	s.mu.RLock()
	defer s.mu.RUnlock()
	src := s.byCategory[category]
	result := make([]Pattern, 0, len(src))
	for _, p := range src {
		if p.Enabled {
			result = append(result, p)
		}
	}
	return result
}

// BySeverity returns enabled patterns at or above the given minimum severity.
func (s *MemoryStore) BySeverity(minSeverity string) []Pattern {
	s.mu.RLock()
	defer s.mu.RUnlock()
	minRank := severityRank(minSeverity)
	result := make([]Pattern, 0)
	for _, p := range s.patterns {
		if p.Enabled && severityRank(p.Severity) >= minRank {
			result = append(result, p)
		}
	}
	return result
}

// Add validates and adds patterns to the store.
func (s *MemoryStore) Add(patterns ...Pattern) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	ids := make(map[string]bool, len(s.patterns))
	for _, p := range s.patterns {
		ids[p.ID] = true
	}
	for _, p := range patterns {
		if err := Validate(p); err != nil {
			return fmt.Errorf("registry: add pattern %q: %w", p.ID, err)
		}
		if ids[p.ID] {
			return fmt.Errorf("registry: add pattern: duplicate ID %q", p.ID)
		}
		ids[p.ID] = true
		s.patterns = append(s.patterns, p)
	}
	s.buildIndices()
	return nil
}

// Remove removes a pattern by ID. Returns true if the pattern was found and removed.
func (s *MemoryStore) Remove(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, p := range s.patterns {
		if p.ID == id {
			s.patterns = append(s.patterns[:i], s.patterns[i+1:]...)
			s.buildIndices()
			return true
		}
	}
	return false
}

// Reload re-validates all patterns and rebuilds indices.
func (s *MemoryStore) Reload(_ context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range s.patterns {
		if err := Validate(p); err != nil {
			return fmt.Errorf("registry: reload: pattern %q: %w", p.ID, err)
		}
	}
	s.buildIndices()
	return nil
}

// buildIndices rebuilds the category index. Must be called with write lock held.
func (s *MemoryStore) buildIndices() {
	s.byCategory = make(map[string][]Pattern)
	for _, p := range s.patterns {
		s.byCategory[p.Category] = append(s.byCategory[p.Category], p)
	}
}

// Validate checks that a Pattern has valid fields and a compilable regex.
func Validate(p Pattern) error {
	if p.ID == "" {
		return fmt.Errorf("empty pattern ID")
	}
	if p.Regex == "" {
		return fmt.Errorf("empty regex")
	}
	if _, err := regexp.Compile(p.Regex); err != nil {
		return fmt.Errorf("invalid regex: %w", err)
	}
	if !validCategories[p.Category] {
		return fmt.Errorf("invalid category %q", p.Category)
	}
	if !validSeverities[p.Severity] {
		return fmt.Errorf("invalid severity %q", p.Severity)
	}
	if p.Weight < 0 || p.Weight > 100 {
		return fmt.Errorf("weight %d out of range [0, 100]", p.Weight)
	}
	return nil
}

// severityRank maps severity strings to comparable integer ranks.
func severityRank(s string) int {
	switch s {
	case SeverityLow:
		return 0
	case SeverityMedium:
		return 1
	case SeverityHigh:
		return 2
	case SeverityCritical:
		return 3
	default:
		return -1
	}
}
