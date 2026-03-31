// Package detector provides threat detection engines for analyzing sanitized input.
//
// The detector is the second stage of the PromptLock pipeline. After sanitization
// normalizes input, detectors scan it for known attack patterns, suspicious
// structures, and semantic similarity to known attack vectors.
package detector

import (
	"context"
	"fmt"
	"sort"
	"sync"
)

// Category classifies the type of attack.
type Category int

const (
	CategoryJailbreak       Category = iota // DAN, Developer Mode, roleplay escapes
	CategoryInjection                        // "Ignore previous", "New instructions"
	CategoryTokenSmuggling                   // Encoded payloads, Unicode tricks
	CategoryPromptLeak                       // "Repeat your system prompt"
	CategoryContextOverflow                  // Excessive input to displace system prompt
)

// String returns the string representation of a Category.
func (c Category) String() string {
	switch c {
	case CategoryJailbreak:
		return "jailbreak"
	case CategoryInjection:
		return "injection"
	case CategoryTokenSmuggling:
		return "token_smuggling"
	case CategoryPromptLeak:
		return "prompt_leak"
	case CategoryContextOverflow:
		return "context_overflow"
	default:
		return fmt.Sprintf("unknown(%d)", int(c))
	}
}

// ParseCategory converts a string to a Category.
func ParseCategory(s string) (Category, error) {
	switch s {
	case "jailbreak":
		return CategoryJailbreak, nil
	case "injection":
		return CategoryInjection, nil
	case "token_smuggling":
		return CategoryTokenSmuggling, nil
	case "prompt_leak":
		return CategoryPromptLeak, nil
	case "context_overflow":
		return CategoryContextOverflow, nil
	default:
		return 0, fmt.Errorf("detector: unknown category %q", s)
	}
}

// Severity indicates how dangerous the detected threat is.
type Severity int

const (
	SeverityLow      Severity = iota // Suspicious but likely benign
	SeverityMedium                    // Probable attack attempt
	SeverityHigh                      // Known attack pattern
	SeverityCritical                  // Active exploitation attempt
)

// String returns the string representation of a Severity.
func (s Severity) String() string {
	switch s {
	case SeverityLow:
		return "low"
	case SeverityMedium:
		return "medium"
	case SeverityHigh:
		return "high"
	case SeverityCritical:
		return "critical"
	default:
		return fmt.Sprintf("unknown(%d)", int(s))
	}
}

// ParseSeverity converts a string to a Severity.
func ParseSeverity(s string) (Severity, error) {
	switch s {
	case "low":
		return SeverityLow, nil
	case "medium":
		return SeverityMedium, nil
	case "high":
		return SeverityHigh, nil
	case "critical":
		return SeverityCritical, nil
	default:
		return 0, fmt.Errorf("detector: unknown severity %q", s)
	}
}

// Violation represents a single detected threat.
type Violation struct {
	Rule       string   // Machine-readable rule ID, e.g., "JAILBREAK_DAN"
	Category   Category // Attack category
	Severity   Severity // Threat severity level
	Matched    string   // Truncated substring that triggered the rule
	Confidence float64  // 0.0–1.0 confidence score
	Offset     int      // Byte offset in the input where match starts
	Weight     int      // Score weight for this pattern
}

// Detector analyzes input and returns any violations found.
// Implementations must be safe for concurrent use after construction.
type Detector interface {
	Detect(ctx context.Context, input string) ([]Violation, error)
}

// Composite runs multiple detectors and merges their results.
type Composite struct {
	detectors []Detector
}

// NewComposite creates a Composite detector that runs all given detectors.
func NewComposite(detectors ...Detector) *Composite {
	return &Composite{detectors: detectors}
}

// Detect runs all detectors concurrently, merges violations, deduplicates
// by rule ID, and returns them sorted by severity (Critical first).
func (c *Composite) Detect(ctx context.Context, input string) ([]Violation, error) {
	if len(c.detectors) == 0 {
		return nil, nil
	}

	if len(c.detectors) == 1 {
		return c.detectors[0].Detect(ctx, input)
	}

	type result struct {
		violations []Violation
		err        error
	}

	results := make([]result, len(c.detectors))
	var wg sync.WaitGroup
	wg.Add(len(c.detectors))

	for i, d := range c.detectors {
		go func(idx int, det Detector) {
			defer wg.Done()
			v, err := det.Detect(ctx, input)
			results[idx] = result{violations: v, err: err}
		}(i, d)
	}
	wg.Wait()

	// Check for errors
	for _, r := range results {
		if r.err != nil {
			return nil, fmt.Errorf("detector: composite: %w", r.err)
		}
	}

	// Merge and deduplicate
	seen := make(map[string]bool)
	var merged []Violation
	for _, r := range results {
		for _, v := range r.violations {
			if !seen[v.Rule] {
				seen[v.Rule] = true
				merged = append(merged, v)
			}
		}
	}

	// Sort by severity descending (Critical first)
	sort.Slice(merged, func(i, j int) bool {
		return merged[i].Severity > merged[j].Severity
	})

	return merged, nil
}
