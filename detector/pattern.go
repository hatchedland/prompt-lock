package detector

import (
	"context"
	"regexp"
	"sort"
)

// SecurityMode controls matching behavior of the PatternDetector.
type SecurityMode int

const (
	ModeBasic      SecurityMode = iota // High + Critical only, short-circuit on Critical
	ModeBalanced                        // All severities, run all patterns
	ModeAggressive                      // All severities, short-circuit on Critical
)

// Rule is a pre-compiled detection rule.
type Rule struct {
	ID          string
	Description string
	Compiled    *regexp.Regexp
	Category    Category
	Severity    Severity
	Weight      int
	Tags        []string
}

// PatternDetector performs regex-based threat detection against pre-compiled rules.
// Safe for concurrent use after construction.
type PatternDetector struct {
	rules    []Rule       // sorted by severity descending (Critical first)
	mode     SecurityMode
	maxMatch int          // max matched substring length in Violation.Matched
}

// PatternOption configures a PatternDetector.
type PatternOption func(*PatternDetector)

// WithSecurityMode sets the matching mode.
func WithSecurityMode(m SecurityMode) PatternOption {
	return func(d *PatternDetector) {
		d.mode = m
	}
}

// WithMaxMatchLength sets the maximum length of the matched substring
// included in Violation.Matched. Longer matches are truncated with "...".
func WithMaxMatchLength(n int) PatternOption {
	return func(d *PatternDetector) {
		d.maxMatch = n
	}
}

// NewPatternDetector creates a PatternDetector with the given rules.
// Rules are sorted by severity descending for optimal short-circuiting.
func NewPatternDetector(rules []Rule, opts ...PatternOption) *PatternDetector {
	sorted := make([]Rule, len(rules))
	copy(sorted, rules)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Severity > sorted[j].Severity
	})

	d := &PatternDetector{
		rules:    sorted,
		mode:     ModeBalanced,
		maxMatch: 100,
	}
	for _, opt := range opts {
		opt(d)
	}
	return d
}

// Detect scans input against all rules per the configured mode.
func (d *PatternDetector) Detect(ctx context.Context, input string) ([]Violation, error) {
	var violations []Violation

	for _, rule := range d.rules {
		// Check context cancellation between patterns
		if err := ctx.Err(); err != nil {
			return violations, err
		}

		// In Basic mode, skip patterns below High severity
		if d.mode == ModeBasic && rule.Severity < SeverityHigh {
			continue
		}

		loc := rule.Compiled.FindStringIndex(input)
		if loc == nil {
			continue
		}

		matched := input[loc[0]:loc[1]]
		if len(matched) > d.maxMatch {
			half := d.maxMatch / 2
			matched = matched[:half] + "..." + matched[len(matched)-half:]
		}

		v := Violation{
			Rule:       rule.ID,
			Category:   rule.Category,
			Severity:   rule.Severity,
			Matched:    matched,
			Confidence: severityToConfidence(rule.Severity),
			Offset:     loc[0],
			Weight:     rule.Weight,
		}
		violations = append(violations, v)

		// Short-circuit on Critical match in Basic and Aggressive modes
		if rule.Severity == SeverityCritical && (d.mode == ModeBasic || d.mode == ModeAggressive) {
			return violations, nil
		}
	}

	return violations, nil
}

// severityToConfidence maps severity to a default confidence score.
func severityToConfidence(s Severity) float64 {
	switch s {
	case SeverityCritical:
		return 0.95
	case SeverityHigh:
		return 0.85
	case SeverityMedium:
		return 0.70
	case SeverityLow:
		return 0.50
	default:
		return 0.50
	}
}
