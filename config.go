package promptlock

import (
	"github.com/rajanyadav/promptlock/detector"
	"github.com/rajanyadav/promptlock/judge"
	"github.com/rajanyadav/promptlock/registry"
)

// SecurityLevel controls the aggressiveness of protection.
type SecurityLevel int

const (
	Basic      SecurityLevel = iota // High + Critical patterns only, no judge, no delimiters
	Balanced                         // All patterns, judge on large suspicious inputs, delimiters on
	Aggressive                       // All patterns, judge always, delimiters on
)

// String returns the string representation of a SecurityLevel.
func (l SecurityLevel) String() string {
	switch l {
	case Basic:
		return "basic"
	case Balanced:
		return "balanced"
	case Aggressive:
		return "aggressive"
	default:
		return "unknown"
	}
}

// Config holds the Shield configuration.
type Config struct {
	Level          SecurityLevel
	RedactPII      bool
	DelimitersOn   bool
	MaxInputLength int
	PatternFile    string
	CustomPatterns []registry.Pattern
	Embedder       detector.Embedder
	Judge          judge.Judge
	OnViolation    func(detector.Violation)
}

// Option configures a Shield.
type Option func(*Config)

// WithLevel sets the security level.
func WithLevel(level SecurityLevel) Option {
	return func(c *Config) {
		c.Level = level
	}
}

// WithRedactPII enables or disables PII redaction.
func WithRedactPII(enabled bool) Option {
	return func(c *Config) {
		c.RedactPII = enabled
	}
}

// WithDelimiters enables or disables security delimiter wrapping.
func WithDelimiters(enabled bool) Option {
	return func(c *Config) {
		c.DelimitersOn = enabled
	}
}

// WithMaxInputLength sets the maximum allowed input length in bytes.
// Inputs exceeding this length are flagged as context overflow.
// Default is 32768 (32KB).
func WithMaxInputLength(n int) Option {
	return func(c *Config) {
		c.MaxInputLength = n
	}
}

// WithPatternFile sets a custom pattern file path.
// If set, patterns are loaded from this file instead of the embedded defaults.
func WithPatternFile(path string) Option {
	return func(c *Config) {
		c.PatternFile = path
	}
}

// WithCustomPatterns adds additional patterns on top of the defaults.
func WithCustomPatterns(patterns ...registry.Pattern) Option {
	return func(c *Config) {
		c.CustomPatterns = append(c.CustomPatterns, patterns...)
	}
}

// WithEmbedder sets the embedding provider for vector similarity detection.
// When set, the VectorDetector is enabled alongside the PatternDetector.
func WithEmbedder(e detector.Embedder) Option {
	return func(c *Config) {
		c.Embedder = e
	}
}

// WithJudge sets the shadow LLM judge for intent classification.
func WithJudge(j judge.Judge) Option {
	return func(c *Config) {
		c.Judge = j
	}
}

// WithOnViolation sets a callback invoked when a violation is detected.
func WithOnViolation(fn func(detector.Violation)) Option {
	return func(c *Config) {
		c.OnViolation = fn
	}
}

// applyDefaults sets default values based on security level.
func (c *Config) applyDefaults() {
	if c.MaxInputLength == 0 {
		c.MaxInputLength = 32768
	}
	switch c.Level {
	case Basic:
		// Delimiters off by default in Basic
	case Balanced:
		c.DelimitersOn = true
	case Aggressive:
		c.DelimitersOn = true
	}
}
