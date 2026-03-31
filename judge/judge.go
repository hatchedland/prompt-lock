// Package judge provides LLM-based intent classification for prompt injection detection.
//
// The judge is the optional third stage of detection, designed to catch novel attacks
// that regex patterns cannot match. It queries a separate "shadow" LLM to classify
// whether input is a genuine user query or a prompt injection attempt.
package judge

import (
	"context"
	"fmt"
)

// Verdict is the judge's classification of user input.
type Verdict int

const (
	VerdictSafe       Verdict = iota // Input appears to be a legitimate query
	VerdictSuspicious                 // Input has some indicators but inconclusive
	VerdictMalicious                  // Input is likely a prompt injection attempt
)

// String returns the string representation of a Verdict.
func (v Verdict) String() string {
	switch v {
	case VerdictSafe:
		return "safe"
	case VerdictSuspicious:
		return "suspicious"
	case VerdictMalicious:
		return "malicious"
	default:
		return fmt.Sprintf("unknown(%d)", int(v))
	}
}

// ParseVerdict converts a string to a Verdict.
func ParseVerdict(s string) Verdict {
	switch s {
	case "safe":
		return VerdictSafe
	case "suspicious":
		return VerdictSuspicious
	case "malicious":
		return VerdictMalicious
	default:
		return VerdictSuspicious // default to suspicious for unknown values
	}
}

// Judge classifies user input as safe or malicious using an LLM.
type Judge interface {
	Classify(ctx context.Context, input string) (Verdict, float64, error)
}
