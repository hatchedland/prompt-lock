package promptlock

import (
	"fmt"
	"strings"
	"time"

	"github.com/rajanyadav/promptlock/detector"
	"github.com/rajanyadav/promptlock/vault"
)

// ScanVerdict is the overall classification based on accumulated score.
type ScanVerdict int

const (
	VerdictClean      ScanVerdict = iota // Score < 15
	VerdictSuspicious                     // Score 15-39
	VerdictLikely                         // Score 40-69
	VerdictMalicious                      // Score >= 70
)

// String returns the string representation of a ScanVerdict.
func (v ScanVerdict) String() string {
	switch v {
	case VerdictClean:
		return "clean"
	case VerdictSuspicious:
		return "suspicious"
	case VerdictLikely:
		return "likely"
	case VerdictMalicious:
		return "malicious"
	default:
		return fmt.Sprintf("unknown(%d)", int(v))
	}
}

// VerdictFromScore maps an accumulated score to a ScanVerdict.
func VerdictFromScore(score int) ScanVerdict {
	switch {
	case score >= 70:
		return VerdictMalicious
	case score >= 40:
		return VerdictLikely
	case score >= 15:
		return VerdictSuspicious
	default:
		return VerdictClean
	}
}

// ScanResult contains the full result of a Protect or ProtectWithResult call.
type ScanResult struct {
	Output     string               // The protected output string
	Clean      bool                 // True if no violations found
	Violations []detector.Violation // All detected threats
	Redactions []vault.RedactedEntity // PII entities that were redacted
	Delimiter  string               // The delimiter tag used (if enabled)
	Score      int                  // Accumulated weight score
	Verdict    ScanVerdict          // Clean, Suspicious, Likely, Malicious
	Latency    time.Duration        // Total processing time
}

// PromptLockError is returned when violations are detected and the input is blocked.
type PromptLockError struct {
	Violations []detector.Violation
	Score      int
	Verdict    ScanVerdict
	Message    string
}

// Error returns a human-readable error message.
func (e *PromptLockError) Error() string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("promptlock: input blocked (verdict=%s, score=%d)", e.Verdict, e.Score))
	if e.Message != "" {
		b.WriteString(": ")
		b.WriteString(e.Message)
	}
	if len(e.Violations) > 0 {
		b.WriteString(fmt.Sprintf(" [%d violation(s): ", len(e.Violations)))
		for i, v := range e.Violations {
			if i > 0 {
				b.WriteString(", ")
			}
			b.WriteString(v.Rule)
		}
		b.WriteString("]")
	}
	return b.String()
}
