package promptlock

import (
	"context"
	"fmt"
	"regexp"
	"time"

	"github.com/rajanyadav/promptlock/delimiter"
	"github.com/rajanyadav/promptlock/detector"
	"github.com/rajanyadav/promptlock/judge"
	"github.com/rajanyadav/promptlock/registry"
	"github.com/rajanyadav/promptlock/sanitizer"
	"github.com/rajanyadav/promptlock/vault"
)

// pipeline orchestrates the sanitize → detect → vault → delimit flow.
type pipeline struct {
	sanitizer sanitizer.Sanitizer
	detector  detector.Detector
	redactor  *vault.PIIRedactor
	delimiter *delimiter.RandomDelimiter
	judge     judge.Judge
	config    Config
}

// buildPipeline constructs the pipeline from Config.
func buildPipeline(cfg Config) (*pipeline, error) {
	// Build sanitizer pipeline
	san := sanitizer.NewPipeline(
		sanitizer.NewUnicodeNormalizer(),
		sanitizer.NewInvisibleCharStripper(),
		sanitizer.NewFormatDecoder(),
	)

	// Load patterns
	patterns, err := loadPatterns(cfg)
	if err != nil {
		return nil, fmt.Errorf("promptlock: load patterns: %w", err)
	}

	// Convert registry patterns to detector rules
	rules, err := convertPatterns(patterns)
	if err != nil {
		return nil, fmt.Errorf("promptlock: convert patterns: %w", err)
	}

	// Map security level to detector mode
	var mode detector.SecurityMode
	switch cfg.Level {
	case Basic:
		mode = detector.ModeBasic
	case Balanced:
		mode = detector.ModeBalanced
	case Aggressive:
		mode = detector.ModeAggressive
	}

	// Build detectors list
	detectors := []detector.Detector{
		detector.NewPatternDetector(rules, detector.WithSecurityMode(mode)),
	}

	// Add VectorDetector if an embedder is configured
	if cfg.Embedder != nil {
		corpus, err := detector.DefaultCorpus()
		if err != nil {
			return nil, fmt.Errorf("promptlock: load corpus: %w", err)
		}
		vd := detector.NewVectorDetector(cfg.Embedder,
			detector.WithAttackCorpus(corpus),
			detector.WithSimilarityThreshold(0.82),
		)
		detectors = append(detectors, vd)
	}

	det := detector.NewComposite(detectors...)

	p := &pipeline{
		sanitizer: san,
		detector:  det,
		judge:     cfg.Judge,
		config:    cfg,
	}

	// Vault (optional)
	if cfg.RedactPII {
		p.redactor = vault.NewPIIRedactor()
	}

	// Delimiter (optional)
	if cfg.DelimitersOn {
		p.delimiter = delimiter.New()
	}

	return p, nil
}

// loadPatterns loads patterns from file or embedded defaults.
func loadPatterns(cfg Config) ([]registry.Pattern, error) {
	var patterns []registry.Pattern

	if cfg.PatternFile != "" {
		loaded, err := registry.LoadFromFile(cfg.PatternFile)
		if err != nil {
			return nil, err
		}
		patterns = loaded
	} else {
		defaults, err := registry.DefaultPatterns()
		if err != nil {
			return nil, err
		}
		patterns = defaults
	}

	// Append custom patterns
	patterns = append(patterns, cfg.CustomPatterns...)

	return patterns, nil
}

// convertPatterns maps registry.Pattern to detector.Rule, compiling regex
// and parsing category/severity strings to enums.
func convertPatterns(patterns []registry.Pattern) ([]detector.Rule, error) {
	rules := make([]detector.Rule, 0, len(patterns))
	for _, p := range patterns {
		if !p.Enabled {
			continue
		}

		compiled, err := regexp.Compile(p.Regex)
		if err != nil {
			return nil, fmt.Errorf("pattern %q: compile regex: %w", p.ID, err)
		}

		category, err := detector.ParseCategory(p.Category)
		if err != nil {
			return nil, fmt.Errorf("pattern %q: %w", p.ID, err)
		}

		severity, err := detector.ParseSeverity(p.Severity)
		if err != nil {
			return nil, fmt.Errorf("pattern %q: %w", p.ID, err)
		}

		rules = append(rules, detector.Rule{
			ID:          p.ID,
			Description: p.Description,
			Compiled:    compiled,
			Category:    category,
			Severity:    severity,
			Weight:      p.Weight,
			Tags:        p.Tags,
		})
	}
	return rules, nil
}

// run executes the full pipeline on the given input.
func (p *pipeline) run(ctx context.Context, input string) (*ScanResult, error) {
	start := time.Now()
	result := &ScanResult{Clean: true}

	// 1. Check max input length
	if len(input) > p.config.MaxInputLength {
		v := detector.Violation{
			Rule:       "CONTEXT_OVERFLOW_LENGTH",
			Category:   detector.CategoryContextOverflow,
			Severity:   detector.SeverityHigh,
			Matched:    fmt.Sprintf("input length %d exceeds max %d", len(input), p.config.MaxInputLength),
			Confidence: 0.9,
			Weight:     55,
		}
		result.Violations = append(result.Violations, v)
		result.Score += v.Weight
	}

	// 2. Sanitize
	sanitized, err := p.sanitizer.Sanitize(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("promptlock: sanitize: %w", err)
	}

	// 3. Detect
	violations, err := p.detector.Detect(ctx, sanitized)
	if err != nil {
		return nil, fmt.Errorf("promptlock: detect: %w", err)
	}
	result.Violations = append(result.Violations, violations...)

	// 4. Calculate score
	for _, v := range violations {
		result.Score += v.Weight
	}

	// 5. Judge (conditional)
	if p.judge != nil {
		shouldJudge := false
		switch p.config.Level {
		case Aggressive:
			shouldJudge = true
		case Balanced:
			// Judge on large inputs with no pattern violations
			shouldJudge = len(violations) == 0 && len(input) > 500
		}

		if shouldJudge {
			verdict, confidence, err := p.judge.Classify(ctx, sanitized)
			if err == nil {
				if verdict == judge.VerdictMalicious && confidence > 0.7 {
					v := detector.Violation{
						Rule:       "JUDGE_MALICIOUS",
						Category:   detector.CategoryInjection,
						Severity:   detector.SeverityHigh,
						Matched:    "classified as malicious by judge LLM",
						Confidence: confidence,
						Weight:     60,
					}
					result.Violations = append(result.Violations, v)
					result.Score += v.Weight
				} else if verdict == judge.VerdictSuspicious && confidence > 0.6 {
					v := detector.Violation{
						Rule:       "JUDGE_SUSPICIOUS",
						Category:   detector.CategoryInjection,
						Severity:   detector.SeverityMedium,
						Matched:    "classified as suspicious by judge LLM",
						Confidence: confidence,
						Weight:     25,
					}
					result.Violations = append(result.Violations, v)
					result.Score += v.Weight
				}
			}
			// Judge errors are non-fatal — we continue without judge input
		}
	}

	// 6. Compute verdict
	result.Verdict = VerdictFromScore(result.Score)
	result.Clean = result.Verdict == VerdictClean

	// 7. Fire violation callback
	if p.config.OnViolation != nil {
		for _, v := range result.Violations {
			p.config.OnViolation(v)
		}
	}

	// 8. Check if blocked
	blocked := isBlocked(p.config.Level, result.Verdict)
	if blocked {
		result.Output = ""
		result.Latency = time.Since(start)
		return result, &PromptLockError{
			Violations: result.Violations,
			Score:      result.Score,
			Verdict:    result.Verdict,
			Message:    "input contains suspected prompt injection",
		}
	}

	// 9. Vault — PII redaction (only if input passed detection)
	output := sanitized
	if p.redactor != nil {
		redacted, entities, err := p.redactor.Redact(ctx, output)
		if err != nil {
			return nil, fmt.Errorf("promptlock: redact: %w", err)
		}
		output = redacted
		result.Redactions = entities
	}

	// 10. Delimiter wrapping
	if p.delimiter != nil {
		wrapped, _, err := p.delimiter.Wrap(output)
		if err != nil {
			return nil, fmt.Errorf("promptlock: delimiter: %w", err)
		}
		output = wrapped
	}

	result.Output = output
	result.Latency = time.Since(start)
	return result, nil
}

// isBlocked determines if the input should be blocked based on security level and verdict.
func isBlocked(level SecurityLevel, verdict ScanVerdict) bool {
	switch level {
	case Basic:
		return verdict >= VerdictMalicious
	case Balanced:
		return verdict >= VerdictLikely
	case Aggressive:
		return verdict >= VerdictSuspicious
	default:
		return verdict >= VerdictMalicious
	}
}
