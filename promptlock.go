// Package promptlock provides defense-in-depth protection against prompt injection
// attacks for LLM-integrated applications.
//
// PromptLock acts as a security layer between user input and the LLM, neutralizing
// malicious injections, jailbreaks, and PII leaks before they reach the model.
//
// Basic usage:
//
//	shield, err := promptlock.New(
//	    promptlock.WithLevel(promptlock.Balanced),
//	    promptlock.WithRedactPII(true),
//	)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	safe, err := shield.Protect(ctx, userInput)
//	if err != nil {
//	    // Input was blocked — handle the PromptLockError
//	    var plErr *promptlock.PromptLockError
//	    if errors.As(err, &plErr) {
//	        log.Printf("blocked: %s (score=%d)", plErr.Verdict, plErr.Score)
//	    }
//	    return
//	}
//	// safe is sanitized, PII-redacted, and delimiter-wrapped
package promptlock

import (
	"context"
	"fmt"
)

// Shield is the main entry point for PromptLock protection.
// It is safe for concurrent use after construction.
type Shield struct {
	pipeline *pipeline
	config   Config
}

// New creates a Shield with the given options.
func New(opts ...Option) (*Shield, error) {
	cfg := Config{
		Level: Balanced,
	}
	for _, opt := range opts {
		opt(&cfg)
	}
	cfg.applyDefaults()

	p, err := buildPipeline(cfg)
	if err != nil {
		return nil, fmt.Errorf("promptlock: build pipeline: %w", err)
	}

	return &Shield{
		pipeline: p,
		config:   cfg,
	}, nil
}

// Protect runs the full protection pipeline on user input.
// Returns the protected output string, or a *PromptLockError if the input is blocked.
func (s *Shield) Protect(ctx context.Context, input string) (string, error) {
	result, err := s.pipeline.run(ctx, input)
	if err != nil {
		return "", err
	}
	return result.Output, nil
}

// VerifyContext scans retrieved RAG context chunks for indirect injections.
// Each chunk is processed through the same pipeline as Protect.
// Returns clean chunks and an error if any chunk is blocked.
func (s *Shield) VerifyContext(ctx context.Context, chunks []string) ([]string, error) {
	clean := make([]string, 0, len(chunks))
	for i, chunk := range chunks {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("promptlock: verify context: %w", err)
		}
		result, err := s.pipeline.run(ctx, chunk)
		if err != nil {
			// If a chunk is blocked, skip it but don't fail the whole batch
			if _, ok := err.(*PromptLockError); ok {
				continue
			}
			return nil, fmt.Errorf("promptlock: verify context chunk[%d]: %w", i, err)
		}
		clean = append(clean, result.Output)
	}
	return clean, nil
}

// ProtectWithResult runs the full pipeline and returns detailed scan results.
func (s *Shield) ProtectWithResult(ctx context.Context, input string) (*ScanResult, error) {
	return s.pipeline.run(ctx, input)
}
