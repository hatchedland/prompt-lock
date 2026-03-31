// Package sanitizer provides input normalization and cleaning for untrusted text.
//
// The sanitizer is the first stage of the PromptLock pipeline. It transforms
// raw user input into a canonical form so downstream detectors can reliably
// match patterns regardless of encoding tricks or Unicode exploits.
package sanitizer

import (
	"context"
	"fmt"
)

// Sanitizer transforms untrusted input into a normalized, safe-to-analyze form.
type Sanitizer interface {
	Sanitize(ctx context.Context, input string) (string, error)
}

// Pipeline chains multiple Sanitizers sequentially.
// The output of each sanitizer becomes the input of the next.
type Pipeline struct {
	sanitizers []Sanitizer
}

// NewPipeline creates a sanitizer pipeline that runs the given sanitizers in order.
func NewPipeline(sanitizers ...Sanitizer) *Pipeline {
	return &Pipeline{sanitizers: sanitizers}
}

// Sanitize runs all sanitizers in sequence. Returns the first error encountered.
func (p *Pipeline) Sanitize(ctx context.Context, input string) (string, error) {
	result := input
	for i, s := range p.sanitizers {
		if err := ctx.Err(); err != nil {
			return "", fmt.Errorf("sanitizer: pipeline stage %d: %w", i, err)
		}
		var err error
		result, err = s.Sanitize(ctx, result)
		if err != nil {
			return "", fmt.Errorf("sanitizer: pipeline stage %d: %w", i, err)
		}
	}
	return result, nil
}
