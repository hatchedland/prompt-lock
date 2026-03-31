package registry

import (
	"bytes"
	_ "embed"
	"fmt"
	"sync"
)

//go:embed patterns/default.json
var defaultPatternsJSON []byte

var (
	defaultPatternsOnce sync.Once
	defaultPatternsVal  []Pattern
	defaultPatternsErr  error
)

// DefaultPatterns returns the embedded default pattern set.
// The patterns are parsed and validated on first call and cached for subsequent calls.
func DefaultPatterns() ([]Pattern, error) {
	defaultPatternsOnce.Do(func() {
		defaultPatternsVal, defaultPatternsErr = LoadFromReader(bytes.NewReader(defaultPatternsJSON))
		if defaultPatternsErr != nil {
			defaultPatternsErr = fmt.Errorf("registry: embedded defaults: %w", defaultPatternsErr)
		}
	})
	if defaultPatternsErr != nil {
		return nil, defaultPatternsErr
	}
	result := make([]Pattern, len(defaultPatternsVal))
	copy(result, defaultPatternsVal)
	return result, nil
}
