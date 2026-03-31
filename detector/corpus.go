package detector

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sync"
)

//go:embed corpus/attacks.json
var defaultCorpusJSON []byte

var (
	defaultCorpusOnce sync.Once
	defaultCorpusVal  []AttackSample
	defaultCorpusErr  error
)

// DefaultCorpus returns the embedded default attack corpus.
func DefaultCorpus() ([]AttackSample, error) {
	defaultCorpusOnce.Do(func() {
		if err := json.Unmarshal(defaultCorpusJSON, &defaultCorpusVal); err != nil {
			defaultCorpusErr = fmt.Errorf("detector: parse corpus: %w", err)
		}
	})
	if defaultCorpusErr != nil {
		return nil, defaultCorpusErr
	}
	result := make([]AttackSample, len(defaultCorpusVal))
	copy(result, defaultCorpusVal)
	return result, nil
}
