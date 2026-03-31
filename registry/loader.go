package registry

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const maxFileSize = 1 << 20 // 1MB

// patternFile is the JSON envelope for a pattern file.
type patternFile struct {
	Patterns []Pattern `json:"patterns"`
}

// LoadFromFile loads patterns from a JSON file at the given path.
func LoadFromFile(path string) ([]Pattern, error) {
	clean := filepath.Clean(path)
	if strings.Contains(clean, "..") {
		return nil, fmt.Errorf("registry: load: path traversal detected in %q", path)
	}

	f, err := os.Open(clean)
	if err != nil {
		return nil, fmt.Errorf("registry: load: %w", err)
	}
	defer f.Close()

	return LoadFromReader(f)
}

// LoadFromReader loads patterns from an io.Reader containing JSON data.
func LoadFromReader(r io.Reader) ([]Pattern, error) {
	limited := io.LimitReader(r, maxFileSize+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("registry: load: read: %w", err)
	}
	if len(data) > maxFileSize {
		return nil, fmt.Errorf("registry: load: file exceeds %d byte limit", maxFileSize)
	}

	var pf patternFile
	if err := json.Unmarshal(data, &pf); err != nil {
		return nil, fmt.Errorf("registry: load: unmarshal: %w", err)
	}

	for i, p := range pf.Patterns {
		if err := Validate(p); err != nil {
			return nil, fmt.Errorf("registry: load: pattern[%d] %q: %w", i, p.ID, err)
		}
	}

	return pf.Patterns, nil
}
