package vault

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// PIIRedactor implements Redactor and Restorer for PII detection and masking.
type PIIRedactor struct {
	patterns          []piiPattern
	enabledTypes      map[EntityType]bool
	placeholderFormat string // e.g., "[%s_%d]"
}

// RedactorOption configures a PIIRedactor.
type RedactorOption func(*PIIRedactor)

// WithEntityTypes restricts detection to the specified entity types.
func WithEntityTypes(types ...EntityType) RedactorOption {
	return func(r *PIIRedactor) {
		r.enabledTypes = make(map[EntityType]bool, len(types))
		for _, t := range types {
			r.enabledTypes[t] = true
		}
	}
}

// WithCustomPattern adds a custom PII detection pattern.
func WithCustomPattern(name string, regex string) RedactorOption {
	return func(r *PIIRedactor) {
		r.patterns = append(r.patterns, piiPattern{
			entityType: EntityCustom,
			compiled:   regexp.MustCompile(regex),
		})
		_ = name // name is for documentation; EntityCustom is the type
	}
}

// WithPlaceholderFormat sets the placeholder format string.
// Must contain %s (type name) and %d (sequence number).
func WithPlaceholderFormat(format string) RedactorOption {
	return func(r *PIIRedactor) {
		r.placeholderFormat = format
	}
}

// NewPIIRedactor creates a PIIRedactor with the given options.
func NewPIIRedactor(opts ...RedactorOption) *PIIRedactor {
	r := &PIIRedactor{
		patterns:          defaultPatterns(),
		placeholderFormat: "[%s_%d]",
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// match represents a single PII match with its position.
type match struct {
	entityType EntityType
	original   string
	start      int
	end        int
}

// Redact detects and replaces PII with placeholder tokens.
func (r *PIIRedactor) Redact(_ context.Context, input string) (string, []RedactedEntity, error) {
	var matches []match

	for _, p := range r.patterns {
		// Skip disabled types
		if r.enabledTypes != nil && !r.enabledTypes[p.entityType] {
			continue
		}

		locs := p.compiled.FindAllStringIndex(input, -1)
		for _, loc := range locs {
			matched := input[loc[0]:loc[1]]

			// Run optional validator
			if p.validator != nil && !p.validator(matched) {
				continue
			}

			matches = append(matches, match{
				entityType: p.entityType,
				original:   matched,
				start:      loc[0],
				end:        loc[1],
			})
		}
	}

	if len(matches) == 0 {
		return input, nil, nil
	}

	// Remove overlapping matches (keep the longest)
	matches = removeOverlaps(matches)

	// Sort by offset ascending for sequential processing
	sort.Slice(matches, func(i, j int) bool {
		return matches[i].start < matches[j].start
	})

	// Build result with placeholders
	// Track value->placeholder for dedup (same email gets same placeholder)
	valueToPlaceholder := make(map[string]string)
	typeCounters := make(map[EntityType]int)
	var entities []RedactedEntity

	var b strings.Builder
	b.Grow(len(input))
	lastEnd := 0

	for _, m := range matches {
		// Write text before this match
		b.WriteString(input[lastEnd:m.start])

		// Get or create placeholder
		placeholder, exists := valueToPlaceholder[m.original]
		if !exists {
			typeCounters[m.entityType]++
			placeholder = fmt.Sprintf(r.placeholderFormat, m.entityType.String(), typeCounters[m.entityType])
			valueToPlaceholder[m.original] = placeholder
		}

		b.WriteString(placeholder)
		lastEnd = m.end

		entities = append(entities, RedactedEntity{
			Type:        m.entityType,
			Original:    m.original,
			Placeholder: placeholder,
			Offset:      m.start,
			Length:      m.end - m.start,
		})
	}

	// Write remaining text
	b.WriteString(input[lastEnd:])

	return b.String(), entities, nil
}

// Restore replaces placeholders with original values.
func (r *PIIRedactor) Restore(redacted string, entities []RedactedEntity) string {
	result := redacted
	for _, e := range entities {
		result = strings.Replace(result, e.Placeholder, e.Original, 1)
	}
	return result
}

// removeOverlaps removes overlapping matches, keeping the longest match.
func removeOverlaps(matches []match) []match {
	if len(matches) <= 1 {
		return matches
	}

	// Sort by start position, then by length descending
	sort.Slice(matches, func(i, j int) bool {
		if matches[i].start == matches[j].start {
			return (matches[i].end - matches[i].start) > (matches[j].end - matches[j].start)
		}
		return matches[i].start < matches[j].start
	})

	var result []match
	result = append(result, matches[0])
	for i := 1; i < len(matches); i++ {
		last := result[len(result)-1]
		if matches[i].start >= last.end {
			result = append(result, matches[i])
		}
	}
	return result
}
