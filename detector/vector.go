package detector

import (
	"context"
	"fmt"
	"math"
	"sync"
)

// Embedder produces vector embeddings for text.
type Embedder interface {
	Embed(ctx context.Context, text string) ([]float32, error)
}

// AttackSample is a known attack text used to build the vector store.
type AttackSample struct {
	Text     string `json:"text"`
	Label    string `json:"label"`
	Category string `json:"category"`
}

// attackVector is a pre-computed embedding of an attack sample.
type attackVector struct {
	sample    AttackSample
	embedding []float32
	category  Category
}

// VectorDetector uses embedding similarity to detect prompt injections
// that are semantically similar to known attack patterns.
//
// At detection time, the input is embedded and compared via cosine similarity
// against a corpus of known attack embeddings. Matches above the threshold
// are returned as violations.
//
// Embeddings are computed lazily on the first Detect() call via sync.Once.
type VectorDetector struct {
	embedder  Embedder
	corpus    []AttackSample
	threshold float64
	maxWeight int

	initOnce sync.Once
	initErr  error
	vectors  []attackVector
}

// VectorOption configures a VectorDetector.
type VectorOption func(*VectorDetector)

// WithSimilarityThreshold sets the cosine similarity threshold above which
// an input is considered a match. Default is 0.82.
func WithSimilarityThreshold(t float64) VectorOption {
	return func(d *VectorDetector) {
		d.threshold = t
	}
}

// WithAttackCorpus sets the attack samples used to build the vector store.
func WithAttackCorpus(corpus []AttackSample) VectorOption {
	return func(d *VectorDetector) {
		d.corpus = corpus
	}
}

// WithMaxVectorWeight sets the maximum violation weight for vector matches.
// The actual weight scales with similarity: weight = int(similarity * maxWeight).
// Default is 70.
func WithMaxVectorWeight(w int) VectorOption {
	return func(d *VectorDetector) {
		d.maxWeight = w
	}
}

// NewVectorDetector creates a VectorDetector with the given embedder and options.
func NewVectorDetector(embedder Embedder, opts ...VectorOption) *VectorDetector {
	d := &VectorDetector{
		embedder:  embedder,
		threshold: 0.82,
		maxWeight: 70,
	}
	for _, opt := range opts {
		opt(d)
	}
	return d
}

// Detect embeds the input and compares it against known attack vectors.
// Returns violations for any matches above the similarity threshold.
func (d *VectorDetector) Detect(ctx context.Context, input string) ([]Violation, error) {
	// Lazy-initialize attack vector embeddings
	d.initOnce.Do(func() {
		d.initErr = d.buildVectors(ctx)
	})
	if d.initErr != nil {
		return nil, fmt.Errorf("detector: vector init: %w", d.initErr)
	}

	if len(d.vectors) == 0 {
		return nil, nil
	}

	// Embed the input
	inputEmb, err := d.embedder.Embed(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("detector: embed input: %w", err)
	}

	// Scan against all attack vectors
	var violations []Violation
	seen := make(map[string]bool)

	for _, av := range d.vectors {
		if err := ctx.Err(); err != nil {
			return violations, err
		}

		sim := cosineSimilarity(inputEmb, av.embedding)
		if sim < d.threshold {
			continue
		}

		ruleID := "VECTOR_" + av.sample.Label
		if seen[ruleID] {
			continue
		}
		seen[ruleID] = true

		weight := int(sim * float64(d.maxWeight))

		violations = append(violations, Violation{
			Rule:       ruleID,
			Category:   av.category,
			Severity:   SeverityHigh,
			Matched:    fmt.Sprintf("similar to %q (%.0f%%)", av.sample.Label, sim*100),
			Confidence: sim,
			Weight:     weight,
		})
	}

	return violations, nil
}

// buildVectors computes embeddings for all attack samples.
func (d *VectorDetector) buildVectors(ctx context.Context) error {
	if len(d.corpus) == 0 {
		return nil
	}

	d.vectors = make([]attackVector, 0, len(d.corpus))
	for _, sample := range d.corpus {
		if err := ctx.Err(); err != nil {
			return err
		}

		emb, err := d.embedder.Embed(ctx, sample.Text)
		if err != nil {
			return fmt.Errorf("embed sample %q: %w", sample.Label, err)
		}

		cat, _ := ParseCategory(sample.Category)

		d.vectors = append(d.vectors, attackVector{
			sample:    sample,
			embedding: emb,
			category:  cat,
		})
	}
	return nil
}

// cosineSimilarity computes the cosine similarity between two vectors.
func cosineSimilarity(a, b []float32) float64 {
	if len(a) != len(b) || len(a) == 0 {
		return 0
	}

	var dot, normA, normB float64
	for i := range a {
		ai, bi := float64(a[i]), float64(b[i])
		dot += ai * bi
		normA += ai * ai
		normB += bi * bi
	}

	if normA == 0 || normB == 0 {
		return 0
	}
	return dot / (math.Sqrt(normA) * math.Sqrt(normB))
}
