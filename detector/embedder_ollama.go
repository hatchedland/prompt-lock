package detector

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// OllamaEmbedder implements Embedder using Ollama's local embedding API.
type OllamaEmbedder struct {
	endpoint   string
	model      string
	httpClient *http.Client
}

// OllamaOption configures an OllamaEmbedder.
type OllamaOption func(*OllamaEmbedder)

// WithOllamaEndpoint sets the Ollama API endpoint.
func WithOllamaEndpoint(url string) OllamaOption {
	return func(e *OllamaEmbedder) {
		e.endpoint = url
	}
}

// WithOllamaModel sets the embedding model name.
func WithOllamaModel(model string) OllamaOption {
	return func(e *OllamaEmbedder) {
		e.model = model
	}
}

// WithOllamaHTTPClient sets a custom HTTP client.
func WithOllamaHTTPClient(c *http.Client) OllamaOption {
	return func(e *OllamaEmbedder) {
		e.httpClient = c
	}
}

// NewOllamaEmbedder creates an embedder that uses a local Ollama instance.
// Default model: nomic-embed-text. Default endpoint: http://localhost:11434.
func NewOllamaEmbedder(opts ...OllamaOption) *OllamaEmbedder {
	e := &OllamaEmbedder{
		endpoint:   "http://localhost:11434",
		model:      "nomic-embed-text",
		httpClient: &http.Client{},
	}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

type ollamaEmbedRequest struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
}

type ollamaEmbedResponse struct {
	Embedding []float64 `json:"embedding"`
}

// Embed sends text to Ollama and returns the embedding vector.
func (e *OllamaEmbedder) Embed(ctx context.Context, text string) ([]float32, error) {
	reqBody := ollamaEmbedRequest{
		Model:  e.model,
		Prompt: text,
	}
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("ollama: marshal: %w", err)
	}

	url := e.endpoint + "/api/embeddings"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("ollama: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ollama: request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20)) // 10MB limit
	if err != nil {
		return nil, fmt.Errorf("ollama: read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ollama: status %d: %s", resp.StatusCode, string(respBody))
	}

	var embedResp ollamaEmbedResponse
	if err := json.Unmarshal(respBody, &embedResp); err != nil {
		return nil, fmt.Errorf("ollama: unmarshal: %w", err)
	}

	if len(embedResp.Embedding) == 0 {
		return nil, fmt.Errorf("ollama: empty embedding returned")
	}

	// Convert float64 to float32
	result := make([]float32, len(embedResp.Embedding))
	for i, v := range embedResp.Embedding {
		result[i] = float32(v)
	}
	return result, nil
}
