// Package interceptor provides an http.RoundTripper that transparently applies
// PromptLock protection to outgoing LLM API requests.
//
// Usage:
//
//	shield, _ := promptlock.New(promptlock.WithLevel(promptlock.Balanced))
//	client := &http.Client{
//	    Transport: interceptor.New(shield),
//	}
//	// Pass this client to your LLM SDK
package interceptor

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/rajanyadav/promptlock"
)

// InterceptorConfig configures the interceptor behavior.
type InterceptorConfig struct {
	FailOpen    bool             // If true, forward request on protection error (default: false)
	OnViolation func(error)      // Callback when injection detected
	OnError     func(error)      // Callback when protection fails
	SkipPaths   []string         // URL paths to skip
	Providers   []providerConfig // Provider configs to use
}

// Interceptor is an http.RoundTripper that applies Shield protection to LLM API requests.
type Interceptor struct {
	next    http.RoundTripper
	shield  *promptlock.Shield
	config  InterceptorConfig
}

// Option configures an Interceptor.
type Option func(*InterceptorConfig)

// WithFailOpen sets fail-open behavior. When true, requests are forwarded
// even if protection fails. Default is false (fail-closed).
func WithFailOpen(failOpen bool) Option {
	return func(c *InterceptorConfig) {
		c.FailOpen = failOpen
	}
}

// WithOnViolation sets a callback invoked when a prompt injection is detected.
func WithOnViolation(fn func(error)) Option {
	return func(c *InterceptorConfig) {
		c.OnViolation = fn
	}
}

// WithOnError sets a callback invoked when protection encounters an error.
func WithOnError(fn func(error)) Option {
	return func(c *InterceptorConfig) {
		c.OnError = fn
	}
}

// WithSkipPaths sets URL paths that should bypass protection.
func WithSkipPaths(paths ...string) Option {
	return func(c *InterceptorConfig) {
		c.SkipPaths = paths
	}
}

// WithProviders restricts interception to specific providers.
func WithProviders(providers ...Provider) Option {
	return func(c *InterceptorConfig) {
		c.Providers = nil
		for _, p := range providers {
			for _, dc := range defaultProviders {
				if dc.provider == p {
					c.Providers = append(c.Providers, dc)
				}
			}
		}
	}
}

// New creates an Interceptor that wraps the given Shield.
// The interceptor uses http.DefaultTransport as the underlying transport.
func New(shield *promptlock.Shield, opts ...Option) *Interceptor {
	cfg := InterceptorConfig{
		Providers: defaultProviders,
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	return &Interceptor{
		next:   http.DefaultTransport,
		shield: shield,
		config: cfg,
	}
}

// RoundTrip implements http.RoundTripper.
func (i *Interceptor) RoundTrip(req *http.Request) (*http.Response, error) {
	// Check if this request targets a known LLM provider
	provider, matched := detectProvider(req, i.config.Providers)
	if !matched {
		return i.next.RoundTrip(req)
	}

	// Check if this path should be skipped
	for _, skip := range i.config.SkipPaths {
		if strings.Contains(req.URL.Path, skip) {
			return i.next.RoundTrip(req)
		}
	}

	// Read request body
	if req.Body == nil {
		return i.next.RoundTrip(req)
	}
	body, err := io.ReadAll(req.Body)
	req.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("interceptor: read body: %w", err)
	}

	// Extract user content
	contents, err := extractUserContent(body, provider)
	if err != nil {
		return i.handleError(req, body, err)
	}

	if len(contents) == 0 {
		// No user content found, forward as-is
		req.Body = io.NopCloser(bytes.NewReader(body))
		return i.next.RoundTrip(req)
	}

	// Protect each user content string
	protected := make([]string, len(contents))
	for idx, content := range contents {
		safe, err := i.shield.Protect(req.Context(), content)
		if err != nil {
			if i.config.OnViolation != nil {
				i.config.OnViolation(err)
			}
			if !i.config.FailOpen {
				return nil, fmt.Errorf("interceptor: protection blocked: %w", err)
			}
			// Fail-open: use original content
			protected[idx] = content
			continue
		}
		protected[idx] = safe
	}

	// Replace content in body
	newBody, err := replaceUserContent(body, provider, protected)
	if err != nil {
		return i.handleError(req, body, err)
	}

	// Rebuild request
	req.Body = io.NopCloser(bytes.NewReader(newBody))
	req.ContentLength = int64(len(newBody))

	return i.next.RoundTrip(req)
}

// handleError handles errors during interception based on fail-open/closed config.
func (i *Interceptor) handleError(req *http.Request, originalBody []byte, err error) (*http.Response, error) {
	if i.config.OnError != nil {
		i.config.OnError(err)
	}
	if i.config.FailOpen {
		// Forward original request
		req.Body = io.NopCloser(bytes.NewReader(originalBody))
		return i.next.RoundTrip(req)
	}
	return nil, fmt.Errorf("interceptor: %w", err)
}
