// Package server provides gRPC and REST servers wrapping the PromptLock Shield.
package server

import (
	"fmt"

	"github.com/rajanyadav/promptlock"
	"github.com/rajanyadav/promptlock/detector"
)

// Config holds server configuration.
type Config struct {
	GRPCPort   int
	HTTPPort   int
	Level      string // "basic", "balanced", "aggressive"
	RedactPII  bool
	OllamaURL  string
	OllamaModel string
}

// NewShield creates a PromptLock Shield from server config.
func NewShield(cfg Config) (*promptlock.Shield, error) {
	var level promptlock.SecurityLevel
	switch cfg.Level {
	case "basic":
		level = promptlock.Basic
	case "balanced", "":
		level = promptlock.Balanced
	case "aggressive":
		level = promptlock.Aggressive
	default:
		return nil, fmt.Errorf("unknown security level: %q", cfg.Level)
	}

	opts := []promptlock.Option{
		promptlock.WithLevel(level),
		promptlock.WithRedactPII(cfg.RedactPII),
	}

	// Enable vector detection if Ollama is configured
	if cfg.OllamaURL != "" {
		model := cfg.OllamaModel
		if model == "" {
			model = "nomic-embed-text"
		}
		embedder := detector.NewOllamaEmbedder(
			detector.WithOllamaEndpoint(cfg.OllamaURL),
			detector.WithOllamaModel(model),
		)
		opts = append(opts, promptlock.WithEmbedder(embedder))
	}

	return promptlock.New(opts...)
}
