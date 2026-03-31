// Example: using PromptLock as HTTP middleware (interceptor).
package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/rajanyadav/promptlock"
	"github.com/rajanyadav/promptlock/interceptor"
)

func main() {
	// Create a Shield
	shield, err := promptlock.New(
		promptlock.WithLevel(promptlock.Aggressive),
		promptlock.WithRedactPII(true),
	)
	if err != nil {
		log.Fatal(err)
	}

	// Wrap the HTTP client with the interceptor
	client := &http.Client{
		Transport: interceptor.New(shield,
			interceptor.WithProviders(interceptor.ProviderOpenAI, interceptor.ProviderAnthropic),
			interceptor.WithFailOpen(false),
			interceptor.WithOnViolation(func(err error) {
				log.Printf("[SECURITY] Prompt injection blocked: %v", err)
			}),
			interceptor.WithSkipPaths("/v1/embeddings", "/v1/models"),
		),
	}

	fmt.Println("PromptLock interceptor configured.")
	fmt.Println("Pass this client to your LLM SDK:")
	fmt.Println()
	fmt.Println("  openaiClient := openai.NewClient(apiKey,")
	fmt.Println("      openai.WithHTTPClient(client),")
	fmt.Println("  )")
	fmt.Println()
	fmt.Println("All outgoing chat completion requests will be")
	fmt.Println("automatically scanned for prompt injections.")

	_ = client // Use with your LLM SDK
}
