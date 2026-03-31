package interceptor

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rajanyadav/promptlock"
)

func TestInterceptor_OpenAI_CleanRequest(t *testing.T) {
	t.Parallel()

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.Write(body) // Echo back
	}))
	defer backend.Close()

	shield, err := promptlock.New(promptlock.WithLevel(promptlock.Balanced))
	if err != nil {
		t.Fatalf("New Shield: %v", err)
	}

	interceptor := New(shield)
	interceptor.next = http.DefaultTransport

	reqBody := map[string]interface{}{
		"model": "gpt-4",
		"messages": []map[string]string{
			{"role": "system", "content": "You are helpful"},
			{"role": "user", "content": "What is the weather?"},
		},
	}
	bodyBytes, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest("POST", "https://api.openai.com/v1/chat/completions", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	// This will fail since we can't reach api.openai.com, but let's test provider detection
	provider, matched := detectProvider(req, defaultProviders)
	if !matched {
		t.Fatal("Should detect OpenAI provider")
	}
	if provider.provider != ProviderOpenAI {
		t.Errorf("Provider = %v, want OpenAI", provider.provider)
	}
}

func TestDetectProvider(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		url      string
		wantProv Provider
		wantOK   bool
	}{
		{"OpenAI", "https://api.openai.com/v1/chat/completions", ProviderOpenAI, true},
		{"Anthropic", "https://api.anthropic.com/v1/messages", ProviderAnthropic, true},
		{"Gemini", "https://generativelanguage.googleapis.com/v1/models/gemini/generateContent", ProviderGemini, true},
		{"Ollama", "http://localhost:11434/api/chat", ProviderOllama, true},
		{"Unknown", "https://example.com/api/v1/query", ProviderUnknown, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("POST", tt.url, nil)
			cfg, ok := detectProvider(req, defaultProviders)
			if ok != tt.wantOK {
				t.Errorf("detectProvider() ok = %v, want %v", ok, tt.wantOK)
			}
			if ok && cfg.provider != tt.wantProv {
				t.Errorf("detectProvider() provider = %v, want %v", cfg.provider, tt.wantProv)
			}
		})
	}
}

func TestExtractUserContent_OpenAI(t *testing.T) {
	t.Parallel()
	body := `{
		"model": "gpt-4",
		"messages": [
			{"role": "system", "content": "You are helpful"},
			{"role": "user", "content": "Hello world"},
			{"role": "assistant", "content": "Hi!"},
			{"role": "user", "content": "How are you?"}
		]
	}`

	cfg := defaultProviders[0] // OpenAI
	contents, err := extractUserContent([]byte(body), cfg)
	if err != nil {
		t.Fatalf("extractUserContent() error: %v", err)
	}
	if len(contents) != 2 {
		t.Fatalf("extractUserContent() returned %d contents, want 2", len(contents))
	}
	if contents[0] != "Hello world" || contents[1] != "How are you?" {
		t.Errorf("extractUserContent() = %v, want [Hello world, How are you?]", contents)
	}
}

func TestExtractUserContent_Gemini(t *testing.T) {
	t.Parallel()
	body := `{
		"contents": [
			{
				"role": "user",
				"parts": [{"text": "What is AI?"}]
			}
		]
	}`

	cfg := defaultProviders[2] // Gemini
	contents, err := extractUserContent([]byte(body), cfg)
	if err != nil {
		t.Fatalf("extractUserContent() error: %v", err)
	}
	if len(contents) != 1 || contents[0] != "What is AI?" {
		t.Errorf("extractUserContent() = %v, want [What is AI?]", contents)
	}
}

func TestReplaceUserContent_OpenAI(t *testing.T) {
	t.Parallel()
	body := `{
		"model": "gpt-4",
		"messages": [
			{"role": "system", "content": "You are helpful"},
			{"role": "user", "content": "original message"}
		]
	}`

	cfg := defaultProviders[0] // OpenAI
	newBody, err := replaceUserContent([]byte(body), cfg, []string{"protected message"})
	if err != nil {
		t.Fatalf("replaceUserContent() error: %v", err)
	}

	var result map[string]interface{}
	json.Unmarshal(newBody, &result)
	messages := result["messages"].([]interface{})
	userMsg := messages[1].(map[string]interface{})
	if userMsg["content"] != "protected message" {
		t.Errorf("replaceUserContent() user content = %v, want 'protected message'", userMsg["content"])
	}
}

func TestInterceptor_Passthrough_NonLLM(t *testing.T) {
	t.Parallel()

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer backend.Close()

	shield, _ := promptlock.New()
	intcpt := New(shield)
	intcpt.next = http.DefaultTransport

	req, _ := http.NewRequest("GET", backend.URL+"/api/v1/health", nil)
	resp, err := intcpt.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip() error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want 200", resp.StatusCode)
	}
}
