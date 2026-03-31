package interceptor

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// Provider identifies an LLM API provider.
type Provider int

const (
	ProviderUnknown   Provider = iota
	ProviderOpenAI             // api.openai.com
	ProviderAnthropic          // api.anthropic.com
	ProviderGemini             // generativelanguage.googleapis.com
	ProviderOllama             // localhost:11434
)

// providerConfig holds detection rules and content paths for each provider.
type providerConfig struct {
	provider     Provider
	urlContains  string
	roleField    string
	contentField string
}

var defaultProviders = []providerConfig{
	{
		provider:     ProviderOpenAI,
		urlContains:  "api.openai.com/v1/chat/completions",
		roleField:    "role",
		contentField: "content",
	},
	{
		provider:     ProviderAnthropic,
		urlContains:  "api.anthropic.com/v1/messages",
		roleField:    "role",
		contentField: "content",
	},
	{
		provider:     ProviderGemini,
		urlContains:  "generativelanguage.googleapis.com",
		roleField:    "role",
		contentField: "text",
	},
	{
		provider:     ProviderOllama,
		urlContains:  "/api/chat",
		roleField:    "role",
		contentField: "content",
	},
}

// detectProvider identifies the LLM provider from the request URL.
func detectProvider(req *http.Request, configs []providerConfig) (providerConfig, bool) {
	urlStr := req.URL.String()
	if req.URL.Host != "" {
		urlStr = req.URL.Host + req.URL.Path
	}

	for _, cfg := range configs {
		if strings.Contains(urlStr, cfg.urlContains) {
			return cfg, true
		}
	}
	return providerConfig{}, false
}

// extractUserContent parses the request body and returns user message content strings.
func extractUserContent(body []byte, cfg providerConfig) ([]string, error) {
	if cfg.provider == ProviderGemini {
		return extractGeminiContent(body)
	}
	return extractChatContent(body, cfg)
}

// extractChatContent handles OpenAI/Anthropic/Ollama format: messages[].content where role=user
func extractChatContent(body []byte, cfg providerConfig) ([]string, error) {
	var req struct {
		Messages []map[string]interface{} `json:"messages"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, fmt.Errorf("interceptor: unmarshal body: %w", err)
	}

	var contents []string
	for _, msg := range req.Messages {
		role, _ := msg[cfg.roleField].(string)
		if role != "user" {
			continue
		}
		content, ok := msg[cfg.contentField].(string)
		if ok && content != "" {
			contents = append(contents, content)
		}
	}
	return contents, nil
}

// extractGeminiContent handles Gemini format: contents[].parts[].text where role=user
func extractGeminiContent(body []byte) ([]string, error) {
	var req struct {
		Contents []struct {
			Role  string `json:"role"`
			Parts []struct {
				Text string `json:"text"`
			} `json:"parts"`
		} `json:"contents"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, fmt.Errorf("interceptor: unmarshal gemini body: %w", err)
	}

	var contents []string
	for _, c := range req.Contents {
		if c.Role != "user" {
			continue
		}
		for _, p := range c.Parts {
			if p.Text != "" {
				contents = append(contents, p.Text)
			}
		}
	}
	return contents, nil
}

// replaceUserContent rebuilds the request body with protected content.
func replaceUserContent(body []byte, cfg providerConfig, protected []string) ([]byte, error) {
	if cfg.provider == ProviderGemini {
		return replaceGeminiContent(body, protected)
	}
	return replaceChatContent(body, cfg, protected)
}

// replaceChatContent replaces user message content in OpenAI/Anthropic/Ollama format.
func replaceChatContent(body []byte, cfg providerConfig, protected []string) ([]byte, error) {
	var req map[string]interface{}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, fmt.Errorf("interceptor: unmarshal body: %w", err)
	}

	messages, ok := req["messages"].([]interface{})
	if !ok {
		return body, nil
	}

	idx := 0
	for _, m := range messages {
		msg, ok := m.(map[string]interface{})
		if !ok {
			continue
		}
		role, _ := msg[cfg.roleField].(string)
		if role != "user" {
			continue
		}
		if idx < len(protected) {
			msg[cfg.contentField] = protected[idx]
			idx++
		}
	}

	return json.Marshal(req)
}

// replaceGeminiContent replaces user content in Gemini format.
func replaceGeminiContent(body []byte, protected []string) ([]byte, error) {
	var req map[string]interface{}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, fmt.Errorf("interceptor: unmarshal body: %w", err)
	}

	contents, ok := req["contents"].([]interface{})
	if !ok {
		return body, nil
	}

	idx := 0
	for _, c := range contents {
		content, ok := c.(map[string]interface{})
		if !ok {
			continue
		}
		role, _ := content["role"].(string)
		if role != "user" {
			continue
		}
		parts, ok := content["parts"].([]interface{})
		if !ok {
			continue
		}
		for _, p := range parts {
			part, ok := p.(map[string]interface{})
			if !ok {
				continue
			}
			if _, hasText := part["text"]; hasText && idx < len(protected) {
				part["text"] = protected[idx]
				idx++
			}
		}
	}

	return json.Marshal(req)
}
