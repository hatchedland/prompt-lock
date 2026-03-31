// Package vault provides PII detection and redaction for untrusted input.
//
// The vault detects personally identifiable information (email, phone, credit cards,
// SSNs, API keys) and replaces them with placeholder tokens before the input
// reaches an LLM API. An optional Restorer can reverse the redaction.
package vault

import "context"

// EntityType classifies the kind of PII detected.
type EntityType int

const (
	EntityEmail      EntityType = iota
	EntityPhone
	EntityCreditCard
	EntitySSN
	EntityAPIKey
	EntityIPAddress
	EntityCustom
)

// String returns the string representation of an EntityType.
func (t EntityType) String() string {
	switch t {
	case EntityEmail:
		return "EMAIL"
	case EntityPhone:
		return "PHONE"
	case EntityCreditCard:
		return "CREDIT_CARD"
	case EntitySSN:
		return "SSN"
	case EntityAPIKey:
		return "API_KEY"
	case EntityIPAddress:
		return "IP_ADDRESS"
	case EntityCustom:
		return "CUSTOM"
	default:
		return "UNKNOWN"
	}
}

// RedactedEntity represents a single piece of PII that was found and masked.
type RedactedEntity struct {
	Type        EntityType
	Original    string // Handle with care — do not log this value.
	Placeholder string // The replacement token, e.g., "[EMAIL_1]"
	Offset      int    // Byte offset in original input
	Length      int    // Length of original value in bytes
}

// Redactor detects and masks PII in text.
type Redactor interface {
	Redact(ctx context.Context, input string) (string, []RedactedEntity, error)
}

// Restorer reverses redaction, replacing placeholders with original values.
type Restorer interface {
	Restore(redacted string, entities []RedactedEntity) string
}
