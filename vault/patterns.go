package vault

import (
	"regexp"
	"strings"
)

// piiPattern holds a compiled regex and optional validator for one PII type.
type piiPattern struct {
	entityType EntityType
	compiled   *regexp.Regexp
	validator  func(match string) bool // optional secondary validation
}

// defaultPatterns returns the built-in PII detection patterns.
func defaultPatterns() []piiPattern {
	return []piiPattern{
		{
			entityType: EntityEmail,
			compiled:   regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`),
		},
		{
			entityType: EntityPhone,
			compiled:   regexp.MustCompile(`(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}`),
		},
		{
			entityType: EntityCreditCard,
			compiled:   regexp.MustCompile(`\b(?:\d[ -]*?){13,19}\b`),
			validator:  luhnCheck,
		},
		{
			entityType: EntitySSN,
			compiled:   regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
		},
		{
			entityType: EntityAPIKey,
			compiled:   regexp.MustCompile(`(?:sk-[a-zA-Z0-9]{20,}|key-[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16})`),
		},
		{
			entityType: EntityIPAddress,
			compiled:   regexp.MustCompile(`\b(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b`),
		},
	}
}

// luhnCheck validates a potential credit card number using the Luhn algorithm.
func luhnCheck(s string) bool {
	// Strip spaces and dashes
	var digits []int
	for _, c := range s {
		if c >= '0' && c <= '9' {
			digits = append(digits, int(c-'0'))
		} else if c != ' ' && c != '-' {
			return false
		}
	}

	if len(digits) < 13 || len(digits) > 19 {
		return false
	}

	sum := 0
	double := false
	for i := len(digits) - 1; i >= 0; i-- {
		d := digits[i]
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum%10 == 0
}

// stripNonDigits removes all non-digit characters from a string.
func stripNonDigits(s string) string {
	var b strings.Builder
	for _, c := range s {
		if c >= '0' && c <= '9' {
			b.WriteRune(c)
		}
	}
	return b.String()
}
