// Package wipeme implements the Wipe.me protocol and API.
package wipeme

import (
	"fmt"
	"net/url"
	"strings"
)

const (
	Base58BTCAlphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	MessageIDLength   = 12
	SecretLength      = 16
	ProtocolVersion   = 1
	ChunkSize         = 4 * 1024 * 1024
)

// NormalizeBase58 removes presentation separators and validates Base58BTC text.
func NormalizeBase58(value string, expectedLength int) (string, error) {
	value = strings.ReplaceAll(strings.ReplaceAll(value, "-", ""), " ", "")
	if len(value) != expectedLength {
		return "", fmt.Errorf("expected %d Base58 characters, got %d", expectedLength, len(value))
	}
	for _, character := range value {
		if !strings.ContainsRune(Base58BTCAlphabet, character) {
			return "", fmt.Errorf("invalid Base58 character %q", character)
		}
	}
	return value, nil
}

// GroupBase58 inserts presentation dashes at the requested interval.
func GroupBase58(value string, size int) (string, error) {
	if size < 1 {
		return "", fmt.Errorf("group size must be positive")
	}
	parts := make([]string, 0, (len(value)+size-1)/size)
	for start := 0; start < len(value); start += size {
		end := start + size
		if end > len(value) {
			end = len(value)
		}
		parts = append(parts, value[start:end])
	}
	return strings.Join(parts, "-"), nil
}

// ParsePrivateLink returns canonical link capabilities. Callers must never send Secret to the service.
func ParsePrivateLink(value string) (messageID, secret string, err error) {
	parsed, err := url.Parse(value)
	if err != nil {
		return "", "", fmt.Errorf("parse private link: %w", err)
	}
	segments := strings.Split(strings.Trim(parsed.Path, "/"), "/")
	messageID, err = NormalizeBase58(segments[len(segments)-1], MessageIDLength)
	if err != nil {
		return "", "", err
	}
	secret, err = NormalizeBase58(parsed.Fragment, SecretLength)
	if err != nil {
		return "", "", err
	}
	return messageID, secret, nil
}

// FormatPrivateLink produces the grouped, human-readable private link.
func FormatPrivateLink(site, messageID, secret string) (string, error) {
	parsed, err := url.Parse(site)
	if err != nil {
		return "", fmt.Errorf("parse site URL: %w", err)
	}
	messageID, err = NormalizeBase58(messageID, MessageIDLength)
	if err != nil {
		return "", err
	}
	secret, err = NormalizeBase58(secret, SecretLength)
	if err != nil {
		return "", err
	}
	groupedID, _ := GroupBase58(messageID, 4)
	groupedSecret, _ := GroupBase58(secret, 4)
	parsed.Path = strings.TrimRight(parsed.Path, "/") + "/" + groupedID
	parsed.Fragment = groupedSecret
	return parsed.String(), nil
}
