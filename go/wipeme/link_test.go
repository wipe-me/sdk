package wipeme

import (
	"bytes"
	"testing"
)

func TestRandomCapabilitiesUseCanonicalBase58(t *testing.T) {
	messageID, err := randomBase58(MessageIDLength, bytes.NewReader(bytes.Repeat([]byte{255, 0, 1, 2, 3, 4, 5, 6}, 16)))
	if err != nil {
		t.Fatal(err)
	}
	secret, err := randomBase58(SecretLength, bytes.NewReader(bytes.Repeat([]byte{7, 8, 9, 10, 11, 12, 13, 14}, 16)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NormalizeBase58(messageID, MessageIDLength); err != nil {
		t.Fatal(err)
	}
	if _, err := NormalizeBase58(secret, SecretLength); err != nil {
		t.Fatal(err)
	}
}

func TestPrivateLinkRoundTrip(t *testing.T) {
	link, err := FormatPrivateLink("https://wipe.me", "1K7mQ2xR8VpC", "7YWHMfk9JCB7P4eG")
	if err != nil {
		t.Fatal(err)
	}
	if link != "https://wipe.me/1K7m-Q2xR-8VpC#7YWH-Mfk9-JCB7-P4eG" {
		t.Fatalf("unexpected link %q", link)
	}
	id, secret, err := ParsePrivateLink(link)
	if err != nil {
		t.Fatal(err)
	}
	if id != "1K7mQ2xR8VpC" || secret != "7YWHMfk9JCB7P4eG" {
		t.Fatalf("unexpected capabilities %q %q", id, secret)
	}
}

func TestRejectsAmbiguousBase58(t *testing.T) {
	if _, err := NormalizeBase58("0K7mQ2xR8VpC", MessageIDLength); err == nil {
		t.Fatal("expected validation error")
	}
}
