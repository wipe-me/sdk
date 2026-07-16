package wipeme

import "testing"

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
