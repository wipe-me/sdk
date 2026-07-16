package wipeme

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

const (
	testID   = "1K7mQ2xR8VpC"
	testHash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	testKey  = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
)

func newTestClient(t *testing.T, handler http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()
	server := httptest.NewServer(handler)
	client, err := NewClient(ClientOptions{BaseURL: server.URL, ClientID: "mobile-ios"})
	if err != nil {
		t.Fatal(err)
	}
	client.now = func() time.Time { return time.Unix(1_800_000_000, 0) }
	return client, server
}

func TestCreateSendsBinaryEnvelopeAndHeaders(t *testing.T) {
	envelope := []byte{0, 1, 2, 0xff}
	client, server := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Path != "/api/messages/"+testID {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		body, _ := io.ReadAll(r.Body)
		if !bytes.Equal(body, envelope) {
			t.Errorf("body = %v", body)
		}
		wantHeaders := map[string]string{
			"Content-Type": "application/octet-stream", "X-Wipe-Content-Hash": testHash,
			"X-Wipe-Deletion-Key": testKey, "X-Wipe-Cipher-Version": "1",
			"X-Wipe-Expires-At": "1800086400000", "X-Wipe-Client": "mobile-ios",
		}
		for name, want := range wantHeaders {
			if got := r.Header.Get(name); got != want {
				t.Errorf("%s = %q, want %q", name, got, want)
			}
		}
		if got := r.Header.Get("X-Wipe-On-Read"); got != "" {
			t.Errorf("obsolete X-Wipe-On-Read sent: %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"id":"`+testID+`","created":true}`)
	})
	defer server.Close()

	result, err := client.CreateMessage(context.Background(), CreateMessageRequest{
		MessageID: testID, Envelope: envelope, ContentHash: testHash, DeletionKey: testKey,
		ExpiresAt: client.now().Add(24 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.ID != testID || !result.Created {
		t.Fatalf("unexpected result %+v", result)
	}
}

func TestRetrieveReturnsOpaqueBinaryAndMetadata(t *testing.T) {
	envelope := []byte{0xde, 0xad, 0, 0xbe, 0xef}
	client, server := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %s", r.Method)
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("X-Wipe-Content-Hash", testHash)
		w.Header().Set("X-Wipe-Cipher-Version", "1")
		_, _ = w.Write(envelope)
	})
	defer server.Close()
	result, err := client.RetrieveMessage(context.Background(), testID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(result.Envelope, envelope) || result.ContentHash != testHash || result.CipherVersion != 1 {
		t.Fatalf("unexpected result %+v", result)
	}
}

func TestDeleteAndHealth(t *testing.T) {
	client, server := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodDelete:
			if r.Header.Get("X-Wipe-Deletion-Key") != testKey {
				t.Error("missing deletion key")
			}
			_, _ = io.WriteString(w, `{"deleted":true}`)
		case r.Method == http.MethodGet && r.URL.Path == "/health":
			_, _ = io.WriteString(w, `{"status":"ok"}`)
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	})
	defer server.Close()
	deleted, err := client.DeleteMessage(context.Background(), testID, testKey)
	if err != nil || !deleted.Deleted {
		t.Fatalf("delete = %+v, %v", deleted, err)
	}
	health, err := client.Health(context.Background())
	if err != nil || health.Status != "ok" {
		t.Fatalf("health = %+v, %v", health, err)
	}
}

func TestTypedAPIErrorSupportsErrorsAs(t *testing.T) {
	client, server := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Retry-After", "99")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(w, `{"error":"Slow down","code":"message_rate_limited","retryAfter":42}`)
	})
	defer server.Close()
	_, err := client.Health(context.Background())
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected APIError, got %T: %v", err, err)
	}
	if apiErr.StatusCode != 429 || apiErr.Code != "message_rate_limited" || apiErr.Message != "Slow down" || apiErr.RetryAfter != 42 {
		t.Fatalf("unexpected APIError %+v", apiErr)
	}
	if extracted, ok := AsAPIError(err); !ok || extracted != apiErr {
		t.Fatal("AsAPIError failed")
	}
}

func TestLegacyErrorPayloadAndRetryHeader(t *testing.T) {
	client, server := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "12")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, `{"error":"Try later"}`)
	})
	defer server.Close()
	_, err := client.Health(context.Background())
	apiErr, ok := AsAPIError(err)
	if !ok || apiErr.Message != "Try later" || apiErr.RetryAfter != 12 {
		t.Fatalf("unexpected error %+v", apiErr)
	}
}

func TestCreateValidatesFreeLimitsBeforeRequest(t *testing.T) {
	requests := 0
	client, server := newTestClient(t, func(http.ResponseWriter, *http.Request) { requests++ })
	defer server.Close()
	valid := CreateMessageRequest{MessageID: testID, Envelope: []byte{1}, ContentHash: testHash, DeletionKey: testKey, ExpiresAt: client.now().Add(time.Hour)}

	cases := []struct {
		name   string
		mutate func(*CreateMessageRequest)
	}{
		{"empty", func(r *CreateMessageRequest) { r.Envelope = nil }},
		{"too large", func(r *CreateMessageRequest) { r.Envelope = make([]byte, MaxFreeMessageSize+1) }},
		{"too late", func(r *CreateMessageRequest) { r.ExpiresAt = client.now().Add(MaxFreeExpiry + time.Millisecond) }},
		{"past", func(r *CreateMessageRequest) { r.ExpiresAt = client.now().Add(-time.Second) }},
		{"hash", func(r *CreateMessageRequest) { r.ContentHash = "ABC" }},
		{"key", func(r *CreateMessageRequest) { r.DeletionKey = "no" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input := valid
			tc.mutate(&input)
			if _, err := client.CreateMessage(context.Background(), input); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
	if requests != 0 {
		t.Fatalf("validation made %d requests", requests)
	}
}

func TestClientIDIsExtensibleButValidated(t *testing.T) {
	for _, value := range []string{"web", "cli", "sdk-go", "mobile-ios", "partner.app_v2"} {
		if _, err := NewClient(ClientOptions{ClientID: value}); err != nil {
			t.Errorf("%q rejected: %v", value, err)
		}
	}
	for _, value := range []string{"Mobile", "-bad", "spaces fail", string(make([]byte, 33))} {
		if _, err := NewClient(ClientOptions{ClientID: value}); err == nil {
			t.Errorf("%q accepted", value)
		}
	}
}

func TestClientRejectsFragmentInBaseURL(t *testing.T) {
	if _, err := NewClient(ClientOptions{BaseURL: "https://wipe.me/#private-secret"}); err == nil {
		t.Fatal("expected private fragment in API base URL to be rejected")
	}
}
